// SPDX-License-Identifier: Apache-2.0
//! The request line of a connection, made acceptable to hyper.
//!
//! podman's server (Go's net/http) takes a query with `"`, `<` or `>` as
//! is, so scripts send JSON filters unencoded (`?filters={"name":["a"]}`),
//! as podman's own test suite does; hyper refuses such a request with an
//! empty 400.  [`FirstLine`] percent-encodes those bytes in the request
//! target of the first request of a connection, which is what such clients
//! send: one request per connection.  The requests that follow on the same
//! connection are passed as they are, since after an attach or an exec the
//! client sends the bytes of the process, which must not be touched.
//!
//! The framing cannot change: only the request target (between the first
//! and the last space of the line) is rewritten, only printable bytes that
//! the http crate refuses there are encoded, and the line ending, the
//! headers and the body are passed as they are.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The longest first line looked at; a longer one is passed as it is.
const MAX_LINE: usize = 16 * 1024;

enum State {
    /// Reading the first line.
    Line(Vec<u8>),
    /// Giving what was read, from the position.
    Drain(Vec<u8>, usize),
    Pass,
}

pub struct FirstLine<S> {
    inner: S,
    state: State,
}

impl<S: std::os::fd::AsFd> std::os::fd::AsFd for FirstLine<S> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl<S> FirstLine<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            state: State::Line(Vec::new()),
        }
    }
}

/// Whether the request target cannot have `b` as is, in its query or in
/// its path; Go's server accepts all of them.
fn needs_encoding(b: u8, in_query: bool) -> bool {
    match b {
        b'<' | b'>' => true,
        b'"' => in_query,
        b'`' => !in_query,
        _ => false,
    }
}

/// `line` with the bytes of its request target that hyper refuses
/// percent-encoded; anything that is not a request line stays as it is.
pub fn fix_request_line(line: &[u8]) -> Vec<u8> {
    let Some(sp1) = line.iter().position(|&b| b == b' ') else {
        return line.to_vec();
    };
    let Some(sp2) = line.iter().rposition(|&b| b == b' ') else {
        return line.to_vec();
    };
    if sp2 <= sp1 + 1 || !line[..sp1].iter().all(u8::is_ascii_uppercase) {
        return line.to_vec();
    }
    let mut out = Vec::with_capacity(line.len() + 32);
    out.extend_from_slice(&line[..=sp1]);
    let mut in_query = false;
    for &b in &line[sp1 + 1..sp2] {
        if b == b'?' {
            in_query = true;
        }
        if needs_encoding(b, in_query) {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        } else {
            out.push(b);
        }
    }
    out.extend_from_slice(&line[sp2..]);
    out
}

impl<S: AsyncRead + Unpin> AsyncRead for FirstLine<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            match &mut this.state {
                State::Pass => return Pin::new(&mut this.inner).poll_read(cx, buf),
                State::Drain(data, pos) => {
                    let n = (data.len() - *pos).min(buf.remaining());
                    buf.put_slice(&data[*pos..*pos + n]);
                    *pos += n;
                    if *pos == data.len() {
                        this.state = State::Pass;
                    }
                    return Poll::Ready(Ok(()));
                }
                State::Line(line) => {
                    let mut chunk = [0u8; 4096];
                    let mut rb = ReadBuf::new(&mut chunk);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {}
                    }
                    let eof = rb.filled().is_empty();
                    line.extend_from_slice(rb.filled());
                    let data = if let Some(end) = line.iter().position(|&b| b == b'\n') {
                        let mut data = fix_request_line(&line[..end]);
                        data.extend_from_slice(&line[end..]);
                        data
                    } else if eof || line.len() >= MAX_LINE {
                        std::mem::take(line)
                    } else {
                        continue;
                    };
                    this.state = if data.is_empty() {
                        State::Pass
                    } else {
                        State::Drain(data, 0)
                    };
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FirstLine<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    async fn read_all(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        FirstLine::new(input).read_to_end(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn the_query_of_the_first_request_is_encoded() {
        let out = read_all(b"GET /v1/x?filters={\"a\":[\"<b>\"]} HTTP/1.1\r\nHost: x\r\n\r\nGET /?\"\" HTTP/1.1\r\n").await;
        assert_eq!(
            out,
            b"GET /v1/x?filters={%22a%22:[%22%3Cb%3E%22]} HTTP/1.1\r\nHost: x\r\n\r\nGET /?\"\" HTTP/1.1\r\n"
        );
    }

    #[tokio::test]
    async fn the_path_keeps_what_hyper_takes() {
        let out = read_all(b"GET /a\"`<b HTTP/1.1\r\n\r\n").await;
        assert_eq!(out, b"GET /a\"%60%3Cb HTTP/1.1\r\n\r\n");
    }

    #[tokio::test]
    async fn what_is_not_a_request_line_is_left_alone() {
        for input in [
            &b"get /?\" HTTP/1.1\r\n"[..],
            b"\"\"\n",
            b"no newline \"",
            b"",
        ] {
            assert_eq!(read_all(input).await, input);
        }
        let long = vec![b'"'; MAX_LINE + 10];
        assert_eq!(read_all(&long).await, long);
    }

    #[tokio::test]
    async fn the_framing_is_left_alone() {
        let head = b"POST /v1/x?f={\"a b\"} HTTP/1.1\r\n";
        let rest = b"Content-Length: 9\r\nTransfer-Encoding: chunked\r\n\r\n{\"x\":\"<\"}GET /?\" HTTP/1.1\r\n\r\n";
        let input = [&head[..], &rest[..]].concat();
        let out = read_all(&input).await;
        let end = out.iter().position(|&b| b == b'\n').unwrap();
        assert_eq!(&out[end + 1..], rest, "only the first line changes");
        let line = &out[..=end];
        assert_eq!(line, b"POST /v1/x?f={%22a b%22} HTTP/1.1\r\n");
        // the method, the version and every space, CR and LF stay
        let spaces = |l: &[u8]| {
            l.iter()
                .filter(|&&b| b == b' ' || b == b'\r' || b == b'\n')
                .count()
        };
        assert_eq!(spaces(line), spaces(head));
        assert!(line.starts_with(b"POST ") && line.ends_with(b" HTTP/1.1\r\n"));
        // nothing but the percent encoding of the refused bytes is added
        let decoded = String::from_utf8_lossy(line).replace("%22", "\"");
        assert_eq!(decoded.as_bytes(), head);
    }

    #[test]
    fn valid_requests_are_unchanged() {
        let line = b"POST /v6.0.0/libpod/containers/create?name=a%20b HTTP/1.1";
        assert_eq!(fix_request_line(line), line);
    }
}
