// SPDX-License-Identifier: Apache-2.0
//! The archive a Docker daemon saves, read from the connection to its
//! socket: `GET /images/NAME/get` of the Engine API answers the tar of
//! `docker save`, which the reader of a docker-archive takes from there.
//! One request with `Connection: close`, no more of HTTP than that needs:
//! the status, the length or the chunks of the body.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;

/// The most a status line, or the headers all together, may have.
const MAX_HEAD: u64 = 64 * 1024;

/// The most of an error's body that is read, for its message.
const MAX_ERROR: u64 = 4096;

fn invalid(why: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why.into())
}

/// The path `reference` has in a request: what is not a character of a
/// name stays out of the request line.
fn escaped(reference: &str) -> String {
    reference
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~'
            | b'/'
            | b':'
            | b'@' => char::from(b).to_string(),
            b => format!("%{b:02X}"),
        })
        .collect()
}

/// What a chunked body gives, chunk after chunk.
struct Chunked<R> {
    inner: R,
    /// What is left of the current chunk
    left: u64,
    done: bool,
}

impl<R: BufRead> Chunked<R> {
    /// The size of the next chunk, at the line that says it.
    fn next_chunk(&mut self) -> io::Result<u64> {
        let mut line = String::new();
        (&mut self.inner).take(MAX_HEAD).read_line(&mut line)?;
        let size = line.split(';').next().unwrap_or("").trim();
        u64::from_str_radix(size, 16).map_err(|_| invalid("the daemon sent a bad chunk size"))
    }

    /// The line break after the data of a chunk.
    fn end_chunk(&mut self) -> io::Result<()> {
        let mut crlf = [0u8; 2];
        self.inner.read_exact(&mut crlf)?;
        if &crlf != b"\r\n" {
            return Err(invalid("the daemon sent a chunk with no end"));
        }
        Ok(())
    }
}

impl<R: BufRead> Read for Chunked<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            self.left = self.next_chunk()?;
            if self.left == 0 {
                self.done = true;
                return Ok(0);
            }
        }
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.left -= n as u64;
        if self.left == 0 {
            self.end_chunk()?;
        }
        Ok(n)
    }
}

/// What the headers of a response say.
struct Head {
    status: u16,
    chunked: bool,
    length: Option<u64>,
}

fn read_head(from: &mut impl BufRead) -> io::Result<Head> {
    let mut from = from.take(MAX_HEAD);
    let mut line = String::new();
    from.read_line(&mut line)?;
    let status = line
        .strip_prefix("HTTP/1.")
        .and_then(|rest| rest.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| invalid("the daemon did not answer with HTTP"))?;
    let mut head = Head {
        status,
        chunked: false,
        length: None,
    };
    loop {
        line.clear();
        if from.read_line(&mut line)? == 0 {
            return Err(invalid(
                "the headers of the daemon are cut short or too long",
            ));
        }
        let line = line.trim_end();
        if line.is_empty() {
            return Ok(head);
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("the daemon sent a header that is no header"))?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            head.chunked = value.eq_ignore_ascii_case("chunked");
        } else if name.eq_ignore_ascii_case("content-length") {
            head.length = value.parse().ok();
        }
    }
}

/// What the daemon says of an error: its `message`, or the text.
fn message(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("message")?.as_str().map(str::to_string))
        .unwrap_or_else(|| String::from_utf8_lossy(body).trim().to_string())
}

/// Ask the daemon on `socket` for the archive of `reference` and write it
/// to `out`, which is refused when it passes `max` bytes.  A daemon that has
/// no such image is `NotFound`, one that answers otherwise is `Other`, and
/// one that is no daemon is `InvalidData`.
pub fn save(socket: File, reference: &str, out: &File, max: u64) -> io::Result<()> {
    let mut stream = UnixStream::from(std::os::fd::OwnedFd::from(socket));
    write!(
        stream,
        "GET /images/{}/get HTTP/1.1\r\nHost: docker\r\nAccept: application/x-tar\r\nConnection: close\r\n\r\n",
        escaped(reference)
    )?;
    let mut from = BufReader::new(stream);
    let head = read_head(&mut from)?;
    let mut body: Box<dyn Read> = match (head.chunked, head.length) {
        (true, _) => Box::new(Chunked {
            inner: from,
            left: 0,
            done: false,
        }),
        (false, Some(length)) => Box::new(from.take(length)),
        (false, None) => Box::new(from),
    };
    if head.status != 200 {
        let mut text = Vec::new();
        body.take(MAX_ERROR).read_to_end(&mut text)?;
        let kind = if head.status == 404 {
            io::ErrorKind::NotFound
        } else {
            io::ErrorKind::Other
        };
        return Err(io::Error::new(
            kind,
            format!("the Docker daemon: {} ({})", message(&text), head.status),
        ));
    }
    let copied = velarx_storage::copy_sparse(&mut (&mut body).take(max + 1), out, |_| {})?;
    if copied > max {
        return Err(invalid(format!("the image is larger than {max} bytes")));
    }
    if !head.chunked && head.length.is_some_and(|length| copied != length) {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A daemon that answers each request with `answer` (the whole text of
    /// the response) and tells the request line it got.
    fn daemon(answer: Vec<u8>) -> (File, std::thread::JoinHandle<String>) {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let served = std::thread::spawn(move || {
            let mut from = BufReader::new(theirs.try_clone().unwrap());
            let mut request = String::new();
            from.read_line(&mut request).unwrap();
            (&theirs).write_all(&answer).unwrap();
            request
        });
        (File::from(std::os::fd::OwnedFd::from(ours)), served)
    }

    fn saved(answer: &[u8], reference: &str, max: u64) -> (io::Result<Vec<u8>>, String) {
        let (socket, served) = daemon(answer.to_vec());
        let out = tempfile::tempfile().unwrap();
        let result = save(socket, reference, &out, max).map(|()| {
            let mut data = vec![0u8; out.metadata().unwrap().len() as usize];
            std::os::unix::fs::FileExt::read_exact_at(&out, &mut data, 0).unwrap();
            data
        });
        (result, served.join().unwrap())
    }

    #[test]
    fn the_name_of_an_image_is_a_path_that_cannot_break_the_request() {
        assert_eq!(escaped("alpine:3"), "alpine:3");
        assert_eq!(escaped("quay.io/a/b@sha256:ab"), "quay.io/a/b@sha256:ab");
        assert_eq!(escaped("a?b#c d%"), "a%3Fb%23c%20d%25");
    }

    #[test]
    fn a_chunked_body_is_the_archive() {
        let (got, request) = saved(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/x-tar\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;x=y\r\n world\r\n0\r\n\r\n",
            "alpine:3",
            1 << 20,
        );
        assert_eq!(got.unwrap(), b"hello world");
        assert_eq!(request, "GET /images/alpine:3/get HTTP/1.1\r\n");
    }

    #[test]
    fn a_body_of_a_length_or_to_the_end_is_the_archive() {
        let (got, _) = saved(
            b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello!",
            "a",
            100,
        );
        assert_eq!(got.unwrap(), b"hello");
        let (got, _) = saved(b"HTTP/1.0 200 OK\r\n\r\nhello!", "a", 100);
        assert_eq!(got.unwrap(), b"hello!");
    }

    #[test]
    fn what_the_daemon_refuses_is_said_with_its_message() {
        let (got, _) = saved(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 40\r\n\r\n{\"message\":\"No such image: nope:latest\"}\n",
            "nope",
            100,
        );
        let e = got.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert!(e.to_string().contains("No such image: nope:latest"), "{e}");
        let (got, _) = saved(b"HTTP/1.1 500 x\r\n\r\nboom", "a", 100);
        let e = got.unwrap_err();
        assert!(
            e.to_string().contains("boom") && e.to_string().contains("500"),
            "{e}"
        );
    }

    #[test]
    fn what_is_no_daemon_or_is_too_large_is_refused() {
        let (got, _) = saved(b"SSH-2.0-x\r\n\r\n", "a", 100);
        assert_eq!(got.unwrap_err().kind(), io::ErrorKind::InvalidData);
        let (got, _) = saved(b"HTTP/1.1 200 OK\r\n\r\n0123456789", "a", 9);
        assert_eq!(got.unwrap_err().kind(), io::ErrorKind::InvalidData);
        let (got, _) = saved(b"HTTP/1.1 200 OK\r\nno header\r\n\r\nx", "a", 100);
        assert_eq!(got.unwrap_err().kind(), io::ErrorKind::InvalidData);
        // (cut short of its length, or in a chunk)
        let (got, _) = saved(
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nhello",
            "a",
            100,
        );
        assert_eq!(got.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        let (got, _) = saved(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nhello",
            "a",
            100,
        );
        assert_eq!(got.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        let (got, _) = saved(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            "a",
            100,
        );
        assert_eq!(got.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
