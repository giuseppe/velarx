// SPDX-License-Identifier: Apache-2.0
//! `multipart/form-data` bodies (podman's manifest modify with artifact
//! files): the parts of a spooled body, each written to a sealed memory
//! file (the engine takes it as a descriptor), with their names.

use std::fs::File;
use std::io::{self, Read, Seek, Write};

/// The chunks of a body, read by a blocking reader.
pub struct Chunks {
    rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    current: bytes::Bytes,
}

impl Chunks {
    pub fn new(rx: tokio::sync::mpsc::Receiver<bytes::Bytes>) -> Self {
        Self {
            rx,
            current: bytes::Bytes::new(),
        }
    }
}

impl Read for Chunks {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.current.is_empty() {
            match self.rx.blocking_recv() {
                Some(c) => self.current = c,
                None => return Ok(0),
            }
        }
        let n = buf.len().min(self.current.len());
        buf[..n].copy_from_slice(&self.current.split_to(n));
        Ok(n)
    }
}

/// The most bytes of the headers of a part.
const MAX_HEADERS: usize = 16 * 1024;

#[derive(Debug)]
pub struct Part {
    /// The `name` of its Content-Disposition.
    pub name: String,
    pub filename: Option<String>,
    /// Its content: a sealed memory file.
    pub content: File,
}

/// A memory file for a part.
fn memory_file() -> io::Result<File> {
    use rustix::fs::{memfd_create, MemfdFlags};
    let fd = memfd_create("part", MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)?;
    Ok(File::from(fd))
}

/// The file written and sealed: nothing changes it.
fn sealed(mut f: File) -> io::Result<File> {
    use rustix::fs::{fcntl_add_seals, SealFlags};
    f.flush()?;
    f.rewind()?;
    fcntl_add_seals(
        &f,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )?;
    Ok(f)
}

fn invalid(m: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.into())
}

/// A parameter of a Content-Disposition header (`name="x"`).
fn disposition_param(header: &str, key: &str) -> Option<String> {
    for p in header.split(';').skip(1) {
        let Some((k, v)) = p.split_once('=') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case(key) {
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(v);
            return Some(v.replace("\\\"", "\"").replace("\\\\", "\\"));
        }
    }
    None
}

/// A reader with the bytes read but not used yet.
struct Buffered<R> {
    r: R,
    buf: Vec<u8>,
}

impl<R: Read> Buffered<R> {
    /// Read more; false at the end of the input.
    fn fill(&mut self) -> io::Result<bool> {
        let len = self.buf.len();
        self.buf.resize(len + 64 * 1024, 0);
        let n = match self.r.read(&mut self.buf[len..]) {
            Ok(n) => n,
            Err(e) => {
                self.buf.truncate(len);
                return Err(e);
            }
        };
        self.buf.truncate(len + n);
        Ok(n > 0)
    }

    /// A line (without its end), at most `max` bytes; None at the end.
    fn line(&mut self, max: usize) -> io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(nl) = self.buf.iter().position(|&b| b == b'\n') {
                let mut line: Vec<u8> = self.buf.drain(..=nl).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(Some(line));
            }
            if self.buf.len() > max {
                return Err(invalid("a line of the multipart body is too long"));
            }
            if !self.fill()? {
                return Ok(None);
            }
        }
    }

    /// Copy to `out` up to `delimiter`, then take what ends its line: `--`
    /// (the last part: true) or a line end.  As Go's reader, the delimiter
    /// counts only when a space, a tab, a line end or `--` follows it; else
    /// it is content.
    fn copy_until(&mut self, delimiter: &[u8], out: &mut dyn Sink) -> io::Result<bool> {
        // (the search starts at `from`: the bytes before it are content not
        // written yet, nothing is moved for a delimiter that is content)
        let mut from = 0;
        loop {
            if let Some(i) = find(&self.buf[from..], delimiter).map(|i| from + i) {
                // (what follows the delimiter decides)
                while self.buf.len() < i + delimiter.len() + 2 {
                    if !self.fill()? {
                        break;
                    }
                }
                let next = &self.buf[i + delimiter.len()..];
                match next.first() {
                    None => return Err(invalid("the multipart body ends in a delimiter")),
                    Some(b'-') if next.get(1) == Some(&b'-') => {
                        out.content(&self.buf[..i])?;
                        return Ok(true);
                    }
                    Some(b' ' | b'\t' | b'\r' | b'\n') => {
                        out.content(&self.buf[..i])?;
                        self.buf.drain(..i + delimiter.len());
                        // The rest of the delimiter line (transport padding).
                        self.line(MAX_HEADERS)?
                            .ok_or_else(|| invalid("the multipart body ends in a delimiter"))?;
                        return Ok(false);
                    }
                    Some(_) => {
                        // Not a delimiter: content, and the search goes on
                        // after its first byte.
                        from = i + 1;
                        continue;
                    }
                }
            }
            // Keep what could be the start of the delimiter.
            let keep = delimiter.len() - 1;
            if self.buf.len() > keep {
                let n = self.buf.len() - keep;
                out.content(&self.buf[..n])?;
                self.buf.drain(..n);
                from = from.saturating_sub(n);
            }
            if !self.fill()? {
                return Err(invalid("the multipart body ends in a part"));
            }
        }
    }
}

/// The error of a body with more parts than its caller takes.
#[derive(Debug)]
pub struct TooManyParts;

impl std::fmt::Display for TooManyParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("too many parts in the multipart body")
    }
}

impl std::error::Error for TooManyParts {}

/// Where the parts of a multipart body go, one after the other.
pub trait Sink {
    /// A part starts: its name and its file name.
    fn open(&mut self, name: &str, filename: Option<&str>) -> io::Result<()>;
    /// A piece of the content of the part.
    fn content(&mut self, data: &[u8]) -> io::Result<()>;
    /// The content of the part ended.
    fn close(&mut self) -> io::Result<()>;
}

/// Go through the parts of the body in `input` (delimited by `boundary`), at
/// most `max_parts` of them: one more is [`TooManyParts`], before its
/// content is read.  Nothing of a part is held but what `sink` holds.
pub fn each_part(
    input: impl Read,
    boundary: &str,
    max_parts: usize,
    sink: &mut dyn Sink,
) -> io::Result<()> {
    let mut r = Buffered {
        r: input,
        buf: Vec::new(),
    };
    let dash = format!("--{boundary}");
    // The preamble, up to the first delimiter line.
    loop {
        let line = r
            .line(MAX_HEADERS)?
            .ok_or_else(|| invalid("no part in the multipart body"))?;
        if line.trim_ascii_end() == dash.as_bytes() {
            break;
        }
    }
    let delimiter = format!("\r\n--{boundary}").into_bytes();
    let mut count = 0;
    loop {
        if count >= max_parts {
            return Err(io::Error::other(TooManyParts));
        }
        count += 1;
        let mut name = None;
        let mut filename = None;
        let mut seen = 0usize;
        loop {
            let line = r
                .line(MAX_HEADERS)?
                .ok_or_else(|| invalid("truncated headers in the multipart body"))?;
            seen += line.len();
            if seen > MAX_HEADERS {
                return Err(invalid("the headers of a part are too long"));
            }
            if line.is_empty() {
                break;
            }
            let text = String::from_utf8_lossy(&line).into_owned();
            if let Some((k, v)) = text.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-disposition") {
                    name = disposition_param(v, "name");
                    filename = disposition_param(v, "filename");
                }
            }
        }
        sink.open(name.as_deref().unwrap_or_default(), filename.as_deref())?;
        let last = r.copy_until(&delimiter, sink)?;
        sink.close()?;
        if last {
            return Ok(());
        }
    }
}

/// The parts of a body as sealed memory files.
#[derive(Default)]
struct Held {
    parts: Vec<Part>,
    /// The part being read: its name, its file name and its file
    open: Option<(String, Option<String>, std::io::BufWriter<File>)>,
}

impl Sink for Held {
    fn open(&mut self, name: &str, filename: Option<&str>) -> io::Result<()> {
        let out = std::io::BufWriter::new(memory_file()?);
        self.open = Some((name.to_string(), filename.map(str::to_string), out));
        Ok(())
    }

    fn content(&mut self, data: &[u8]) -> io::Result<()> {
        match &mut self.open {
            Some((_, _, out)) => out.write_all(data),
            None => Ok(()),
        }
    }

    fn close(&mut self) -> io::Result<()> {
        if let Some((name, filename, out)) = self.open.take() {
            let content = sealed(out.into_inner().map_err(|e| e.into_error())?)?;
            self.parts.push(Part {
                name,
                filename,
                content,
            });
        }
        Ok(())
    }
}

/// Split the body in `input` (delimited by `boundary`) into its parts, at
/// most `max_parts` of them, each in a sealed memory file.
pub fn split(input: impl Read, boundary: &str, max_parts: usize) -> io::Result<Vec<Part>> {
    let mut held = Held::default();
    each_part(input, boundary, max_parts, &mut held)?;
    Ok(held.parts)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let first = needle[0];
    let mut start = 0;
    while let Some(off) = haystack[start..=haystack.len() - needle.len()]
        .iter()
        .position(|&b| b == first)
    {
        let i = start + off;
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
        start = i + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts_of(body: &[u8], boundary: &str) -> io::Result<Vec<(Part, Vec<u8>)>> {
        let parts = split(body, boundary, 10)?;
        Ok(parts
            .into_iter()
            .map(|mut p| {
                let mut data = Vec::new();
                p.content.read_to_end(&mut data).unwrap();
                (p, data)
            })
            .collect())
    }

    #[test]
    fn a_large_part() {
        let mut body = b"--b\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\n".to_vec();
        let data: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();
        body.extend_from_slice(&data);
        body.extend_from_slice(b"\r\n--b--");
        let parts = parts_of(&body, "b").unwrap();
        assert_eq!(parts[0].1, data);
    }

    #[test]
    fn the_parts_have_their_names_and_are_sealed() {
        let body = b"preamble\r\n--b\r\nContent-Disposition: form-data; name=\"r\"\r\n\r\n{}\r\n--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a/b.txt\"\r\n\r\nhi\r\n--b--\r\n";
        let parts = parts_of(body, "b").unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(
            (parts[0].0.name.as_str(), parts[0].1.as_slice()),
            ("r", &b"{}"[..])
        );
        assert_eq!(parts[1].0.filename.as_deref(), Some("a/b.txt"));
        assert_eq!(parts[1].1, b"hi");
        // (a sealed file cannot be written)
        let mut again = parts.into_iter().nth(1).unwrap().0.content;
        assert!(again.write_all(b"x").is_err());
        assert!(split(&b"no part"[..], "b", 10).is_err());
    }

    #[test]
    fn a_delimiter_followed_by_other_bytes_is_content() {
        // (as Go's reader: `--b` then a byte that is not a space, a tab, a
        // line end or a second dash does not end the part)
        let body = b"--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nx\r\n--bz\r\n--b-y\r\n--b \r\nContent-Disposition: form-data; name=\"g\"\r\n\r\ny\r\n--b--";
        let parts = parts_of(body, "b").unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].1, b"x\r\n--bz\r\n--b-y");
        assert_eq!(parts[1].1, b"y");
    }

    /// Delimiters that are content are copied with the content around them,
    /// in large pieces (each was a write of its own and a move of the rest
    /// of the buffer).
    #[test]
    fn delimiters_that_are_content_are_copied_in_large_pieces() {
        struct Counted(Vec<u8>, usize);
        impl Sink for Counted {
            fn open(&mut self, _: &str, _: Option<&str>) -> io::Result<()> {
                Ok(())
            }
            fn content(&mut self, data: &[u8]) -> io::Result<()> {
                self.0.extend_from_slice(data);
                self.1 += 1;
                Ok(())
            }
            fn close(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let data = b"\r\n--bz".repeat(1 << 16);
        let mut body = b"--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n".to_vec();
        body.extend_from_slice(&data);
        body.extend_from_slice(b"\r\n--b--");
        let mut copied = Counted(Vec::new(), 0);
        each_part(&body[..], "b", 10, &mut copied).unwrap();
        assert!(copied.0 == data);
        assert!(copied.1 < 64, "{} writes", copied.1);
    }

    #[test]
    fn a_part_more_than_the_caller_takes_is_refused_before_its_content() {
        let mut body = Vec::new();
        for i in 0..3 {
            body.extend_from_slice(
                format!("--b\r\nContent-Disposition: form-data; name=\"p{i}\"\r\n\r\nx\r\n")
                    .as_bytes(),
            );
        }
        body.extend_from_slice(b"--b--");
        assert_eq!(split(&body[..], "b", 3).unwrap().len(), 3);
        let e = split(&body[..], "b", 2).unwrap_err();
        assert!(e.get_ref().is_some_and(|e| e.is::<TooManyParts>()), "{e}");
    }

    #[test]
    fn truncated_bodies_are_errors() {
        for body in [
            &b"--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nx"[..],
            b"--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nx\r\n--b",
            b"--b\r\nContent-Disposition: form-data; name=\"f\"\r\n",
            b"",
        ] {
            assert!(
                split(body, "b", 10).is_err(),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }
}
