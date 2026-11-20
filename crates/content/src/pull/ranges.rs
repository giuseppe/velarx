// SPDX-License-Identifier: Apache-2.0
//! Range requests on a blob: what is checked of the answers (the requests
//! are made by the registry fetcher, `velarx_registry_lib::net::ranges`).
//!
//! A request carries several ranges (`Range: bytes=a-b,c-d`); the answer is a
//! `multipart/byteranges` body, a single `206` part, or, from a server that
//! ignores `Range`, the whole blob.  The body is parsed as it arrives and the
//! bytes are handed out with their offset in the blob.  Every part must be one
//! of the ranges asked for, in order: the server cannot make us accept other
//! bytes than the ones we requested.

use bytes::Bytes;
use std::ops::Range;
use velarx_proto::transfer::FailureClass;
use velarx_types::ImageError;

/// Longest header block of a part.
const MAX_PART_HEADERS: usize = 8 * 1024;

/// Bytes of preamble tolerated before the first boundary.
const MAX_PREAMBLE: usize = 4 * 1024;

/// `Range` header limits: ranges per request and the size of the value.
pub const MAX_RANGES_PER_REQUEST: usize = 64;
pub const MAX_RANGE_HEADER: usize = 4096;

#[derive(Debug)]
pub enum RangesError {
    /// The server refuses the request (400, 416, the status): fewer ranges
    /// may work.
    Rejected(u16),
    /// The server cannot give a part of the blob: it answered a request
    /// for more than a prefix with the whole blob (it ignores `Range`), or
    /// refused a single range; its body was not read.  The blob is asked
    /// once, whole, and the parts are read from what came.
    WholeBlob,
    Other(ImageError),
}

impl From<ImageError> for RangesError {
    fn from(e: ImageError) -> Self {
        RangesError::Other(e)
    }
}

pub fn bad(msg: impl Into<String>) -> RangesError {
    RangesError::Other(ImageError::transfer(
        "registry",
        FailureClass::Unavailable,
        msg,
    ))
}

/// What the client learnt of the range requests of a registry: a
/// lower limit of ranges per request (it refused more with 400 or 416),
/// and whether it ignores `Range` (it answered 200 with the whole blob).
/// Kept per registry host for the life of the process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Learnt {
    pub per_request: Option<usize>,
    pub whole: bool,
}

static LEARNT: std::sync::Mutex<Option<std::collections::HashMap<String, Learnt>>> =
    std::sync::Mutex::new(None);
/// Registries remembered
const MAX_LEARNT: usize = 256;

fn learn(host: &str, f: impl FnOnce(&mut Learnt)) {
    let mut m = LEARNT.lock().unwrap_or_else(|e| e.into_inner());
    let m = m.get_or_insert_with(Default::default);
    if m.len() >= MAX_LEARNT && !m.contains_key(host) {
        m.clear();
    }
    f(m.entry(host.to_string()).or_default());
}

/// What is known of the range requests of the registry `host`.
pub fn learnt(host: &str) -> Learnt {
    LEARNT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(host).copied())
        .unwrap_or_default()
}

/// The registry refused a request of more ranges than `n`.
pub fn lower_limit(host: &str, n: usize) {
    learn(host, |l| {
        l.per_request = Some(n.max(1).min(l.per_request.unwrap_or(usize::MAX)))
    });
}

/// The registry answers range requests with the whole blob.
pub fn ignores_ranges(host: &str) {
    learn(host, |l| l.whole = true);
}

/// The bytes of the ranges of a request handed to their members: the
/// chunks each range holds, each after the gap of bytes nobody asked for
/// that precedes it (merged ranges).
pub struct Assembler {
    /// Per range: (gap before, length) of each member
    members: Vec<Vec<(u64, usize)>>,
    state: Vec<Assembly>,
}

struct Assembly {
    next: usize,
    skip: u64,
    acc: bytes::BytesMut,
}

impl Assembler {
    pub fn new(members: Vec<Vec<(u64, usize)>>) -> Self {
        let state = members
            .iter()
            .map(|m| Assembly {
                next: 0,
                skip: m.first().map_or(0, |(gap, _)| *gap),
                acc: bytes::BytesMut::new(),
            })
            .collect();
        Self { members, state }
    }

    /// The members of `range` that `data`, its next bytes, completes (by
    /// their index in the range), and how many bytes were gaps.
    pub fn push(
        &mut self,
        range: usize,
        mut data: Bytes,
    ) -> Result<(Vec<(usize, Bytes)>, u64), RangesError> {
        let (Some(a), Some(members)) = (self.state.get_mut(range), self.members.get(range)) else {
            return Err(bad("bytes of a range that was not asked"));
        };
        let mut ready = Vec::new();
        let mut skipped = 0u64;
        while !data.is_empty() && a.next < members.len() {
            if a.skip > 0 {
                let n = a.skip.min(data.len() as u64);
                let _ = data.split_to(n as usize);
                a.skip -= n;
                skipped += n;
                continue;
            }
            let want = members[a.next].1;
            if a.acc.is_empty() && data.len() >= want {
                ready.push((a.next, data.split_to(want)));
            } else {
                let take = (want - a.acc.len()).min(data.len());
                a.acc.extend_from_slice(&data.split_to(take));
                if a.acc.len() < want {
                    continue;
                }
                ready.push((a.next, std::mem::take(&mut a.acc).freeze()));
            }
            a.next += 1;
            a.skip = members.get(a.next).map_or(0, |(gap, _)| *gap);
        }
        // what follows the last member of a range is a gap too
        skipped += data.len() as u64;
        Ok((ready, skipped))
    }
}

/// The `Range` header value for ranges of `[start, end)`.
pub fn range_header(ranges: &[Range<u64>]) -> String {
    let list: Vec<String> = ranges
        .iter()
        .map(|r| format!("{}-{}", r.start, r.end - 1))
        .collect();
    format!("bytes={}", list.join(","))
}

/// `bytes a-b/total` or `bytes a-b/*` as a half open range.
pub fn parse_content_range(value: &str) -> Option<Range<u64>> {
    let rest = value.trim().strip_prefix("bytes")?.trim_start();
    let rest = rest.strip_prefix(' ').unwrap_or(rest);
    let (span, _total) = rest.split_once('/')?;
    let (a, b) = span.split_once('-')?;
    let start: u64 = a.trim().parse().ok()?;
    let end: u64 = b.trim().parse().ok()?;
    (end >= start && end < u64::MAX).then(|| start..end + 1)
}

pub fn boundary_of(content_type: &str) -> Option<String> {
    let lower = content_type.to_ascii_lowercase();
    if !lower.trim_start().starts_with("multipart/byteranges") {
        return None;
    }
    let idx = lower.find("boundary=")?;
    let rest = &content_type[idx + "boundary=".len()..];
    let value = if let Some(q) = rest.strip_prefix('"') {
        q.split('"').next()?
    } else {
        rest.split(';').next()?.trim()
    };
    (!value.is_empty() && value.len() <= 200).then(|| value.to_string())
}

/// A piece of the answer: the range it belongs to, the offset of its first
/// byte in the blob and the bytes.
pub struct Piece {
    pub range: usize,
    pub offset: u64,
    pub data: Bytes,
}

enum State {
    /// Before the first boundary.
    Preamble,
    /// After a boundary: `\r\n` and the headers of the part.
    Headers,
    /// The data of part `current`; this many bytes left.
    Body(u64),
    /// After the data: `\r\n--boundary`, then `--` (end) or `\r\n`.
    Delimiter,
    Done,
}

/// Incremental parser of a `multipart/byteranges` body.
pub struct Multipart<'a> {
    expected: &'a [Range<u64>],
    delimiter: Vec<u8>,
    state: State,
    scratch: Vec<u8>,
    current: usize,
    next_offset: u64,
}

impl<'a> Multipart<'a> {
    pub fn new(boundary: &str, expected: &'a [Range<u64>]) -> Self {
        Self {
            expected,
            delimiter: format!("\r\n--{boundary}").into_bytes(),
            state: State::Preamble,
            scratch: Vec::new(),
            current: 0,
            next_offset: 0,
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done) && self.current == self.expected.len()
    }

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }

    fn parse_headers(&mut self, block: &[u8]) -> Result<(), RangesError> {
        let text = std::str::from_utf8(block).map_err(|_| bad("part headers are not UTF-8"))?;
        let mut range = None;
        for line in text.split("\r\n") {
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("content-range") {
                    range = parse_content_range(value);
                }
            }
        }
        let range = range.ok_or_else(|| bad("a part has no valid Content-Range"))?;
        let want = self
            .expected
            .get(self.current)
            .ok_or_else(|| bad("the server sent more parts than the ranges requested"))?;
        if range != *want {
            return Err(bad(format!(
                "the server sent bytes {}-{} where {}-{} were requested",
                range.start,
                range.end - 1,
                want.start,
                want.end - 1
            )));
        }
        self.next_offset = range.start;
        self.state = State::Body(range.end - range.start);
        Ok(())
    }

    /// Feed bytes of the body; the pieces of data they carry are appended to
    /// `out`.
    pub fn push(&mut self, mut input: Bytes, out: &mut Vec<Piece>) -> Result<(), RangesError> {
        while !input.is_empty() {
            match self.state {
                State::Body(left) => {
                    let n = left.min(input.len() as u64) as usize;
                    let data = input.split_to(n);
                    out.push(Piece {
                        range: self.current,
                        offset: self.next_offset,
                        data,
                    });
                    self.next_offset += n as u64;
                    if left == n as u64 {
                        self.current += 1;
                        self.scratch.clear();
                        self.state = State::Delimiter;
                    } else {
                        self.state = State::Body(left - n as u64);
                    }
                }
                State::Preamble => {
                    self.scratch.extend_from_slice(&input);
                    input = Bytes::new();
                    // The first boundary starts the body or follows a CRLF.
                    let probe = &self.delimiter[2..];
                    let found = self
                        .scratch
                        .windows(probe.len())
                        .enumerate()
                        .find(|(i, w)| {
                            *w == probe
                                && (*i == 0 || (*i >= 2 && self.scratch[*i - 2..*i] == *b"\r\n"))
                        })
                        .map(|(i, _)| i + probe.len());
                    if let Some(end) = found {
                        let rest = self.scratch.split_off(end);
                        self.scratch.clear();
                        self.state = State::Headers;
                        input = Bytes::from(rest);
                    } else if self.scratch.len() > MAX_PREAMBLE + probe.len() {
                        return Err(bad("no multipart boundary found"));
                    }
                }
                State::Headers => {
                    self.scratch.extend_from_slice(&input);
                    input = Bytes::new();
                    if let Some(i) = Self::find(&self.scratch, b"\r\n\r\n") {
                        let rest = self.scratch.split_off(i + 4);
                        let block = std::mem::take(&mut self.scratch);
                        // The CRLF after the boundary opens the header block.
                        let block = block.strip_prefix(b"\r\n").unwrap_or(&block).to_vec();
                        self.parse_headers(&block)?;
                        input = Bytes::from(rest);
                    } else if self.scratch.len() > MAX_PART_HEADERS {
                        return Err(bad("the headers of a part are too large"));
                    }
                }
                State::Delimiter => {
                    // `\r\n--boundary` followed by `--` or `\r\n`.
                    let need = self.delimiter.len() + 2;
                    let take = (need - self.scratch.len()).min(input.len());
                    self.scratch.extend_from_slice(&input.split_to(take));
                    if self.scratch.len() == need {
                        if !self.scratch.starts_with(&self.delimiter) {
                            return Err(bad("multipart delimiter expected"));
                        }
                        let tail = &self.scratch[self.delimiter.len()..];
                        match tail {
                            b"--" => self.state = State::Done,
                            b"\r\n" => self.state = State::Headers,
                            _ => return Err(bad("invalid multipart delimiter")),
                        }
                        self.scratch.clear();
                    }
                }
                State::Done => {
                    // Epilogue: ignored.
                    input = Bytes::new();
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembler_skips_the_gaps() {
        // range 0: a gap of 2, a member of 3, a gap of 1, a member of 2;
        // range 1: one member of 4
        let mut a = Assembler::new(vec![vec![(2, 3), (1, 2)], vec![(0, 4)]]);
        let (r, s) = a.push(0, Bytes::from_static(b"xxAB")).unwrap();
        assert!(r.is_empty() && s == 2);
        let (r, s) = a.push(0, Bytes::from_static(b"Cy")).unwrap();
        assert_eq!(r, vec![(0, Bytes::from_static(b"ABC"))]);
        assert_eq!(s, 1);
        let (r, s) = a.push(0, Bytes::from_static(b"DEzz")).unwrap();
        assert_eq!(r, vec![(1, Bytes::from_static(b"DE"))]);
        assert_eq!(s, 2);
        let (r, _) = a.push(1, Bytes::from_static(b"1234")).unwrap();
        assert_eq!(r, vec![(0, Bytes::from_static(b"1234"))]);
        assert!(a.push(2, Bytes::from_static(b"?")).is_err());
    }

    #[test]
    fn registries_are_remembered() {
        let host = "learnt.example:5000";
        assert_eq!(learnt(host), Learnt::default());
        lower_limit(host, 16);
        lower_limit(host, 32);
        assert_eq!(learnt(host).per_request, Some(16));
        lower_limit(host, 0);
        assert_eq!(learnt(host).per_request, Some(1));
        ignores_ranges(host);
        assert!(learnt(host).whole);
        assert_eq!(learnt("other.example").per_request, None);
    }

    fn body(parts: &[(Range<u64>, &[u8])], boundary: &str, total: u64) -> Vec<u8> {
        let mut out = Vec::new();
        for (r, data) in parts {
            out.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Type: application/octet-stream\r\nContent-Range: bytes {}-{}/{}\r\n\r\n",
                    r.start,
                    r.end - 1,
                    total
                )
                .as_bytes(),
            );
            out.extend_from_slice(data);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        out
    }

    fn collect(
        body: &[u8],
        step: usize,
        expected: &[Range<u64>],
    ) -> Result<Vec<(usize, u64, Vec<u8>)>, RangesError> {
        let mut p = Multipart::new("BOUND", expected);
        let mut pieces = Vec::new();
        for chunk in body.chunks(step) {
            p.push(Bytes::copy_from_slice(chunk), &mut pieces)?;
        }
        assert!(p.is_done() || pieces.is_empty());
        let mut merged: Vec<(usize, u64, Vec<u8>)> = Vec::new();
        for piece in pieces {
            match merged.last_mut() {
                Some((r, off, d)) if *r == piece.range && *off + d.len() as u64 == piece.offset => {
                    d.extend_from_slice(&piece.data)
                }
                _ => merged.push((piece.range, piece.offset, piece.data.to_vec())),
            }
        }
        Ok(merged)
    }

    #[test]
    fn test_multipart_any_split() {
        let expected = vec![10..15, 100..103, 200..201];
        let b = body(
            &[(10..15, b"abcde"), (100..103, b"xyz"), (200..201, b"\r")],
            "BOUND",
            1000,
        );
        for step in [1, 2, 3, 7, 64, 4096] {
            let got = collect(&b, step, &expected).unwrap();
            assert_eq!(
                got,
                vec![
                    (0, 10, b"abcde".to_vec()),
                    (1, 100, b"xyz".to_vec()),
                    (2, 200, b"\r".to_vec())
                ],
                "step {step}"
            );
        }
    }

    #[test]
    fn test_multipart_with_preamble_and_epilogue() {
        let mut b = b"preamble\r\n".to_vec();
        b.extend(body(&[(0..3, b"abc")], "BOUND", 10));
        b.extend_from_slice(b"epilogue");
        let got = collect(&b, 5, &[0..3]).unwrap();
        assert_eq!(got, vec![(0, 0, b"abc".to_vec())]);
    }

    #[test]
    fn test_multipart_rejects_wrong_ranges() {
        let b = body(&[(10..15, b"abcde")], "BOUND", 1000);
        assert!(collect(&b, 100, &[10..16]).is_err());
        assert!(collect(&b, 100, &[11..16]).is_err());
        let two = body(&[(10..15, b"abcde"), (20..22, b"zz")], "BOUND", 1000);
        assert!(collect(&two, 100, &[10..15]).is_err());
    }

    #[test]
    fn test_multipart_truncated_is_not_done() {
        let b = body(&[(0..3, b"abc"), (5..6, b"d")], "BOUND", 10);
        let mut p = Multipart::new("BOUND", &[0..3, 5..6][..]);
        let mut pieces = Vec::new();
        p.push(Bytes::copy_from_slice(&b[..b.len() - 10]), &mut pieces)
            .unwrap();
        assert!(!p.is_done());
    }

    #[test]
    fn test_multipart_garbage_is_an_error() {
        assert!(collect(&vec![b'x'; 10_000], 100, &[0..3]).is_err());
        let mut b = body(&[(0..3, b"abc")], "BOUND", 10);
        let i = b.windows(3).position(|w| w == b"abc").unwrap();
        b[i + 3] = b'X';
        assert!(collect(&b, 100, &[0..3]).is_err());
    }

    #[test]
    fn test_headers_and_boundary() {
        assert_eq!(range_header(&[0..10, 20..21]), "bytes=0-9,20-20");
        assert_eq!(parse_content_range("bytes 5-9/100"), Some(5..10));
        assert_eq!(parse_content_range("bytes 5-9/*"), Some(5..10));
        assert_eq!(parse_content_range("bytes 9-5/100"), None);
        assert_eq!(parse_content_range("items 1-2/3"), None);
        assert_eq!(
            boundary_of("multipart/byteranges; boundary=abc123").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            boundary_of("multipart/byteranges; boundary=\"a b\"").as_deref(),
            Some("a b")
        );
        assert_eq!(boundary_of("application/octet-stream"), None);
    }
}
