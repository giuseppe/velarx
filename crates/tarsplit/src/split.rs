// SPDX-License-Identifier: Apache-2.0
//! The tar-split of a zstd:chunked layer, and its replay.
//!
//! tar-split records a layer as a sequence of entries: raw segments (the tar
//! headers and padding) and references to the files whose content goes in
//! between.  Replaying it with the files of the layer gives back the exact
//! uncompressed tar stream, whose digest is the diff id.  That is how a layer
//! pulled by ranges, without ever seeing the stream, is bound to the image
//! configuration, and its metadata comes from the verified headers.

use crate::crc64;
use crate::tar::{normalize_path, Header, Sink};
use base64::Engine;
use serde::Deserialize;
use std::collections::{HashMap, VecDeque};
use std::io::{self, BufRead, BufReader, Read, Write};

/// Largest line (one entry) accepted.
const MAX_LINE: u64 = 64 * 1024 * 1024;

const FILE_TYPE: i64 = 1;
const SEGMENT_TYPE: i64 = 2;

/// An entry of a tar-split.
#[derive(Debug)]
pub enum Item {
    /// Bytes of the stream that are not file content.
    Segment(Vec<u8>),
    /// The content of the entry `name`, `size` bytes, comes here (every
    /// tar entry has one, with a size of 0 when it has no content).
    File {
        /// The name of the entry, as the tar header has it.
        name: String,
        /// The size of the content.
        size: u64,
    },
}

#[derive(Deserialize)]
struct Line {
    #[serde(rename = "type")]
    kind: i64,
    position: Option<i64>,
    payload: Option<String>,
    name: Option<String>,
    name_raw: Option<String>,
    size: Option<i64>,
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("tar-split: {}", msg.into()),
    )
}

fn b64(s: &str) -> io::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| invalid("invalid base64"))
}

/// Iterator over the entries of a tar-split stream (JSON lines).
pub struct Entries<R: BufRead> {
    input: R,
    position: i64,
    line: Vec<u8>,
}

impl<R: BufRead> Entries<R> {
    /// The entries of the JSON lines `input` (uncompressed: see
    /// [`decoder`]).  A line is at most 64 MiB; the size of the whole is
    /// bounded by the reader.
    pub fn new(input: R) -> Self {
        Self {
            input,
            position: 0,
            line: Vec::new(),
        }
    }

    fn read_line(&mut self) -> io::Result<bool> {
        self.line.clear();
        let n = (&mut self.input)
            .take(MAX_LINE + 1)
            .read_until(b'\n', &mut self.line)?;
        if n as u64 > MAX_LINE {
            return Err(invalid("line too long"));
        }
        Ok(n > 0)
    }

    fn parse(&mut self) -> io::Result<Option<Item>> {
        let line: Line = serde_json::from_slice(&self.line).map_err(|e| invalid(e.to_string()))?;
        if line.position != Some(self.position) {
            return Err(invalid(format!("unexpected position {:?}", line.position)));
        }
        self.position += 1;
        match line.kind {
            SEGMENT_TYPE => {
                let payload = b64(line.payload.as_deref().unwrap_or(""))?;
                if payload.is_empty() {
                    return Ok(None);
                }
                Ok(Some(Item::Segment(payload)))
            }
            FILE_TYPE => {
                let size = line.size.unwrap_or(0);
                let size = u64::try_from(size).map_err(|_| invalid("invalid size"))?;
                let name = match line.name_raw.as_deref() {
                    Some(raw) => {
                        let raw = b64(raw)?;
                        if raw.contains(&0) {
                            return Err(invalid("invalid name"));
                        }
                        String::from_utf8(raw).map_err(|_| invalid("name is not UTF-8"))?
                    }
                    None => line.name.unwrap_or_default(),
                };
                if name.contains('\0') {
                    return Err(invalid("invalid name"));
                }
                Ok(Some(Item::File { name, size }))
            }
            other => Err(invalid(format!("unknown entry type {other}"))),
        }
    }
}

impl<R: BufRead> Iterator for Entries<R> {
    type Item = io::Result<Item>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.read_line() {
                Ok(false) => return None,
                Ok(true) => {}
                Err(e) => return Some(Err(e)),
            }
            let blank = self.line.iter().all(|b| b.is_ascii_whitespace());
            if blank {
                continue;
            }
            match self.parse() {
                Ok(Some(item)) => return Some(Ok(item)),
                Ok(None) => continue,
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

/// Where the content of a file of the tar-split comes from.
pub trait Contents {
    /// Open the content of the file `name` of `size` bytes, waiting for it
    /// if it is still being downloaded.
    fn open(&mut self, name: &str, size: u64) -> io::Result<Box<dyn Read + Send>>;
}

enum Current {
    Segment(io::Cursor<Vec<u8>>),
    File(Box<dyn Read + Send>, u64),
    None,
}

/// The tar stream rebuilt from a tar-split and the files it refers to.
pub struct Replay<R: BufRead, C: Contents> {
    entries: Entries<R>,
    contents: C,
    current: Current,
}

impl<R: BufRead, C: Contents> Replay<R, C> {
    /// The stream of `entries`, with the files from `contents`; a file
    /// shorter than its entry is an error, what is longer is not read.
    pub fn new(entries: Entries<R>, contents: C) -> Self {
        Self {
            entries,
            contents,
            current: Current::None,
        }
    }

    /// Where the files come from.
    pub fn contents(&self) -> &C {
        &self.contents
    }

    /// Where the files come from, to ask it what it did while the stream
    /// was read.
    pub fn contents_mut(&mut self) -> &mut C {
        &mut self.contents
    }

    /// The parts of the stream: the entries it is not done with, and the
    /// contents.
    pub fn into_parts(self) -> (Entries<R>, C) {
        (self.entries, self.contents)
    }
}

impl<R: BufRead, C: Contents> Read for Replay<R, C> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match &mut self.current {
                Current::Segment(c) => {
                    let n = c.read(buf)?;
                    if n > 0 {
                        return Ok(n);
                    }
                }
                Current::File(f, left) => {
                    if *left > 0 {
                        let want = buf.len().min(usize::try_from(*left).unwrap_or(usize::MAX));
                        let n = f.read(&mut buf[..want])?;
                        if n == 0 {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "tar-split: a file is shorter than its entry",
                            ));
                        }
                        *left -= n as u64;
                        return Ok(n);
                    }
                }
                Current::None => {}
            }
            self.current = match self.entries.next() {
                None => return Ok(0),
                Some(Err(e)) => return Err(e),
                Some(Ok(Item::Segment(s))) => Current::Segment(io::Cursor::new(s)),
                Some(Ok(Item::File { name, size })) => {
                    if size == 0 {
                        Current::None
                    } else {
                        Current::File(self.contents.open(&name, size)?, size)
                    }
                }
            };
        }
    }
}

/// A regular file of a layer, as a driver knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFile {
    /// The name of the file in the layer (it is normalized by
    /// [`ContentIndex::new`]; a name that cannot be is left out).
    pub name: String,
    /// The size of its content in bytes.
    pub size: u64,
    /// What the driver finds the content by (a digest, a path, ...): it is
    /// given back untouched.
    pub key: String,
    /// A number of the driver's own (the position of the file in its table
    /// of contents, say), given back untouched.
    pub slot: usize,
}

/// The files of a layer by name, in the order of the layer: the file entries
/// of a tar-split are matched with the files a driver has, known by a key of
/// its own (a digest of the content, say).
///
/// A name may occur more than once (a layer can hold a file again): the
/// entries of the tar-split take the files called so in the order they were
/// given.
pub struct ContentIndex {
    files: HashMap<String, VecDeque<(String, u64, usize)>>,
}

impl ContentIndex {
    /// The index of `files`, in the order of the layer.
    pub fn new(files: impl IntoIterator<Item = ContentFile>) -> Self {
        let mut index: HashMap<String, VecDeque<(String, u64, usize)>> = HashMap::new();
        for f in files {
            if let Some(name) = normalize_path(&f.name) {
                index
                    .entry(name)
                    .or_default()
                    .push_back((f.key, f.size, f.slot));
            }
        }
        Self { files: index }
    }

    /// The next file called `name` (as the tar-split has it), which must
    /// have `size` bytes, with its name normalized.  A file is taken once:
    /// the next entry of the same name gets the next file so called.
    pub fn take(&mut self, name: &str, size: u64) -> io::Result<ContentFile> {
        let norm =
            normalize_path(name).ok_or_else(|| invalid(format!("invalid file name `{name}`")))?;
        let (key, want, slot) = self
            .files
            .get_mut(&norm)
            .and_then(|q| q.pop_front())
            .ok_or_else(|| invalid(format!("no content for `{norm}` in the index")))?;
        if want != size {
            return Err(invalid(format!(
                "the file `{norm}` of the index does not match the tar-split"
            )));
        }
        Ok(ContentFile {
            name: norm,
            size,
            key,
            slot,
        })
    }
}

/// Largest tar-split accepted or produced, uncompressed.
pub const MAX_SIZE: u64 = 1024 * 1024 * 1024;

/// Segments are written when they reach this size.
const SEGMENT_FLUSH: usize = 1024 * 1024;

struct OpenFile {
    name: String,
    size: u64,
    crc: u64,
}

/// Writer of the JSON lines of a tar-split, in the format of
/// `github.com/vbatts/tar-split`: the bytes between the contents of the
/// files are segments, every tar entry is a file entry with the CRC-64 of its
/// content.
pub struct Writer<W: Write> {
    out: W,
    position: u64,
    written: u64,
    segment: Vec<u8>,
    file: Option<OpenFile>,
}

impl<W: Write> Writer<W> {
    /// A tar-split written to `out`, at most [`MAX_SIZE`] bytes.
    pub fn new(out: W) -> Self {
        Self {
            out,
            position: 0,
            written: 0,
            segment: Vec::new(),
            file: None,
        }
    }

    fn line(&mut self, line: &str) -> io::Result<()> {
        self.written += line.len() as u64 + 1;
        if self.written > MAX_SIZE {
            return Err(invalid("the tar-split is too large"));
        }
        self.out.write_all(line.as_bytes())?;
        self.out.write_all(b"\n")?;
        self.position += 1;
        Ok(())
    }

    fn flush_segment(&mut self) -> io::Result<()> {
        if self.segment.is_empty() {
            return Ok(());
        }
        let segment = std::mem::take(&mut self.segment);
        let line = format!(
            "{{\"type\":2,\"payload\":\"{}\",\"position\":{}}}",
            base64::engine::general_purpose::STANDARD.encode(&segment),
            self.position
        );
        self.line(&line)
    }

    /// Bytes of the tar stream that are not file content.
    pub fn segment(&mut self, data: &[u8]) -> io::Result<()> {
        if self.file.is_some() {
            return Err(invalid("a segment inside a file entry"));
        }
        self.segment.extend_from_slice(data);
        if self.segment.len() >= SEGMENT_FLUSH {
            self.flush_segment()?;
        }
        Ok(())
    }

    /// Start the entry of the file `name` (as in the tar header).
    pub fn file_begin(&mut self, name: &str) -> io::Result<()> {
        if self.file.is_some() {
            return Err(invalid("nested file entries"));
        }
        self.flush_segment()?;
        self.file = Some(OpenFile {
            name: name.to_string(),
            size: 0,
            crc: 0,
        });
        Ok(())
    }

    /// Bytes of the content of the file entry.
    pub fn file_data(&mut self, data: &[u8]) -> io::Result<()> {
        let f = self
            .file
            .as_mut()
            .ok_or_else(|| invalid("file data outside a file entry"))?;
        f.crc = crc64::update(f.crc, data);
        f.size += data.len() as u64;
        Ok(())
    }

    /// The same as `file_data` with `len` bytes of zeros.
    pub fn file_hole(&mut self, len: u64) -> io::Result<()> {
        let f = self
            .file
            .as_mut()
            .ok_or_else(|| invalid("file data outside a file entry"))?;
        f.crc = crc64::update_zeros(f.crc, len);
        f.size += len;
        Ok(())
    }

    /// End the file entry: it is written with its size and CRC-64.
    pub fn file_end(&mut self) -> io::Result<()> {
        let f = self
            .file
            .take()
            .ok_or_else(|| invalid("file end outside a file entry"))?;
        let name = serde_json::to_string(&f.name).map_err(|e| invalid(e.to_string()))?;
        let line = if f.size > 0 {
            format!(
                "{{\"type\":1,\"name\":{name},\"size\":{},\"payload\":\"{}\",\"position\":{}}}",
                f.size,
                base64::engine::general_purpose::STANDARD.encode(f.crc.to_be_bytes()),
                self.position
            )
        } else {
            format!(
                "{{\"type\":1,\"name\":{name},\"payload\":null,\"position\":{}}}",
                self.position
            )
        };
        self.line(&line)
    }

    /// Write what is pending and give the output back.
    pub fn finish(mut self) -> io::Result<(W, u64)> {
        if self.file.is_some() {
            return Err(invalid("an unterminated file entry"));
        }
        self.flush_segment()?;
        Ok((self.out, self.written))
    }
}

/// A tar-split being built while a tar stream goes by, compressed as it is
/// written.
pub struct Recorder {
    writer: Writer<zstd::stream::write::Encoder<'static, Vec<u8>>>,
}

impl Sink for Recorder {
    fn segment(&mut self, data: &[u8]) -> io::Result<()> {
        self.writer.segment(data)
    }

    fn file_begin(&mut self, header: &Header) -> io::Result<()> {
        self.writer.file_begin(&header.path)
    }

    fn file_data(&mut self, data: &[u8]) -> io::Result<()> {
        self.writer.file_data(data)
    }

    fn file_hole(&mut self, len: u64) -> io::Result<()> {
        self.writer.file_hole(len)
    }

    fn file_end(&mut self) -> io::Result<()> {
        self.writer.file_end()
    }
}

/// A finished, compressed tar-split.
pub struct Recorded {
    /// The tar-split, compressed with zstd.
    pub compressed: Vec<u8>,
}

impl Recorder {
    /// An empty recording.
    pub fn new() -> io::Result<Self> {
        let enc = zstd::stream::write::Encoder::new(Vec::new(), 3)?;
        Ok(Self {
            writer: Writer::new(enc),
        })
    }

    /// The tar-split of what went by; an entry left open is an error.
    pub fn finish(self) -> io::Result<Recorded> {
        let (enc, _) = self.writer.finish()?;
        Ok(Recorded {
            compressed: enc.finish()?,
        })
    }
}

/// Decode a zstd compressed tar-split of at most `max` bytes.
pub fn decoder(
    compressed: impl AsRef<[u8]> + Send + 'static,
    max: u64,
) -> io::Result<impl BufRead + Send> {
    let dec = crate::zstd_decoder(io::Cursor::new(compressed))?;
    Ok(BufReader::new(dec.take(max)))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;

    pub fn line(position: i64, kind: i64, payload: &[u8], name: Option<&str>, size: i64) -> String {
        let e = base64::engine::general_purpose::STANDARD;
        let mut s = format!(
            "{{\"type\":{kind},\"position\":{position},\"payload\":\"{}\"",
            e.encode(payload)
        );
        if let Some(n) = name {
            s += &format!(",\"name_raw\":\"{}\"", e.encode(n));
        }
        if kind == FILE_TYPE {
            s += &format!(",\"size\":{size}");
        }
        s + "}\n"
    }

    struct Files(HashMap<String, Vec<u8>>);

    impl Contents for Files {
        fn open(&mut self, name: &str, size: u64) -> io::Result<Box<dyn Read + Send>> {
            let data = self
                .0
                .get(name)
                .filter(|d| d.len() as u64 == size)
                .ok_or_else(|| invalid("no such file"))?;
            Ok(Box::new(io::Cursor::new(data.clone())))
        }
    }

    #[test]
    fn test_a_hole_is_recorded_as_the_zeros() {
        let record = |hole: bool| {
            let mut w = Writer::new(Vec::new());
            w.file_begin("f").unwrap();
            w.file_data(b"head").unwrap();
            if hole {
                w.file_hole(100_000).unwrap();
            } else {
                w.file_data(&vec![0u8; 100_000]).unwrap();
            }
            w.file_data(b"tail").unwrap();
            w.file_end().unwrap();
            w.finish().unwrap().0
        };
        assert_eq!(record(true), record(false));
    }

    #[test]
    fn test_replay_rebuilds_the_stream() {
        let ts = [
            line(0, 2, b"HEADER1", None, 0),
            line(1, 1, &[0; 8], Some("a/b"), 5),
            line(2, 2, b"PAD", None, 0),
            line(3, 2, b"", None, 0),
            line(4, 1, &[0; 8], Some("c"), 0),
            line(5, 2, b"END", None, 0),
        ]
        .concat();
        let files = Files(HashMap::from([("a/b".to_string(), b"hello".to_vec())]));
        let mut r = Replay::new(Entries::new(io::Cursor::new(ts.into_bytes())), files);
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"HEADER1helloPADEND");
    }

    #[test]
    fn test_replay_gives_its_contents_back() {
        let ts = line(0, 2, b"A", None, 0);
        let files = Files(HashMap::from([("a".to_string(), b"x".to_vec())]));
        let mut r = Replay::new(Entries::new(io::Cursor::new(ts.into_bytes())), files);
        assert_eq!(r.contents().0.len(), 1);
        r.contents_mut().0.clear();
        let (_, files) = r.into_parts();
        assert!(files.0.is_empty());
    }

    #[test]
    fn test_positions_must_be_sequential() {
        let ts = [line(0, 2, b"a", None, 0), line(2, 2, b"b", None, 0)].concat();
        let e: Result<Vec<_>, _> = Entries::new(io::Cursor::new(ts.into_bytes())).collect();
        assert!(e.is_err());
    }

    #[test]
    fn test_invalid_entries() {
        for bad in [
            "not json\n".to_string(),
            "{\"type\":9,\"position\":0}\n".to_string(),
            "{\"type\":1,\"position\":0,\"size\":-1}\n".to_string(),
            "{\"type\":2,\"position\":0,\"payload\":\"***\"}\n".to_string(),
            line(0, 1, &[0; 8], Some("a\0b"), 1),
        ] {
            let e: Result<Vec<_>, _> = Entries::new(io::Cursor::new(bad.into_bytes())).collect();
            assert!(e.is_err());
        }
    }

    #[test]
    fn test_short_file_is_an_error() {
        let ts = line(0, 1, &[0; 8], Some("f"), 10);
        struct Short;
        impl Contents for Short {
            fn open(&mut self, _: &str, _: u64) -> io::Result<Box<dyn Read + Send>> {
                Ok(Box::new(io::Cursor::new(vec![1u8; 4])))
            }
        }
        let mut r = Replay::new(Entries::new(io::Cursor::new(ts.into_bytes())), Short);
        let mut out = Vec::new();
        assert!(r.read_to_end(&mut out).is_err());
    }

    #[test]
    fn test_compressed_decoder_is_bounded() {
        let ts = line(0, 2, &vec![7u8; 100_000], None, 0);
        let z = zstd::encode_all(ts.as_bytes(), 3).unwrap();
        let mut ok = Vec::new();
        decoder(z.clone(), 1 << 20)
            .unwrap()
            .read_to_end(&mut ok)
            .unwrap();
        assert_eq!(ok.len(), ts.len());
        let mut cut = Vec::new();
        decoder(z, 100).unwrap().read_to_end(&mut cut).unwrap();
        assert_eq!(cut.len(), 100);
        assert!(Entries::new(io::Cursor::new(cut)).next().unwrap().is_err());
    }

    #[test]
    fn test_writer_output_is_read_back() {
        let mut w = Writer::new(Vec::new());
        w.segment(b"HEADER").unwrap();
        w.file_begin("a/<b>\u{e9}").unwrap();
        w.file_data(b"hel").unwrap();
        w.file_data(b"lo").unwrap();
        w.file_end().unwrap();
        w.segment(b"PAD").unwrap();
        w.file_begin("dir/").unwrap();
        w.file_end().unwrap();
        w.segment(b"END").unwrap();
        let (out, size) = w.finish().unwrap();
        assert_eq!(size, out.len() as u64);
        let text = String::from_utf8(out.clone()).unwrap();
        // CRC-64/ISO of "hello", big endian, as tar-split writes it.
        let crc = base64::engine::general_purpose::STANDARD
            .encode(crc64::update(0, b"hello").to_be_bytes());
        assert!(
            text.contains(&format!("\"size\":5,\"payload\":\"{crc}\"")),
            "{text}"
        );
        assert!(text.contains("\"payload\":null"));
        let items: Vec<Item> = Entries::new(io::Cursor::new(out))
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(items.len(), 5);
        assert!(matches!(&items[1], Item::File { name, size: 5 } if name == "a/<b>\u{e9}"));
        assert!(matches!(&items[3], Item::File { size: 0, .. }));
    }

    /// The bytes of a tar-split are a format shared with other tools
    /// (`github.com/vbatts/tar-split`) and with the layers already stored:
    /// they must not change.
    #[test]
    fn test_golden_writer_output() {
        let mut w = Writer::new(Vec::new());
        w.segment(b"HEADER").unwrap();
        w.file_begin("a/b").unwrap();
        w.file_data(b"hello").unwrap();
        w.file_end().unwrap();
        w.segment(b"PAD").unwrap();
        w.file_begin("empty").unwrap();
        w.file_end().unwrap();
        w.segment(b"END").unwrap();
        let (out, size) = w.finish().unwrap();
        let golden = concat!(
            "{\"type\":2,\"payload\":\"SEVBREVS\",\"position\":0}\n",
            "{\"type\":1,\"name\":\"a/b\",\"size\":5,\"payload\":\"PD7u4tgQAAA=\",\"position\":1}\n",
            "{\"type\":2,\"payload\":\"UEFE\",\"position\":2}\n",
            "{\"type\":1,\"name\":\"empty\",\"payload\":null,\"position\":3}\n",
            "{\"type\":2,\"payload\":\"RU5E\",\"position\":4}\n",
        );
        assert_eq!(String::from_utf8(out).unwrap(), golden);
        assert_eq!(size, golden.len() as u64);
        let mut r = Replay::new(
            Entries::new(io::Cursor::new(golden)),
            Files(HashMap::from([("a/b".to_string(), b"hello".to_vec())])),
        );
        let mut stream = Vec::new();
        r.read_to_end(&mut stream).unwrap();
        assert_eq!(stream, b"HEADERhelloPADEND");
    }

    /// A tar-split as the Go tool writes it: `name` for a name that is
    /// UTF-8, `name_raw` for any other, a CRC-64 payload that is not read.
    #[test]
    fn test_golden_reader_input() {
        let golden = concat!(
            "{\"type\":2,\"payload\":\"AAEC\",\"position\":0}\n",
            "{\"type\":1,\"name\":\"x\",\"size\":2,\"payload\":\"AAAAAAAAAAA=\",\"position\":1}\n",
            "{\"type\":1,\"name_raw\":\"eS96\",\"size\":1,\"payload\":\"AAAAAAAAAAA=\",\"position\":2}\n",
            "{\"type\":1,\"name\":\"d/\",\"payload\":null,\"position\":3}\n",
        );
        let items: Vec<Item> = Entries::new(io::Cursor::new(golden))
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(matches!(&items[0], Item::Segment(s) if s == &[0, 1, 2]));
        assert!(matches!(&items[1], Item::File { name, size: 2 } if name == "x"));
        assert!(matches!(&items[2], Item::File { name, size: 1 } if name == "y/z"));
        assert!(matches!(&items[3], Item::File { name, size: 0 } if name == "d/"));
    }

    #[test]
    fn test_content_index() {
        let file = |name: &str, size, key: &str, slot| ContentFile {
            name: name.into(),
            size,
            key: key.into(),
            slot,
        };
        let mut index = ContentIndex::new([
            file("./a/b", 3, "k1", 7),
            file("a/b", 4, "k2", 9),
            file("../escape", 1, "k3", 10),
            file("c", 1, "k4", 11),
        ]);
        assert_eq!(index.take("a/b", 3).unwrap(), file("a/b", 3, "k1", 7));
        // the size has to be the one of the file
        assert!(index.take("a/b", 5).is_err());
        assert!(
            index.take("a/b", 4).is_err(),
            "a failed take uses the file up"
        );
        assert!(index.take("escape", 1).is_err());
        assert_eq!(index.take("/c", 1).unwrap(), file("c", 1, "k4", 11));
        assert!(index.take("c", 1).is_err());
        assert!(index.take("..", 1).is_err());
    }

    /// A driver records and replays on threads of its own.
    #[test]
    fn test_the_types_can_move_between_threads() {
        fn send<T: Send>() {}
        send::<Recorder>();
        send::<Writer<Vec<u8>>>();
        send::<ContentIndex>();
        send::<Entries<io::Cursor<Vec<u8>>>>();
        send::<Replay<io::Cursor<Vec<u8>>, Files>>();
    }

    #[test]
    fn test_writer_refuses_misuse() {
        let mut w = Writer::new(Vec::new());
        assert!(w.file_data(b"x").is_err());
        assert!(w.file_end().is_err());
        w.file_begin("a").unwrap();
        assert!(w.file_begin("b").is_err());
        assert!(w.segment(b"x").is_err());
        assert!(w.finish().is_err());
    }
}
