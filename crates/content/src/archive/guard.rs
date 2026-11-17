// SPDX-License-Identifier: Apache-2.0
//! Telling a stream that is not a tar archive from one that is, as it
//! comes: before a byte of it is kept.
//!
//! The streams a command takes (`load`, `import`, `volume import`, a build
//! context, a checkpoint) are written to disk before they are read.  What
//! is not an archive (`cat /dev/zero | velarx load`) used to be written
//! until the disk was full.  A [`Guard`] reads the blocks as they pass: the
//! first that is not the header of an entry ends the stream with an
//! `InvalidData` error, and for gzip and zstd the first error of the
//! decompression does too.

use std::io::{self, Write};

const BLOCK: usize = 512;

/// The most of the end of an archive (records are padded with zeros) that
/// is let by: beyond it the stream is not only an archive.
const PADDING_MAX: u64 = 16 << 20;

/// The most of an archive with no entry (an empty one, its end padded
/// as a record) that is let by.
const EMPTY_MAX: u64 = 64 << 10;

/// The largest extended header (pax) that is read for the size of the
/// entry that follows it.
const PAX_MAX: u64 = 1 << 20;

/// How much of a compressed stream is decompressed to check it: the first
/// headers say what it is, the rest is read when it is used.
const COMPRESSED_CHECKED: u64 = 8 << 20;

/// What a stream may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accept {
    /// A tar archive.
    Tar,
    /// A tar archive, or one compressed with gzip or zstd.
    Compressed,
}

/// What a [`Guard`] refuses: the bytes are not a tar archive (or not a
/// valid compressed one).  The error is of the kind `InvalidData` and
/// carries this; [`is_not_an_archive`] finds it.
#[derive(Debug)]
pub struct NotAnArchive(String);

impl std::fmt::Display for NotAnArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NotAnArchive {}

/// Whether `e` is the refusal of a [`Guard`].
pub fn is_not_an_archive(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<NotAnArchive>())
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, NotAnArchive(msg.into()))
}

/// The headers and data of a tar stream, walked as it comes.
struct Walk {
    block: [u8; BLOCK],
    filled: usize,
    /// Data and padding of the entry that is being passed.
    skip: u64,
    /// Blocks of the sparse map of an old GNU sparse entry follow.
    extension: bool,
    /// The extended header (pax) being passed, read for its `size`.
    pax: Option<Vec<u8>>,
    /// The size an extended header gave to the entry that follows.
    next_size: Option<u64>,
    entries: u64,
    /// The end of the archive was seen: only padding follows.
    ended: Option<u64>,
    /// Bytes that went by.
    seen: u64,
    /// Stop looking after this many bytes.
    limit: Option<u64>,
}

impl Walk {
    fn new(limit: Option<u64>) -> Self {
        Self {
            block: [0; BLOCK],
            filled: 0,
            skip: 0,
            extension: false,
            pax: None,
            next_size: None,
            entries: 0,
            ended: None,
            seen: 0,
            limit,
        }
    }

    fn trusted(&self) -> bool {
        self.limit.is_some_and(|l| self.seen >= l)
    }

    /// At the start of an entry.
    fn at_boundary(&self) -> bool {
        self.skip == 0 && self.filled == 0 && !self.extension && self.pax.is_none()
    }

    fn header(&mut self) -> io::Result<()> {
        let block = &self.block;
        if block.iter().all(|b| *b == 0) {
            self.ended = Some(BLOCK as u64);
            return Ok(());
        }
        let stored = octal(&block[148..156]).ok_or_else(|| {
            invalid("not a tar archive: the checksum of a header is not a number")
        })?;
        let unsigned: u64 = block
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    u64::from(*b)
                }
            })
            .sum();
        let signed: i64 = block
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    i64::from(*b as i8)
                }
            })
            .sum();
        if stored != unsigned && i64::try_from(stored).ok() != Some(signed) {
            return Err(invalid(format!(
                "not a tar archive: the checksum of the header of entry {} does not match",
                self.entries + 1
            )));
        }
        let size = if block[124] & 0x80 != 0 {
            // GNU: a big-endian number after the first byte's mark
            let mut n = u64::from(block[124] & 0x7f);
            for b in &block[125..136] {
                n = n
                    .checked_mul(256)
                    .and_then(|n| n.checked_add(u64::from(*b)))
                    .ok_or_else(|| invalid("not a tar archive: an entry is too large"))?;
            }
            n
        } else {
            octal(&block[124..136])
                .ok_or_else(|| invalid("not a tar archive: the size of an entry is not a number"))?
        };
        let kind = block[156];
        // (an extended header gives the size of the next entry, which its
        // own header may not hold)
        let size = match self.next_size.take() {
            Some(s) if !matches!(kind, b'x' | b'g') => s,
            _ => size,
        };
        if kind == b'x' && size <= PAX_MAX {
            self.pax = Some(Vec::new());
        }
        self.extension = kind == b'S' && block[482] != 0;
        self.skip = size
            .checked_add(BLOCK as u64 - 1)
            .map(|n| n / BLOCK as u64 * BLOCK as u64)
            .ok_or_else(|| invalid("not a tar archive: an entry is too large"))?;
        self.entries += 1;
        Ok(())
    }

    fn feed(&mut self, mut data: &[u8]) -> io::Result<()> {
        self.seen += data.len() as u64;
        while !data.is_empty() {
            if let Some(padding) = &mut self.ended {
                *padding += data.len() as u64;
                if data.iter().any(|b| *b != 0) {
                    return Err(invalid(if self.entries == 0 {
                        "not a tar archive: its first block is empty"
                    } else {
                        "not a tar archive: data follows its end"
                    }));
                }
                let max = if self.entries == 0 {
                    EMPTY_MAX
                } else {
                    PADDING_MAX
                };
                if *padding > max {
                    return Err(invalid("not a tar archive: it goes on after its end"));
                }
                return Ok(());
            }
            if self.skip > 0 && !self.extension {
                let n = (data.len() as u64).min(self.skip);
                if let Some(pax) = &mut self.pax {
                    pax.extend_from_slice(&data[..n as usize]);
                }
                self.skip -= n;
                data = &data[n as usize..];
                if self.skip == 0 {
                    if let Some(pax) = self.pax.take() {
                        self.next_size = pax_size(&pax);
                    }
                }
                continue;
            }
            let n = data.len().min(BLOCK - self.filled);
            self.block[self.filled..self.filled + n].copy_from_slice(&data[..n]);
            self.filled += n;
            data = &data[n..];
            if self.filled == BLOCK {
                self.filled = 0;
                if self.extension {
                    self.extension = self.block[504] != 0;
                } else {
                    self.header()?;
                }
            }
        }
        Ok(())
    }

    fn end(&self) -> io::Result<()> {
        if self.ended.is_some() || self.at_boundary() && self.entries > 0 || self.trusted() {
            return Ok(());
        }
        if self.seen == 0 {
            return Ok(());
        }
        Err(invalid(
            "not a tar archive: it ends in the middle of an entry",
        ))
    }
}

/// The `size` record of an extended header (`LEN size=N\n` records).
fn pax_size(mut records: &[u8]) -> Option<u64> {
    let mut size = None;
    while let Some(space) = records.iter().position(|b| *b == b' ') {
        let len: usize = std::str::from_utf8(&records[..space]).ok()?.parse().ok()?;
        let record = records.get(space + 1..len)?;
        if let Some(n) = record.strip_prefix(b"size=") {
            size = std::str::from_utf8(n.strip_suffix(b"\n")?)
                .ok()?
                .parse()
                .ok();
        }
        records = &records[len..];
    }
    size
}

/// An octal number of a header field (spaces and NULs around it).
fn octal(field: &[u8]) -> Option<u64> {
    let s: Vec<u8> = field
        .iter()
        .copied()
        .skip_while(|b| *b == b' ')
        .take_while(|b| (b'0'..=b'7').contains(b))
        .collect();
    let rest = &field[field.iter().take_while(|b| **b == b' ').count() + s.len()..];
    if s.is_empty() || rest.iter().any(|b| *b != 0 && *b != b' ') {
        return None;
    }
    std::str::from_utf8(&s)
        .ok()
        .and_then(|s| u64::from_str_radix(s, 8).ok())
}

impl Write for Walk {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.trusted() {
            return Ok(buf.len());
        }
        self.feed(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

enum Kind {
    Undecided,
    Tar(Box<Walk>),
    Gzip(Box<flate2::write::MultiGzDecoder<Walk>>),
    Zstd(Box<zstd::stream::write::Decoder<'static, Walk>>),
    /// Looked at enough: what follows is not looked at.
    Checked,
}

/// The check of a stream, fed with what comes.
pub struct Guard {
    accept: Accept,
    head: Vec<u8>,
    kind: Kind,
}

impl Guard {
    pub fn new(accept: Accept) -> Self {
        Self {
            accept,
            head: Vec::new(),
            kind: Kind::Undecided,
        }
    }

    fn decide(&mut self) -> io::Result<()> {
        let head = std::mem::take(&mut self.head);
        let compressed = self.accept == Accept::Compressed;
        self.kind = if compressed && head.starts_with(&[0x1f, 0x8b]) {
            Kind::Gzip(Box::new(flate2::write::MultiGzDecoder::new(Walk::new(
                Some(COMPRESSED_CHECKED),
            ))))
        } else if compressed && head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            Kind::Zstd(Box::new(
                zstd::stream::write::Decoder::new(Walk::new(Some(COMPRESSED_CHECKED)))
                    .map_err(|e| invalid(format!("not an archive: {e}")))?,
            ))
        } else {
            Kind::Tar(Box::new(Walk::new(None)))
        };
        self.write_to_kind(&head)
    }

    fn write_to_kind(&mut self, data: &[u8]) -> io::Result<()> {
        let wrap = |e: io::Error| {
            if is_not_an_archive(&e) {
                e
            } else {
                invalid(format!("not a valid compressed archive: {e}"))
            }
        };
        match &mut self.kind {
            Kind::Tar(w) => w.feed(data),
            Kind::Gzip(d) => {
                // (what follows the gzip stream of an archive that ended,
                // zeros of a record, is left to the reader)
                if let Err(e) = d.write_all(data) {
                    if e.kind() == io::ErrorKind::InvalidData || d.get_ref().ended.is_none() {
                        return Err(wrap(e));
                    }
                    self.kind = Kind::Checked;
                    return Ok(());
                }
                if d.get_ref().trusted() {
                    self.kind = Kind::Checked;
                }
                Ok(())
            }
            Kind::Zstd(d) => {
                d.write_all(data).map_err(wrap)?;
                if d.get_ref().trusted() {
                    self.kind = Kind::Checked;
                }
                Ok(())
            }
            Kind::Undecided | Kind::Checked => Ok(()),
        }
    }

    /// The next bytes of the stream: an error as soon as it is known not to
    /// be an archive.
    pub fn feed(&mut self, data: &[u8]) -> io::Result<()> {
        if let Kind::Undecided = self.kind {
            // the first bytes say compressed or not
            self.head.extend_from_slice(data);
            if self.head.len() < 4 {
                return Ok(());
            }
            return self.decide();
        }
        self.write_to_kind(data)
    }

    /// The stream ended: an error if it ended where an archive does not.
    pub fn end(&mut self) -> io::Result<()> {
        if let Kind::Undecided = self.kind {
            if self.head.is_empty() {
                return Ok(());
            }
            self.decide()?;
        }
        match &mut self.kind {
            Kind::Tar(w) => w.end(),
            Kind::Gzip(d) => {
                if let Err(e) = d.try_finish() {
                    if e.kind() == io::ErrorKind::InvalidData || d.get_ref().ended.is_none() {
                        return Err(invalid(format!("not a valid compressed archive: {e}")));
                    }
                }
                d.get_ref().end()
            }
            Kind::Zstd(d) => {
                d.flush()
                    .map_err(|e| invalid(format!("not a valid compressed archive: {e}")))?;
                d.get_ref().end()
            }
            Kind::Undecided | Kind::Checked => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refusal is known by its type, not by its words; an error of
    /// another source with the same words is not one.
    #[test]
    fn a_refusal_is_typed() {
        let junk = vec![b'x'; 4096];
        let e = check(Accept::Compressed, &junk, 512).unwrap_err();
        assert!(is_not_an_archive(&e), "{e}");
        let bad_gzip = [&[0x1f, 0x8b, 8, 0][..], &junk[..]].concat();
        let e = check(Accept::Compressed, &bad_gzip, 512).unwrap_err();
        assert!(is_not_an_archive(&e), "{e}");
        let same_words = io::Error::new(io::ErrorKind::InvalidData, "not a tar archive: x");
        assert!(!is_not_an_archive(&same_words));
        assert!(check(Accept::Compressed, &tar(&[("a", b"1")]), 512).is_ok());
    }

    fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, *data).unwrap();
        }
        b.into_inner().unwrap()
    }

    fn check(accept: Accept, data: &[u8], piece: usize) -> io::Result<()> {
        let mut g = Guard::new(accept);
        for p in data.chunks(piece) {
            g.feed(p)?;
        }
        g.end()
    }

    #[test]
    fn archives_pass_however_they_come() {
        let t = tar(&[("a", b"hello"), ("dir/b", &[7u8; 5000])]);
        for piece in [1, 7, 511, 512, 513, 100_000] {
            check(Accept::Tar, &t, piece).unwrap();
            check(Accept::Compressed, &t, piece).unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&t).unwrap();
        let gz = gz.finish().unwrap();
        let zst = zstd::encode_all(&t[..], 1).unwrap();
        for piece in [1, 13, 100_000] {
            check(Accept::Compressed, &gz, piece).unwrap();
            check(Accept::Compressed, &zst, piece).unwrap();
        }
        // padded as a record
        let mut padded = t.clone();
        padded.resize(10240, 0);
        check(Accept::Tar, &padded, 4096).unwrap();
        // nothing is nothing, left to what takes it
        check(Accept::Tar, b"", 1).unwrap();
        // an empty archive (an empty volume's export), as a record
        check(Accept::Tar, &[0u8; 1024], 100).unwrap();
        check(Accept::Compressed, &[0u8; 10240], 4096).unwrap();
        // zeros after the gzip stream of an archive, as a record pads it
        let mut trailing = gz.clone();
        trailing.extend_from_slice(&[0u8; 1000]);
        check(Accept::Compressed, &trailing, 64).unwrap();
    }

    #[test]
    fn extended_headers_and_sparse_maps_are_not_taken_for_entries() {
        // the size of an entry in its extended header (pax), its own field
        // empty, as for a file too large for it
        let data = [5u8; 3000];
        let record = "13 size=3000\n";
        let mut out = Vec::new();
        let mut x = tar::Header::new_ustar();
        x.set_entry_type(tar::EntryType::XHeader);
        x.set_size(record.len() as u64);
        x.set_cksum();
        out.extend_from_slice(x.as_bytes());
        out.extend_from_slice(record.as_bytes());
        out.resize(out.len().next_multiple_of(BLOCK), 0);
        let mut h = tar::Header::new_ustar();
        h.set_path("big").unwrap();
        h.set_size(0);
        h.set_cksum();
        out.extend_from_slice(h.as_bytes());
        out.extend_from_slice(&data);
        out.resize(out.len().next_multiple_of(BLOCK) + 2 * BLOCK, 0);
        check(Accept::Tar, &out, 100).unwrap();
        // an old GNU sparse entry: its map goes on in a block of its own
        // before its data
        let mut h = tar::Header::new_gnu();
        h.set_path("sparse").unwrap();
        h.set_entry_type(tar::EntryType::GNUSparse);
        h.set_size(1024);
        h.as_gnu_mut().unwrap().isextended[0] = 1;
        h.set_cksum();
        let mut out = h.as_bytes().to_vec();
        let mut map = [0u8; BLOCK];
        map[..12].copy_from_slice(b"00000001000\0");
        out.extend_from_slice(&map);
        out.extend_from_slice(&[9u8; 1024]);
        out.extend_from_slice(&[0u8; 2 * BLOCK]);
        check(Accept::Tar, &out, 100).unwrap();
    }

    #[test]
    fn what_is_not_an_archive_fails_at_its_first_block() {
        let first = |data: &[u8]| {
            let mut g = Guard::new(Accept::Compressed);
            for (i, p) in data.chunks(100).enumerate() {
                if let Err(e) = g.feed(p) {
                    assert_eq!(e.kind(), io::ErrorKind::InvalidData);
                    return Some(i * 100);
                }
            }
            g.end().err().map(|_| data.len())
        };
        // an endless stream of zeros, of text, of noise
        // (zeros pass as long as an empty archive may be)
        assert!(first(&vec![0u8; 100 << 20]).unwrap() <= EMPTY_MAX as usize + 100);
        assert!(first(&b"hello world\n".repeat(1 << 20)).unwrap() <= 1024);
        let noise: Vec<u8> = (0..(1u32 << 20))
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        assert!(first(&noise).unwrap() <= 1024);
        // a tar cut in the middle of its data, or of a header
        let t = tar(&[("a", &[1u8; 4000])]);
        assert!(first(&t[..2000]).is_some());
        assert!(first(&t[..300]).is_some());
        // data after the end
        let mut t = tar(&[("a", b"x")]);
        t.extend_from_slice(b"garbage after the archive");
        assert!(first(&t).is_some());
        // a header that is not one, after good ones
        let mut t = tar(&[("a", b"x")]);
        t.truncate(1024);
        t.extend_from_slice(&[b'x'; 2048]);
        assert!(first(&t).unwrap() <= 1600);
    }

    #[test]
    fn a_compressed_stream_fails_at_its_first_error_or_header() {
        let fails = |accept, data: &[u8]| check(accept, data, 64).unwrap_err();
        // a gzip of zeros: the first block is empty
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&vec![0u8; 1 << 20]).unwrap();
        let zeros = gz.finish().unwrap();
        assert_eq!(
            fails(Accept::Compressed, &zeros).kind(),
            io::ErrorKind::InvalidData
        );
        // text compressed with zstd
        let text = zstd::encode_all(&b"just text, not a tar archive\n".repeat(100)[..], 1).unwrap();
        assert_eq!(
            fails(Accept::Compressed, &text).kind(),
            io::ErrorKind::InvalidData
        );
        // a gzip header and noise
        let mut bad = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        bad.extend((0..4096u32).map(|i| (i.wrapping_mul(2654435761) >> 11) as u8));
        assert_eq!(
            fails(Accept::Compressed, &bad).kind(),
            io::ErrorKind::InvalidData
        );
        // not accepted where the stream must be a tar
        let t = tar(&[("a", b"x")]);
        let zst = zstd::encode_all(&t[..], 1).unwrap();
        assert!(check(Accept::Tar, &zst, 64).is_err());
    }
}
