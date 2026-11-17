// SPDX-License-Identifier: Apache-2.0
//! Telling gzip and zstd content by its first bytes and reading it, for
//! content that is not trusted: a gzip stream of several members is read to
//! its end, and a zstd frame may not ask for a window larger than
//! [`crate::ZSTD_WINDOW_LOG_MAX`].

use std::io::{self, BufRead, Read};

/// How a stream is compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Not compressed (or not with a method this knows).
    None,
    /// gzip, of one member or more.
    Gzip,
    /// zstd.
    Zstd,
}

/// The compression of a stream that starts with `head` (its first 4 bytes
/// tell it).
pub fn sniff(head: &[u8]) -> Kind {
    if head.starts_with(&[0x1f, 0x8b]) {
        Kind::Gzip
    } else if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Kind::Zstd
    } else {
        Kind::None
    }
}

/// A stream decompressed.
pub enum Decoder<R: BufRead> {
    /// The stream as it is.
    Plain(R),
    /// A gzip stream.
    Gzip(Box<flate2::bufread::MultiGzDecoder<R>>),
    /// A zstd stream, its window capped.
    Zstd(Box<zstd::stream::read::Decoder<'static, R>>),
}

impl<R: BufRead> Decoder<R> {
    /// `input` read as `kind` says.
    pub fn new(kind: Kind, input: R) -> io::Result<Self> {
        Ok(match kind {
            Kind::None => Self::Plain(input),
            Kind::Gzip => Self::Gzip(Box::new(flate2::bufread::MultiGzDecoder::new(input))),
            Kind::Zstd => {
                let mut d = zstd::stream::read::Decoder::with_buffer(input)?;
                d.window_log_max(crate::ZSTD_WINDOW_LOG_MAX)?;
                Self::Zstd(Box::new(d))
            }
        })
    }

    /// `input` read as its first bytes say (nothing is consumed to tell).
    pub fn detect(mut input: R) -> io::Result<Self> {
        let kind = sniff(input.fill_buf()?);
        Self::new(kind, input)
    }
}

impl<R: BufRead> Read for Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(r) => r.read(buf),
            Self::Gzip(r) => r.read(buf),
            Self::Zstd(r) => r.read(buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn read_all(r: impl Read) -> Vec<u8> {
        let mut out = Vec::new();
        io::BufReader::new(r).read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn the_first_bytes_tell_the_compression() {
        assert_eq!(sniff(&[0x1f, 0x8b, 8]), Kind::Gzip);
        assert_eq!(sniff(&[0x28, 0xb5, 0x2f, 0xfd]), Kind::Zstd);
        assert_eq!(sniff(b"ustar"), Kind::None);
        assert_eq!(sniff(b""), Kind::None);
    }

    #[test]
    fn plain_gzip_and_zstd_are_read_back() {
        let data = b"hello hello hello".to_vec();
        let zst = zstd::encode_all(&data[..], 1).unwrap();
        for input in [data.clone(), gzip(&data), zst] {
            let d = Decoder::detect(io::Cursor::new(input)).unwrap();
            assert_eq!(read_all(d), data);
        }
    }

    #[test]
    fn a_gzip_stream_of_two_members_is_read_to_its_end() {
        let mut two = gzip(b"one ");
        two.extend(gzip(b"two"));
        let d = Decoder::detect(io::Cursor::new(two)).unwrap();
        assert_eq!(read_all(d), b"one two");
    }

    #[test]
    fn a_zstd_frame_with_a_window_over_the_cap_is_refused() {
        let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        enc.window_log(crate::ZSTD_WINDOW_LOG_MAX + 3).unwrap();
        enc.write_all(&vec![7u8; 1 << 20]).unwrap();
        let frame = enc.finish().unwrap();
        let mut d = Decoder::detect(io::Cursor::new(frame)).unwrap();
        assert!(d.read_to_end(&mut Vec::new()).is_err());
    }
}
