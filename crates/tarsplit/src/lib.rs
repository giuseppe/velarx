// SPDX-License-Identifier: Apache-2.0
//! tar-split: a tar stream recorded without the contents of its files, and
//! rebuilt from them byte for byte.
//!
//! A layer of an image is a tar stream whose digest (the diff id) is in the
//! image configuration.  A storage driver that unpacks the layer into files
//! of its own loses the exact stream: the order of the entries, the padding,
//! the PAX records, the way a name was split between header and prefix.  To
//! push, save or export the layer again with the same diff id, the driver
//! records everything that is *not* file content while it ingests the layer,
//! and replays it between the files it stored.  This package is that
//! recording and that replay, independent of how and where a driver keeps
//! the files.
//!
//! # The format
//!
//! The format is the one of `github.com/vbatts/tar-split`, which is also what
//! zstd:chunked layers carry in their metadata, so a tar-split from a
//! registry and one made here are the same thing.  It is a sequence of JSON
//! objects, one per line, `position` counting from 0 without gaps:
//!
//! ```text
//! {"type":2,"payload":"<base64 of raw bytes>","position":0}
//! {"type":1,"name":"usr/bin/ls","size":142088,"payload":"<base64 of the CRC-64>","position":1}
//! {"type":1,"name":"usr/bin/empty","payload":null,"position":2}
//! ```
//!
//! * type 2, a *segment*: bytes of the stream that are not file content (tar
//!   headers, padding, the end of the archive), standard base64;
//! * type 1, a *file*: the content of the entry called `name` comes here, its
//!   `size` bytes; `payload` is the CRC-64 (ISO polynomial, big endian) of
//!   the content, `null` for an empty file.  A name that is not valid UTF-8
//!   is given as `name_raw` (base64) instead.
//!
//! The stream is the concatenation, in order, of the segments and the
//! contents of the files.  The tar-split is compressed with zstd when it is
//! stored or exchanged; [`MAX_SIZE`] bounds it uncompressed.
//!
//! # Recording
//!
//! [`tar::TarReader`] reads a tar stream that is not trusted yet (everything
//! is bounded, a malformed header is an error) and reports every byte to a
//! [`tar::Sink`].  [`Recorder`] is a sink that builds the compressed
//! tar-split; the driver stores the files as it reads them:
//!
//! ```
//! use std::io::Read;
//! use velarx_tarsplit::{tar::TarReader, Recorder};
//!
//! # fn archive() -> Vec<u8> {
//! #     let mut b = tar::Builder::new(Vec::new());
//! #     let mut h = tar::Header::new_gnu();
//! #     h.set_size(5);
//! #     h.set_mode(0o644);
//! #     b.append_data(&mut h, "hello.txt", &b"hello"[..]).unwrap();
//! #     b.into_inner().unwrap()
//! # }
//! # fn main() -> std::io::Result<()> {
//! let stream = archive();
//! let mut reader = TarReader::with_sink(&stream[..], Recorder::new()?);
//! while let Some(entry) = reader.next_entry()? {
//!     let mut content = Vec::new();
//!     reader.read_to_end(&mut content)?;
//!     // the driver stores `content` as `entry.path`, in its own way
//! }
//! let (_, recorder) = reader.finish()?;
//! let tarsplit = recorder.finish()?.compressed;
//! # let _ = tarsplit;
//! # Ok(()) }
//! ```
//!
//! # Replaying
//!
//! [`Replay`] reads the entries of a tar-split ([`Entries`], fed by
//! [`decoder`]) and asks a [`Contents`] for the files; what it reads is the
//! original stream, whose sha256 is the diff id.  A driver that knows its
//! files by a key (a digest, say) lists them in a [`ContentIndex`], in the
//! order of the layer, and finds each file the tar-split names with it.
//!
//! ```
//! use std::io::{self, Read};
//! use velarx_tarsplit::{Contents, Entries, Replay};
//!
//! struct Files;
//! impl Contents for Files {
//!     fn open(&mut self, name: &str, size: u64) -> io::Result<Box<dyn Read + Send>> {
//!         assert_eq!((name, size), ("hello.txt", 5));
//!         Ok(Box::new(io::Cursor::new(b"hello".to_vec())))
//!     }
//! }
//!
//! let tarsplit = concat!(
//!     "{\"type\":2,\"payload\":\"SEVBREVS\",\"position\":0}\n",
//!     "{\"type\":1,\"name\":\"hello.txt\",\"size\":5,\"payload\":null,\"position\":1}\n",
//!     "{\"type\":2,\"payload\":\"RU5E\",\"position\":2}\n",
//! );
//! let entries = Entries::new(io::Cursor::new(tarsplit));
//! let mut stream = Vec::new();
//! Replay::new(entries, Files).read_to_end(&mut stream)?;
//! assert_eq!(stream, b"HEADERhelloEND");
//! # Ok::<(), io::Error>(())
//! ```
//!
//! The replay does not check the CRC-64 of the files, nor the digest of what
//! it gives: the one who needs a byte-identical layer compares the digest of
//! the stream with the diff id of the image.
//!
//! # Other pieces
//!
//! [`crc64`] is the checksum, [`Writer`] writes the JSON lines without
//! compression (for a driver that records by other means than a
//! [`tar::TarReader`]), and [`zstd_decoder`] reads untrusted zstd content with
//! its window capped.

#![warn(missing_docs)]

pub mod crc64;
pub mod decompress;
mod split;
pub mod tar;

pub use split::{
    decoder, ContentFile, ContentIndex, Contents, Entries, Item, Recorded, Recorder, Replay,
    Writer, MAX_SIZE,
};

/// The largest zstd window a frame of untrusted content may ask for
/// (128 MiB, the default limit of libzstd, set where the content is read
/// so that it does not depend on the library).
pub const ZSTD_WINDOW_LOG_MAX: u32 = 27;

/// A zstd decoder of untrusted content, its window capped.
pub fn zstd_decoder<'a, R: std::io::Read + 'a>(
    input: R,
) -> std::io::Result<zstd::stream::read::Decoder<'a, std::io::BufReader<R>>> {
    let mut d = zstd::stream::read::Decoder::new(input)?;
    d.window_log_max(ZSTD_WINDOW_LOG_MAX)?;
    Ok(d)
}
