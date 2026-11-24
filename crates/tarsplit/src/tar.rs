// SPDX-License-Identifier: Apache-2.0
//! A streaming tar reader for archives that are not trusted yet.
//!
//! A layer is parsed while it is downloaded, before its digest can be
//! checked, so everything here is bounded: names, extension headers and
//! extended attributes have caps, nothing is allocated from a size declared
//! in the archive, and a malformed header is an error (never a panic).
//! Sparse files are refused.  The results are only used if the diff id of the
//! layer matches the image configuration.

use std::collections::BTreeMap;
use std::io::{self, Read};

use velarx_tarsplit_header::{
    self as header, checksum_ok, cstr, decimal, padding, pax_record, pax_time, NumError, PaxError,
    BLOCK,
};

/// Longest path or link target accepted.
pub const MAX_NAME_LEN: usize = 4096;

/// The most components of the name of an entry: deeper than any image
/// needs, and well below what a name of `MAX_NAME_LEN` bytes can hold.
pub const MAX_PATH_DEPTH: usize = 512;

/// Whether a name has more than `MAX_PATH_DEPTH` components.
pub fn too_deep(path: &str) -> bool {
    path.split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .count()
        > MAX_PATH_DEPTH
}

/// Largest PAX extended header or GNU long name record accepted.
const MAX_EXTENSION_SIZE: u64 = 1024 * 1024;

/// Extension headers (PAX, GNU long name) before the header they belong to.
const MAX_EXTENSION_HEADERS: usize = 16;

/// Extended attributes of one entry.
pub const MAX_XATTRS: usize = 1024;

/// Total size of the names and values of the extended attributes of an entry.
pub const MAX_XATTR_BYTES: usize = 1024 * 1024;

/// The type of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A regular file, with content.
    Regular,
    /// A directory.
    Directory,
    /// A symbolic link to [`Header::link`].
    Symlink,
    /// A hard link to the entry [`Header::link`] names.
    Hardlink,
    /// A character device.
    Char,
    /// A block device.
    Block,
    /// A named pipe.
    Fifo,
}

/// The header of an entry, with the PAX and GNU extensions applied.
#[derive(Debug, Clone)]
pub struct Header {
    /// The name of the entry, as the archive has it (not normalized).
    pub path: String,
    /// The type of the entry.
    pub kind: Kind,
    /// The size of the content that follows the header, as declared.
    pub size: u64,
    /// The permission bits, with setuid, setgid and sticky.
    pub mode: u32,
    /// The owner.
    pub uid: u32,
    /// The group.
    pub gid: u32,
    /// The modification time: seconds since the epoch (before it for a time
    /// before 1970) and the nanoseconds after them.
    pub mtime: (i64, u32),
    /// The target of a symbolic or hard link.
    pub link: Option<String>,
    /// The major number of a device.
    pub dev_major: u32,
    /// The minor number of a device.
    pub dev_minor: u32,
    /// The extended attributes (PAX `SCHILY.xattr.` records).
    pub xattrs: BTreeMap<String, Vec<u8>>,
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// An octal or base-256 number field.
fn number(field: &[u8], what: &str) -> io::Result<u64> {
    header::number(field).map_err(|e| num_error(e, what))
}

fn num_error(e: NumError, what: &str) -> io::Error {
    invalid(match e {
        NumError::Negative => format!("negative {what}"),
        NumError::Overflow => format!("{what} overflows"),
        NumError::Invalid => format!("invalid {what}"),
    })
}

fn utf8(bytes: &[u8], what: &str) -> io::Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| invalid(format!("{what} is not UTF-8")))
}

/// The properties a PAX record or a GNU extension can override.
#[derive(Default)]
struct Overrides {
    path: Option<String>,
    link: Option<String>,
    size: Option<u64>,
    uid: Option<u64>,
    gid: Option<u64>,
    mtime: Option<(i64, u32)>,
    xattrs: BTreeMap<String, Vec<u8>>,
    xattr_bytes: usize,
}

/// Parse `len key=value\n` records.
fn parse_pax(data: &[u8], out: &mut Overrides) -> io::Result<()> {
    let mut rest = data;
    while !rest.is_empty() {
        let record = pax_record(rest).map_err(|e| match e {
            PaxError::Length => invalid("invalid PAX record length"),
            PaxError::Record => invalid("invalid PAX record"),
        })?;
        let key =
            std::str::from_utf8(&rest[record.key]).map_err(|_| invalid("PAX key is not UTF-8"))?;
        let value = &rest[record.value];
        rest = &rest[record.len..];
        match key {
            "path" => out.path = Some(utf8(value, "PAX path")?),
            "linkpath" => out.link = Some(utf8(value, "PAX linkpath")?),
            "size" => out.size = Some(decimal(value).map_err(|_| invalid("invalid PAX size"))?),
            "uid" | "gid" => {
                let v = decimal(value).map_err(|_| invalid("invalid PAX id"))?;
                if key == "uid" {
                    out.uid = Some(v)
                } else {
                    out.gid = Some(v)
                }
            }
            "mtime" => {
                out.mtime = Some(pax_time(value).map_err(|_| invalid("invalid PAX mtime"))?);
            }
            // the formats of GNU tar that store a file with holes as a
            // regular entry of its packed data: as the sparse type, refused
            _ if key.starts_with("GNU.sparse.") => {
                return Err(invalid("sparse files are not supported"));
            }
            _ => {
                if let Some(name) = key.strip_prefix("SCHILY.xattr.") {
                    if out.xattrs.len() >= MAX_XATTRS {
                        return Err(invalid("too many extended attributes"));
                    }
                    out.xattr_bytes += name.len() + value.len();
                    if out.xattr_bytes > MAX_XATTR_BYTES {
                        return Err(invalid("extended attributes are too large"));
                    }
                    out.xattrs.insert(name.to_string(), value.to_vec());
                }
            }
        }
    }
    Ok(())
}

/// What a reader of a tar stream reports besides the entries: the bytes of
/// the stream that are not file content, and the content of each entry.
pub trait Sink {
    /// Headers, padding and the end of the archive.
    fn segment(&mut self, data: &[u8]) -> io::Result<()>;
    /// An entry starts (its header was reported as a segment).
    fn file_begin(&mut self, header: &Header) -> io::Result<()>;
    /// Bytes of the content of the entry.
    fn file_data(&mut self, data: &[u8]) -> io::Result<()>;
    /// The content of the entry is over (its padding comes as a segment).
    fn file_end(&mut self) -> io::Result<()>;
}

/// The sink of a reader that only wants the entries.
pub struct NoSink;

impl Sink for NoSink {
    fn segment(&mut self, _: &[u8]) -> io::Result<()> {
        Ok(())
    }
    fn file_begin(&mut self, _: &Header) -> io::Result<()> {
        Ok(())
    }
    fn file_data(&mut self, _: &[u8]) -> io::Result<()> {
        Ok(())
    }
    fn file_end(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reader of the entries of a tar archive.
pub struct TarReader<R: Read, S: Sink = NoSink> {
    inner: R,
    /// Bytes of the current entry not read yet.
    remaining: u64,
    /// Padding after the data of the current entry.
    padding: u64,
    finished: bool,
    in_entry: bool,
    sink: S,
}

impl<R: Read> TarReader<R> {
    /// A reader of the archive `inner`.
    pub fn new(inner: R) -> Self {
        Self::with_sink(inner, NoSink)
    }
}

impl<R: Read, S: Sink> TarReader<R, S> {
    /// A reader that reports every byte of the stream to `sink`; the stream
    /// has to be read to its end with `finish`.
    pub fn with_sink(inner: R, sink: S) -> Self {
        Self {
            inner,
            remaining: 0,
            padding: 0,
            finished: false,
            in_entry: false,
            sink,
        }
    }

    /// The reader the archive is read from.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// The reader the archive is read from, to ask it what it saw: reading
    /// from it directly would skip bytes of the archive.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Read `buf` entirely from what is not file content.
    fn read_raw(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.inner.read_exact(buf)?;
        self.sink.segment(buf)
    }

    /// Skip `n` bytes: the content of the current entry if `data`, the rest
    /// of the stream (padding, headers) otherwise.
    fn skip(&mut self, mut n: u64, data: bool) -> io::Result<()> {
        let mut buf = [0u8; 8192];
        while n > 0 {
            let want = n.min(buf.len() as u64) as usize;
            let got = self.inner.read(&mut buf[..want])?;
            if got == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            if data {
                self.sink.file_data(&buf[..got])?;
            } else {
                self.sink.segment(&buf[..got])?;
            }
            n -= got as u64;
        }
        Ok(())
    }

    /// Finish the entry in progress: its content that was not read, and the
    /// padding.
    fn end_entry(&mut self) -> io::Result<()> {
        let remaining = std::mem::take(&mut self.remaining);
        self.skip(remaining, true)?;
        if std::mem::take(&mut self.in_entry) {
            self.sink.file_end()?;
        }
        let padding = std::mem::take(&mut self.padding);
        self.skip(padding, false)
    }

    /// Read the rest of the stream, which is reported to the sink too, and
    /// give back the reader and the sink.
    pub fn finish(mut self) -> io::Result<(R, S)> {
        self.end_entry()?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = self.inner.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.sink.segment(&buf[..n])?;
        }
        Ok((self.inner, self.sink))
    }

    /// Read a header block; `None` at the end of the archive.
    fn read_block(&mut self) -> io::Result<Option<[u8; BLOCK]>> {
        let mut block = [0u8; BLOCK];
        let mut filled = 0;
        while filled < BLOCK {
            let n = self.inner.read(&mut block[filled..])?;
            if n == 0 {
                if filled == 0 {
                    // A stream that ends without the zero blocks is accepted.
                    return Ok(None);
                }
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            filled += n;
        }
        self.sink.segment(&block)?;
        if block.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        Ok(Some(block))
    }

    fn read_extension(&mut self, size: u64) -> io::Result<Vec<u8>> {
        if size > MAX_EXTENSION_SIZE {
            return Err(invalid("tar extension header is too large"));
        }
        let mut data = vec![0u8; size as usize];
        self.read_raw(&mut data)?;
        self.skip(size.next_multiple_of(BLOCK as u64) - size, false)?;
        Ok(data)
    }

    /// The next entry, after skipping what is left of the current one.
    pub fn next_entry(&mut self) -> io::Result<Option<Header>> {
        if self.finished {
            return Ok(None);
        }
        self.end_entry()?;

        let mut ov = Overrides::default();
        let mut gnu_path: Option<String> = None;
        let mut gnu_link: Option<String> = None;

        for _ in 0..=MAX_EXTENSION_HEADERS {
            let Some(block) = self.read_block()? else {
                self.finished = true;
                return Ok(None);
            };
            if !checksum_ok(&block).map_err(|e| num_error(e, "checksum"))? {
                return Err(invalid("invalid tar header checksum"));
            }
            let size = number(&block[124..136], "size")?;
            match block[156] {
                b'x' => {
                    let data = self.read_extension(size)?;
                    parse_pax(&data, &mut ov)?;
                    continue;
                }
                b'g' => {
                    // Global extended headers are not applied.
                    self.read_extension(size)?;
                    continue;
                }
                b'L' | b'K' => {
                    let data = self.read_extension(size)?;
                    let name = utf8(cstr(&data), "GNU long name")?;
                    if block[156] == b'L' {
                        gnu_path = Some(name);
                    } else {
                        gnu_link = Some(name);
                    }
                    continue;
                }
                _ => {}
            }
            return self
                .finish_header(&block, size, ov, gnu_path, gnu_link)
                .map(Some);
        }
        Err(invalid("too many tar extension headers"))
    }

    fn finish_header(
        &mut self,
        block: &[u8; BLOCK],
        size: u64,
        ov: Overrides,
        gnu_path: Option<String>,
        gnu_link: Option<String>,
    ) -> io::Result<Header> {
        let kind = match block[156] {
            0 | b'0' | b'7' => Kind::Regular,
            b'1' => Kind::Hardlink,
            b'2' => Kind::Symlink,
            b'3' => Kind::Char,
            b'4' => Kind::Block,
            b'5' => Kind::Directory,
            b'6' => Kind::Fifo,
            b'S' => return Err(invalid("sparse files are not supported")),
            other => return Err(invalid(format!("unsupported tar entry type {other:#x}"))),
        };

        let posix = &block[257..263] == b"ustar\0";
        let path = if let Some(p) = ov.path.or(gnu_path) {
            p
        } else {
            let name = cstr(&block[0..100]);
            let prefix = if posix { cstr(&block[345..500]) } else { &[] };
            if prefix.is_empty() {
                utf8(name, "path")?
            } else {
                format!("{}/{}", utf8(prefix, "path prefix")?, utf8(name, "path")?)
            }
        };
        let link = match ov.link.or(gnu_link) {
            Some(l) => Some(l),
            None => {
                let l = cstr(&block[157..257]);
                if l.is_empty() {
                    None
                } else {
                    Some(utf8(l, "link name")?)
                }
            }
        };
        if path.len() > MAX_NAME_LEN || link.as_ref().is_some_and(|l| l.len() > MAX_NAME_LEN) {
            return Err(invalid(format!(
                "tar path is too long (more than {MAX_NAME_LEN} bytes)"
            )));
        }
        if too_deep(&path) {
            return Err(invalid(format!(
                "tar path is too deep (more than {MAX_PATH_DEPTH} components)"
            )));
        }
        if path.as_bytes().contains(&0) {
            return Err(invalid("tar path contains a NUL"));
        }

        let size = ov.size.unwrap_or(size);
        let uid = ov.uid.map_or_else(|| number(&block[108..116], "uid"), Ok)?;
        let gid = ov.gid.map_or_else(|| number(&block[116..124], "gid"), Ok)?;
        let mtime = match ov.mtime {
            Some(m) => m,
            None => (
                i64::try_from(number(&block[136..148], "mtime")?).unwrap_or(0),
                0,
            ),
        };
        let uid = u32::try_from(uid).map_err(|_| invalid("uid is too large"))?;
        let gid = u32::try_from(gid).map_err(|_| invalid("gid is too large"))?;
        let mode = (number(&block[100..108], "mode")? & 0o7777) as u32;
        let (dev_major, dev_minor) = if matches!(kind, Kind::Char | Kind::Block) {
            (
                u32::try_from(number(&block[329..337], "device major")?)
                    .map_err(|_| invalid("device major is too large"))?,
                u32::try_from(number(&block[337..345], "device minor")?)
                    .map_err(|_| invalid("device minor is too large"))?,
            )
        } else {
            (0, 0)
        };

        self.padding = padding(size).ok_or_else(|| invalid("tar entry size is too large"))?;
        self.remaining = size;
        let header = Header {
            path,
            kind,
            size,
            mode,
            uid,
            gid,
            mtime,
            link,
            dev_major,
            dev_minor,
            xattrs: ov.xattrs,
        };
        self.sink.file_begin(&header)?;
        self.in_entry = true;
        Ok(header)
    }
}

/// The data of the current entry.
impl<R: Read, S: Sink> Read for TarReader<R, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.sink.file_data(&buf[..n])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// The name of an entry as stored in a TOC: no leading `./` or `/`, no
/// trailing `/`, no empty, `.` or `..` components.  `None` for a name that is
/// the root or that tries to leave it.
pub fn normalize_path(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => return None,
            p => parts.push(p),
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn entry(builder: &mut tar::Builder<Vec<u8>>, path: &str, kind: tar::EntryType, data: &[u8]) {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(kind);
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_uid(1000);
        h.set_gid(2000);
        h.set_mtime(1_700_000_000);
        builder.append_data(&mut h, path, data).unwrap();
    }

    fn read_all(archive: Vec<u8>) -> io::Result<Vec<(Header, Vec<u8>)>> {
        let mut r = TarReader::new(Cursor::new(archive));
        let mut out = Vec::new();
        while let Some(h) = r.next_entry()? {
            let mut data = Vec::new();
            r.read_to_end(&mut data)?;
            out.push((h, data));
        }
        Ok(out)
    }

    #[test]
    fn test_basic_entries() {
        let mut b = tar::Builder::new(Vec::new());
        entry(&mut b, "dir/", tar::EntryType::Directory, b"");
        entry(&mut b, "dir/file", tar::EntryType::Regular, b"hello");
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, "dir/link", "file").unwrap();
        let entries = read_all(b.into_inner().unwrap()).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0.kind, Kind::Directory);
        assert_eq!(entries[1].0.path, "dir/file");
        assert_eq!(entries[1].0.size, 5);
        assert_eq!(entries[1].0.uid, 1000);
        assert_eq!(entries[1].0.gid, 2000);
        assert_eq!(entries[1].0.mode, 0o644);
        assert_eq!(entries[1].1, b"hello");
        assert_eq!(entries[2].0.kind, Kind::Symlink);
        assert_eq!(entries[2].0.link.as_deref(), Some("file"));
    }

    #[test]
    fn test_mtime_from_pax() {
        let mut pax = tar::Builder::new(Vec::new());
        pax.append_pax_extensions([("mtime", b"1700000000.25".as_slice())])
            .unwrap();
        entry(&mut pax, "a", tar::EntryType::Regular, b"");
        pax.append_pax_extensions([("mtime", b"-1.5".as_slice())])
            .unwrap();
        entry(&mut pax, "b", tar::EntryType::Regular, b"");
        entry(&mut pax, "c", tar::EntryType::Regular, b"");
        let entries = read_all(pax.into_inner().unwrap()).unwrap();
        assert_eq!(entries[0].0.mtime, (1_700_000_000, 250_000_000));
        assert_eq!(entries[1].0.mtime, (-2, 500_000_000));
        assert_eq!(entries[2].0.mtime, (1_700_000_000, 0));
    }

    #[test]
    fn test_unread_data_is_skipped() {
        let mut b = tar::Builder::new(Vec::new());
        entry(&mut b, "a", tar::EntryType::Regular, &[7u8; 1000]);
        entry(&mut b, "b", tar::EntryType::Regular, b"x");
        let mut r = TarReader::new(Cursor::new(b.into_inner().unwrap()));
        assert_eq!(r.next_entry().unwrap().unwrap().path, "a");
        assert_eq!(r.next_entry().unwrap().unwrap().path, "b");
        assert!(r.next_entry().unwrap().is_none());
    }

    #[test]
    fn test_long_name_and_pax() {
        let long = format!("{}/file", "d".repeat(200));
        let mut b = tar::Builder::new(Vec::new());
        entry(&mut b, &long, tar::EntryType::Regular, b"1");
        let mut pax = tar::Builder::new(Vec::new());
        pax.append_pax_extensions([
            ("path", b"pax/path".as_slice()),
            ("SCHILY.xattr.user.k", b"value".as_slice()),
            ("uid", b"4000000".as_slice()),
        ])
        .unwrap();
        entry(&mut pax, "short", tar::EntryType::Regular, b"22");
        let mut archive = b.into_inner().unwrap();
        archive.truncate(archive.len() - 1024);
        archive.extend(pax.into_inner().unwrap());
        let entries = read_all(archive).unwrap();
        assert_eq!(entries[0].0.path, long);
        assert_eq!(entries[1].0.path, "pax/path");
        assert_eq!(entries[1].0.uid, 4_000_000);
        assert_eq!(entries[1].0.xattrs["user.k"], b"value");
        assert_eq!(entries[1].1, b"22");
    }

    #[test]
    fn test_a_path_that_is_too_deep_is_refused() {
        let deep = |n: usize| vec!["d"; n].join("/");
        assert!(!too_deep(&deep(MAX_PATH_DEPTH)));
        assert!(!too_deep(&format!("./{}//", deep(MAX_PATH_DEPTH))));
        assert!(too_deep(&deep(MAX_PATH_DEPTH + 1)));
        let ok = format!("{}/f", deep(MAX_PATH_DEPTH - 1));
        let mut b = tar::Builder::new(Vec::new());
        entry(&mut b, &ok, tar::EntryType::Regular, b"x");
        assert_eq!(read_all(b.into_inner().unwrap()).unwrap().len(), 1);
        let mut b = tar::Builder::new(Vec::new());
        entry(&mut b, &format!("{ok}/f"), tar::EntryType::Regular, b"x");
        let err = read_all(b.into_inner().unwrap()).unwrap_err();
        assert!(err.to_string().contains("too deep"), "{err}");
    }

    #[test]
    fn test_hardlink_and_devices() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Link);
        h.set_size(0);
        b.append_link(&mut h, "link", "target").unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Char);
        h.set_size(0);
        h.set_device_major(1).unwrap();
        h.set_device_minor(3).unwrap();
        h.set_mode(0o666);
        b.append_data(&mut h, "dev/null", io::empty()).unwrap();
        let entries = read_all(b.into_inner().unwrap()).unwrap();
        assert_eq!(entries[0].0.kind, Kind::Hardlink);
        assert_eq!(entries[0].0.link.as_deref(), Some("target"));
        assert_eq!(entries[1].0.kind, Kind::Char);
        assert_eq!((entries[1].0.dev_major, entries[1].0.dev_minor), (1, 3));
    }

    /// A size whose padding does not fit in 64 bits is an error, in the
    /// header and in a PAX record.
    #[test]
    fn test_size_at_the_limit_is_refused() {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.as_old_mut().size = [
            0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        h.set_cksum();
        let mut archive = h.as_bytes().to_vec();
        archive.extend_from_slice(&[0u8; 1024]);
        assert!(read_all(archive).is_err());

        let rec = format!("size={}\n", u64::MAX);
        let rec = format!("{} {rec}", rec.len() + 3);
        let mut x = tar::Header::new_ustar();
        x.set_entry_type(tar::EntryType::XHeader);
        x.set_size(rec.len() as u64);
        x.set_cksum();
        let mut archive = x.as_bytes().to_vec();
        archive.extend_from_slice(rec.as_bytes());
        archive.resize(1024, 0);
        let mut h = tar::Header::new_ustar();
        h.set_path("f").unwrap();
        h.set_size(0);
        h.set_cksum();
        archive.extend_from_slice(h.as_bytes());
        archive.extend_from_slice(&[0u8; 1024]);
        assert!(read_all(archive).is_err());
    }

    #[test]
    fn test_bad_checksum_and_truncation() {
        let mut b = tar::Builder::new(Vec::new());
        entry(&mut b, "a", tar::EntryType::Regular, b"abc");
        let archive = b.into_inner().unwrap();
        let mut bad = archive.clone();
        bad[0] ^= 1;
        assert!(read_all(bad).is_err());
        assert!(read_all(archive[..700].to_vec()).is_err());
    }

    #[test]
    fn test_unsupported_entries_are_refused() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::GNUSparse);
        h.set_size(0);
        b.append_data(&mut h, "sparse", io::empty()).unwrap();
        assert!(read_all(b.into_inner().unwrap()).is_err());
        // the pax formats of GNU tar: a regular entry of the packed data
        for key in ["GNU.sparse.size", "GNU.sparse.major", "GNU.sparse.map"] {
            let record = format!(" {key}=1\n");
            let record = format!("{}{record}", record.len() + 2);
            let mut b = tar::Builder::new(Vec::new());
            let mut x = tar::Header::new_ustar();
            x.set_entry_type(tar::EntryType::XHeader);
            x.set_size(record.len() as u64);
            b.append_data(&mut x, "PaxHeaders/f", record.as_bytes())
                .unwrap();
            let mut h = tar::Header::new_ustar();
            h.set_size(0);
            b.append_data(&mut h, "GNUSparseFile.1/f", io::empty())
                .unwrap();
            let err = read_all(b.into_inner().unwrap()).unwrap_err();
            assert!(err.to_string().contains("sparse"), "{key}: {err}");
        }
    }

    #[test]
    fn test_oversized_extension_is_refused_without_allocating() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::XHeader);
        h.set_size(1 << 40);
        h.set_cksum();
        let mut archive = Vec::new();
        archive.extend_from_slice(h.as_bytes());
        drop(b.finish());
        let err = read_all(archive).unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    /// The PAX record of `key=value`, with its length.
    fn record_of(kv: &str) -> Vec<u8> {
        let mut len = kv.len() + 3;
        while format!("{len} {kv}\n").len() != len {
            len += 1;
        }
        format!("{len} {kv}\n").into_bytes()
    }

    #[test]
    fn test_pax_limits() {
        let mut ov = Overrides::default();
        assert!(parse_pax(b"6 a=b\n", &mut ov).is_ok());
        assert!(parse_pax(b"99 a=b\n", &mut Overrides::default()).is_err());
        assert!(parse_pax(b"nonsense", &mut Overrides::default()).is_err());
        let mut many = Vec::new();
        for i in 0..=MAX_XATTRS {
            many.extend(record_of(&format!("SCHILY.xattr.k{i}=v")));
        }
        assert!(parse_pax(&many, &mut Overrides::default()).is_err());
    }

    /// `str::parse` took a leading `+` in the length of a record and in
    /// `size`, `uid` and `gid`; they are refused now, as the numbers of a
    /// header are (`mtime` refused it before).
    #[test]
    fn test_pax_plus_is_refused() {
        for kv in ["size=+5", "uid=+5", "gid=+5", "mtime=+5"] {
            let mut ov = Overrides::default();
            assert!(parse_pax(&record_of(kv), &mut ov).is_err(), "{kv}");
        }
        assert!(parse_pax(b"+7 a=b\n", &mut Overrides::default()).is_err());
    }

    #[test]
    fn test_pax_numbers() {
        let mut ov = Overrides::default();
        let mut all = Vec::new();
        for kv in ["size=42", "uid=7", "gid=8", "mtime=-1.5"] {
            all.extend(record_of(kv));
        }
        parse_pax(&all, &mut ov).unwrap();
        assert_eq!((ov.size, ov.uid, ov.gid), (Some(42), Some(7), Some(8)));
        assert_eq!(ov.mtime, Some((-2, 500_000_000)));
        for kv in ["size=4x", "size=", "uid=-1", "mtime=x"] {
            assert!(parse_pax(&record_of(kv), &mut Overrides::default()).is_err());
        }
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(
            normalize_path("./etc//passwd").as_deref(),
            Some("etc/passwd")
        );
        assert_eq!(normalize_path("/usr/bin/").as_deref(), Some("usr/bin"));
        assert_eq!(normalize_path("./"), None);
        assert_eq!(normalize_path("a/../b"), None);
        assert_eq!(normalize_path(".."), None);
    }

    /// Garbage never panics, whatever the bytes are.
    #[test]
    fn test_random_input_does_not_panic() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let mut b = tar::Builder::new(Vec::new());
        entry(&mut b, "a/b", tar::EntryType::Regular, b"data");
        let valid = b.into_inner().unwrap();
        for _ in 0..2000 {
            let mut data = valid.clone();
            for _ in 0..rng.gen_range(1..8) {
                let i = rng.gen_range(0..data.len());
                data[i] = rng.gen();
            }
            let _ = read_all(data);
        }
        for _ in 0..200 {
            let len = rng.gen_range(0..4096);
            let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            let _ = read_all(data);
        }
    }

    /// Replaying the recorded tar-split with the contents gives back the
    /// stream, whatever is in it.
    #[test]
    fn test_recorded_tarsplit_replays_the_stream() {
        use crate::{decoder, Contents, Entries, Recorder, Replay, MAX_SIZE};
        use std::collections::HashMap;

        struct Files(HashMap<String, Vec<u8>>);
        impl Contents for Files {
            fn open(&mut self, name: &str, _: u64) -> io::Result<Box<dyn Read + Send>> {
                let data = self.0.get(name).ok_or_else(|| invalid("missing"))?;
                Ok(Box::new(Cursor::new(data.clone())))
            }
        }

        let long = format!("{}/file", "d".repeat(150));
        let mut b = tar::Builder::new(Vec::new());
        entry(&mut b, "dir/", tar::EntryType::Directory, b"");
        entry(&mut b, "dir/empty", tar::EntryType::Regular, b"");
        entry(&mut b, "dir/small", tar::EntryType::Regular, b"hello");
        entry(&mut b, &long, tar::EntryType::Regular, &vec![7u8; 1500]);
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, "dir/link", "small").unwrap();
        let mut stream = b.into_inner().unwrap();
        // Padding to a record, as tar does, and unknown trailing bytes.
        stream.extend(vec![0u8; 4096]);
        stream.extend(b"trailing");

        let contents: HashMap<String, Vec<u8>> = HashMap::from([
            ("dir/small".to_string(), b"hello".to_vec()),
            (long.clone(), vec![7u8; 1500]),
        ]);
        let mut r = TarReader::with_sink(Cursor::new(stream.clone()), Recorder::new().unwrap());
        let mut names = Vec::new();
        while let Some(h) = r.next_entry().unwrap() {
            names.push(h.path.clone());
            // Read the content of some, leave the rest to be skipped.
            if h.path == "dir/small" {
                io::copy(&mut r, &mut io::sink()).unwrap();
            }
        }
        assert_eq!(names.len(), 5);
        let (_, recorder) = r.finish().unwrap();
        let recorded = recorder.finish().unwrap();

        let input = decoder(recorded.compressed, MAX_SIZE).unwrap();
        let mut replay = Replay::new(Entries::new(input), Files(contents));
        let mut out = Vec::new();
        replay.read_to_end(&mut out).unwrap();
        assert_eq!(out, stream);
    }
}
