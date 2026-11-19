// SPDX-License-Identifier: Apache-2.0
//! Holes in the tar stream of a layer.
//!
//! The content of a sparse file is read with `SEEK_DATA` and `SEEK_HOLE`: the
//! bytes of a hole are not read, and they are not copied to the writer
//! either: they travel as a length ([`HoleWrite::hole`]).

use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::FileExt;

/// A hole shorter than this is read as data: it is not worth a message, and
/// the holes of a file that has one every few pages stay in the stream.
pub const MIN_HOLE: u64 = 64 * 1024;

const BUFFER: usize = 256 * 1024;

/// A source file that does not have the size it had: it was written while
/// it was read.
pub fn changed(path: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::ResourceBusy,
        format!("`{path}` changed while reading it"),
    )
}

/// Write `len` bytes of zeros.
pub fn write_zeros(out: &mut (impl Write + ?Sized), mut len: u64) -> io::Result<()> {
    let zeros = [0u8; 8192];
    while len > 0 {
        let n = len.min(zeros.len() as u64) as usize;
        out.write_all(&zeros[..n])?;
        len -= n as u64;
    }
    Ok(())
}

/// The padding after `size` bytes of content.
pub fn pad(out: &mut (impl Write + ?Sized), size: u64) -> io::Result<()> {
    write_zeros(out, (512 - size % 512) % 512)
}

/// A writer of a tar stream that can be told of a hole in the content of a
/// file.  The default is to write the zeros.
pub trait HoleWrite: Write {
    fn hole(&mut self, len: u64) -> io::Result<()> {
        write_zeros(self, len)
    }
}

impl HoleWrite for Vec<u8> {}
impl HoleWrite for File {}
impl HoleWrite for io::Sink {}
impl HoleWrite for std::io::PipeWriter {}
impl<W: Write> HoleWrite for io::BufWriter<W> {}
impl<W: HoleWrite + ?Sized> HoleWrite for &mut W {
    fn hole(&mut self, len: u64) -> io::Result<()> {
        (**self).hole(len)
    }
}

/// A new, empty file written in order, where the holes of the stream are
/// holes of the file: they are not written.  [`SparseFile::finish`] gives it
/// its length.
pub struct SparseFile {
    file: File,
    /// Where `buf` goes in the file.
    pos: u64,
    buf: Vec<u8>,
}

impl SparseFile {
    pub fn new(file: File) -> Self {
        Self {
            file,
            pos: 0,
            buf: Vec::with_capacity(BUFFER),
        }
    }

    /// The file, with the length of the stream (a stream that ends in a
    /// hole), at its start.
    pub fn finish(mut self) -> io::Result<File> {
        use io::Seek;
        self.flush()?;
        self.file.set_len(self.pos)?;
        self.file.seek(io::SeekFrom::Start(0))?;
        Ok(self.file)
    }
}

impl Write for SparseFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.buf.len() + buf.len() > BUFFER {
            self.flush()?;
        }
        if buf.len() >= BUFFER {
            self.file.write_all_at(buf, self.pos)?;
            self.pos += buf.len() as u64;
        } else {
            self.buf.extend_from_slice(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.write_all_at(&self.buf, self.pos)?;
        self.pos += self.buf.len() as u64;
        self.buf.clear();
        Ok(())
    }
}

impl HoleWrite for SparseFile {
    fn hole(&mut self, len: u64) -> io::Result<()> {
        self.flush()?;
        self.pos += len;
        Ok(())
    }
}

/// Copy the first `size` bytes of `file` to `out`, the holes of the file as
/// holes (but the short ones).  A file that has less is an error.
pub fn copy_file(file: &File, size: u64, out: &mut dyn HoleWrite, path: &str) -> io::Result<()> {
    use rustix::fs::{seek, SeekFrom};
    let mut buf = vec![0u8; BUFFER];
    let mut pos = 0;
    while pos < size {
        // a file system that cannot say gives the whole file as data
        let data = match seek(file, SeekFrom::Data(pos)) {
            Ok(d) => d.min(size),
            Err(rustix::io::Errno::NXIO) => {
                // a trailing hole, unless the file got shorter
                if file.metadata()?.len() < size {
                    return Err(changed(path));
                }
                size
            }
            Err(_) => pos,
        };
        if data - pos >= MIN_HOLE {
            out.hole(data - pos)?;
            pos = data;
        }
        let end = match seek(file, SeekFrom::Hole(data)) {
            Ok(h) if data < size => h.max(pos + 1).min(size),
            _ => size,
        };
        while pos < end {
            let want = (end - pos).min(buf.len() as u64) as usize;
            let n = file.read_at(&mut buf[..want], pos)?;
            if n == 0 {
                return Err(changed(path));
            }
            out.write_all(&buf[..n])?;
            pos += n as u64;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file of `size` bytes with `data` at the offsets: the rest is a
    /// hole, where the file system has them.
    fn sparse(size: u64, data: &[(u64, &[u8])]) -> File {
        let f = tempfile::tempfile().unwrap();
        f.set_len(size).unwrap();
        for (off, d) in data {
            f.write_all_at(d, *off).unwrap();
        }
        f
    }

    #[derive(Debug, PartialEq)]
    enum Piece {
        Data(Vec<u8>),
        Hole(u64),
    }

    /// What `copy_file` writes, as pieces (neighbours merged) and as bytes.
    #[derive(Default)]
    struct Pieces(Vec<Piece>);

    impl Write for Pieces {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            match self.0.last_mut() {
                Some(Piece::Data(d)) => d.extend_from_slice(b),
                _ => self.0.push(Piece::Data(b.to_vec())),
            }
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl HoleWrite for Pieces {
        fn hole(&mut self, len: u64) -> io::Result<()> {
            self.0.push(Piece::Hole(len));
            Ok(())
        }
    }

    impl Pieces {
        fn bytes(&self) -> Vec<u8> {
            let mut out = Vec::new();
            for p in &self.0 {
                match p {
                    Piece::Data(d) => out.extend(d),
                    Piece::Hole(n) => out.resize(out.len() + *n as usize, 0),
                }
            }
            out
        }
    }

    fn content(f: &File, size: u64) -> Vec<u8> {
        let mut v = vec![0u8; size as usize];
        f.read_exact_at(&mut v, 0).unwrap();
        v
    }

    /// Whether the file system of the test has holes at all.
    fn has_holes(f: &File) -> bool {
        use rustix::fs::{seek, SeekFrom};
        seek(f, SeekFrom::Hole(0)).is_ok_and(|h| h < f.metadata().unwrap().len())
    }

    const M: u64 = MIN_HOLE;

    /// A copy into a sparse file has the content of the source and its
    /// holes, also one that ends it.
    #[test]
    fn a_sparse_file_keeps_the_holes_of_what_is_copied() {
        let size = 40 * M + 7;
        let f = sparse(size, &[(0, b"head"), (20 * M, &[5u8; 300_000])]);
        let mut out = SparseFile::new(tempfile::tempfile().unwrap());
        copy_file(&f, size, &mut out, "f").unwrap();
        out.write_all(b"tail").unwrap();
        out.hole(3 * M).unwrap();
        let copy = out.finish().unwrap();
        let mut want = content(&f, size);
        want.extend(b"tail");
        want.extend(vec![0u8; 3 * M as usize]);
        assert_eq!(copy.metadata().unwrap().len(), want.len() as u64);
        assert_eq!(content(&copy, want.len() as u64), want);
        if has_holes(&f) {
            // the holes as `SEEK_DATA` and `SEEK_HOLE` see them, not
            // `st_blocks`: xfs also counts the speculative preallocation of
            // the writes at increasing offsets, and reports the delayed
            // allocation after the data as data, so the hole that follows
            // the data may start later than its end
            use rustix::fs::{seek, SeekFrom};
            assert_eq!(seek(&copy, SeekFrom::Data(M)).unwrap(), 20 * M);
            let hole = seek(&copy, SeekFrom::Hole(20 * M)).unwrap();
            assert!(hole < 40 * M, "data up to {hole}");
            assert_eq!(seek(&copy, SeekFrom::Data(hole)).unwrap(), 40 * M);
        }
    }

    #[test]
    fn holes_at_the_start_the_middle_and_the_end() {
        let size = 10 * M + 100;
        let f = sparse(size, &[(3 * M, b"abc"), (7 * M + 5, b"xyz")]);
        let mut out = Pieces::default();
        copy_file(&f, size, &mut out, "f").unwrap();
        assert_eq!(out.bytes(), content(&f, size));
        if has_holes(&f) {
            // the hole of 3 M, the data, the hole up to the next data,
            // the data, and the hole to the end
            let holes: Vec<u64> = out
                .0
                .iter()
                .filter_map(|p| match p {
                    Piece::Hole(n) => Some(*n),
                    _ => None,
                })
                .collect();
            assert_eq!(holes.len(), 3);
            assert!(holes.iter().sum::<u64>() > 9 * M);
            for p in &out.0 {
                if let Piece::Data(d) = p {
                    assert!(d.len() < M as usize, "{}", d.len());
                }
            }
        }
    }

    #[test]
    fn data_then_a_hole_and_a_file_that_is_one_hole() {
        let size = 5 * M;
        let f = sparse(size, &[(0, b"head")]);
        let mut out = Pieces::default();
        copy_file(&f, size, &mut out, "f").unwrap();
        assert_eq!(out.bytes(), content(&f, size));
        if has_holes(&f) {
            assert!(matches!(out.0.last(), Some(Piece::Hole(n)) if *n > 4 * M));
        }

        let f = sparse(size, &[]);
        let mut out = Pieces::default();
        copy_file(&f, size, &mut out, "f").unwrap();
        assert_eq!(out.bytes(), vec![0u8; size as usize]);
        if has_holes(&f) {
            assert_eq!(out.0, vec![Piece::Hole(size)]);
        }
    }

    #[test]
    fn small_files_and_short_holes_are_data() {
        for size in [1u64, 100, 4095, 4096, 4097, M - 1] {
            let f = sparse(size, &[]);
            let mut out = Pieces::default();
            copy_file(&f, size, &mut out, "f").unwrap();
            assert_eq!(out.0, vec![Piece::Data(vec![0; size as usize])], "{size}");
        }
        // holes of a few pages between data
        let size = 100 * 4096;
        let writes: Vec<(u64, &[u8])> =
            (0..100).step_by(2).map(|i| (i * 4096, &b"d"[..])).collect();
        let f = sparse(size, &writes);
        let mut out = Pieces::default();
        copy_file(&f, size, &mut out, "f").unwrap();
        assert_eq!(out.bytes(), content(&f, size));
        assert!(out.0.iter().all(|p| matches!(p, Piece::Data(_))));
    }

    #[test]
    fn holes_that_are_not_aligned() {
        // the data ends in the middle of a page: the page is data, the
        // hole starts at the next one
        let size = 4 * M + 1000;
        let f = sparse(size, &[(10, b"0123456789"), (3 * M + 4000, b"tail")]);
        let mut out = Pieces::default();
        copy_file(&f, size, &mut out, "f").unwrap();
        assert_eq!(out.bytes(), content(&f, size));
    }

    #[test]
    fn a_file_that_shrinks_or_grows_is_the_size_it_was() {
        let f = sparse(2 * M, &[(0, b"x")]);
        // grew since it was seen: only the size seen is copied
        let mut out = Pieces::default();
        copy_file(&f, M, &mut out, "f").unwrap();
        assert_eq!(out.bytes().len() as u64, M);
        // shrank: an error, as for a file that is read
        f.set_len(100).unwrap();
        let mut out = Pieces::default();
        let e = copy_file(&f, 2 * M, &mut out, "f").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ResourceBusy);
    }
}
