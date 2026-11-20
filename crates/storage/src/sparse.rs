// SPDX-License-Identifier: Apache-2.0
//! Files written with holes where their content is zeros: the copies and
//! the files a pull writes keep the holes of a sparse file (a layer that
//! has one stores it with as few blocks as the file had).

use std::borrow::Borrow;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::FileExt;

/// Blocks of zeros of this size, at offsets that are multiples of it, are
/// holes; what is not a whole block of zeros is written.
pub const HOLE_BLOCK: usize = 4096;

/// Writes a file from its start, in order, leaving whole blocks of zeros
/// unwritten, however the content is cut.  [`SparseWriter::finish`] gives
/// the file its size (a file that ends in a hole).
pub struct SparseWriter<F: Borrow<File>> {
    file: F,
    /// Where `block` starts: a multiple of HOLE_BLOCK.
    pos: u64,
    /// The block in progress.
    block: Vec<u8>,
}

impl<F: Borrow<File>> SparseWriter<F> {
    pub fn new(file: F) -> Self {
        Self::at(file, 0)
    }

    /// A writer whose content starts at `base` of the file.
    /// [`SparseWriter::finish`] gives the offset the content ends at.
    pub fn at(file: F, base: u64) -> Self {
        Self {
            file,
            pos: base,
            block: Vec::with_capacity(HOLE_BLOCK),
        }
    }

    pub fn write(&mut self, mut data: &[u8]) -> io::Result<()> {
        if !self.block.is_empty() {
            let n = data.len().min(HOLE_BLOCK - self.block.len());
            self.block.extend_from_slice(&data[..n]);
            data = &data[n..];
            if self.block.len() < HOLE_BLOCK {
                return Ok(());
            }
            let block = std::mem::take(&mut self.block);
            if is_zeros(&block) {
                self.pos += HOLE_BLOCK as u64;
            } else {
                self.put(&block)?;
            }
            self.block = block;
            self.block.clear();
        }
        // whole blocks, then what is left of one
        let whole = data.len() - data.len() % HOLE_BLOCK;
        let (blocks, rest) = data.split_at(whole);
        let mut start = 0;
        for (i, b) in blocks.as_chunks::<HOLE_BLOCK>().0.iter().enumerate() {
            if is_zeros(b) {
                // the data before the hole, in one write
                self.put(&blocks[start..i * HOLE_BLOCK])?;
                self.pos += HOLE_BLOCK as u64;
                start = (i + 1) * HOLE_BLOCK;
            }
        }
        self.put(&blocks[start..])?;
        self.block.extend_from_slice(rest);
        Ok(())
    }

    /// Write `data` at the position, which it advances.
    fn put(&mut self, data: &[u8]) -> io::Result<()> {
        if !data.is_empty() {
            self.file.borrow().write_all_at(data, self.pos)?;
        }
        self.pos += data.len() as u64;
        Ok(())
    }

    /// The size written; the file is extended to it.
    pub fn finish(mut self) -> io::Result<u64> {
        let last = std::mem::take(&mut self.block);
        let size = self.pos + last.len() as u64;
        if !is_zeros(&last) {
            self.put(&last)?;
        }
        if self.file.borrow().metadata()?.len() < size {
            self.file.borrow().set_len(size)?;
        }
        Ok(size)
    }
}

impl<F: Borrow<File>> Write for SparseWriter<F> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        SparseWriter::write(self, data)?;
        Ok(data.len())
    }

    /// (the block in progress is written by [`SparseWriter::finish`])
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Write `data` at `offset` of a file that has its length (`set_len`) and
/// nothing there yet, leaving whole blocks of zeros, at multiples of
/// [`HOLE_BLOCK`] of the file, as holes.
pub fn write_at_sparse(file: &File, data: &[u8], offset: u64) -> io::Result<()> {
    let block = HOLE_BLOCK as u64;
    // (what comes before the first block of the file is data)
    let head = ((block - offset % block) % block).min(data.len() as u64) as usize;
    // where the data not written yet starts, and the block looked at
    let (mut run, mut pos) = (0, head);
    for b in data[head..].chunks(HOLE_BLOCK) {
        if b.len() == HOLE_BLOCK && is_zeros(b) {
            if run < pos {
                file.write_all_at(&data[run..pos], offset + run as u64)?;
            }
            run = pos + HOLE_BLOCK;
        }
        pos += b.len();
    }
    if run < pos {
        file.write_all_at(&data[run..pos], offset + run as u64)?;
    }
    Ok(())
}

pub fn is_zeros(data: &[u8]) -> bool {
    data.iter().all(|&b| b == 0)
}

/// Copy all of `from` to `to` (empty), with the holes of zeros; calls
/// `seen` with each piece of the content as it goes.  Returns the size.
pub fn copy_sparse(mut from: impl Read, to: &File, mut seen: impl FnMut(&[u8])) -> io::Result<u64> {
    let mut w = SparseWriter::new(to);
    // (a buffer that grows with the file: a megabyte cleared for each of
    // 100,000 small files is most of what a copy of them costs)
    let mut buf = vec![0u8; 16 << 10];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        seen(&buf[..n]);
        w.write(&buf[..n])?;
        if n == buf.len() && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 4, 0);
        }
    }
    w.finish()
}

/// The most one `copy_file_range` call is asked for: a copy can be stopped
/// between two.
const COPY_STEP: u64 = 64 << 20;

/// Copy the first `len` bytes of `from` to `to` (empty), keeping its holes:
/// only the data is copied (cloned where the file system can), the file gets
/// its size with `ftruncate`.  On a file system that cannot tell the holes,
/// a file with fewer blocks than its size is read and its blocks of zeros
/// are left as holes; any other is copied whole (zeros a file has written
/// are its own: a dense file stays dense).  `step` is called between the
/// pieces: an error from it ends the copy.  Returns the size.
pub fn copy_file(
    from: &File,
    to: &File,
    len: u64,
    step: impl FnMut() -> io::Result<()>,
) -> io::Result<u64> {
    let size = from.metadata()?.len().min(len);
    copy_region(from, 0, to, 0, size, step)?;
    Ok(size)
}

/// Copy the `len` bytes from `from_at` of `from` to `to_at` of `to`, as
/// [`copy_file`] copies a file: its holes stay holes, and `to` is at least
/// `to_at + len` bytes long.  The region must lie in `from`.
pub fn copy_region(
    from: &File,
    from_at: u64,
    to: &File,
    to_at: u64,
    len: u64,
    step: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    copy_region_holes(from, from_at, to, to_at, len, step, &mut |_, _| {})
}

/// [`copy_region`], telling `hole(at, length)` of each hole the region has
/// (offsets from the start of the region, in order), as the copy leaves it.
/// A file system that cannot tell the holes tells none.
pub fn copy_region_holes(
    from: &File,
    from_at: u64,
    to: &File,
    to_at: u64,
    len: u64,
    mut step: impl FnMut() -> io::Result<()>,
    hole: &mut dyn FnMut(u64, u64),
) -> io::Result<()> {
    use rustix::fs::{seek, SeekFrom};
    use std::os::unix::fs::{FileExt, MetadataExt};
    // (a region of less than a block has no hole: one read and one write, no
    // seeks and no clone)
    if len < HOLE_BLOCK as u64 {
        let mut buf = [0u8; HOLE_BLOCK];
        let buf = &mut buf[..len as usize];
        step()?;
        from.read_exact_at(buf, from_at).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                shorter()
            } else {
                e
            }
        })?;
        to.write_all_at(buf, to_at)?;
        return Ok(());
    }
    let meta = from.metadata()?;
    let end_of = from_at
        .checked_add(len)
        .filter(|e| *e <= meta.len())
        .ok_or_else(shorter)?;
    let to_end = to_at
        .checked_add(len)
        .ok_or_else(|| io::Error::other("a region ends beyond the file"))?;
    let mut pos = from_at;
    while pos < end_of {
        let data = match seek(from, SeekFrom::Data(pos)) {
            Ok(d) => d.min(end_of),
            // nothing but a hole is left
            Err(rustix::io::Errno::NXIO) => {
                if pos < end_of {
                    hole(pos - from_at, end_of - pos);
                }
                break;
            }
            // a file system that cannot tell, and a file with holes
            Err(_) if pos == from_at && meta.blocks() * 512 < meta.len() => {
                return copy_zeros_as_holes(from, from_at, to, to_at, len, step);
            }
            // a file system that cannot tell: all data
            Err(_) => pos,
        };
        if data > pos {
            hole(pos - from_at, data - pos);
        }
        let stop = match seek(from, SeekFrom::Hole(data)) {
            Ok(h) => h.min(end_of),
            Err(_) => end_of,
        };
        let mut at = data;
        while at < stop {
            step()?;
            let n = copy_range(
                from,
                at,
                to,
                to_at + (at - from_at),
                (stop - at).min(COPY_STEP),
            )?;
            if n == 0 {
                return Err(shorter());
            }
            at += n;
        }
        pos = stop;
    }
    if to.metadata()?.len() < to_end {
        to.set_len(to_end)?;
    }
    Ok(())
}

/// Copy the `len` bytes from `from_at` of `from`, read whole, to `to_at` of
/// `to`, its blocks of zeros left as holes.
fn copy_zeros_as_holes(
    from: &File,
    from_at: u64,
    to: &File,
    to_at: u64,
    len: u64,
    mut step: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    let mut w = SparseWriter::at(to, to_at);
    let mut buf = vec![0u8; COPY_STEP.min(1 << 20) as usize];
    let mut at = 0;
    while at < len {
        step()?;
        let want = (len - at).min(buf.len() as u64) as usize;
        let n = from.read_at(&mut buf[..want], from_at + at)?;
        if n == 0 {
            return Err(shorter());
        }
        w.write(&buf[..n])?;
        at += n as u64;
    }
    w.finish().map(drop)
}

/// A file that got shorter while it was copied.
fn shorter() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "the file got shorter while it was copied",
    )
}

/// [`std::fs::copy`] where the holes of the file stay holes: the new file
/// has the permissions of `from`.
pub fn copy_path(from: &std::path::Path, to: &std::path::Path) -> io::Result<u64> {
    let source = File::open(from)?;
    let mode = source.metadata()?;
    let dest = File::create(to)?;
    let size = copy_file(&source, &dest, u64::MAX, || Ok(()))?;
    dest.set_permissions(mode.permissions())?;
    Ok(size)
}

/// Copy up to `len` bytes at `at` of `from` to `to_at` of `to`; returns how
/// many.
fn copy_range(from: &File, at: u64, to: &File, to_at: u64, len: u64) -> io::Result<u64> {
    let (mut off_in, mut off_out) = (at, to_at);
    match rustix::fs::copy_file_range(
        from,
        Some(&mut off_in),
        to,
        Some(&mut off_out),
        len as usize,
    ) {
        Ok(n) => return Ok(n as u64),
        // not on this file system or between these: read and write
        Err(
            rustix::io::Errno::XDEV
            | rustix::io::Errno::NOSYS
            | rustix::io::Errno::INVAL
            | rustix::io::Errno::OPNOTSUPP
            | rustix::io::Errno::PERM,
        ) => {}
        Err(e) => return Err(e.into()),
    }
    let mut buf = vec![0u8; len.min(1 << 20) as usize];
    let n = from.read_at(&mut buf, at)?;
    to.write_all_at(&buf[..n], to_at)?;
    Ok(n as u64)
}

/// A piece of the content of a file [`read_sparse`] gives: bytes it read,
/// or the length of a hole (zeros it did not read).
pub enum Piece<'a> {
    Data(&'a [u8]),
    Zeros(u64),
}

/// Give all of `file` to `f` in order, its holes (`SEEK_HOLE`) as lengths;
/// a file system that cannot tell has none.  Returns the size.
pub fn read_sparse(file: &File, f: impl FnMut(Piece<'_>)) -> io::Result<u64> {
    read_sparse_by(file, 1 << 20, f)
}

/// [`read_sparse`], its data given in pieces of at most `most` bytes.
pub fn read_sparse_by(file: &File, most: u64, mut f: impl FnMut(Piece<'_>)) -> io::Result<u64> {
    use rustix::fs::{seek, SeekFrom};
    let size = file.metadata()?.len();
    // (not a megabyte cleared for each of 100,000 small files)
    let mut buf = vec![0u8; size.min(most) as usize];
    let mut pos = 0;
    while pos < size {
        // (one seek for a file that has no hole)
        let mut end = match seek(file, SeekFrom::Hole(pos)) {
            Ok(h) => h.min(size),
            Err(_) => size,
        };
        if end == pos {
            match seek(file, SeekFrom::Data(pos)) {
                Ok(d) if d > pos => {
                    let d = d.min(size);
                    f(Piece::Zeros(d - pos));
                    pos = d;
                    continue;
                }
                Err(rustix::io::Errno::NXIO) => {
                    f(Piece::Zeros(size - pos));
                    break;
                }
                _ => end = size,
            }
        }
        while pos < end {
            let want = (end - pos).min(buf.len() as u64) as usize;
            let n = file.read_at(&mut buf[..want], pos)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the file got shorter while it was read",
                ));
            }
            f(Piece::Data(&buf[..n]));
            pos += n as u64;
        }
    }
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// A region is copied with its holes, which are told with offsets from
    /// the start of the region; a region of less than a block is copied
    /// without a look at the holes, and one past the end of the source is
    /// an error either way.
    #[test]
    fn the_holes_of_a_region_are_told() {
        let dir = tempfile::tempdir().unwrap();
        let from = File::create(dir.path().join("from")).unwrap();
        let mut data = vec![3u8; 100];
        data.resize(3 * 4096, 0);
        data.extend(vec![4u8; 4096]);
        data.extend(vec![0u8; 2 * 4096]);
        copy_sparse(&data[..], &from, |_| {}).unwrap();
        let from = File::open(dir.path().join("from")).unwrap();
        let rw = |n: &str| {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(dir.path().join(n))
                .unwrap()
        };
        let to = rw("to");
        let mut holes = Vec::new();
        copy_region_holes(
            &from,
            0,
            &to,
            4096,
            data.len() as u64,
            || Ok(()),
            &mut |at, len| holes.push((at, len)),
        )
        .unwrap();
        // (a file system that cannot tell holes tells none)
        if !holes.is_empty() {
            assert_eq!(holes, [(4096, 2 * 4096), (4 * 4096, 2 * 4096)]);
        }
        let mut got = vec![0u8; data.len()];
        std::os::unix::fs::FileExt::read_exact_at(&to, &mut got, 4096).unwrap();
        assert!(got == data);
        // a small region: read and written, no hole told
        let mut told = 0;
        let small = rw("small");
        copy_region_holes(&from, 10, &small, 7, 50, || Ok(()), &mut |_, _| told += 1).unwrap();
        assert_eq!(told, 0);
        assert_eq!(small.metadata().unwrap().len(), 57);
        let mut got = [0u8; 50];
        std::os::unix::fs::FileExt::read_exact_at(&small, &mut got, 7).unwrap();
        assert_eq!(got[..], data[10..60]);
        // past the end of the source
        let e = copy_region(&from, data.len() as u64 - 10, &small, 0, 100, || Ok(())).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        let e =
            copy_region(&from, data.len() as u64 - 10, &small, 0, 20000, || Ok(())).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// The pieces are the content, the holes of the file as zeros, however
    /// the file starts and ends.
    #[test]
    fn a_sparse_read_gives_the_content() {
        let dir = tempfile::tempdir().unwrap();
        for (i, (head, tail)) in [(0, 0), (1 << 20, 0), (0, 3 << 20), (5000, 1 << 20)]
            .into_iter()
            .enumerate()
        {
            let mut data = vec![0u8; head];
            data.extend(vec![9u8; 10_000]);
            data.extend(vec![0u8; 2 << 20]);
            data.extend(b"middle");
            data.extend(vec![0u8; tail]);
            let path = dir.path().join(format!("f{i}"));
            let f = File::create(&path).unwrap();
            copy_sparse(&data[..], &f, |_| {}).unwrap();
            let f = File::open(&path).unwrap();
            let (mut read, mut zeros) = (Vec::new(), 0);
            let size = read_sparse(&f, |p| match p {
                Piece::Data(d) => read.extend_from_slice(d),
                Piece::Zeros(n) => {
                    zeros += n;
                    read.extend(std::iter::repeat_n(0, n as usize));
                }
            })
            .unwrap();
            assert_eq!(size, data.len() as u64);
            assert_eq!(read, data, "{head} {tail}");
            assert_eq!(
                crate::fsverity_digest_file(velarx_types::digest::Algorithm::Sha256, &f).unwrap(),
                crate::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, &data)
            );
            // (a file system that has holes did not read them)
            if f.metadata().unwrap().blocks() < 1024 {
                assert!(zeros >= (2 << 20) - 2 * HOLE_BLOCK as u64, "{zeros}");
            }
        }
    }

    #[test]
    fn whole_blocks_of_zeros_are_holes() {
        let mut data = vec![7u8; 100];
        data.extend(vec![0u8; 1 << 20]);
        data.extend(b"middle");
        data.extend(vec![0u8; 1 << 20]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        let f = File::create(&path).unwrap();
        let mut hashed = Vec::new();
        // in odd pieces, as a stream gives them
        let size = copy_sparse(std::io::Cursor::new(&data), &f, |b| {
            hashed.extend_from_slice(b)
        })
        .unwrap();
        assert_eq!(size, data.len() as u64);
        assert_eq!(hashed, data);
        assert_eq!(std::fs::read(&path).unwrap(), data);
        // two blocks of data at most, where the file system has holes
        let blocks = f.metadata().unwrap().blocks();
        assert!(blocks <= 64, "{blocks} blocks of 512 bytes");

        let g = File::create(dir.path().join("g")).unwrap();
        let mut w = SparseWriter::new(&g);
        for piece in data.chunks(1000) {
            w.write(piece).unwrap();
        }
        let blocks = g.metadata().unwrap().blocks();
        assert!(
            blocks <= 64,
            "{blocks} blocks of 512 bytes, in pieces of 1000"
        );
        assert_eq!(w.finish().unwrap(), data.len() as u64);
        assert_eq!(std::fs::read(dir.path().join("g")).unwrap(), data);
        assert!(is_zeros(&[0; 33]) && !is_zeros(&[0, 0, 1]) && is_zeros(&[]));
    }

    /// A file of `size` bytes with `data` at the offsets, the rest a hole.
    fn holey(dir: &std::path::Path, name: &str, size: u64, data: &[(u64, &[u8])]) -> File {
        let f = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.join(name))
            .unwrap();
        f.set_len(size).unwrap();
        for (off, d) in data {
            f.write_all_at(d, *off).unwrap();
        }
        f
    }

    /// A copy has the content, the size and the holes of the file: a 1 GiB
    /// file with a few bytes takes a few blocks, and so does its copy.
    #[test]
    fn a_copy_of_a_file_keeps_its_holes() {
        let dir = tempfile::tempdir().unwrap();
        const G: u64 = 1 << 30;
        let from = holey(
            dir.path(),
            "a",
            G,
            &[(0, b"head"), (G / 2 + 5, b"mid"), (G - 3, b"end")],
        );
        if from.metadata().unwrap().blocks() > 1024 {
            eprintln!("no holes in this file system: skipped");
            return;
        }
        let to = File::create(dir.path().join("b")).unwrap();
        let steps = std::cell::Cell::new(0);
        let n = copy_file(&from, &to, u64::MAX, || {
            steps.set(steps.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(n, G);
        assert!(steps.get() >= 3);
        assert_eq!(to.metadata().unwrap().len(), G);
        let blocks = to.metadata().unwrap().blocks();
        assert!(blocks < 64, "{blocks} blocks of 512 bytes");
        let to = File::open(dir.path().join("b")).unwrap();
        let mut word = [0u8; 4];
        to.read_exact_at(&mut word, G / 2 + 4).unwrap();
        assert_eq!(&word, b"\0mid");
        to.read_exact_at(&mut word[..3], G - 3).unwrap();
        assert_eq!(&word[..3], b"end");
        // the digest of the content is that of a file without holes
        assert_eq!(
            crate::fsverity_digest_file(velarx_types::digest::Algorithm::Sha256, &to).unwrap(),
            crate::fsverity_digest_file(velarx_types::digest::Algorithm::Sha256, &from).unwrap()
        );
        // a part of the file, and a file that ends in a hole
        let part = File::create(dir.path().join("c")).unwrap();
        assert_eq!(copy_file(&from, &part, 100, || Ok(())).unwrap(), 100);
        let part = File::open(dir.path().join("c")).unwrap();
        assert_eq!(part.metadata().unwrap().len(), 100);
        let mut head = [0u8; 4];
        part.read_exact_at(&mut head, 0).unwrap();
        assert_eq!(&head, b"head");
        // a step that fails ends the copy
        let e = copy_file(
            &from,
            &File::create(dir.path().join("d")).unwrap(),
            u64::MAX,
            || Err(io::Error::other("stop")),
        )
        .unwrap_err();
        assert_eq!(e.to_string(), "stop");
        // the same by name, with the permissions
        let mode = std::os::unix::fs::PermissionsExt::from_mode(0o640);
        std::fs::set_permissions(dir.path().join("a"), mode).unwrap();
        copy_path(&dir.path().join("a"), &dir.path().join("e")).unwrap();
        let e = std::fs::metadata(dir.path().join("e")).unwrap();
        assert_eq!(e.len(), G);
        assert!(e.blocks() < 64);
        assert_eq!(e.mode() & 0o777, 0o640);
    }

    /// A file read whole (a file system that cannot tell its holes) is
    /// copied with its blocks of zeros as holes, and its size.
    #[test]
    fn a_file_read_whole_is_copied_with_holes() {
        let dir = tempfile::tempdir().unwrap();
        let mut want = vec![0u8; (8 << 20) + 100];
        want[10..20].fill(3);
        want[(5 << 20) + 7] = 9;
        std::fs::write(dir.path().join("a"), &want).unwrap();
        let from = File::open(dir.path().join("a")).unwrap();
        let to = File::create(dir.path().join("b")).unwrap();
        let steps = std::cell::Cell::new(0);
        copy_zeros_as_holes(&from, 0, &to, 0, want.len() as u64, || {
            steps.set(steps.get() + 1);
            Ok(())
        })
        .unwrap();
        assert!(steps.get() >= 8);
        assert_eq!(std::fs::read(dir.path().join("b")).unwrap(), want);
        let probe = holey(dir.path(), "p", 1 << 20, &[]);
        if probe.metadata().unwrap().blocks() == 0 {
            let blocks = to.metadata().unwrap().blocks();
            assert!(blocks < 128, "{blocks} blocks of 512 bytes");
        }
    }

    /// A region of a file goes to another place of another, with its holes,
    /// and the file is long enough.
    #[test]
    fn a_region_is_copied_to_another_place() {
        let dir = tempfile::tempdir().unwrap();
        let mut src = vec![0u8; 3 << 20];
        src[(1 << 20) + 5..(1 << 20) + 15].fill(7);
        src[(2 << 20) + 100] = 9;
        let from = holey(dir.path(), "from", 3 << 20, &[]);
        from.write_all_at(&src[(1 << 20) + 5..(1 << 20) + 15], (1 << 20) + 5)
            .unwrap();
        from.write_all_at(&src[(2 << 20) + 100..(2 << 20) + 101], (2 << 20) + 100)
            .unwrap();
        let to = holey(dir.path(), "to", 0, &[]);
        let (at, len) = (1u64 << 20, 2u64 << 20);
        copy_region(&from, at, &to, 8192, len, || Ok(())).unwrap();
        let got = std::fs::read(dir.path().join("to")).unwrap();
        assert_eq!(got.len() as u64, 8192 + len);
        assert!(got[..8192].iter().all(|b| *b == 0));
        assert_eq!(&got[8192..], &src[at as usize..(at + len) as usize]);
        let e = copy_region(&from, 3 << 20, &to, 0, 1, || Ok(())).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        let w = SparseWriter::at(&to, 4096);
        assert_eq!(w.finish().unwrap(), 4096);
    }

    /// A chunk of zeros written into a file that has its size leaves holes,
    /// whatever its alignment, and the content is as written.
    #[test]
    fn zeros_written_at_an_offset_are_holes() {
        let dir = tempfile::tempdir().unwrap();
        let size = 8 << 20;
        let f = holey(dir.path(), "f", size, &[]);
        let mut want = vec![0u8; size as usize];
        // data, zeros, data, in pieces that are not aligned
        let pieces: [(u64, Vec<u8>); 3] = [
            (
                100,
                [vec![1u8; 50], vec![0u8; 3 << 20], vec![2u8; 70]].concat(),
            ),
            ((3 << 20) + 5000, vec![0u8; 2 << 20]),
            (size - 10, vec![7u8; 10]),
        ];
        for (off, d) in &pieces {
            write_at_sparse(&f, d, *off).unwrap();
            want[*off as usize..*off as usize + d.len()].copy_from_slice(d);
        }
        assert_eq!(std::fs::read(dir.path().join("f")).unwrap(), want);
        let blocks = f.metadata().unwrap().blocks();
        assert!(blocks < 128, "{blocks} blocks of 512 bytes");
    }

    /// A `SparseWriter` is a writer: what `io::copy` gives it is a file
    /// with holes.
    #[test]
    fn a_sparse_writer_is_a_writer() {
        let dir = tempfile::tempdir().unwrap();
        let f = File::create(dir.path().join("f")).unwrap();
        let mut data = vec![0u8; 4 << 20];
        data.extend(b"x");
        let mut w = SparseWriter::new(f.try_clone().unwrap());
        std::io::copy(&mut &data[..], &mut w).unwrap();
        w.flush().unwrap();
        w.finish().unwrap();
        assert_eq!(std::fs::read(dir.path().join("f")).unwrap(), data);
        assert!(f.metadata().unwrap().blocks() < 64);
    }

    /// On a file system with fs-verity (VELARX_VERITY_DIR): a sparse
    /// file has it, keeps its holes, and the kernel measures the digest of
    /// its content.
    #[test]
    fn fs_verity_of_a_sparse_file_is_that_of_its_content() {
        let Some(dir) = std::env::var_os("VELARX_VERITY_DIR") else {
            eprintln!("VELARX_VERITY_DIR not set: skipped");
            return;
        };
        let tmp = tempfile::tempdir_in(dir).unwrap();
        let path = tmp.path().join("f");
        let mut data = vec![3u8; 4096];
        data.extend(vec![0u8; 8 << 20]);
        let f = File::create(&path).unwrap();
        copy_sparse(&data[..], &f, |_| {}).unwrap();
        drop(f);
        crate::FsVerityManager::new().enable(&path).unwrap();
        let f = File::open(&path).unwrap();
        let m = crate::measure_file(&f).unwrap();
        assert_eq!(
            m.object().unwrap().to_string(),
            crate::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, &data)
        );
        assert!(f.metadata().unwrap().blocks() < 1024);
        assert_eq!(std::fs::read(&path).unwrap(), data);
    }
}
