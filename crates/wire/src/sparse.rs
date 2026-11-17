// SPDX-License-Identifier: Apache-2.0
//! Sparse files in the tar archives a user hands to the engine (a build
//! context, `cp`, a volume).
//!
//! GNU tar and the `tar` crate write a file with holes in one of four
//! ways: an entry of type `S` with its map in the header (old GNU), or an
//! ordinary entry with `GNU.sparse.*` records in an extended header (0.0,
//! 0.1) and, in 1.0, the map in the first blocks of the data.  The `tar`
//! crate reads the map of the first and hands over its data packed
//! (`Entry::take_sparse_blocks`); the others it hands over as a
//! file of the packed data under another name.  Here they all become the
//! file they describe, its holes kept (nothing is written for them), with
//! the limits a stream of this kind needs: the size of the file, the
//! blocks of the map, the order of the blocks and their sum.
//!
//! Layers of images are not read here: they are never sparse.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;

/// The largest file a sparse entry may describe.
pub const MAX_REAL_SIZE: u64 = 64 << 30;

/// The most blocks a map may have.
const MAX_BLOCKS: u64 = 1 << 20;

/// An archive whose sparse entries [`copy`] can make into files.
pub fn archive<R: Read>(r: R) -> tar::Archive<R> {
    tar::Archive::new(r)
}

/// The size of a block of the archive.
const BLOCK: u64 = 512;

/// Zeros are looked for in pieces of this size.
const PIECE: usize = 4096;

const PREFIX: &[u8] = b"GNU.sparse.";

/// The (offset, length) pairs of a map: the pieces of a file that hold data.
type Blocks = Vec<(u64, u64)>;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// What the `GNU.sparse.*` records of an extended header say.
#[derive(Default)]
struct Records {
    any: bool,
    major: Option<u64>,
    minor: Option<u64>,
    name: Option<Vec<u8>>,
    size: Option<u64>,
    realsize: Option<u64>,
    numblocks: Option<u64>,
    map: Option<Vec<u8>>,
    /// The (offset, length) pairs of the format 0.0, in the order they came.
    pairs: Vec<(u64, u64)>,
    pending: Option<u64>,
}

fn number(value: &[u8], what: &str) -> io::Result<u64> {
    std::str::from_utf8(value)
        .ok()
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| invalid(format!("invalid sparse {what}")))
}

fn records<R: Read>(entry: &mut tar::Entry<'_, R>) -> io::Result<Records> {
    let mut r = Records::default();
    // (the records of a global header, which the crate hands over as an
    // entry, are its own: GNU tar never puts a sparse file's there)
    if entry.header().entry_type().is_pax_global_extensions() {
        return Ok(r);
    }
    let Some(exts) = entry.pax_extensions()? else {
        return Ok(r);
    };
    for ext in exts {
        let ext = ext?;
        let Some(key) = ext.key_bytes().strip_prefix(PREFIX) else {
            continue;
        };
        r.any = true;
        let v = ext.value_bytes();
        match key {
            b"major" => r.major = Some(number(v, "format")?),
            b"minor" => r.minor = Some(number(v, "format")?),
            b"name" => r.name = Some(v.to_vec()),
            b"size" => r.size = Some(number(v, "size")?),
            b"realsize" => r.realsize = Some(number(v, "size")?),
            b"numblocks" => r.numblocks = Some(number(v, "block count")?),
            b"map" => r.map = Some(v.to_vec()),
            b"offset" => {
                if r.pending.replace(number(v, "offset")?).is_some() {
                    return Err(invalid("a sparse offset without a length"));
                }
                if r.pairs.len() as u64 >= MAX_BLOCKS {
                    return Err(invalid("too many blocks in a sparse map"));
                }
            }
            b"numbytes" => {
                let off = r
                    .pending
                    .take()
                    .ok_or_else(|| invalid("a sparse length without an offset"))?;
                r.pairs.push((off, number(v, "length")?));
            }
            _ => {}
        }
    }
    if r.pending.is_some() {
        return Err(invalid("a sparse offset without a length"));
    }
    Ok(r)
}

/// The name a sparse file has in the archive: the real one for the formats
/// that store the file under another.
pub fn path<R: Read>(entry: &mut tar::Entry<'_, R>) -> io::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    match records(entry)?.name {
        Some(n) => Ok(PathBuf::from(std::ffi::OsString::from_vec(n))),
        None => Ok(entry.path()?.into_owned()),
    }
}

/// The size of the file of an entry that is sparse, `None` for one that is
/// not.
pub fn real_size<R: Read>(entry: &mut tar::Entry<'_, R>) -> io::Result<Option<u64>> {
    if entry.header().entry_type() == tar::EntryType::GNUSparse {
        return Ok(Some(entry.size()));
    }
    let r = records(entry)?;
    if !r.any {
        return Ok(None);
    }
    Ok(Some(declared_size(&r)?))
}

fn declared_size(r: &Records) -> io::Result<u64> {
    let one = r.major == Some(1);
    let size = if one {
        r.realsize.or(r.size)
    } else {
        r.size.or(r.realsize)
    };
    size.ok_or_else(|| invalid("a sparse file without a size"))
}

/// Write the file of an entry of an [`archive`] to
/// `out` (empty, at its start), holes kept.  An entry that is not sparse
/// is copied as it is.  A file of more than `max` bytes is refused.
pub fn copy<R: Read>(entry: &mut tar::Entry<'_, R>, out: &mut File, max: u64) -> io::Result<()> {
    let Some((real, blocks)) = plan(entry, max)? else {
        io::copy(entry, out)?;
        return Ok(());
    };
    for (off, len) in blocks {
        out.seek(SeekFrom::Start(off))?;
        let n = copy_holes(&mut entry.by_ref().take(len), out)?;
        if n != len {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
    }
    out.set_len(real)?;
    Ok(())
}

/// The size and the checked blocks of the file of a sparse entry, before
/// its data is read (in the format 1.0, the map is); `None` for an entry
/// that is not sparse.
fn plan<R: Read>(entry: &mut tar::Entry<'_, R>, max: u64) -> io::Result<Option<(u64, Blocks)>> {
    let typed = entry.header().entry_type() == tar::EntryType::GNUSparse;
    let r = if typed {
        Records::default()
    } else {
        records(entry)?
    };
    if !typed && !r.any {
        return Ok(None);
    }
    let (real, blocks, packed) = if typed {
        // (the `tar` crate has the map checked, in memory and in number;
        // the holes are dropped: the data is read packed, as in the
        // other formats)
        let blocks = entry
            .take_sparse_blocks()
            .ok_or_else(|| invalid("a sparse entry without a map"))?;
        let packed = blocks.iter().map(|(_, len)| len).sum();
        (entry.size(), blocks, packed)
    } else {
        let real = declared_size(&r)?;
        let (blocks, packed) = map_of(entry, &r)?;
        (real, blocks, packed)
    };
    if real > max {
        return Err(invalid(format!(
            "a sparse file of {real} bytes: more than {max} bytes to write: refused"
        )));
    }
    check(&blocks, real, packed)?;
    Ok(Some((real, blocks)))
}

/// Whether one of `entries` is sparse.
pub fn any_sparse<R: Read>(entries: tar::Entries<'_, R>) -> io::Result<bool> {
    for entry in entries {
        if real_size(&mut entry?)?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Write the tar `input` to `out` with its sparse entries made regular
/// files of their real size, zeros for the holes: for an archive that
/// becomes a layer, which is never sparse (as with podman, whose import
/// expands them).  The other entries keep their headers, links and
/// extended records.  An archive of more than `max` bytes of files is
/// refused.
pub fn expand<R: Read, W: io::Write>(input: R, out: W, max: u64) -> io::Result<W> {
    let mut ar = archive(input);
    let mut b = tar::Builder::new(out);
    // (the names as they are: absolute ones too)
    b.preserve_absolute(true);
    let mut left = max;
    for entry in ar.entries()? {
        let mut e = entry?;
        let name = path(&mut e)?;
        let plan = plan(&mut e, left)?;
        let size = plan.as_ref().map_or(e.size(), |(real, _)| *real);
        left = left
            .checked_sub(size)
            .ok_or_else(|| invalid(format!("more than {max} bytes of files: refused")))?;
        // the records but the sparse ones, and for a sparse entry the name
        // and the size that its header written here has
        let mut kept: Vec<(String, Vec<u8>)> = Vec::new();
        // (a global header is copied as it is, below)
        let global = e.header().entry_type().is_pax_global_extensions();
        let exts = if global { None } else { e.pax_extensions()? };
        if let Some(exts) = exts {
            for ext in exts {
                let ext = ext?;
                let key = ext
                    .key()
                    .map_err(|_| invalid("a pax key that is not UTF-8"))?;
                if key.starts_with("GNU.sparse.")
                    || (plan.is_some() && matches!(key, "path" | "size"))
                {
                    continue;
                }
                kept.push((key.to_string(), ext.value_bytes().to_vec()));
            }
        }
        if !kept.is_empty() {
            b.append_pax_extensions(kept.iter().map(|(k, v)| (k.as_str(), v.as_slice())))?;
        }
        let mut h = e.header().clone();
        match plan {
            Some((real, blocks)) => {
                let mut regular = tar::Header::new_gnu();
                // (a field that is no number is 0, as an empty one)
                regular.set_mode(h.mode().unwrap_or(0o644));
                regular.set_uid(h.uid().unwrap_or(0));
                regular.set_gid(h.gid().unwrap_or(0));
                regular.set_mtime(h.mtime().unwrap_or(0));
                if let Some(u) = h.username_bytes() {
                    let _ = regular.set_username(&String::from_utf8_lossy(u));
                }
                if let Some(g) = h.groupname_bytes() {
                    let _ = regular.set_groupname(&String::from_utf8_lossy(g));
                }
                regular.set_entry_type(tar::EntryType::Regular);
                regular.set_size(real);
                let data = Expanded {
                    data: &mut e,
                    blocks: blocks.into_iter(),
                    block: None,
                    pos: 0,
                    real,
                };
                b.append_data(&mut regular, &name, data)?;
            }
            None => match h.entry_type() {
                tar::EntryType::Link | tar::EntryType::Symlink => {
                    let target = e
                        .link_name()?
                        .ok_or_else(|| invalid("a link without a target"))?
                        .into_owned();
                    b.append_link(&mut h, &name, target)?;
                }
                tar::EntryType::XGlobalHeader => {
                    let mut data = Vec::new();
                    e.read_to_end(&mut data)?;
                    b.append(&h, &data[..])?;
                }
                _ => {
                    h.set_size(e.size());
                    b.append_data(&mut h, &name, &mut e)?;
                }
            },
        }
    }
    b.into_inner()
}

/// The file of a sparse entry, read: zeros for its holes.
struct Expanded<'a, R: Read> {
    data: &'a mut R,
    blocks: std::vec::IntoIter<(u64, u64)>,
    block: Option<(u64, u64)>,
    pos: u64,
    real: u64,
}

impl<R: Read> Read for Expanded<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.pos >= self.real || buf.is_empty() {
                return Ok(0);
            }
            if self.block.is_none_or(|(off, len)| self.pos >= off + len) {
                self.block = self.blocks.next();
            }
            // (the blocks are checked: in order, within the file)
            let (start, end, data) = match self.block {
                Some((off, _)) if self.pos < off => (self.pos, off, false),
                Some((off, len)) if len > 0 => (self.pos, off + len, true),
                Some(_) => continue,
                None => (self.pos, self.real, false),
            };
            let n = buf
                .len()
                .min(usize::try_from(end - start).unwrap_or(usize::MAX));
            let n = if data {
                let got = self.data.read(&mut buf[..n])?;
                if got == 0 {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                got
            } else {
                buf[..n].fill(0);
                n
            };
            self.pos += n as u64;
            return Ok(n);
        }
    }
}

/// The blocks of the map of an entry in the extended header or, in the
/// format 1.0, in its data, and the bytes of data after it.
fn map_of<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    r: &Records,
) -> io::Result<(Vec<(u64, u64)>, u64)> {
    let size = entry.size();
    if r.major == Some(1) {
        if r.minor != Some(0) {
            return Err(invalid("an unsupported sparse format"));
        }
        let (blocks, used) = read_map_1(entry)?;
        let packed = size
            .checked_sub(used)
            .ok_or_else(|| invalid("a sparse map longer than its entry"))?;
        return Ok((blocks, packed));
    }
    if r.major.is_some_and(|m| m != 0) || r.minor.is_some_and(|m| m > 1) {
        return Err(invalid("an unsupported sparse format"));
    }
    let blocks = match &r.map {
        Some(m) => parse_map_01(m)?,
        None => r.pairs.clone(),
    };
    if r.numblocks.is_some_and(|n| n != blocks.len() as u64) {
        return Err(invalid("a sparse map does not have the blocks it counts"));
    }
    Ok((blocks, size))
}

/// `offset,length,offset,length...`
fn parse_map_01(map: &[u8]) -> io::Result<Vec<(u64, u64)>> {
    let mut nums = Vec::new();
    if !map.is_empty() {
        for n in map.split(|b| *b == b',') {
            if nums.len() as u64 >= 2 * MAX_BLOCKS {
                return Err(invalid("too many blocks in a sparse map"));
            }
            nums.push(number(n, "map")?);
        }
    }
    if nums.len() % 2 != 0 {
        return Err(invalid("a sparse offset without a length"));
    }
    Ok(nums.chunks(2).map(|c| (c[0], c[1])).collect())
}

/// The format 1.0: lines of decimal numbers (the count of blocks, then
/// offsets and lengths) at the start of the data, padded to a block.
/// Returns the blocks and how many bytes of the data the map takes.
fn read_map_1<R: Read>(entry: &mut tar::Entry<'_, R>) -> io::Result<(Vec<(u64, u64)>, u64)> {
    let mut text: Vec<u8> = Vec::new();
    let mut want: Option<u64> = None;
    // (counted block by block: a map of a million blocks is read once)
    let mut lines = 0u64;
    loop {
        let mut block = [0u8; BLOCK as usize];
        entry
            .read_exact(&mut block)
            .map_err(|_| invalid("a sparse map that ends early"))?;
        text.extend_from_slice(&block);
        lines += block.iter().filter(|b| **b == b'\n').count() as u64;
        if want.is_none() && lines >= 1 {
            let first = text.split(|b| *b == b'\n').next().unwrap_or_default();
            let n = number(first, "block count")?;
            if n > MAX_BLOCKS {
                return Err(invalid("too many blocks in a sparse map"));
            }
            want = Some(n);
        }
        if want.is_some_and(|n| lines > 2 * n) {
            break;
        }
        if text.len() as u64 > (2 * MAX_BLOCKS + 1) * 21 + BLOCK {
            return Err(invalid("a sparse map that is too long"));
        }
    }
    let n = want.unwrap_or(0);
    let mut fields = text.split(|b| *b == b'\n');
    fields.next();
    let mut blocks = Vec::new();
    for _ in 0..n {
        let off = number(fields.next().unwrap_or_default(), "offset")?;
        let len = number(fields.next().unwrap_or_default(), "length")?;
        blocks.push((off, len));
    }
    Ok((blocks, text.len() as u64))
}

/// The blocks lie in order, within the file, and are all of the data.
fn check(blocks: &[(u64, u64)], real: u64, packed: u64) -> io::Result<()> {
    let mut end = 0u64;
    let mut sum = 0u64;
    for (off, len) in blocks {
        if *off < end {
            return Err(invalid("out of order or overlapping sparse blocks"));
        }
        end = off
            .checked_add(*len)
            .filter(|e| *e <= real)
            .ok_or_else(|| invalid("a sparse block beyond the end of the file"))?;
        sum = sum
            .checked_add(*len)
            .ok_or_else(|| invalid("more bytes listed in a sparse file than u64 can hold"))?;
    }
    if sum != packed {
        return Err(invalid("a sparse map does not match the data of its entry"));
    }
    Ok(())
}

/// Copy `r` to `out`, going over the pieces that are all zeros: they
/// leave a hole.  Returns the bytes read.
fn copy_holes(r: &mut impl Read, out: &mut File) -> io::Result<u64> {
    use std::io::Write;
    let mut buf = vec![0u8; 64 * PIECE];
    let mut total = 0u64;
    // the zeros not written yet: one seek for a run of them
    let mut skip = 0i64;
    loop {
        let mut n = 0;
        while n < buf.len() {
            let got = r.read(&mut buf[n..])?;
            if got == 0 {
                break;
            }
            n += got;
        }
        for piece in buf[..n].chunks(PIECE) {
            // (no early exit: the whole piece is or-ed, which vectorizes)
            if piece.iter().fold(0u8, |a, b| a | b) == 0 {
                skip += piece.len() as i64;
            } else {
                if skip > 0 {
                    out.seek(SeekFrom::Current(skip))?;
                    skip = 0;
                }
                out.write_all(piece)?;
            }
        }
        total += n as u64;
        if n < buf.len() {
            if skip > 0 {
                out.seek(SeekFrom::Current(skip))?;
            }
            return Ok(total);
        }
    }
}

/// The most pieces of data the map of an entry [`append_file`] writes has:
/// a file with more has its shortest holes written as zeros (a reader keeps
/// the map in memory, the `tar` crate takes 1 << 15 pieces).
const MAX_WRITTEN: usize = 1 << 12;

/// The pieces of the first `size` bytes of `file` that hold data, by
/// `SEEK_DATA` and `SEEK_HOLE`, each but the last a multiple of [`BLOCK`]
/// long (what a piece gets past its data is read as zeros); `None` for a
/// file without a hole, or on a file system that cannot tell.
fn data_map(file: &File, size: u64) -> Option<Blocks> {
    use rustix::fs::{seek, SeekFrom};
    if size == 0 {
        return None;
    }
    let mut blocks: Blocks = Vec::new();
    let mut pos = 0;
    while pos < size {
        let data = match seek(file, SeekFrom::Data(pos)) {
            Ok(d) if d >= size => break,
            Ok(d) => d,
            Err(rustix::io::Errno::NXIO) => break,
            Err(_) => return None,
        };
        let start = data / BLOCK * BLOCK;
        let end = match seek(file, SeekFrom::Hole(data)) {
            Ok(h) if h >= size => size,
            Ok(h) => h.div_ceil(BLOCK) * BLOCK,
            Err(_) => return None,
        };
        if end <= pos {
            // (the file changed while it was looked at)
            return None;
        }
        match blocks.last_mut() {
            Some(last) if last.0 + last.1 >= start => last.1 = end - last.0,
            _ => blocks.push((start, end - start)),
        }
        pos = end;
    }
    if blocks == [(0, size)] {
        return None;
    }
    if blocks.len() > MAX_WRITTEN {
        let mut gaps: Vec<u64> = blocks
            .windows(2)
            .map(|w| w[1].0 - w[0].0 - w[0].1)
            .collect();
        let k = blocks.len() - MAX_WRITTEN;
        let (_, most, _) = gaps.select_nth_unstable(k - 1);
        let most = *most;
        let mut fewer: Blocks = Vec::with_capacity(MAX_WRITTEN);
        for b in blocks {
            match fewer.last_mut() {
                Some(last) if b.0 - last.0 - last.1 <= most => last.1 = b.0 + b.1 - last.0,
                _ => fewer.push(b),
            }
        }
        blocks = fewer;
    }
    Some(blocks)
}

/// Append the first `size` bytes of `file` to `b` as `path`, with `h`, the
/// header of a regular file: a file with holes is a sparse entry of the old
/// GNU format (type `S`, the map in the header and the blocks after it, its
/// data only, as GNU tar `--sparse` writes it), any other a regular entry.
/// The file may change while it is read: what is missing is read as zeros.
pub fn append_file<W: io::Write>(
    b: &mut tar::Builder<W>,
    h: &mut tar::Header,
    path: impl AsRef<std::path::Path>,
    file: &File,
    size: u64,
) -> io::Result<()> {
    let map = h.as_gnu().and_then(|_| data_map(file, size));
    let Some(blocks) = map else {
        // (read at offsets: the seeks moved the position of the file)
        h.set_size(size);
        let data = Pieces {
            file,
            blocks: vec![(0, size)].into_iter(),
            at: (0, 0),
        };
        return b.append_data(h, path, data);
    };
    let mut entries = blocks.clone();
    if entries.last().is_none_or(|&(off, len)| off + len < size) {
        entries.push((size, 0));
    }
    h.set_entry_type(tar::EntryType::GNUSparse);
    h.set_size(blocks.iter().map(|(_, len)| len).sum());
    let gnu = h.as_gnu_mut().expect("a GNU header");
    gnu.set_real_size(size);
    let (head, rest) = entries.split_at(entries.len().min(gnu.sparse.len()));
    for (slot, &(off, len)) in gnu.sparse.iter_mut().zip(head) {
        slot.set_offset(off);
        slot.set_length(len);
    }
    gnu.set_is_extended(!rest.is_empty());
    let mut ext = Vec::new();
    let mut groups = rest.chunks(21).peekable();
    while let Some(group) = groups.next() {
        let mut e = tar::GnuExtSparseHeader::new();
        for (slot, &(off, len)) in e.sparse.iter_mut().zip(group) {
            slot.set_offset(off);
            slot.set_length(len);
        }
        e.set_is_extended(groups.peek().is_some());
        ext.extend_from_slice(e.as_bytes());
    }
    let data = Pieces {
        file,
        blocks: blocks.into_iter(),
        at: (0, 0),
    };
    b.append_data(h, path, (&ext[..]).chain(data))
}

/// The data of the pieces of a file, one after the other; zeros for what
/// the file no longer has.
struct Pieces<'a> {
    file: &'a File,
    blocks: std::vec::IntoIter<(u64, u64)>,
    /// The piece being read: where it is, what is left of it
    at: (u64, u64),
}

impl Read for Pieces<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::unix::fs::FileExt;
        while self.at.1 == 0 {
            match self.blocks.next() {
                Some(b) => self.at = b,
                None => return Ok(0),
            }
        }
        let want = buf
            .len()
            .min(usize::try_from(self.at.1).unwrap_or(usize::MAX));
        let n = match self.file.read_at(&mut buf[..want], self.at.0)? {
            0 => {
                buf[..want].fill(0);
                want
            }
            n => n,
        };
        self.at = (self.at.0 + n as u64, self.at.1 - n as u64);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;

    fn octal(v: u64) -> [u8; 12] {
        let mut b = [0u8; 12];
        if v >= 1 << 33 {
            b[0] = 0x80;
            b[4..].copy_from_slice(&v.to_be_bytes());
        } else {
            b[..11].copy_from_slice(format!("{v:011o}").as_bytes());
        }
        b
    }

    fn pad(mut v: Vec<u8>) -> Vec<u8> {
        v.resize(v.len().div_ceil(512) * 512, 0);
        v
    }

    fn end(mut v: Vec<u8>) -> Vec<u8> {
        v.extend([0u8; 1024]);
        v
    }

    /// An entry of the old GNU format: `blocks` of `data` (concatenated).
    fn old_gnu(real: u64, blocks: &[(u64, u64)], data: &[u8]) -> Vec<u8> {
        let mut h = tar::Header::new_gnu();
        h.set_path("sp").unwrap();
        h.set_entry_type(tar::EntryType::GNUSparse);
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        {
            let g = h.as_gnu_mut().unwrap();
            g.realsize = octal(real);
            for (i, (off, len)) in blocks.iter().take(4).enumerate() {
                g.sparse[i].offset = octal(*off);
                g.sparse[i].numbytes = octal(*len);
            }
            g.isextended[0] = u8::from(blocks.len() > 4);
        }
        h.set_cksum();
        let mut out = h.as_bytes().to_vec();
        let rest: Vec<_> = blocks.iter().skip(4).collect();
        let chunks: Vec<_> = rest.chunks(21).collect();
        for (i, c) in chunks.iter().enumerate() {
            let mut e = tar::GnuExtSparseHeader::new();
            for (j, (off, len)) in c.iter().enumerate() {
                e.sparse[j].offset = octal(*off);
                e.sparse[j].numbytes = octal(*len);
            }
            e.isextended[0] = u8::from(i + 1 < chunks.len());
            out.extend_from_slice(e.as_bytes());
        }
        out.extend(pad(data.to_vec()));
        end(out)
    }

    fn record(key: &str, value: &[u8]) -> Vec<u8> {
        let rest = key.len() + value.len() + 3;
        let mut len = rest + 1;
        while len.to_string().len() + rest != len {
            len = len.to_string().len() + rest;
        }
        let mut r = format!("{len} {key}=").into_bytes();
        r.extend_from_slice(value);
        r.push(b'\n');
        r
    }

    /// An entry of a pax format: `records` in an extended header, `data`
    /// as the data of the entry named `name`.
    fn pax(records: &[(&str, &str)], name: &str, data: &[u8]) -> Vec<u8> {
        let mut text = Vec::new();
        for (k, v) in records {
            text.extend(record(k, v.as_bytes()));
        }
        let mut x = tar::Header::new_ustar();
        x.set_path("PaxHeaders/sp").unwrap();
        x.set_entry_type(tar::EntryType::XHeader);
        x.set_size(text.len() as u64);
        x.set_cksum();
        let mut out = x.as_bytes().to_vec();
        out.extend(pad(text));
        let mut h = tar::Header::new_ustar();
        h.set_path(name).unwrap();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        out.extend_from_slice(h.as_bytes());
        out.extend(pad(data.to_vec()));
        end(out)
    }

    /// The file the first entry of `tar` makes, or why it does not.
    fn unpack(tar: &[u8], max: u64) -> io::Result<(PathBuf, File)> {
        let mut ar = archive(tar);
        let mut e = ar.entries()?.next().unwrap()?;
        let name = path(&mut e)?;
        let mut f = tempfile::tempfile()?;
        copy(&mut e, &mut f, max)?;
        Ok((name, f))
    }

    /// The bytes of `f` that are data, as `SEEK_DATA` and `SEEK_HOLE` see
    /// them; not `st_blocks`, which on xfs also counts the speculative
    /// preallocation of a file written at increasing offsets.
    fn data_bytes(f: &File) -> u64 {
        use rustix::fs::{seek, SeekFrom};
        let (mut pos, mut n) = (0, 0);
        while let Ok(d) = seek(f, SeekFrom::Data(pos)) {
            let h = seek(f, SeekFrom::Hole(d)).unwrap();
            n += h - d;
            pos = h;
        }
        n
    }

    fn content(mut f: File) -> Vec<u8> {
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut v = Vec::new();
        f.read_to_end(&mut v).unwrap();
        v
    }

    fn expected(real: usize, parts: &[(usize, &[u8])]) -> Vec<u8> {
        let mut v = vec![0u8; real];
        for (off, d) in parts {
            v[*off..*off + d.len()].copy_from_slice(d);
        }
        v
    }

    fn fails(tar: &[u8], max: u64) {
        let err = unpack(tar, max).expect_err("must be refused");
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof | io::ErrorKind::Other
            ),
            "{err}"
        );
    }

    const A: &[u8] = b"first block";
    const B: &[u8] = b"second";

    #[test]
    fn old_gnu_format_keeps_holes() {
        let real = 3 << 20;
        let mut data = pad(A.to_vec());
        data.extend(B);
        let tar = old_gnu(
            real,
            &[(0, 512), (2 << 20, B.len() as u64), (real, 0)],
            &data,
        );
        let (name, f) = unpack(&tar, MAX_REAL_SIZE).unwrap();
        assert_eq!(name, PathBuf::from("sp"));
        let md = f.metadata().unwrap();
        assert_eq!(md.len(), real);
        assert!(md.blocks() * 512 < 64 << 10, "{} blocks", md.blocks());
        let mut want = expected(real as usize, &[(0, A), (2 << 20, B)]);
        want[A.len()..512].fill(0);
        assert_eq!(content(f), want);
    }

    #[test]
    fn old_gnu_format_with_extension_blocks() {
        // 30 blocks of 512 bytes and the end: 4 in the header, 21 and 6 in two more
        let mut blocks: Vec<(u64, u64)> = (0..30).map(|i| (i * 1024, 512)).collect();
        blocks.push((30 * 1024, 0));
        let data: Vec<u8> = (0..30 * 512).map(|i| (i % 251) as u8 | 1).collect();
        let tar = old_gnu(30 * 1024, &blocks, &data);
        let (_, f) = unpack(&tar, MAX_REAL_SIZE).unwrap();
        let got = content(f);
        for i in 0..30usize {
            assert_eq!(got[i * 1024..i * 1024 + 512], data[i * 512..(i + 1) * 512]);
            if i < 29 {
                assert!(got[i * 1024 + 512..(i + 1) * 1024].iter().all(|b| *b == 0));
            }
        }
    }

    #[test]
    fn old_gnu_format_ending_in_a_hole() {
        let tar = old_gnu(10 << 20, &[(0, 6), (10 << 20, 0)], &B[..6]);
        let (_, f) = unpack(&tar, MAX_REAL_SIZE).unwrap();
        assert_eq!(f.metadata().unwrap().len(), 10 << 20);
    }

    #[test]
    fn old_gnu_format_hostile() {
        let data = pad(vec![1u8; 1024]);
        // overlapping, out of order
        fails(
            &old_gnu(4096, &[(512, 512), (0, 512), (4096, 0)], &data[..1024]),
            MAX_REAL_SIZE,
        );
        fails(
            &old_gnu(4096, &[(0, 512), (256, 512), (4096, 0)], &data[..1024]),
            MAX_REAL_SIZE,
        );
        // beyond the size
        fails(
            &old_gnu(600, &[(0, 512), (512, 512)], &data[..1024]),
            MAX_REAL_SIZE,
        );
        // offset and length that overflow
        fails(
            &old_gnu(
                4096,
                &[(u64::MAX >> 1, u64::MAX >> 1), (u64::MAX >> 1, 2)],
                &data[..512],
            ),
            MAX_REAL_SIZE,
        );
        // data that is not what the map says
        fails(
            &old_gnu(4096, &[(0, 512), (4096, 0)], &data[..1024]),
            MAX_REAL_SIZE,
        );
        // more than the limit
        fails(
            &old_gnu(1 << 20, &[(0, 512), (1 << 20, 0)], &data[..512]),
            4096,
        );
    }

    /// Maps of the old GNU format that cost only what the archive has: a
    /// piece longer than the data, and a chain of extension blocks with no
    /// piece that the archive ends in, are refused at once.
    #[test]
    fn old_gnu_format_maps_cost_their_archive_only() {
        let t = std::time::Instant::now();
        fails(
            &old_gnu(1 << 40, &[(0, 1 << 40)], &pad(vec![1u8; 512])),
            u64::MAX,
        );
        let mut tar = old_gnu(4096, &[(0, 0), (1, 0), (2, 0), (3, 0), (4096, 0)], b"");
        tar.truncate(512);
        for _ in 0..10_000 {
            let mut e = tar::GnuExtSparseHeader::new();
            e.isextended[0] = 1;
            tar.extend_from_slice(e.as_bytes());
        }
        assert!(archive(&tar[..])
            .entries()
            .unwrap()
            .next()
            .unwrap()
            .is_err());
        assert!(
            t.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            t.elapsed()
        );
    }

    /// A map of the old GNU format of many blocks: the most there may be
    /// is read in a moment, one extension block more is refused while the
    /// map is read, with the pieces kept in memory up to that.
    #[test]
    fn old_gnu_format_map_is_capped() {
        let n = 1 << 15;
        let blocks: Vec<(u64, u64)> = (1..=n).map(|i| (i, 0)).collect();
        let t = std::time::Instant::now();
        let (_, f) = unpack(&old_gnu(n, &blocks, b""), MAX_REAL_SIZE).unwrap();
        assert_eq!(f.metadata().unwrap().len(), n);
        assert!(t.elapsed() < std::time::Duration::from_secs(20));
        let blocks: Vec<(u64, u64)> = (1..=n + 22).map(|i| (i, 0)).collect();
        let err = unpack(&old_gnu(n + 22, &blocks, b""), MAX_REAL_SIZE).unwrap_err();
        assert!(err.to_string().contains("pieces"), "{err}");
    }

    /// The holes of an old GNU entry are not read: a file of the largest
    /// size with a hole of that size takes no time, and a few blocks of
    /// data between holes land where the map says.
    #[test]
    fn old_gnu_format_holes_are_skipped_not_read() {
        let real = MAX_REAL_SIZE;
        let mut data = pad(A.to_vec());
        data.extend(pad(B.to_vec()));
        let tar = old_gnu(real, &[(0, 512), (real / 2, 512), (real, 0)], &data);
        let t = std::time::Instant::now();
        let (_, f) = unpack(&tar, MAX_REAL_SIZE).unwrap();
        assert!(
            t.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            t.elapsed()
        );
        let md = f.metadata().unwrap();
        assert_eq!(md.len(), real);
        assert!(md.blocks() * 512 < 64 << 10, "{} blocks", md.blocks());
        let mut f = f;
        let mut at = |off: u64, len: usize| {
            f.seek(SeekFrom::Start(off)).unwrap();
            let mut v = vec![0; len];
            f.read_exact(&mut v).unwrap();
            v
        };
        assert_eq!(&at(0, A.len())[..], A);
        assert_eq!(&at(real / 2, B.len())[..], B);
        assert_eq!(at(real / 4, 16), vec![0; 16]);
    }

    #[test]
    fn pax_0_0() {
        let tar = pax(
            &[
                ("GNU.sparse.size", "1048576"),
                ("GNU.sparse.numblocks", "2"),
                ("GNU.sparse.offset", "0"),
                ("GNU.sparse.numbytes", "11"),
                ("GNU.sparse.offset", "524288"),
                ("GNU.sparse.numbytes", "6"),
            ],
            "GNUSparseFile.1/sp",
            b"first blocksecond",
        );
        let (name, f) = unpack(&tar, MAX_REAL_SIZE).unwrap();
        assert_eq!(name, PathBuf::from("GNUSparseFile.1/sp"));
        assert!(f.metadata().unwrap().blocks() * 512 < 64 << 10);
        assert_eq!(content(f), expected(1 << 20, &[(0, A), (524288, B)]));
    }

    #[test]
    fn pax_0_1() {
        let tar = pax(
            &[
                ("GNU.sparse.name", "dir/sp"),
                ("GNU.sparse.major", "0"),
                ("GNU.sparse.minor", "1"),
                ("GNU.sparse.realsize", "1048576"),
                ("GNU.sparse.numblocks", "2"),
                ("GNU.sparse.map", "0,11,524288,6"),
            ],
            "GNUSparseFile.1/sp",
            b"first blocksecond",
        );
        let mut ar = tar::Archive::new(&tar[..]);
        let mut e = ar.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(real_size(&mut e).unwrap(), Some(1 << 20));
        let (name, f) = unpack(&tar, MAX_REAL_SIZE).unwrap();
        assert_eq!(name, PathBuf::from("dir/sp"));
        assert_eq!(content(f), expected(1 << 20, &[(0, A), (524288, B)]));
    }

    fn pax_1_0_data(blocks: &[(u64, u64)], data: &[u8]) -> Vec<u8> {
        let mut map = format!("{}\n", blocks.len());
        for (o, l) in blocks {
            map.push_str(&format!("{o}\n{l}\n"));
        }
        let mut v = pad(map.into_bytes());
        v.extend_from_slice(data);
        v
    }

    fn pax_1_0(real: u64, blocks: &[(u64, u64)], data: &[u8]) -> Vec<u8> {
        pax(
            &[
                ("GNU.sparse.major", "1"),
                ("GNU.sparse.minor", "0"),
                ("GNU.sparse.name", "sp"),
                ("GNU.sparse.realsize", &real.to_string()),
            ],
            "GNUSparseFile.1/sp",
            &pax_1_0_data(blocks, data),
        )
    }

    #[test]
    fn pax_1_0_keeps_holes() {
        let tar = pax_1_0(1 << 20, &[(0, 11), (524288, 6)], b"first blocksecond");
        let (name, f) = unpack(&tar, MAX_REAL_SIZE).unwrap();
        assert_eq!(name, PathBuf::from("sp"));
        assert!(f.metadata().unwrap().blocks() * 512 < 64 << 10);
        assert_eq!(content(f), expected(1 << 20, &[(0, A), (524288, B)]));
    }

    #[test]
    fn pax_1_0_map_of_several_blocks() {
        // 100 blocks: the map takes more than one block of the archive
        let blocks: Vec<(u64, u64)> = (0..100).map(|i| (i * 1_000_000_000, 3)).collect();
        let data: Vec<u8> = b"abc".repeat(100);
        let tar = pax_1_0(100 * 1_000_000_000, &blocks, &data);
        let (_, f) = unpack(&tar, 1 << 40).unwrap();
        assert_eq!(f.metadata().unwrap().len(), 100 * 1_000_000_000);
        assert!(data_bytes(&f) < 1 << 20, "{} bytes of data", data_bytes(&f));
    }

    #[test]
    fn pax_hostile() {
        let ok = [(0u64, 11u64), (524288, 6)];
        let data = b"first blocksecond";
        // too large
        fails(&pax_1_0(1 << 20, &ok, data), 1 << 19);
        // beyond the end, overlapping, out of order, overflowing
        fails(&pax_1_0(524290, &ok, data), MAX_REAL_SIZE);
        fails(&pax_1_0(1 << 20, &[(0, 11), (5, 6)], data), MAX_REAL_SIZE);
        fails(&pax_1_0(1 << 20, &[(100, 11), (0, 6)], data), MAX_REAL_SIZE);
        fails(
            &pax_1_0(1 << 20, &[(u64::MAX - 3, 11), (u64::MAX, 6)], data),
            u64::MAX,
        );
        // a sum that is not the data
        fails(&pax_1_0(1 << 20, &ok, b"first block"), MAX_REAL_SIZE);
        fails(
            &pax_1_0(1 << 20, &ok, b"first blocksecond and more"),
            MAX_REAL_SIZE,
        );
        // a count of blocks that is not met or is absurd
        let mut map = b"3\n0\n11\n".to_vec();
        map = pad(map);
        map.extend_from_slice(data);
        let x = [
            ("GNU.sparse.major", "1"),
            ("GNU.sparse.minor", "0"),
            ("GNU.sparse.realsize", "4096"),
        ];
        fails(&pax(&x, "f", &map), MAX_REAL_SIZE);
        let huge = pad(b"99999999999\n0\n0\n".to_vec());
        fails(&pax(&x, "f", &huge), MAX_REAL_SIZE);
        let junk = pad(b"1\nx\n1\n".to_vec());
        fails(&pax(&x, "f", &junk), MAX_REAL_SIZE);
        fails(&pax(&x, "f", b""), MAX_REAL_SIZE);
        // a format that is unknown
        fails(
            &pax(
                &[
                    ("GNU.sparse.major", "2"),
                    ("GNU.sparse.minor", "0"),
                    ("GNU.sparse.realsize", "9"),
                ],
                "f",
                b"x",
            ),
            MAX_REAL_SIZE,
        );
        // no size, a count that is not met, an offset without a length
        fails(
            &pax(&[("GNU.sparse.map", "0,5")], "f", b"hello"),
            MAX_REAL_SIZE,
        );
        fails(
            &pax(
                &[
                    ("GNU.sparse.size", "10"),
                    ("GNU.sparse.numblocks", "2"),
                    ("GNU.sparse.map", "0,5"),
                ],
                "f",
                b"hello",
            ),
            MAX_REAL_SIZE,
        );
        fails(
            &pax(
                &[("GNU.sparse.size", "10"), ("GNU.sparse.map", "0,5,7")],
                "f",
                b"hello",
            ),
            MAX_REAL_SIZE,
        );
        fails(
            &pax(
                &[("GNU.sparse.size", "10"), ("GNU.sparse.offset", "0")],
                "f",
                b"hello",
            ),
            MAX_REAL_SIZE,
        );
        fails(
            &pax(
                &[("GNU.sparse.size", "10"), ("GNU.sparse.numbytes", "5")],
                "f",
                b"hello",
            ),
            MAX_REAL_SIZE,
        );
        fails(
            &pax(
                &[("GNU.sparse.size", "ten"), ("GNU.sparse.map", "0,5")],
                "f",
                b"hello",
            ),
            MAX_REAL_SIZE,
        );
    }

    /// The largest map there may be, of blocks of nothing: read in one
    /// pass (a count of the lines of all the text read so far, for every
    /// block of the archive, took minutes).
    #[test]
    fn pax_1_0_map_of_the_most_blocks() {
        let blocks = vec![(0u64, 0u64); MAX_BLOCKS as usize];
        let tar = pax_1_0(4096, &blocks, b"");
        let t = std::time::Instant::now();
        let (_, f) = unpack(&tar, MAX_REAL_SIZE).unwrap();
        assert_eq!(f.metadata().unwrap().len(), 4096);
        assert!(t.elapsed() < std::time::Duration::from_secs(20));
        // one more is refused, in the data or in the extended header
        let blocks = vec![(0u64, 0u64); MAX_BLOCKS as usize + 1];
        fails(&pax_1_0(4096, &blocks, b""), MAX_REAL_SIZE);
        let map = "0,0,".repeat(MAX_BLOCKS as usize + 1);
        fails(
            &pax(
                &[
                    ("GNU.sparse.size", "4096"),
                    ("GNU.sparse.map", &map[..map.len() - 1]),
                ],
                "f",
                b"",
            ),
            MAX_REAL_SIZE,
        );
        // a count that the data cannot hold
        let x = [
            ("GNU.sparse.major", "1"),
            ("GNU.sparse.minor", "0"),
            ("GNU.sparse.realsize", "4096"),
        ];
        fails(&pax(&x, "f", &pad(b"1048576\n0\n".to_vec())), MAX_REAL_SIZE);
        // a first line that never ends
        fails(&pax(&x, "f", &vec![b'1'; 64 << 20]), MAX_REAL_SIZE);
    }

    /// Records that are not numbers, or numbers out of range.
    #[test]
    fn pax_records_that_are_not_numbers() {
        for v in [
            "-1",
            "+1",
            " 1",
            "1 ",
            "0x10",
            "1e3",
            "18446744073709551616",
            "",
        ] {
            fails(
                &pax(&[("GNU.sparse.size", v), ("GNU.sparse.map", "")], "f", b""),
                MAX_REAL_SIZE,
            );
            fails(
                &pax(
                    &[
                        ("GNU.sparse.size", "10"),
                        ("GNU.sparse.map", &format!("0,{v}")),
                    ],
                    "f",
                    b"",
                ),
                MAX_REAL_SIZE,
            );
        }
    }

    /// A file that is all a hole, and a size over the limit refused before
    /// the file is made that large.
    #[test]
    fn holes_only_and_the_limit_first() {
        let tar = pax(
            &[("GNU.sparse.size", "1099511627776"), ("GNU.sparse.map", "")],
            "f",
            b"",
        );
        let (_, f) = unpack(&tar, 1 << 40).unwrap();
        let md = f.metadata().unwrap();
        assert_eq!((md.len(), md.blocks()), (1 << 40, 0));
        let mut ar = archive(&tar[..]);
        let mut e = ar.entries().unwrap().next().unwrap().unwrap();
        let mut f = tempfile::tempfile().unwrap();
        assert!(copy(&mut e, &mut f, MAX_REAL_SIZE).is_err());
        assert_eq!(f.metadata().unwrap().len(), 0);
    }

    /// The extended header of a sparse entry is not the next entry's.
    #[test]
    fn the_records_are_of_one_entry() {
        let mut tar = pax_1_0(1 << 20, &[(0, 11), (524288, 6)], b"first blocksecond");
        tar.truncate(tar.len() - 1024);
        let mut h = tar::Header::new_ustar();
        h.set_path("next").unwrap();
        h.set_size(5);
        h.set_mode(0o644);
        h.set_cksum();
        tar.extend_from_slice(h.as_bytes());
        tar.extend(pad(b"hello".to_vec()));
        let tar = end(tar);
        let mut ar = archive(&tar[..]);
        let mut entries = ar.entries().unwrap();
        let mut e = entries.next().unwrap().unwrap();
        assert_eq!(path(&mut e).unwrap(), PathBuf::from("sp"));
        let mut f = tempfile::tempfile().unwrap();
        copy(&mut e, &mut f, MAX_REAL_SIZE).unwrap();
        drop(e);
        let mut e = entries.next().unwrap().unwrap();
        assert_eq!(path(&mut e).unwrap(), PathBuf::from("next"));
        assert_eq!(real_size(&mut e).unwrap(), None);
        let mut f = tempfile::tempfile().unwrap();
        copy(&mut e, &mut f, 5).unwrap();
        assert_eq!(content(f), b"hello");
    }

    /// The records of a global header are not those of a sparse file.
    #[test]
    fn a_global_header_is_not_sparse() {
        let mut text = record("GNU.sparse.name", b"../x");
        text.extend(record("GNU.sparse.size", b"99999999999999"));
        let mut g = tar::Header::new_ustar();
        g.set_path("pax_global_header").unwrap();
        g.set_entry_type(tar::EntryType::XGlobalHeader);
        g.set_size(text.len() as u64);
        g.set_cksum();
        let mut tar = g.as_bytes().to_vec();
        tar.extend(pad(text));
        let tar = end(tar);
        let mut ar = archive(&tar[..]);
        let mut e = ar.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(path(&mut e).unwrap(), PathBuf::from("pax_global_header"));
        assert_eq!(real_size(&mut e).unwrap(), None);
        assert!(plan(&mut e, 1).unwrap().is_none());
    }

    /// An archive that ends in the data of a sparse entry.
    #[test]
    fn a_truncated_archive_fails() {
        let tar = pax_1_0(1 << 20, &[(0, 11), (524288, 6)], b"first blocksecond");
        // the end, and all but 3 bytes of the data
        let cut = &tar[..tar.len() - 1024 - 512 + 14];
        let mut ar = archive(cut);
        let mut e = ar.entries().unwrap().next().unwrap().unwrap();
        let mut f = tempfile::tempfile().unwrap();
        assert!(copy(&mut e, &mut f, MAX_REAL_SIZE).is_err());
    }

    /// The entries of `tar`: name, type, link, size, data, the records of
    /// its extended header.
    #[allow(clippy::type_complexity)]
    fn entries_of(
        tar: &[u8],
    ) -> Vec<(
        String,
        tar::EntryType,
        Option<String>,
        u64,
        Vec<u8>,
        Vec<String>,
    )> {
        let mut ar = tar::Archive::new(tar);
        let mut out = Vec::new();
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            let keys = match e.pax_extensions().unwrap() {
                Some(x) => x.map(|r| r.unwrap().key().unwrap().to_string()).collect(),
                None => Vec::new(),
            };
            let name = e.path().unwrap().display().to_string();
            let link = e.link_name().unwrap().map(|l| l.display().to_string());
            let (kind, size) = (e.header().entry_type(), e.size());
            let mut data = Vec::new();
            e.read_to_end(&mut data).unwrap();
            out.push((name, kind, link, size, data, keys));
        }
        out
    }

    /// The tar of an import, its sparse files written whole: the other
    /// entries as they were (long names, links, records).
    #[test]
    fn expand_makes_sparse_files_regular() {
        let long = format!("{}/file", "d".repeat(120));
        let mut b = tar::Builder::new(Vec::new());
        let text = record("comment", b"global");
        let mut g = tar::Header::new_ustar();
        g.set_entry_type(tar::EntryType::XGlobalHeader);
        g.set_size(text.len() as u64);
        b.append_data(&mut g, "pax_global_header", &text[..])
            .unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_mode(0o755);
        h.set_size(0);
        b.append_data(&mut h, "dir/", io::empty()).unwrap();
        b.append_pax_extensions([("SCHILY.xattr.user.k", &b"v"[..])])
            .unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o640);
        h.set_size(5);
        b.append_data(&mut h, &long, &b"hello"[..]).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, "dir/link", &long).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Link);
        h.set_size(0);
        b.append_link(&mut h, "hard", &long).unwrap();
        let mut tar = b.into_inner().unwrap();
        tar.truncate(tar.len() - 1024);
        // a pax 1.0 entry, then one of the old GNU format
        let mut one = pax_1_0(1 << 20, &[(0, 11), (524288, 6)], b"first blocksecond");
        one.truncate(one.len() - 1024);
        tar.extend(one);
        let mut gnu = old_gnu(3 << 20, &[(0, 6), (3 << 20, 0)], B);
        gnu.truncate(gnu.len() - 1024);
        tar.extend(gnu);
        let tar = end(tar);

        let out = expand(&tar[..], Vec::new(), 1 << 30).unwrap();
        let got = entries_of(&out);
        let want = entries_of(&tar);
        // (the global header first, as it was: its records are no entry's)
        assert_eq!(out[156], b'g');
        assert_eq!(got.len(), 7);
        for i in 0..5 {
            assert_eq!(got[i], want[i], "entry {i}");
        }
        let (name, kind, _, size, data, keys) = &got[5];
        assert_eq!(
            (name.as_str(), *kind, *size),
            ("sp", tar::EntryType::Regular, 1 << 20)
        );
        assert_eq!(*data, expected(1 << 20, &[(0, A), (524288, B)]));
        assert!(
            keys.iter().all(|k| !k.starts_with("GNU.sparse.")),
            "{keys:?}"
        );
        let (name, kind, _, size, data, _) = &got[6];
        assert_eq!(
            (name.as_str(), *kind, *size),
            ("sp", tar::EntryType::Regular, 3 << 20)
        );
        assert_eq!(*data, expected(3 << 20, &[(0, B)]));

        // the files together are bounded
        let err = expand(&tar[..], Vec::new(), 4 << 20).unwrap_err();
        assert!(err.to_string().contains("refused"), "{err}");
        // and a map that is not right is refused as for a copy
        let bad = pax_1_0(1 << 20, &[(0, 11), (5, 6)], b"first blocksecond");
        assert!(expand(&bad[..], Vec::new(), 1 << 30).is_err());

        // whether an archive has a sparse entry
        let any = |t: &[u8]| any_sparse(tar::Archive::new(t).entries().unwrap()).unwrap();
        assert!(any(&tar));
        assert!(!any(&out));
    }

    #[test]
    fn a_file_that_is_not_sparse_is_copied() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(5);
        h.set_mode(0o644);
        b.append_data(&mut h, "plain", &b"hello"[..]).unwrap();
        let tar = b.into_inner().unwrap();
        assert_eq!(
            real_size(
                &mut tar::Archive::new(&tar[..])
                    .entries()
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            None
        );
        let (name, f) = unpack(&tar, 1).unwrap();
        assert_eq!(name, PathBuf::from("plain"));
        assert_eq!(content(f), b"hello");
    }

    #[test]
    fn what_the_builder_writes_comes_back() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        let mut f = File::create(&p).unwrap();
        f.set_len(8 << 20).unwrap();
        f.seek(SeekFrom::Start(4 << 20)).unwrap();
        f.write_all(b"middle").unwrap();
        f.set_len(8 << 20).unwrap();
        drop(f);
        let mut b = tar::Builder::new(Vec::new());
        b.append_path_with_name(&p, "f").unwrap();
        let tar = b.into_inner().unwrap();
        let (_, out) = unpack(&tar, MAX_REAL_SIZE).unwrap();
        assert_eq!(out.metadata().unwrap().len(), 8 << 20);
        assert!(out.metadata().unwrap().blocks() * 512 < 64 << 10);
        assert_eq!(content(out), std::fs::read(&p).unwrap());
    }

    /// A file with `data` at the offsets, the rest holes.
    fn holey(size: u64, data: &[(u64, &[u8])]) -> File {
        use std::os::unix::fs::FileExt;
        let f = tempfile::tempfile().unwrap();
        f.set_len(size).unwrap();
        for (off, d) in data {
            f.write_all_at(d, *off).unwrap();
        }
        f
    }

    /// The archive of one file written by `append_file`.
    fn appended(f: &File, name: &str) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o640);
        h.set_entry_type(tar::EntryType::Regular);
        let size = f.metadata().unwrap().len();
        append_file(&mut b, &mut h, name, f, size).unwrap();
        b.into_inner().unwrap()
    }

    /// A file with holes (one at the start, data at offsets that are not
    /// aligned, one at the end) is a sparse entry of its data, and comes
    /// back whole with its holes, through this module and the `tar` crate.
    #[test]
    fn append_file_writes_the_data_only() {
        let size = 64u64 << 20;
        let f = holey(
            size,
            &[
                (5 << 20, b"first"),
                ((20 << 20) + 4093, b"across"),
                (40 << 20, b"x"),
            ],
        );
        if data_bytes(&f) > 1 << 20 {
            eprintln!("no holes in this file system: skipped");
            return;
        }
        let want = content(f.try_clone().unwrap());
        let tar = appended(&f, "a/f");
        assert!(tar.len() < 128 << 10, "{} bytes", tar.len());
        let mut ar = tar::Archive::new(&tar[..]);
        let mut e = ar.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(e.header().entry_type(), tar::EntryType::GNUSparse);
        assert_eq!(e.header().mode().unwrap(), 0o640);
        let mut all = Vec::new();
        e.read_to_end(&mut all).unwrap();
        assert_eq!(all, want);
        let (name, out) = unpack(&tar, MAX_REAL_SIZE).unwrap();
        assert_eq!(name, PathBuf::from("a/f"));
        assert_eq!(out.metadata().unwrap().len(), size);
        assert!(data_bytes(&out) < 1 << 20);
        assert_eq!(content(out), want);
    }

    /// A file that is a hole only, and one without a hole.
    #[test]
    fn append_file_of_a_hole_and_of_a_dense_file() {
        let f = holey(1 << 20, &[]);
        let tar = appended(&f, "hole");
        let (_, out) = unpack(&tar, MAX_REAL_SIZE).unwrap();
        assert_eq!(content(out), vec![0u8; 1 << 20]);
        let mut dense = tempfile::tempfile().unwrap();
        dense.write_all(&[7u8; 10_000]).unwrap();
        let tar = appended(&dense, "dense");
        let mut ar = tar::Archive::new(&tar[..]);
        let e = ar.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(e.header().entry_type(), tar::EntryType::Regular);
        let (_, out) = unpack(&tar, MAX_REAL_SIZE).unwrap();
        assert_eq!(content(out), vec![7u8; 10_000]);
    }

    /// A file with more pieces than a map takes has its shortest holes
    /// written as zeros; the content is the same.
    #[test]
    fn append_file_bounds_the_map() {
        let n = MAX_WRITTEN as u64 * 2 + 10;
        let pieces: Vec<(u64, Vec<u8>)> = (0..n)
            .map(|i| {
                (
                    i * (64 << 10) + (i % 3) * 4096,
                    vec![1 + (i % 250) as u8; 100],
                )
            })
            .collect();
        let refs: Vec<(u64, &[u8])> = pieces.iter().map(|(o, d)| (*o, &d[..])).collect();
        let f = holey(n * (64 << 10), &refs);
        if data_bytes(&f) > (n * (64 << 10)) / 2 {
            eprintln!("no holes in this file system: skipped");
            return;
        }
        let blocks = data_map(&f, f.metadata().unwrap().len()).unwrap();
        assert!(blocks.len() <= MAX_WRITTEN, "{}", blocks.len());
        let want = content(f.try_clone().unwrap());
        let tar = appended(&f, "many");
        let mut ar = tar::Archive::new(&tar[..]);
        let mut e = ar.entries().unwrap().next().unwrap().unwrap();
        let mut all = Vec::new();
        e.read_to_end(&mut all).unwrap();
        assert_eq!(all, want);
    }
}
