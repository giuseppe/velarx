// SPDX-License-Identifier: Apache-2.0
//! The archive of a checkpoint (`checkpoint --export`, `restore
//! --import`), in podman's layout: `checkpoint/` (the images of CRIU),
//! `config.dump` (here: what makes the container again), `spec.dump` (its
//! OCI configuration) and `rootfs-diff.tar` (the changes of its root file
//! system, a layer).  zstd, gzip or no compression.
//!
//! An archive to import is untrusted: only those names are taken, as
//! regular files written to new inodes below a directory of the engine
//! (`O_EXCL | O_NOFOLLOW`, no `..`, no absolute path, no link, device or
//! hard link entry), within limits of size and number.

use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{mkdirat, openat, AtFlags, Mode, OFlags};
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::{Component, Path};

pub const IMAGES: &str = "checkpoint";
/// The images of a pre-checkpoint (`checkpoint --pre-checkpoint --export`).
pub const PRE_IMAGES: &str = "pre-checkpoint";
pub const CONFIG_DUMP: &str = "config.dump";
pub const SPEC_DUMP: &str = "spec.dump";
pub const ROOTFS_DIFF: &str = "rootfs-diff.tar";

/// The compression of an archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compress {
    Zstd,
    Gzip,
    None,
}

impl Compress {
    pub fn parse(s: Option<&str>) -> Result<Self, String> {
        match s.unwrap_or("zstd") {
            "zstd" | "" => Ok(Self::Zstd),
            "gzip" => Ok(Self::Gzip),
            "none" => Ok(Self::None),
            other => Err(format!("unknown compression `{other}` (zstd, gzip, none)")),
        }
    }
}

/// How much of an imported archive is taken.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// All the bytes of the (decompressed) archive
    pub total: u64,
    /// `config.dump` and `spec.dump`
    pub dump: u64,
    /// Entries
    pub entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            total: 16 << 30,
            dump: 16 << 20,
            entries: 100_000,
        }
    }
}

fn invalid(m: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m)
}

/// Write the archive: the regular files of `images`, the dumps and the
/// diff (a file, rewound).
#[cfg(test)]
pub fn write<W: Write>(
    out: W,
    compress: Compress,
    images: &Path,
    config_dump: &[u8],
    spec_dump: &[u8],
    rootfs_diff: Option<&mut File>,
) -> io::Result<()> {
    write_as(
        out,
        compress,
        IMAGES,
        images,
        config_dump,
        spec_dump,
        rootfs_diff,
    )
}

/// [`write`] with the images in the directory `name` of the archive
/// ([`IMAGES`] or [`PRE_IMAGES`]).
pub fn write_as<W: Write>(
    out: W,
    compress: Compress,
    name: &str,
    images: &Path,
    config_dump: &[u8],
    spec_dump: &[u8],
    rootfs_diff: Option<&mut File>,
) -> io::Result<()> {
    let out: Box<dyn Write> = match compress {
        Compress::Zstd => Box::new(zstd::Encoder::new(out, 3)?.auto_finish()),
        Compress::Gzip => Box::new(flate2::write::GzEncoder::new(
            out,
            flate2::Compression::default(),
        )),
        Compress::None => Box::new(out),
    };
    let mut b = tar::Builder::new(out);
    b.follow_symlinks(false);
    let mut dir = tar::Header::new_gnu();
    dir.set_entry_type(tar::EntryType::Directory);
    dir.set_mode(0o700);
    dir.set_size(0);
    b.append_data(&mut dir, name, io::empty())?;
    let mut files: Vec<_> = std::fs::read_dir(images)?
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.file_name())
        .collect();
    files.sort();
    for n in files {
        let mut f = File::open(images.join(&n))?;
        b.append_file(Path::new(name).join(&n), &mut f)?;
    }
    for (name, data) in [(CONFIG_DUMP, config_dump), (SPEC_DUMP, spec_dump)] {
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o600);
        h.set_size(data.len() as u64);
        b.append_data(&mut h, name, data)?;
    }
    if let Some(f) = rootfs_diff {
        use std::io::Seek;
        f.seek(io::SeekFrom::Start(0))?;
        let len = f.metadata()?.len();
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o600);
        h.set_size(len);
        b.append_data(&mut h, ROOTFS_DIFF, f.take(len))?;
    }
    b.into_inner()?.flush()
}

/// Counts what is read, and fails past the limit.
struct Limited<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Limited<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.left = self
            .left
            .checked_sub(n as u64)
            .ok_or_else(|| invalid("the archive is bigger than the limit of an import".into()))?;
        Ok(n)
    }
}

/// The decompressed stream of `r`, by its first bytes.
fn decompressed<'a, R: Read + 'a>(r: R) -> io::Result<Box<dyn Read + 'a>> {
    Ok(Box::new(velarx_content::decompress::Decoder::detect(
        BufReader::new(r),
    )?))
}

/// Write the content of an entry to a new file `name` of `dir`.
fn new_file(dir: BorrowedFd<'_>, name: &str, data: &mut dyn Read) -> io::Result<()> {
    let fd = openat(
        dir,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|e| io::Error::new(io::Error::from(e).kind(), format!("{name}: {e}")))?;
    // (the zeros of the pages are holes of the file)
    let file = File::from(fd);
    velarx_storage::copy_sparse(data, &file, |_| {})?;
    Ok(())
}

/// Extract the archive read from `r` into the directory `dest` (empty, the
/// engine's): `checkpoint/*`, `config.dump`, `spec.dump` and
/// `rootfs-diff.tar`; other files of podman's archives are skipped.
#[cfg(test)]
pub fn extract<R: Read>(r: R, dest: BorrowedFd<'_>, limits: &Limits) -> io::Result<()> {
    extract_as(r, dest, IMAGES, limits)
}

/// [`extract`] of an archive whose images are in the directory `name`
/// ([`IMAGES`] or [`PRE_IMAGES`]).
pub fn extract_as<R: Read>(
    r: R,
    dest: BorrowedFd<'_>,
    name: &str,
    limits: &Limits,
) -> io::Result<()> {
    // (the limit is of the decompressed bytes: a small bomb is stopped)
    let r = Limited {
        inner: decompressed(r)?,
        left: limits.total,
    };
    let mut ar = tar::Archive::new(r);
    let mut images: Option<OwnedFd> = None;
    let mut count = 0usize;
    for entry in ar.entries()? {
        let mut entry = entry?;
        count += 1;
        if count > limits.entries {
            return Err(invalid(format!(
                "the archive has more than {} entries",
                limits.entries
            )));
        }
        let path = entry.path()?.into_owned();
        let mut parts = Vec::new();
        for c in path.components() {
            match c {
                Component::Normal(n) => parts.push(
                    n.to_str()
                        .ok_or_else(|| invalid(format!("invalid name {}", path.display())))?
                        .to_string(),
                ),
                Component::CurDir => {}
                _ => {
                    return Err(invalid(format!(
                        "the entry {} leaves the archive",
                        path.display()
                    )))
                }
            }
        }
        let kind = entry.header().entry_type();
        match kind {
            tar::EntryType::Regular | tar::EntryType::Continuous | tar::EntryType::Directory => {}
            tar::EntryType::XGlobalHeader | tar::EntryType::XHeader => continue,
            other => {
                return Err(invalid(format!(
                    "the entry {} is a {other:?}: only files are taken",
                    path.display()
                )))
            }
        }
        let size = entry.header().size()?;
        let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
        match (parts.as_slice(), kind) {
            ([d], tar::EntryType::Directory) if *d == name => {}
            ([], _) => {}
            ([d, file], tar::EntryType::Regular | tar::EntryType::Continuous) if *d == name => {
                if images.is_none() {
                    match mkdirat(dest, name, Mode::from_raw_mode(0o700)) {
                        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                        Err(e) => return Err(e.into()),
                    }
                    images = Some(openat(
                        dest,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )?);
                }
                let dir = images.as_ref().map(|d| d.as_fd()).unwrap_or(dest);
                new_file(dir, file, &mut entry)?;
            }
            (
                [name @ (CONFIG_DUMP | SPEC_DUMP)],
                tar::EntryType::Regular | tar::EntryType::Continuous,
            ) => {
                if size > limits.dump {
                    return Err(invalid(format!(
                        "{name} is bigger than {} bytes",
                        limits.dump
                    )));
                }
                new_file(dest, name, &mut entry)?;
            }
            ([ROOTFS_DIFF], tar::EntryType::Regular | tar::EntryType::Continuous) => {
                new_file(dest, ROOTFS_DIFF, &mut entry)?;
            }
            // podman's other files (network.status, stats-dump,
            // volumes/...): not taken
            (
                _,
                tar::EntryType::Regular | tar::EntryType::Continuous | tar::EntryType::Directory,
            ) => {
                tracing::debug!("checkpoint archive: {} skipped", path.display());
            }
            _ => unreachable!(),
        }
    }
    if images.is_none() {
        return Err(invalid(format!("the archive has no {name}/ images")));
    }
    // (an archive a container cannot come from)
    match rustix::fs::statat(dest, CONFIG_DUMP, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(()),
        Err(_) => Err(invalid("the archive has no config.dump".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_fd(p: &Path) -> OwnedFd {
        openat(
            rustix::fs::CWD,
            p,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    /// A tar with raw headers: names and types as an attacker writes them.
    fn crafted(entries: &[(&str, tar::EntryType, &[u8], Option<&str>)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, kind, data, link) in entries {
            let mut h = tar::Header::new_gnu();
            // bypass the builder's checks of the path
            h.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name.as_bytes());
            h.set_entry_type(*kind);
            h.set_mode(0o644);
            h.set_size(data.len() as u64);
            if let Some(l) = link {
                h.set_link_name(l).unwrap();
            }
            h.set_cksum();
            b.append(&h, *data).unwrap();
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn an_archive_round_trips_in_every_compression() {
        let d = tempfile::tempdir().unwrap();
        let images = d.path().join("images");
        std::fs::create_dir(&images).unwrap();
        std::fs::write(images.join("inventory.img"), b"inv").unwrap();
        std::fs::write(images.join("pages-1.img"), vec![7u8; 100_000]).unwrap();
        let mut diff = tempfile::tempfile().unwrap();
        diff.write_all(b"layer").unwrap();
        for c in [Compress::Zstd, Compress::Gzip, Compress::None] {
            let mut out = Vec::new();
            write(&mut out, c, &images, b"{\"c\":1}", b"{}", Some(&mut diff)).unwrap();
            let dest = tempfile::tempdir().unwrap();
            extract(&out[..], dir_fd(dest.path()).as_fd(), &Limits::default()).unwrap();
            assert_eq!(
                std::fs::read(dest.path().join("checkpoint/inventory.img")).unwrap(),
                b"inv"
            );
            assert_eq!(
                std::fs::read(dest.path().join("checkpoint/pages-1.img"))
                    .unwrap()
                    .len(),
                100_000
            );
            assert_eq!(
                std::fs::read(dest.path().join("config.dump")).unwrap(),
                b"{\"c\":1}"
            );
            assert_eq!(
                std::fs::read(dest.path().join("rootfs-diff.tar")).unwrap(),
                b"layer"
            );
        }
        assert!(Compress::parse(Some("lz4")).is_err());
    }

    #[test]
    fn crafted_archives_are_refused() {
        let ok: &[u8] = b"x";
        let base = [
            (
                "checkpoint/inventory.img",
                tar::EntryType::Regular,
                ok,
                None,
            ),
            ("config.dump", tar::EntryType::Regular, ok, None),
        ];
        type Entry<'a> = (&'a str, tar::EntryType, &'a [u8], Option<&'a str>);
        let cases: Vec<(&str, Vec<Entry>)> = vec![
            (
                "dotdot",
                vec![("../evil", tar::EntryType::Regular, ok, None)],
            ),
            (
                "deep dotdot",
                vec![("checkpoint/../../evil", tar::EntryType::Regular, ok, None)],
            ),
            (
                "absolute",
                vec![("/tmp/evil", tar::EntryType::Regular, ok, None)],
            ),
            (
                "symlink",
                vec![(
                    "checkpoint/x.img",
                    tar::EntryType::Symlink,
                    b"",
                    Some("/etc/shadow"),
                )],
            ),
            (
                "hard link",
                vec![(
                    "config.dump",
                    tar::EntryType::Link,
                    b"",
                    Some("/etc/shadow"),
                )],
            ),
            (
                "device",
                vec![("checkpoint/d", tar::EntryType::Char, b"", None)],
            ),
            ("fifo", vec![("spec.dump", tar::EntryType::Fifo, b"", None)]),
            // a link planted first, then a file written through it
            (
                "write through a link",
                vec![
                    ("checkpoint", tar::EntryType::Symlink, b"", Some("/tmp")),
                    ("checkpoint/x.img", tar::EntryType::Regular, ok, None),
                ],
            ),
            (
                "duplicate",
                vec![("config.dump", tar::EntryType::Regular, ok, None)],
            ),
        ];
        for (what, extra) in cases {
            let mut entries: Vec<_> = base.to_vec();
            entries.extend(extra);
            let tar = crafted(&entries);
            let dest = tempfile::tempdir().unwrap();
            let outside = dest.path().join("..").join("evil");
            let r = extract(&tar[..], dir_fd(dest.path()).as_fd(), &Limits::default());
            assert!(r.is_err(), "{what}");
            assert!(!outside.exists(), "{what}");
        }
        // a link the engine did not make is never followed: a directory
        // named like the images that is a link
        let dest = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), dest.path().join("checkpoint")).unwrap();
        let tar = crafted(&base);
        assert!(extract(&tar[..], dir_fd(dest.path()).as_fd(), &Limits::default()).is_err());
        assert_eq!(std::fs::read_dir(elsewhere.path()).unwrap().count(), 0);
        // no images, no config
        let tar = crafted(&[("config.dump", tar::EntryType::Regular, ok, None)]);
        let dest = tempfile::tempdir().unwrap();
        assert!(extract(&tar[..], dir_fd(dest.path()).as_fd(), &Limits::default()).is_err());
        let tar = crafted(&[("checkpoint/a", tar::EntryType::Regular, ok, None)]);
        let dest = tempfile::tempdir().unwrap();
        assert!(extract(&tar[..], dir_fd(dest.path()).as_fd(), &Limits::default()).is_err());
        // other files of podman's archives are skipped
        let mut entries = base.to_vec();
        entries.push(("network.status", tar::EntryType::Regular, ok, None));
        entries.push(("volumes", tar::EntryType::Directory, b"", None));
        let dest = tempfile::tempdir().unwrap();
        extract(
            &crafted(&entries)[..],
            dir_fd(dest.path()).as_fd(),
            &Limits::default(),
        )
        .unwrap();
        assert!(!dest.path().join("network.status").exists());
    }

    #[test]
    fn the_limits_hold() {
        let big = vec![0u8; 10_000];
        let entries = [
            (
                "checkpoint/inventory.img",
                tar::EntryType::Regular,
                &big[..],
                None,
            ),
            ("config.dump", tar::EntryType::Regular, &big[..], None),
        ];
        let tar = crafted(&entries);
        let small = Limits {
            total: 5_000,
            ..Limits::default()
        };
        let dest = tempfile::tempdir().unwrap();
        assert!(extract(&tar[..], dir_fd(dest.path()).as_fd(), &small).is_err());
        let small = Limits {
            dump: 1_000,
            ..Limits::default()
        };
        let dest = tempfile::tempdir().unwrap();
        assert!(extract(&tar[..], dir_fd(dest.path()).as_fd(), &small).is_err());
        let small = Limits {
            entries: 1,
            ..Limits::default()
        };
        let dest = tempfile::tempdir().unwrap();
        assert!(extract(&tar[..], dir_fd(dest.path()).as_fd(), &small).is_err());
        // a compression bomb: small compressed, big inflated
        let mut z = zstd::Encoder::new(Vec::new(), 19).unwrap();
        z.write_all(&crafted(&[
            (
                "checkpoint/a",
                tar::EntryType::Regular,
                &vec![0u8; 1 << 20][..],
                None,
            ),
            ("config.dump", tar::EntryType::Regular, b"x", None),
        ]))
        .unwrap();
        let bomb = z.finish().unwrap();
        assert!(bomb.len() < 10_000);
        let small = Limits {
            total: 100_000,
            ..Limits::default()
        };
        let dest = tempfile::tempdir().unwrap();
        assert!(extract(&bomb[..], dir_fd(dest.path()).as_fd(), &small).is_err());
    }
}
