// SPDX-License-Identifier: Apache-2.0
//! Files with no name.

use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

/// A file in `dir` with no name (`O_TMPFILE`): what is written to it counts
/// against the quota of the file system from the first byte, and a process
/// that fails or dies leaves nothing behind.  A directory that cannot have
/// one is an error naming it.  It can never be given a name (`O_EXCL`):
/// a process it is passed to cannot link it into a directory and keep it.
pub fn unnamed_file(dir: &Path) -> io::Result<File> {
    unnamed_in(rustix::fs::CWD, dir, true)
}

/// [`unnamed_file`] in the open directory `dir`.
pub fn unnamed_file_at(dir: &File) -> io::Result<File> {
    unnamed_in(dir, Path::new("."), true)
}

/// [`unnamed_file`] that can be given a name later (`linkat` of its
/// descriptor): the file of a commit that is copied, which no process but
/// the engine ever sees.
pub fn unnamed_to_link(dir: &Path) -> io::Result<File> {
    unnamed_in(rustix::fs::CWD, dir, false)
}

fn unnamed_in(at: impl std::os::fd::AsFd, dir: &Path, exclusive: bool) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags};
    let excl = if exclusive {
        OFlags::EXCL
    } else {
        OFlags::empty()
    };
    rustix::fs::openat(
        at,
        dir,
        OFlags::TMPFILE | excl | OFlags::RDWR | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map(File::from)
    .map_err(|e| match e {
        rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::ISDIR | rustix::io::Errno::INVAL => {
            io::Error::other(format!(
                "{} cannot hold files without a name (O_TMPFILE): {e}",
                dir.display()
            ))
        }
        e => io::Error::from(e),
    })
}

/// A file with no name in `dir` (`O_TMPFILE`) holding `bytes`, opened again
/// read-only: the writable descriptor is closed here, so no process can
/// change what the one that is passed on reads, and nothing is left behind
/// by a process that dies.
pub fn read_only_unnamed(dir: &Path, bytes: &[u8]) -> io::Result<OwnedFd> {
    let mut file = crate::pull::unnamed::unnamed_file(dir)?;
    io::Write::write_all(&mut file, bytes)?;
    // (read-only for its owner too: the descriptor cannot be reopened for
    // writing through /proc by a process of the same user)
    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o400))?;
    let reopened = velarx_sys::fd::reopen_read_only(&file)?;
    Ok(reopened.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unnamed_read_only_file_cannot_be_written_and_leaves_no_name() {
        let dir = tempfile::tempdir().unwrap();
        let fd = read_only_unnamed(dir.path(), b"index").unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        let file = std::fs::File::from(fd);
        assert!(std::io::Write::write_all(&mut &file, b"more").is_err());
        let mut back = vec![0u8; 5];
        std::os::unix::fs::FileExt::read_exact_at(&file, &mut back, 0).unwrap();
        assert_eq!(back, b"index");
        // (nor reopened for writing through /proc, but by root)
        if rustix::process::geteuid().is_root() {
            return;
        }
        let again = std::fs::OpenOptions::new()
            .write(true)
            .open(velarx_sys::fd::proc_str(&file));
        assert!(again.is_err());
    }

    #[test]
    fn an_unnamed_file_leaves_no_name() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let mut f = unnamed_file(dir.path()).unwrap();
        f.write_all(&[1u8; 4096]).unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        // (nor can it be given one)
        let named = dir.path().join("named");
        let linked = rustix::fs::linkat(
            rustix::fs::CWD,
            velarx_sys::fd::proc_str(&f),
            rustix::fs::CWD,
            &named,
            rustix::fs::AtFlags::SYMLINK_FOLLOW,
        );
        assert!(linked.is_err() && !named.exists());
        drop(f);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        let missing = dir.path().join("no/such");
        assert!(unnamed_file(&missing).is_err());
        let plain = dir.path().join("plain");
        std::fs::write(&plain, "").unwrap();
        assert!(unnamed_file(&plain).is_err());
    }
}
