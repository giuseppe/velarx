// SPDX-License-Identifier: Apache-2.0
//! Temporary files in the store whose writer does not hold the lock of the
//! store (the image server fetching a file of a lazy image, the FUSE file system
//! writing a profile): each holds an exclusive `flock` on its temporary
//! file from the moment it has one until the file has its name, and the
//! collection removes a temporary file only when it can take that lock
//! itself, which means the writer is gone (the kernel drops the lock when
//! the process ends, however it ends).  The lock is on a read-only
//! descriptor of its own, so that the writer can close the file for writing
//! (what enabling fs-verity needs) and keep the lock.

use rustix::fs::{FlockOperation, Mode, OFlags};
use std::fs::File;
use std::io;
use std::os::fd::BorrowedFd;
use std::path::Path;
use velarx_sys::flock::flock_retrying;

/// The lock of a temporary file, held as long as this value lives.
#[derive(Debug)]
pub struct TempLock {
    file: File,
}

impl TempLock {
    /// The file, open for reading only (for what needs a descriptor of the
    /// file that is not open for writing).
    pub fn file(&self) -> &File {
        &self.file
    }
}

/// Open `path` for reading and take the exclusive lock without waiting;
/// `None` when someone holds it.
fn try_lock(path: &Path) -> io::Result<Option<File>> {
    try_lock_at(rustix::fs::CWD, path)
}

/// [`try_lock`] of the name `name` in the directory `dir`.
fn try_lock_at(dir: BorrowedFd<'_>, name: &Path) -> io::Result<Option<File>> {
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let file = File::from(fd);
    match flock_retrying(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(Some(file)),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

/// A new temporary file in `dir` (named from `prefix`, with `mode`) and its
/// lock.  The collection may remove a file in the moment between its making
/// and its lock; then another one is made.  It may also have opened the
/// file before this did, locked it, removed it and let it go before this
/// locks it: the lock is then of a file that has no name any more, which
/// its count of links tells (the collection removes a file only under its
/// lock, so a file that still has its name once locked here keeps it).
pub fn create_locked(
    dir: &Path,
    prefix: &str,
    mode: u32,
) -> io::Result<(tempfile::NamedTempFile, TempLock)> {
    use std::os::unix::fs::PermissionsExt;
    loop {
        let temp = tempfile::Builder::new()
            .prefix(prefix)
            .permissions(std::fs::Permissions::from_mode(mode))
            .tempfile_in(dir)?;
        match try_lock(temp.path()) {
            Ok(Some(file)) if still_named(&file, temp.as_file())? => {
                return Ok((temp, TempLock { file }))
            }
            Ok(Some(_)) => {}
            // taken by the collection that found it, or gone: it was not
            // locked yet
            Ok(None) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
}

/// [`create_locked`] in the directory `dir` that a descriptor names, never
/// by a path: the open file, its name there and its lock.  The name is
/// that of a file made here (`O_EXCL`, no link followed).
pub fn create_locked_at(
    dir: BorrowedFd<'_>,
    prefix: &str,
    mode: u32,
) -> io::Result<(File, String, TempLock)> {
    use std::hash::{BuildHasher, Hasher};
    loop {
        let name = format!(
            "{prefix}{:016x}",
            std::collections::hash_map::RandomState::new()
                .build_hasher()
                .finish()
        );
        let made = match rustix::fs::openat(
            dir,
            &name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(mode),
        ) {
            Ok(fd) => File::from(fd),
            Err(rustix::io::Errno::EXIST) => continue,
            Err(e) => return Err(e.into()),
        };
        match try_lock_at(dir, Path::new(&name)) {
            Ok(Some(file)) if still_named(&file, &made)? => {
                return Ok((made, name, TempLock { file }))
            }
            Ok(Some(_)) | Ok(None) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
}

/// Whether `locked` is the file `made` and it still has a name.
fn still_named(locked: &File, made: &File) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let (l, m) = (locked.metadata()?, made.metadata()?);
    Ok(l.dev() == m.dev() && l.ino() == m.ino() && l.nlink() > 0)
}

/// Remove the temporary file `path` if no writer holds its lock: the bytes
/// freed, `None` when a writer holds it (or it is gone).
pub fn remove_abandoned(path: &Path) -> io::Result<Option<u64>> {
    let file = match try_lock(path) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    // (removed while the lock is held: a writer that opened it after this
    // sees it taken)
    let size = file.metadata()?.len();
    match std::fs::remove_file(path) {
        Ok(()) => Ok(Some(size)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each test takes the lock of a file again after its holder dropped it:
    // in a child of its own, as the tests of `lock` do.  A process another
    // test of this binary starts (`cp`, `sleep`) holds a copy of every
    // descriptor between its fork and its exec, and with it the lock of a
    // file that was just closed: `remove_abandoned` then sees a writer.

    #[test]
    fn a_locked_file_is_kept_and_an_abandoned_one_goes() {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let (temp, lock) = create_locked(dir.path(), ".tmp", 0o644).unwrap();
            let path = temp.path().to_path_buf();
            std::fs::write(&path, b"abc").unwrap();
            // the writer lives: its file stays, however old it is
            assert_eq!(remove_abandoned(&path).unwrap(), None);
            assert!(path.exists());
            // the writer closes the file for writing and keeps the lock
            let path = temp.into_temp_path();
            assert_eq!(remove_abandoned(&path).unwrap(), None);
            assert!(lock.file().metadata().is_ok());
            drop(lock);
            // the writer is gone
            let path_buf = path.keep().unwrap();
            assert_eq!(remove_abandoned(&path_buf).unwrap(), Some(3));
            assert!(!path_buf.exists());
            // nothing left to remove
            assert_eq!(remove_abandoned(&path_buf).unwrap(), None);
        });
    }

    /// The file made in a directory by its descriptor has the name returned,
    /// is locked, and is not removed while the lock is held.
    #[test]
    fn a_locked_file_of_a_directory_descriptor_is_kept_and_an_abandoned_one_goes() {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let fd = rustix::fs::open(
                dir.path(),
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            let (mut file, name, lock) =
                create_locked_at(std::os::fd::AsFd::as_fd(&fd), ".tmp-", 0o644).unwrap();
            assert!(name.starts_with(".tmp-"));
            io::Write::write_all(&mut file, b"abc").unwrap();
            let path = dir.path().join(&name);
            assert_eq!(remove_abandoned(&path).unwrap(), None);
            assert_eq!(std::fs::read(&path).unwrap(), b"abc");
            drop(lock);
            assert_eq!(remove_abandoned(&path).unwrap(), Some(3));
            assert!(!path.exists());
        });
    }

    /// A lock taken on a file the collection removed meanwhile (it opened
    /// the file first, took the lock and removed it) is no lock of a
    /// temporary file: it has no name.
    #[test]
    fn a_lock_of_a_file_that_lost_its_name_does_not_count() {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let made = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
            let locked = try_lock(made.path()).unwrap().unwrap();
            assert!(still_named(&locked, made.as_file()).unwrap());
            drop(locked);
            let opened = File::open(made.path()).unwrap();
            assert_eq!(remove_abandoned(made.path()).unwrap(), Some(0));
            flock_retrying(&opened, FlockOperation::NonBlockingLockExclusive).unwrap();
            assert!(!still_named(&opened, made.as_file()).unwrap());
            // (another file at the same place is not the one that was made)
            std::fs::write(made.path(), b"").unwrap();
            let other = try_lock(made.path()).unwrap().unwrap();
            assert!(!still_named(&other, made.as_file()).unwrap());
        });
    }
}
