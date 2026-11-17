// SPDX-License-Identifier: Apache-2.0
//! The lock of the start of a container.

use std::io;
use std::path::Path;

/// Lock the file `path` (created when it is not there) exclusively.  The
/// removal of a container unlinks the file while it holds the lock: a lock
/// on a file that is gone is none, the one that waited takes the lock again
/// on the file that replaces it (else two processes would hold "the" lock).
pub fn exclusive(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    loop {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        velarx_sys::flock::flock_retrying(&file, rustix::fs::FlockOperation::LockExclusive)?;
        if is_file_at(&file, path)? {
            return Ok(file);
        }
    }
}

/// Whether `file` is the file at `path` (not one unlinked, or replaced).
fn is_file_at(file: &std::fs::File, path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(path) {
        Ok(m) => Ok(m.ino() == file.metadata()?.ino()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}
