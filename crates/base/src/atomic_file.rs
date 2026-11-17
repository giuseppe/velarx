// SPDX-License-Identifier: Apache-2.0
//! Files replaced whole: written to a temporary file of their own, renamed
//! over the name.
//!
//! A temporary name shared by the writers (`NAME.tmp`) lets two of them
//! truncate and write the one file, and the rename of the first publishes
//! what the second has written so far.  The name here is the writer's own,
//! made with `O_EXCL`, so a reader sees one writer's whole content or the
//! other's, never a mix.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Replace `path` by a file with `data`, made with `mode` (less the umask),
/// atomically.  The temporary file is in the directory of `path` and is
/// removed when the write fails.  Nothing is synced: for state files that a
/// crash may take back to their former content (or, on some file systems,
/// leave empty), as the `NAME.tmp` writes this replaces.
pub fn write(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    write_impl(path, data, mode, false)
}

/// Like [`write`], and the data is on disk before the rename: a crash leaves
/// the former file or the new one, never an empty one.
pub fn write_durable(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    write_impl(path, data, mode, true)
}

fn write_impl(path: &Path, data: &[u8], mode: u32, sync: bool) -> io::Result<()> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    };
    // A file of the name may be left by a writer that died with the pid
    // this process has now (a pid namespace makes it likely): the next
    // name then.
    let mut tries = 0;
    let (tmp, mut f) = loop {
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(name);
        tmp_name.push(format!(
            ".{}.{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let tmp = dir.join(tmp_name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)
        {
            Ok(f) => break (tmp, f),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && tries < 100 => tries += 1,
            Err(e) => return Err(e),
        }
    };
    let result = f.write_all(data).and_then(|()| {
        if sync {
            f.sync_all()?;
        }
        drop(f);
        std::fs::rename(&tmp, path)
    });
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writers_of_one_name_never_publish_a_mixed_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.json");
        // each writer's content is its own letter, long enough that a
        // shared temporary file would be seen half written
        let contents: Vec<Vec<u8>> = (b'a'..=b'h').map(|c| vec![c; 1 << 20]).collect();
        let stop = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|s| {
            let reader = s.spawn(|| {
                let mut seen = 0usize;
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(data) = std::fs::read(&path) {
                        assert_eq!(data.len(), 1 << 20, "a partial file");
                        assert!(data.iter().all(|b| *b == data[0]), "a mixed file");
                        seen += 1;
                    }
                }
                seen
            });
            let writers: Vec<_> = contents
                .iter()
                .map(|c| {
                    let path = &path;
                    s.spawn(move || {
                        for _ in 0..30 {
                            write(path, c, 0o600).unwrap();
                        }
                    })
                })
                .collect();
            for w in writers {
                w.join().unwrap();
            }
            stop.store(true, Ordering::Relaxed);
            reader.join().unwrap();
        });
        let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(names.len(), 1, "temporary files left: {names:?}");
    }

    #[test]
    fn a_temporary_file_left_by_a_dead_writer_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        let next = NEXT.load(Ordering::Relaxed);
        for n in next..next + 4 {
            let left = dir
                .path()
                .join(format!(".f.{}.{n}.tmp", std::process::id()));
            std::fs::write(left, b"old").unwrap();
        }
        write(&path, b"new", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn a_name_of_the_old_fixed_kind_is_neither_followed_nor_used() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let path = dir.path().join("rec.json");
        std::os::unix::fs::symlink(&victim, dir.path().join(".rec.json.tmp")).unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join(".rec.json.new")).unwrap();
        write_durable(&path, b"new", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    }

    #[test]
    fn a_failed_write_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("f");
        assert!(write(&path, b"x", 0o600).is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
