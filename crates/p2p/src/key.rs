// SPDX-License-Identifier: Apache-2.0
//! Reading the swarm key from its file.
//!
//! Whoever holds the key can join the network, so the file has to be the
//! owner's: it is refused when group or others can access it, when it is
//! not a regular file or when another user owns it.

use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// A key file is a few dozen bytes.
const MAX_KEY_FILE: u64 = 4096;

pub fn read_key_file(path: &Path) -> io::Result<String> {
    // The checks are on the descriptor that is read: no race with a rename.
    let file = std::fs::File::open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot open {}: {e}", path.display())))?;
    let meta = file.metadata()?;
    let invalid = |msg: String| io::Error::new(io::ErrorKind::PermissionDenied, msg);
    if !meta.is_file() {
        return Err(invalid(format!("{} is not a regular file", path.display())));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(invalid(format!(
            "{} has mode {:04o}: the swarm key must not be accessible to group or others \
             (chmod 600 it, and generate a new one if others could have read it)",
            path.display(),
            meta.mode() & 0o7777
        )));
    }
    let me = rustix::process::geteuid().as_raw();
    if meta.uid() != me && meta.uid() != 0 {
        return Err(invalid(format!(
            "{} is owned by uid {}, not by uid {me}",
            path.display(),
            meta.uid()
        )));
    }
    if meta.len() > MAX_KEY_FILE {
        return Err(invalid(format!(
            "{} is too large for a swarm key",
            path.display()
        )));
    }
    let mut content = String::new();
    file.take(MAX_KEY_FILE).read_to_string(&mut content)?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn key_file(dir: &Path, mode: u32) -> std::path::PathBuf {
        let path = dir.join("swarm.key");
        let _ = std::fs::remove_file(&path);
        crate::control::generate_swarm_key(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn test_a_private_key_file_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_file(dir.path(), 0o600);
        assert!(read_key_file(&path)
            .unwrap()
            .starts_with("/key/swarm/psk/1.0.0/"));
        // Read only for the owner is fine too.
        let path = key_file(dir.path(), 0o400);
        assert!(read_key_file(&path).is_ok());
    }

    #[test]
    fn test_a_key_file_others_can_access_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o640, 0o604, 0o644, 0o660, 0o666, 0o607] {
            let path = key_file(dir.path(), mode);
            let err = read_key_file(&path).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{mode:o}");
            assert!(err.to_string().contains("chmod 600"));
        }
    }

    #[test]
    fn test_generating_a_key_makes_it_private_and_keeps_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swarm.key");
        crate::control::generate_swarm_key(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        let first = std::fs::read(&path).unwrap();
        assert!(crate::control::generate_swarm_key(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), first);
    }

    #[test]
    fn test_what_is_not_a_key_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_key_file(&dir.path().join("missing")).is_err());
        assert!(read_key_file(dir.path()).is_err());
        let big = dir.path().join("big");
        std::fs::write(&big, vec![b'a'; 10_000]).unwrap();
        std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_key_file(&big).is_err());
    }
}
