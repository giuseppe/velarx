// SPDX-License-Identifier: Apache-2.0
//! The identity of a node: its libp2p key pair, kept in a file, so that the
//! node is the same peer after a restart.
//!
//! Everything a node remembers about another is keyed by its peer id: the
//! failures and wrong bytes, what was learnt of who has which layer, the
//! provider records in the DHT.  With an identity made at every start none of
//! that carried across a restart (and a restarted honest node left records of a dead id behind for
//! two days).
//!
//! The file holds the protobuf encoding of the key pair (libp2p's own
//! format, which names the key type: a key of another type can replace it
//! without a change here), owned by the user the service runs as, mode 0600,
//! and is made whole or not at all: the key is written to a file with no
//! name (`O_TMPFILE`), synced, and linked to its name (`linkat`), which fails
//! when the name exists, so a node never reads half a key, two starts at
//! once end up with one, and a start that dies leaves no copy of a key
//! behind.  It is never logged.  Deleted while the node runs, it changes
//! nothing until the next start, which makes a new one.  To get a new identity stop the service and remove the
//! file: the peer id is then new, as is the overlay's subnet it gives.
//!
//! A peer id is no credential: the swarm key or the certificate is
//! (docs/THREAT-MODEL.md).

use libp2p::identity::Keypair;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

/// A key pair of the key types libp2p has is a few dozen bytes.
const MAX_IDENTITY_FILE: u64 = 4096;

/// The identity in `path`; made, with its directory, when there is none.
pub fn load_or_create(path: &Path) -> io::Result<Keypair> {
    match load(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => create(path),
        other => other,
    }
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// The identity of the file.  The checks are on the descriptor that is read:
/// no race with a rename.
pub fn load(path: &Path) -> io::Result<Keypair> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot open {}: {e}", path.display())))?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(invalid(format!("{} is not a regular file", path.display())));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(invalid(format!(
            "{} has mode {:04o}: the identity of the node must not be accessible to group or \
             others (chmod 600 it, or remove it for a new identity)",
            path.display(),
            meta.mode() & 0o7777
        )));
    }
    let me = rustix::process::geteuid().as_raw();
    if meta.uid() != me {
        return Err(invalid(format!(
            "{} is owned by uid {}, not by uid {me}",
            path.display(),
            meta.uid()
        )));
    }
    if meta.len() > MAX_IDENTITY_FILE {
        return Err(invalid(format!(
            "{} is too large for an identity",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.take(MAX_IDENTITY_FILE).read_to_end(&mut bytes)?;
    Keypair::from_protobuf_encoding(&bytes).map_err(|e| {
        invalid(format!(
            "{} is not the identity of a node ({e}); remove it for a new one",
            path.display()
        ))
    })
}

fn create(path: &Path) -> io::Result<Keypair> {
    use rustix::fs::{AtFlags, Mode, OFlags, CWD};
    let Some(dir) = path.parent().filter(|_| path.file_name().is_some()) else {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let key = Keypair::generate_ed25519();
    let bytes = key
        .to_protobuf_encoding()
        .map_err(|e| io::Error::other(format!("cannot encode the identity: {e}")))?;
    let cannot = |what: &Path, e: rustix::io::Errno| {
        io::Error::new(
            io::Error::from(e).kind(),
            format!("cannot write {}: {e}", what.display()),
        )
    };
    // The key goes to a file with no name first (nothing is left behind by a
    // start that dies before it is whole), synced, and is then given its
    // name, which fails when the name exists: another start made it.
    let mut file = std::fs::File::from(
        rustix::fs::open(
            dir,
            OFlags::TMPFILE | OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| cannot(dir, e))?,
    );
    file.write_all(&bytes)?;
    file.sync_all()?;
    match rustix::fs::linkat(&file, "", CWD, path, AtFlags::EMPTY_PATH) {
        Ok(()) => {
            // (the name is in the directory when this returns)
            std::fs::File::open(dir)?.sync_all()?;
            Ok(key)
        }
        // (another start's identity: not replaced)
        Err(rustix::io::Errno::EXIST) => load(path),
        Err(e) => Err(cannot(path, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_node_keeps_its_peer_id_when_it_starts_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/p2p/identity.key");
        let first = load_or_create(&path).unwrap();
        let again = load_or_create(&path).unwrap();
        assert_eq!(first.public().to_peer_id(), again.public().to_peer_id());
        // (another file, another node)
        let other = load_or_create(&dir.path().join("other.key")).unwrap();
        assert_ne!(first.public().to_peer_id(), other.public().to_peer_id());
    }

    #[test]
    fn the_file_and_its_directory_are_the_owners_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/identity.key");
        load_or_create(&path).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().mode() & 0o7777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        // no temporary file is left beside it
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["identity.key"]);
    }

    #[test]
    fn an_identity_others_can_read_is_refused_not_used() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        load_or_create(&path).unwrap();
        for mode in [0o640, 0o604, 0o644, 0o660] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let e = load_or_create(&path).unwrap_err();
            assert!(e.to_string().contains("must not be accessible"), "{e}");
        }
        // (and nothing was replaced to get around it)
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(load_or_create(&path).is_ok());
    }

    #[test]
    fn a_file_that_is_no_identity_is_an_error_not_a_new_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        std::fs::write(&path, b"not a key").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let e = load_or_create(&path).unwrap_err();
        assert!(e.to_string().contains("not the identity of a node"), "{e}");
        // the file is still there, as it was
        assert_eq!(std::fs::read(&path).unwrap(), b"not a key");
    }

    #[test]
    fn a_link_or_a_directory_is_no_identity() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.key");
        load_or_create(&real).unwrap();
        let link = dir.path().join("link.key");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(load_or_create(&link).is_err());
        assert!(load_or_create(dir.path()).is_err());
        // (a link to where nothing is yet is not followed to make it there)
        let elsewhere = dir.path().join("elsewhere.key");
        let dangling = dir.path().join("dangling.key");
        std::os::unix::fs::symlink(&elsewhere, &dangling).unwrap();
        assert!(load_or_create(&dangling).is_err());
        assert!(elsewhere.symlink_metadata().is_err());
    }

    #[test]
    fn nodes_that_start_at_once_end_up_with_one_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let ids: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || load_or_create(&path).unwrap().public().to_peer_id())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect();
        assert!(ids.iter().all(|id| *id == ids[0]), "{ids:?}");
    }
}
