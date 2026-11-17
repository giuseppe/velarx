// SPDX-License-Identifier: Apache-2.0
//! The root file system the monitor attached, as the engine recognises the
//! processes of a container by it.
//!
//! A storage driver can make a new mount at every start (a composefs overlay
//! or a FUSE server as a descriptor, a varlink driver's `Mounts`), so the root
//! of a running container cannot be compared with the mount of a later
//! `Mounts` call.  The monitor records `(st_dev, st_ino)` of the root it
//! attached in its run directory, with the boot it was attached in, and the
//! engine compares `/proc/PID/root` with that.
//!
//! The boot matters: the device number of a mount that has no device (a FUSE
//! server, an EROFS image, an overlay) is handed out again as soon as its
//! superblock is gone, and the inode of the top directory of such a file
//! system is often the same for every mount (1 for FUSE).  A record that
//! survived a reboot (a state directory that is not a tmpfs) would otherwise
//! name the root of whatever process now runs on a mount that got the same
//! number.  A record of another boot recognises no process.

use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// The file of the monitor's run directory that holds the identity.
pub const FILE: &str = "rootfs-id";

const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";

/// The identity of a root: the device and the inode of its top directory, and
/// the boot it was attached in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootId {
    pub dev: u64,
    pub ino: u64,
    pub boot: String,
}

fn boot_id() -> io::Result<String> {
    Ok(std::fs::read_to_string(BOOT_ID)?.trim().to_string())
}

/// Forget the identity of an earlier start.
pub fn forget(dir: &Path) {
    let _ = std::fs::remove_file(dir.join(FILE));
}

/// Record the identity of the directory `root`, the mount the monitor just
/// attached (written to a name of its own and renamed, so that the engine
/// reads all of it or none).
pub fn record(dir: &Path, root: &Path) -> io::Result<()> {
    let m = std::fs::metadata(root)?;
    let text = format!("{} {} {}\n", m.dev(), m.ino(), boot_id()?);
    velarx_base::atomic_file::write(&dir.join(FILE), text.as_bytes(), 0o644)
}

/// The identity the monitor of `dir` recorded (`None`: it recorded none, the
/// root is of a kind the driver recognises itself).
pub fn recorded(dir: &Path) -> io::Result<Option<RootId>> {
    let text = match std::fs::read_to_string(dir.join(FILE)) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{FILE} is not `dev ino boot`"),
        )
    };
    let mut it = text.split_whitespace();
    let dev = it.next().and_then(|n| n.parse().ok()).ok_or_else(bad)?;
    let ino = it.next().and_then(|n| n.parse().ok()).ok_or_else(bad)?;
    let boot = it.next().ok_or_else(bad)?.to_string();
    if it.next().is_some() {
        return Err(bad());
    }
    Ok(Some(RootId { dev, ino, boot }))
}

/// Whether `proc_root` (`/proc/PID/root`) is the root `id`: the same device
/// and inode, recorded in this boot.
pub fn is_root(proc_root: &Path, id: &RootId) -> io::Result<bool> {
    is_root_in(proc_root, id, &boot_id()?)
}

fn is_root_in(proc_root: &Path, id: &RootId, boot: &str) -> io::Result<bool> {
    if id.boot != boot {
        return Ok(false);
    }
    let m = std::fs::metadata(proc_root)?;
    Ok((m.dev(), m.ino()) == (id.dev, id.ino))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_record_is_written_to_a_temporary_name_of_its_own() {
        let d = tempfile::tempdir().unwrap();
        let victim = d.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, d.path().join(format!("{FILE}.new"))).unwrap();
        record(d.path(), Path::new("/")).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        assert!(recorded(d.path()).unwrap().is_some());
    }

    #[test]
    fn the_recorded_root_is_the_one_a_process_is_compared_with() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(recorded(d.path()).unwrap(), None);
        record(d.path(), Path::new("/")).unwrap();
        let id = recorded(d.path()).unwrap().unwrap();
        assert_eq!(id.boot, boot_id().unwrap());
        assert!(is_root(Path::new("/proc/self/root"), &id).unwrap());
        assert!(!is_root(d.path(), &id).unwrap());
        // (a record of another boot names no process: the device number of
        // a mount without a device is handed out again)
        assert!(!is_root_in(Path::new("/proc/self/root"), &id, "another boot").unwrap());
        forget(d.path());
        assert_eq!(recorded(d.path()).unwrap(), None);
        for bad in ["x", "1 2", "1 2 b extra", "a 2 b"] {
            std::fs::write(d.path().join(FILE), bad).unwrap();
            assert!(recorded(d.path()).is_err(), "{bad:?}");
        }
    }
}
