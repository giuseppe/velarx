// SPDX-License-Identifier: Apache-2.0
//! Which stubs the overlay of a user namespace follows.
//!
//! The layers of an image are stubs that redirect to the data-only layers of
//! the store.  The overlay of a user namespace (`userxattr`) follows them in
//! every lower layer with `redirect_dir=followdata`, in the lowest lower
//! layer only without it (a stub of a layer above is refused, EPERM) or on a
//! kernel that does not have the option (EINVAL).  Which this kernel
//! does is found by trying, as the container libraries do for the features
//! of the overlay: a small overlay of three layers is mounted, with a stub
//! in the middle one, and the stub is read.  It is tried when an image of
//! more than one layer needs the answer first, by the process that mounts
//! the overlay of the container (its user namespace, its credentials), on a
//! file system of its own that is not attached anywhere: whatever happens
//! to the process, nothing of the probe is left.  The answer is kept for
//! the boot as the feature `overlay-datadir-every-layer` of the run root
//! (`monitor::features`): yes, the kernel follows the stubs of every lower
//! layer; no, only the lowest layer's.

use crate::imagemount::readonly_overlay;
use std::io;
use std::path::Path;
use velarx_fuse::erofs_tree::Stubs;
use velarx_fuse::layer_erofs::{metacopy, redirect};
use velarx_types::digest::{Algorithm, Digest};

const FEATURE: &str = "overlay-datadir-every-layer";

/// The content of the file the stubs of the probe redirect to.
const CONTENT: &[u8] = b"velarx";

/// The stubs the overlay of a container follows: every layer's as root, in a
/// user namespace (`userxattr`) what the kernel does ([`followed`]).  An image
/// of one layer has no stub above the lowest: it needs no answer.
pub(crate) fn followed_stubs(userxattr: bool, layers: usize, run: &Path) -> io::Result<Stubs> {
    match userxattr && layers > 1 {
        true => followed(run),
        false => Ok(Stubs::Every),
    }
}

/// The stubs followed by the overlay of a user namespace here: the answer
/// kept in the run root `run`, else found now and kept.  A run root that
/// cannot keep it is an error.
fn followed(run: &Path) -> io::Result<Stubs> {
    followed_with(run, || answer(probe()))
}

fn followed_with(run: &Path, probe: impl FnOnce() -> Option<Stubs>) -> io::Result<Stubs> {
    let found = crate::monitor::features::cached(run, FEATURE, "", || {
        Ok(probe().map(|s| s == Stubs::Every))
    })?;
    // (no answer: the lowest layer's, the safe one, not kept)
    Ok(match found {
        Some(true) => Stubs::Every,
        _ => Stubs::Lowest,
    })
}

/// The answer of a probe: what the read of the stub says, the lowest layer
/// where the kernel does not have `redirect_dir=followdata` (an answer of
/// the kernel, kept as the others), none where no overlay could be tried.
fn answer(probed: io::Result<io::Result<Vec<u8>>>) -> Option<Stubs> {
    match probed {
        Ok(read) => classify(read, CONTENT),
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {
            tracing::debug!("overlay stubs: {e}");
            Some(Stubs::Lowest)
        }
        Err(e) => {
            // (no overlay could be tried: no answer to keep)
            tracing::debug!("overlay stubs: the probe cannot be mounted: {e}");
            None
        }
    }
}

/// What the read of the stub of the middle layer says: followed if it gave
/// the content, only the lowest layer's if the kernel refused it (EPERM is
/// what a kernel that does not follow it answers).  Any other result is no
/// answer of the kernel (a failing read, other content): none, so that
/// nothing is kept for the boot and the next container asks again.
fn classify(read: io::Result<Vec<u8>>, want: &[u8]) -> Option<Stubs> {
    match read {
        Ok(got) if got == want => Some(Stubs::Every),
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => Some(Stubs::Lowest),
        Ok(_) => {
            tracing::warn!("overlay stubs: the stub of a middle layer reads other content");
            None
        }
        Err(e) => {
            tracing::warn!("overlay stubs: the probe failed: {e}");
            None
        }
    }
}

/// Mount the overlay of the probe and read the stub of its middle layer:
/// Err when the overlay cannot be mounted, else what the read gave.  Its
/// layers are on a tmpfs mounted detached, which only the descriptor of the
/// mount reaches (and frees with it), as the overlay over them.  The user
/// namespace is the process's own, the one the overlay of the containers is
/// mounted in.
fn probe() -> io::Result<io::Result<Vec<u8>>> {
    use rustix::fs::{openat, Mode, OFlags};
    use rustix::mount::{
        fsconfig_create, fsmount, fsopen, FsMountFlags, FsOpenFlags, MountAttrFlags,
    };
    use std::io::Read;
    use std::os::fd::AsFd;
    let tmpfs = fsopen("tmpfs", FsOpenFlags::FSOPEN_CLOEXEC)?;
    fsconfig_create(tmpfs.as_fd())?;
    let scratch = fsmount(
        tmpfs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::MOUNT_ATTR_NODEV
            | MountAttrFlags::MOUNT_ATTR_NOSUID
            | MountAttrFlags::MOUNT_ATTR_NOEXEC,
    )?;
    let root = velarx_sys::fd::proc_path(&scratch);
    let digest = Digest::fsverity(Algorithm::Sha256, &[0x5a; 32]).expect("32 bytes");
    let data = root.join("data");
    let object = data.join(&String::from_utf8_lossy(&redirect(&digest))[1..]);
    std::fs::create_dir_all(object.parent().expect("the object is in a directory"))?;
    std::fs::write(&object, CONTENT)?;
    let mut lowers = Vec::new();
    for layer in ["top", "mid", "low"] {
        let dir = root.join(layer);
        std::fs::create_dir(&dir)?;
        if layer != "top" {
            // (the stub as the image has it: the size of the file, no data)
            let path = dir.join(layer);
            std::fs::File::create(&path)?.set_len(CONTENT.len() as u64)?;
            for (name, value) in [
                ("user.overlay.redirect", redirect(&digest)),
                ("user.overlay.metacopy", metacopy(&digest)),
            ] {
                rustix::fs::setxattr(&path, name, &value, rustix::fs::XattrFlags::empty())?;
            }
        }
        lowers.push(dir.to_string_lossy().into_owned());
    }
    let mount = readonly_overlay(
        &lowers,
        &[data.to_string_lossy().into_owned()],
        "off",
        true,
        Stubs::Every,
        None,
    )?;
    let read = |name: &str| -> io::Result<Vec<u8>> {
        let fd = openat(
            mount.as_fd(),
            name,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let mut out = Vec::new();
        std::fs::File::from(fd).read_to_end(&mut out)?;
        Ok(out)
    };
    let got = read("mid");
    if let Err(e) = &got {
        // (the stub of the lowest layer tells a kernel that follows none)
        tracing::debug!(
            "overlay stubs: the middle layer: {e}; the lowest layer: {:?}",
            read("low").map(|c| c == CONTENT)
        );
    }
    Ok(got)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn errno(e: i32) -> io::Result<Vec<u8>> {
        Err(io::Error::from_raw_os_error(e))
    }

    #[test]
    fn the_read_of_the_middle_stub_tells_what_the_overlay_follows() {
        assert_eq!(classify(Ok(CONTENT.to_vec()), CONTENT), Some(Stubs::Every));
        assert_eq!(classify(errno(libc::EPERM), CONTENT), Some(Stubs::Lowest));
        // (any other failure is no answer: nothing to keep for the boot)
        assert_eq!(classify(errno(libc::EIO), CONTENT), None);
        assert_eq!(classify(errno(libc::ENOENT), CONTENT), None);
        assert_eq!(classify(Ok(Vec::new()), CONTENT), None);
        assert_eq!(classify(Ok(b"other".to_vec()), CONTENT), None);
    }

    /// A kernel without `redirect_dir=followdata` answers the lowest layer
    /// (kept); an overlay that could not be tried answers nothing.
    #[test]
    fn a_kernel_without_followdata_answers_the_lowest_layer() {
        use crate::imagemount::option_error;
        let einval = rustix::io::Errno::INVAL;
        let refused = option_error("redirect_dir", "followdata", einval);
        assert_eq!(answer(Err(refused)), Some(Stubs::Lowest));
        assert_eq!(answer(Err(option_error("verity", "off", einval))), None);
        assert_eq!(answer(Err(io::Error::from_raw_os_error(libc::EPERM))), None);
        assert_eq!(answer(Ok(Ok(CONTENT.to_vec()))), Some(Stubs::Every));
        assert_eq!(answer(Ok(errno(libc::EPERM))), Some(Stubs::Lowest));
    }

    /// The kernel's answer is a feature of the run root: yes follows every
    /// layer, no the lowest; no answer is the safe one and kept nowhere.
    #[test]
    fn the_answer_is_a_feature_of_the_run_root() {
        let tmp = tempfile::tempdir().unwrap();
        let run = tmp.path();
        let features = run.join("features");
        assert_eq!(followed_with(run, || None).unwrap(), Stubs::Lowest);
        assert!(!features.exists());
        assert_eq!(
            followed_with(run, || Some(Stubs::Every)).unwrap(),
            Stubs::Every
        );
        assert!(features.join("overlay-datadir-every-layer-yes").is_file());
        // kept, whatever the probe would say
        assert_eq!(
            followed_with(run, || panic!("asked")).unwrap(),
            Stubs::Every
        );
        std::fs::remove_dir_all(&features).unwrap();
        assert_eq!(
            followed_with(run, || Some(Stubs::Lowest)).unwrap(),
            Stubs::Lowest
        );
        assert!(features.join("overlay-datadir-every-layer-no").is_file());
    }
}
