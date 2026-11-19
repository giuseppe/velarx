// SPDX-License-Identifier: Apache-2.0
//! The root file systems of the containers: the EROFS images of the layers
//! of their image (`layer_erofs`), made when the layer is pulled and kept in
//! the store next to its objects, one per layer, shared by every image that
//! has the layer.  The overlay of a container has them as its lower layers
//! and the objects of the store as its data-only layers: the overlay merges
//! the layers, follows the redirects of the stubs to the objects, and, as
//! root with `verity=`, checks the fs-verity digest of each file it opens.
//! A root engine's storage driver mounts the images with the kernel's EROFS
//! and hands the overlay over as a mount descriptor; where the kernel does
//! not (rootless, a lazy image, unmapped owners, a kernel mount that failed)
//! the image server serves the same images by FUSE, one mount with a
//! directory per layer (`erofs_tree`), and hands its overlay over the same
//! way.
//!
//! An image is the store's: its fs-verity digest is in the record of its
//! layer and is checked before it is used; one that is missing or not the
//! one recorded is an error, never made again behind the user's back.

use std::path::{Path, PathBuf};

/// The directory of the images, next to the objects of the store.
pub const DIR: &str = "composefs";
/// The layers an overlay takes, its lower and its data-only layers together
/// (`OVL_MAX_STACK` of the kernel).
pub const OVERLAY_MAX_STACK: usize = 500;
/// The version of the images: a new one makes new names (4: the stubs and
/// the index are sized by the algorithm of the digests of the layer; 5: the
/// nanoseconds of the times and the root directory of a pulled layer).
const FORMAT: u32 = 5;

/// The directory of the EROFS images, the indexes and the profiles of the
/// store whose objects are `objects`.
pub fn images_dir(objects: &Path) -> PathBuf {
    objects.parent().unwrap_or(objects).join(DIR)
}

/// The EROFS image of the layer named `stem` (the name of its key,
/// `LayerKey::file_stem`: the hex of its blob, `toc-` and the hex of its TOC)
/// in the store whose objects are `objects`.
pub fn layer_image_path(objects: &Path, stem: &str) -> PathBuf {
    images_dir(objects).join(format!("layer-{stem}.v{FORMAT}.erofs"))
}

/// The index of the files of the layer named `stem` (`erofs_tree::Index`).
pub fn layer_index_path(objects: &Path, stem: &str) -> PathBuf {
    images_dir(objects).join(format!("layer-{stem}.v{FORMAT}.index"))
}

/// The image of the layer named `stem`: in the store whose objects are the
/// first of `objects` that has it (this store, then the read-only image
/// stores).
pub fn find_layer_image(objects: &[&Path], stem: &str) -> Option<(PathBuf, PathBuf)> {
    objects.iter().find_map(|o| {
        let image = layer_image_path(o, stem);
        image.is_file().then(|| (image, layer_index_path(o, stem)))
    })
}

/// The startup profile of an image: the files its containers looked up
/// first (`fuse::profile`).
pub fn profile_path(objects: &Path, image_id: &str) -> PathBuf {
    images_dir(objects).join(format!("{image_id}.profile.json"))
}

/// The owners of the files of a layer as its record keeps them (uids, gids).
pub fn parse_owners(owners: &str) -> Option<(Vec<u32>, Vec<u32>)> {
    serde_json::from_str(owners).ok()
}

/// Open the EROFS image at `path` once, for the whole life of the mount or
/// the file system that serves it: from the descriptor of its directory, as
/// a name that is no symlink (`velarx_sys::fs::open_beneath`), so that
/// nothing between the check and the use of the image can name another
/// file; a regular file (a FIFO put there is refused, not waited on).
/// Everything after this works on the
/// descriptor: the measure of its fs-verity digest (`measure_layer_image`),
/// the mount (the descriptor is the `source` of the EROFS, which keeps it
/// open), the mapping the FUSE file system reads.
///
/// The descriptor holds a shared `flock` of the image, for as long as it is
/// open: that is how the collection knows the layer is in use
/// ([`lock_unused_layer_image`]).  A mount holds it as long as the file
/// system exists (the kernel keeps the open file), a server as long as it
/// runs, and a process that dies loses it with its descriptors.  An image
/// the collection is removing is [`LayerBusy`].
pub fn open_layer_image(path: &Path) -> std::io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};
    use velarx_sys::fs::{open_beneath, Beneath, BeneathError};
    let fail = |errno: rustix::io::Errno| {
        std::io::Error::new(
            std::io::Error::from(errno).kind(),
            OpenFailed {
                path: path.to_path_buf(),
                errno,
            },
        )
    };
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other(format!("{} names no file", path.display())))?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let dir = rustix::fs::open(
        dir,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(fail)?;
    match open_beneath(
        std::os::fd::AsFd::as_fd(&dir),
        Path::new(name),
        Beneath::File,
    ) {
        Ok(fd) => {
            let file: std::fs::File = fd.into();
            match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockShared) {
                Ok(()) => Ok(file),
                Err(rustix::io::Errno::WOULDBLOCK) => Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    LayerBusy(path.to_path_buf()),
                )),
                Err(e) => Err(fail(e)),
            }
        }
        Err(BeneathError::Errno(e)) => Err(fail(e)),
        Err(BeneathError::NotRegular) => Err(std::io::Error::other(format!(
            "{} is not a regular file",
            path.display()
        ))),
    }
}

/// An image that could not be opened, with the error the kernel gave
/// ([`open_errno`] finds it again).
#[derive(Debug)]
struct OpenFailed {
    path: PathBuf,
    errno: rustix::io::Errno,
}

impl std::fmt::Display for OpenFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.errno)
    }
}

impl std::error::Error for OpenFailed {}

/// The error the kernel gave to [`open_layer_image`] that failed with `e`.
pub fn open_errno(e: &std::io::Error) -> Option<rustix::io::Errno> {
    e.get_ref()
        .and_then(|i| i.downcast_ref::<OpenFailed>())
        .map(|f| f.errno)
}

/// The image of a layer that the collection is removing: it holds the lock
/// of the image exclusive, so nothing may use the layer any more.
#[derive(Debug)]
pub struct LayerBusy(pub PathBuf);

impl std::fmt::Display for LayerBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the image {} is being removed by a garbage collection",
            self.0.display()
        )
    }
}

impl std::error::Error for LayerBusy {}

/// Whether `e`, the failure of [`open_layer_image`], is [`LayerBusy`].
pub fn is_layer_busy(e: &std::io::Error) -> bool {
    e.get_ref().is_some_and(|i| i.is::<LayerBusy>())
}

/// What [`lock_unused_layer_image`] found.
#[derive(Debug)]
pub enum LayerUse {
    /// Nothing holds the image (or there is none): the descriptor, when
    /// there is an image, holds the lock exclusive until it is dropped, so
    /// that no mount or server takes the layer while it is removed.
    Unused(Option<std::fs::File>),
    /// A mount or a server holds the image.
    InUse,
}

/// Whether anything uses the layer whose image is `path`: tries to take the
/// lock of the image exclusive without waiting (the holders of
/// [`open_layer_image`] have it shared).  Any other failure than a held lock
/// is an error: a collection that cannot tell removes nothing.
pub fn lock_unused_layer_image(path: &Path) -> std::io::Result<LayerUse> {
    use rustix::fs::{flock, FlockOperation, Mode, OFlags};
    let file = match rustix::fs::open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()) {
        Ok(fd) => std::fs::File::from(fd),
        Err(rustix::io::Errno::NOENT) => return Ok(LayerUse::Unused(None)),
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::Error::from(e).kind(),
                format!("{}: {e}", path.display()),
            ))
        }
    };
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(LayerUse::Unused(Some(file))),
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(LayerUse::InUse),
        Err(e) => Err(std::io::Error::new(
            std::io::Error::from(e).kind(),
            format!("{}: {e}", path.display()),
        )),
    }
}

/// The image at `path`, opened (`open_layer_image`) and checked against the
/// fs-verity digests `accepted` (`measure_layer_image`) through the same
/// descriptor, which is what the caller mounts or serves.  An image that
/// fails the check is closed.
pub fn open_checked_layer_image(
    path: &Path,
    accepted: &[String],
    strict: bool,
) -> std::io::Result<std::fs::File> {
    let file = open_layer_image(path)?;
    measure_layer_image(&file, path, accepted, strict)?;
    Ok(file)
}

/// The fs-verity digest of the open image `file` (`sha256:HEX` or
/// `sha512:HEX`) where it has fs-verity: what a check that failed found, for
/// the debug log.
pub fn layer_image_digest(file: &std::fs::File) -> Option<String> {
    velarx_storage::measure_file(file)
        .ok()
        .map(|m| m.to_string())
}

/// Check that the image at `file` has one of the fs-verity digests
/// `accepted` (`sha256:HEX` or `sha512:HEX`): where the file has fs-verity the
/// kernel gives its digest in constant time.  Not `strict`, a file without it
/// (a file system without fs-verity) or with fs-verity made otherwise than
/// the digests (blocks of other than 4096 bytes, a salt) passes unmeasured
/// (`system check` reads such a file whole); `strict`, which the enforcement
/// of the digests of a manifest is, makes both an error, and so is an empty
/// list.  Gives the digest it measured (none: the image passed unmeasured).
pub fn measure_layer_image(
    file: &std::fs::File,
    path: &Path,
    accepted: &[String],
    strict: bool,
) -> std::io::Result<Option<String>> {
    if accepted.is_empty() {
        return Err(std::io::Error::other(format!(
            "no fs-verity digest to check the EROFS image {} against",
            path.display()
        )));
    }
    let unmeasured = |why: &str| match strict {
        true => Err(std::io::Error::other(format!(
            "the EROFS image {} cannot be measured ({why}) and the digests are enforced",
            path.display()
        ))),
        false => Ok(None),
    };
    let m = match velarx_storage::measure_file(file) {
        Ok(m) => m,
        Err(velarx_storage::FsVerityError::NotEnabled) => {
            return unmeasured("it has no fs-verity");
        }
        Err(velarx_storage::FsVerityError::NotSupported) => {
            return unmeasured("its file system has no fs-verity");
        }
        Err(e) => return Err(std::io::Error::other(e)),
    };
    // (the digests that name the images are made with blocks of 4096 bytes
    // and no salt: the descriptor of the file says how this one was made)
    let made = velarx_storage::verity_parameters(file).map_err(std::io::Error::other)?;
    if made != velarx_storage::VerityParameters::canonical(m.algorithm.algorithm()) {
        return unmeasured(&format!(
            "its fs-verity has blocks of {} bytes and a salt of {} bytes, not those of the digests that name images",
            1u64 << made.log_blocksize,
            made.salt_size
        ));
    }
    let got = m.to_string();
    if !accepted.contains(&got) {
        return Err(std::io::Error::other(format!(
            "the EROFS image {} has the fs-verity digest {got}, expected {}",
            path.display(),
            accepted.join(", ")
        )));
    }
    Ok(Some(got))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_files_of_a_layer_are_named_by_its_key() {
        let objects = Path::new("/s/objects");
        let whole = "ab".repeat(32);
        let toc = format!("toc-{whole}");
        assert_eq!(
            layer_image_path(objects, &whole),
            Path::new(&format!("/s/composefs/layer-{whole}.v5.erofs"))
        );
        assert_eq!(
            layer_index_path(objects, &toc),
            Path::new(&format!("/s/composefs/layer-{toc}.v5.index"))
        );
        assert_ne!(
            layer_image_path(objects, &whole),
            layer_image_path(objects, &toc)
        );
    }

    /// An open image holds a shared lock for as long as the descriptor is
    /// open (a copy of it counts: a mount keeps the open file), the
    /// collection sees the image in use then, and gets it, held, when
    /// nothing uses it; a held image is not opened while it is removed.
    /// (in a process of its own: the lock is the open file's, which a
    /// process that another test forks shares until it runs its program,
    /// and would hold beyond the drops here)
    #[test]
    fn an_open_image_is_in_use_until_it_is_closed() {
        velarx_base::testing::in_child(|| {
            let d = tempfile::tempdir().unwrap();
            let image = d.path().join("x.erofs");
            std::fs::write(&image, b"an image").unwrap();
            // no image, nothing uses it
            assert!(matches!(
                lock_unused_layer_image(&d.path().join("none")).unwrap(),
                LayerUse::Unused(None)
            ));
            let first = open_layer_image(&image).unwrap();
            let second = open_layer_image(&image).unwrap();
            assert!(matches!(
                lock_unused_layer_image(&image).unwrap(),
                LayerUse::InUse
            ));
            drop(first);
            assert!(matches!(
                lock_unused_layer_image(&image).unwrap(),
                LayerUse::InUse
            ));
            // the kernel keeps a mount's open file: a duplicate is that
            let kept = rustix::io::dup(&second).unwrap();
            drop(second);
            assert!(matches!(
                lock_unused_layer_image(&image).unwrap(),
                LayerUse::InUse
            ));
            drop(kept);
            let LayerUse::Unused(Some(hold)) = lock_unused_layer_image(&image).unwrap() else {
                panic!("the image is not in use");
            };
            // (held: nothing opens it meanwhile, and says why)
            let e = open_layer_image(&image).unwrap_err();
            assert!(is_layer_busy(&e), "{e}");
            assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock);
            assert!(!is_layer_busy(
                &open_layer_image(&d.path().join("none")).unwrap_err()
            ));
            drop(hold);
            open_layer_image(&image).unwrap();
        });
    }

    /// A process that dies (killed, nothing runs in it) holds no lock: the
    /// kernel closes its descriptors.  The holder is a shell that takes the
    /// lock of the image on a descriptor of its own (`flock(1)`) and then
    /// is `sleep`, which says so when it holds it.
    #[test]
    fn a_killed_holder_releases_the_image() {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        struct Holder(std::process::Child);
        impl Drop for Holder {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let d = tempfile::tempdir().unwrap();
        let image = d.path().join("x.erofs");
        std::fs::write(&image, b"an image").unwrap();
        let mut holder = Holder(
            Command::new("sh")
                .arg("-c")
                .arg(r#"exec 9<"$1" && flock -s 9 && echo held && exec sleep 600"#)
                .arg("sh")
                .arg(&image)
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut line = String::new();
        std::io::BufReader::new(holder.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "held\n");
        assert!(matches!(
            lock_unused_layer_image(&image).unwrap(),
            LayerUse::InUse
        ));
        // (kill -9, and wait for it: its descriptors are closed then)
        holder.0.kill().unwrap();
        holder.0.wait().unwrap();
        assert!(matches!(
            lock_unused_layer_image(&image).unwrap(),
            LayerUse::Unused(Some(_))
        ));
    }

    #[test]
    fn an_image_is_opened_by_a_name_that_is_no_symlink() {
        let d = tempfile::tempdir().unwrap();
        let image = d.path().join("x.erofs");
        std::fs::write(&image, b"an image").unwrap();
        let other = d.path().join("other");
        std::fs::write(&other, b"other").unwrap();
        // the descriptor is the file, whatever happens to its name
        let mut f = open_layer_image(&image).unwrap();
        std::fs::rename(&other, &image).unwrap();
        std::fs::remove_file(&image).unwrap();
        let mut got = String::new();
        std::io::Read::read_to_string(&mut f, &mut got).unwrap();
        assert_eq!(got, "an image");
        // a symlink is refused, as the file
        std::fs::write(&other, b"other").unwrap();
        std::os::unix::fs::symlink(&other, &image).unwrap();
        let e = open_layer_image(&image).unwrap_err();
        assert!(e.to_string().contains("x.erofs"), "{e}");
        assert!(open_layer_image(&d.path().join("missing")).is_err());
        // a FIFO is refused, not waited on
        let fifo = d.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let e = open_layer_image(&fifo).unwrap_err();
        assert!(e.to_string().contains("not a regular file"), "{e}");
        // (the directory of the image may be reached through a link)
        let link = d.path().join("dir-link");
        std::os::unix::fs::symlink(d.path(), &link).unwrap();
        open_layer_image(&link.join("other")).unwrap();
        // an image that fails the check is an error
        let none = ["sha256:00".to_string()];
        assert!(open_checked_layer_image(&other, &none, true).is_err());
        open_checked_layer_image(&other, &none, false).unwrap();
    }

    #[test]
    fn an_image_without_fs_verity_is_not_measured() {
        let d = tempfile::tempdir().unwrap();
        let image = d.path().join("x.erofs");
        std::fs::write(&image, b"an image").unwrap();
        let f = std::fs::File::open(&image).unwrap();
        let none = ["sha256:00".to_string()];
        measure_layer_image(&f, &image, &none, false).unwrap();
        let e = measure_layer_image(&f, &image, &none, true).unwrap_err();
        assert!(e.to_string().contains("cannot be measured"), "{e}");
        let e = measure_layer_image(&f, &image, &[], false).unwrap_err();
        assert!(e.to_string().contains("no fs-verity digest"), "{e}");
        let Some(dir) = std::env::var_os("VELARX_VERITY_DIR") else {
            eprintln!("VELARX_VERITY_DIR not set: the part with fs-verity is skipped");
            return;
        };
        let d = tempfile::tempdir_in(dir).unwrap();
        let image = d.path().join("x.erofs");
        std::fs::write(&image, b"an image").unwrap();
        velarx_storage::VerityMode::On
            .manager()
            .unwrap()
            .enable(&image)
            .unwrap();
        let f = std::fs::File::open(&image).unwrap();
        let want = velarx_storage::composefs_digest_of(
            velarx_types::digest::Algorithm::Sha256,
            b"an image",
        );
        let other = "sha256:00".to_string();
        measure_layer_image(&f, &image, std::slice::from_ref(&want), true).unwrap();
        measure_layer_image(&f, &image, &[other.clone(), want.clone()], true).unwrap();
        let e = measure_layer_image(&f, &image, &[other], true).unwrap_err();
        assert!(e.to_string().contains("expected sha256:00"), "{e}");
    }

    /// An image whose fs-verity was made with blocks of another size than
    /// the digests that name images have is not one the digests tell
    /// anything of: it passes unmeasured, or is refused when the digests are
    /// enforced.  (Needs a file system with fs-verity, `VELARX_VERITY_DIR`.)
    #[test]
    fn an_image_with_smaller_fs_verity_blocks_is_not_measured() {
        let Some(dir) = std::env::var_os("VELARX_VERITY_DIR") else {
            eprintln!("VELARX_VERITY_DIR not set: skipped");
            return;
        };
        let d = tempfile::tempdir_in(dir).unwrap();
        let image = d.path().join("x.erofs");
        std::fs::write(&image, b"an image").unwrap();
        velarx_storage::FsVerityManager::with_config(velarx_storage::FsVerityConfig {
            block_size: 1024,
            ..Default::default()
        })
        .enable(&image)
        .unwrap();
        let f = std::fs::File::open(&image).unwrap();
        assert_eq!(
            velarx_storage::verity_parameters(&f).unwrap().log_blocksize,
            10
        );
        let want = velarx_storage::composefs_digest_of(
            velarx_types::digest::Algorithm::Sha256,
            b"an image",
        );
        let accepted = [want];
        assert_eq!(
            measure_layer_image(&f, &image, &accepted, false).unwrap(),
            None
        );
        let e = measure_layer_image(&f, &image, &accepted, true).unwrap_err();
        assert!(e.to_string().contains("blocks of 1024 bytes"), "{e}");
    }
}
