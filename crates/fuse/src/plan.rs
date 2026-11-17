// SPDX-License-Identifier: Apache-2.0
//! The plan of the root file system of a container: what the storage driver
//! of the store says the monitor mounts, written by the engine into the
//! bundle at create and read by the monitor at each start.  The plan is the
//! driver's: the engine never looks into it, the monitor has one executor
//! per kind (`RootfsPlan`), and a driver that needs another way to make the
//! root file system adds a kind (a directory made for the container, for a
//! driver that copies) without a change to the engine's reading and writing.
//!
//! The file is `rootfs.json` in the bundle (`imagevol/N.rootfs.json` for an
//! image mounted in the container).  The kind is the member `"kind"` of the
//! object.
//!
//! There is no file of an earlier layout to read: the start of a container
//! of an image whose bundle has no `rootfs.json` (made by another version, or
//! the file was removed) is refused.  A kind that this version does not know
//! is an error that names it, never a guess.

use std::io;
use std::path::{Path, PathBuf};

/// The file of the plan in a bundle (and, after `N.`, in `imagevol`).
pub const FILE: &str = "rootfs.json";

/// How the monitor makes the root file system of a container.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RootfsPlan {
    /// A plain directory made for the container (a driver that copies the
    /// layers): the monitor makes it the root, nothing is mounted over it.
    Directory(Directory),
    /// A file system of the driver that the engine hands the monitor as a
    /// detached mount descriptor, at the spawn of the monitor.
    MountFd(MountFd),
}

/// The root file system of a container as a detached mount that the storage
/// driver made (`open_tree(OPEN_TREE_CLONE)` or `fsmount`), for a driver
/// whose root is not a directory of this host's tree (a network or FUSE file
/// system, a snapshotter's mount).
///
/// The plan holds no descriptor and no path: only the place of the
/// descriptor among those the engine passed to the monitor when it started it
/// (`SpawnOptions::rootfs_fds`, the monitor's `MonitorConfig::rootfs_fds`).
/// The number of a descriptor is the monitor's own and is never read from the
/// file, so the file cannot name an inherited descriptor that was not passed
/// for this purpose.  The descriptor is used once, by the start of the
/// monitor that got it: the plan of a container whose descriptor is not
/// there (the engine restarted, or the monitor is started again) is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MountFd {
    /// Which of the descriptors the monitor got for the mounts of the
    /// container, 0 for the first: the root file system is 0 when the driver
    /// hands it over as a mount, the image mounts (`--mount type=image`) come
    /// after it, 1 to 15.
    pub fd_index: u32,
    /// The monitor puts the container's id mapping on its clone of the
    /// mount (`mount_setattr` with `MOUNT_ATTR_IDMAP`, from the same holder
    /// user namespace as an idmapped composefs image or a `--rootfs`)
    /// before it attaches it: the owners of the files are ids of the
    /// container (an image's), and they show as the host ids of its mapping
    /// (1000 as 101000 for `0 100000 65536`), which its own user namespace
    /// shows as 1000 again.  False: the ids are shown as the driver has
    /// them (it delivered mapped ids, or there is no mapping).  Refused with
    /// the reason when the kernel refuses the mapping (a file system that
    /// does not take idmapped mounts, one that is idmapped already, a monitor
    /// that is not root of the initial user namespace).
    #[serde(default, skip_serializing_if = "is_false")]
    pub idmap: bool,
    /// A process serves the file system (an image server: FUSE) and the
    /// engine passed its pidfd as the descriptor after the mount's
    /// (`fd_index + 1`).  The monitor puts the process in its own cgroup,
    /// logs when it ends, and, for a mount whose digests the server checks
    /// (`VerityDone::OnOpen`), does not take the mount without it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub server: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// What enforces the fs-verity digests of a mount the driver hands over, as
/// the driver says it and the engine checks it (`Rootfs::verity`), and the
/// engine tells the monitor in its own configuration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerityDone {
    /// Nothing the engine can rely on: the mount carries no enforcement.
    #[default]
    None,
    /// The driver measured the EROFS image of every layer against the digests
    /// the engine accepts, before it mounted them, and the overlay it made
    /// has `verity=require`: the kernel checks the digest of every file it
    /// opens.
    Kernel,
    /// A process that serves the mount checks the digests when a file is
    /// opened.
    OnOpen,
}

/// The most descriptors of mounts the engine passes to a monitor, the pidfds
/// of the servers of the mounts included.
pub const MAX_MOUNT_FDS: u32 = velarx_base::spawn::MAX_ROOTFS_FDS as u32;

/// The most image mounts that come as descriptors, besides the root file
/// system's.
pub const MAX_VOLUME_FDS: u32 = 15;

impl MountFd {
    /// The index must be one a monitor can have got.
    pub fn validate(&self) -> Result<(), String> {
        if self.fd_index + u32::from(self.server) >= MAX_MOUNT_FDS {
            return Err(format!(
                "fd_index {} is not below {MAX_MOUNT_FDS}, the most descriptors of mounts the monitor gets{}",
                self.fd_index,
                if self.server { " (the pidfd of its server follows the mount)" } else { "" }
            ));
        }
        Ok(())
    }
}

/// The root file system of a container as a directory the driver made.
///
/// The monitor is privileged and this file is data it reads, so the
/// directory is named in two parts that it holds to different rules: a base
/// it checks (`beneath`) and a path that cannot leave it (`path`).  It never
/// mounts a directory the base does not contain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Directory {
    /// The base: an absolute, normalized path (no `.`, `..` or empty
    /// component, not `/`) of a directory owned by the monitor's user or by
    /// root and not writable by its group or others (the bundle of the
    /// container, for a driver that copies).  The monitor opens it without
    /// following a link.
    pub beneath: PathBuf,
    /// The directory, relative to `beneath` (no leading `/`, no `.`, `..` or
    /// empty component): it is the container's own, written by the
    /// container.  It is resolved from the descriptor of `beneath` and cannot
    /// leave it, follow a link or cross a mount.
    pub path: PathBuf,
}

/// The longest `beneath` or `path` (Linux's `PATH_MAX` without the NUL).
pub const MAX_PATH: usize = 4095;
/// The longest component of either (`NAME_MAX`).
pub const MAX_NAME: usize = 255;

impl Directory {
    /// The syntax of the two parts, which a plan must have whoever wrote it:
    /// the monitor checks it when it reads the plan and again before it opens
    /// anything; the engine's own drivers hold their plans to it too.
    pub fn validate(&self) -> Result<(), String> {
        let beneath = plain(&self.beneath, "beneath")?;
        let path = plain(&self.path, "path")?;
        if !beneath.starts_with('/') {
            return Err(format!("beneath {beneath:?} is not an absolute path"));
        }
        if beneath == "/" {
            return Err(
                "beneath is `/`, the whole host: it must be a directory of the store".to_string(),
            );
        }
        if path.starts_with('/') {
            return Err(format!("path {path:?} is not relative to beneath"));
        }
        if path.is_empty() {
            return Err(
                "path is empty: the root file system is a directory below beneath".to_string(),
            );
        }
        components(&beneath[1..], "beneath")?;
        components(path, "path")
    }
}

fn plain<'a>(p: &'a Path, what: &str) -> Result<&'a str, String> {
    let s = p
        .to_str()
        .ok_or_else(|| format!("{what} {} is not UTF-8", p.display()))?;
    if s.len() > MAX_PATH {
        return Err(format!("{what} is longer than {MAX_PATH} bytes"));
    }
    Ok(s)
}

/// Each component of `p` is a name: not empty, not `.` or `..`, not too long
/// (`Path::components` drops a `.` in the middle and an empty one, so the
/// text is read).
pub fn components(p: &str, what: &str) -> Result<(), String> {
    for c in p.split('/') {
        if c.is_empty() || c == "." || c == ".." || c.len() > MAX_NAME || c.contains('\0') {
            return Err(format!(
                "{what} {p:?} has a component that is empty, `.`, `..`, with a NUL or longer than {MAX_NAME} bytes"
            ));
        }
    }
    Ok(())
}

impl RootfsPlan {
    /// The text of the file (an error for a path that is not UTF-8, which
    /// JSON cannot hold).
    pub fn to_vec(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// The plan of the text of a file.
    pub fn from_slice(data: &[u8]) -> Result<Self, serde_json::Error> {
        let plan = serde_json::from_slice(data);
        if plan.is_err() {
            // a directory plan of the layout before `beneath`: say what to do
            // (there is no reading of it: it named any directory of the host)
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
                if v["kind"] == "directory" && v.get("beneath").is_none() {
                    return Err(<serde_json::Error as serde::de::Error>::custom(
                        "the plan of the directory kind has no `beneath` (it was made by another version of velarx, whose layout is not read any more): remove the container and create it again",
                    ));
                }
            }
        }
        plan
    }
}

/// The file of the plan of `stem` in `dir` (`""` for the bundle, `"N."` for
/// the image mount N).
pub fn file(dir: &Path, stem: &str) -> PathBuf {
    dir.join(format!("{stem}{FILE}"))
}

/// Write the plan of `stem` in `dir`.
pub fn write(dir: &Path, stem: &str, plan: &RootfsPlan) -> io::Result<()> {
    let path = file(dir, stem);
    let data = plan
        .to_vec()
        .map_err(|e| io::Error::other(format!("{}: {e}", path.display())))?;
    std::fs::write(path, data)
}

/// Read the plan of `stem` in `dir`: None when the bundle has none (a
/// container with a `--rootfs` directory).
pub fn read(dir: &Path, stem: &str) -> io::Result<Option<RootfsPlan>> {
    let path = file(dir, stem);
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    RootfsPlan::from_slice(&data)
        .map(Some)
        .map_err(|e| io::Error::other(format!("{}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_composefs_plan_is_no_plan() {
        let e = RootfsPlan::from_slice(br#"{"kind":"composefs"}"#).unwrap_err();
        assert!(e.to_string().contains("composefs"), "{e}");
    }

    #[test]
    fn an_unknown_kind_is_an_error_that_names_it() {
        let e = RootfsPlan::from_slice(br#"{"kind":"squashfs"}"#).unwrap_err();
        assert!(e.to_string().contains("squashfs"), "{e}");
        assert!(RootfsPlan::from_slice(b"[]").is_err());
        // the members of a plan without its kind are no plan
        let e = RootfsPlan::from_slice(br#"{"fd_index":0}"#).unwrap_err();
        assert!(e.to_string().contains("kind"), "{e}");
    }

    fn dir(beneath: &str, path: &str) -> Directory {
        Directory {
            beneath: beneath.into(),
            path: path.into(),
        }
    }

    #[test]
    fn a_directory_plan_has_its_kind_a_base_and_a_path() {
        let plan = RootfsPlan::Directory(dir("/var/lib/c/1", "vfs/root"));
        let v: serde_json::Value = serde_json::from_slice(&plan.to_vec().unwrap()).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"kind": "directory", "beneath": "/var/lib/c/1", "path": "vfs/root"})
        );
        assert_eq!(
            RootfsPlan::from_slice(&plan.to_vec().unwrap()).unwrap(),
            plan
        );
        assert!(RootfsPlan::from_slice(br#"{"kind":"directory"}"#).is_err());
        // either member alone is no plan; a member that is not a text neither
        assert!(RootfsPlan::from_slice(br#"{"kind":"directory","beneath":"/b"}"#).is_err());
        assert!(RootfsPlan::from_slice(br#"{"kind":"directory","path":"r"}"#).is_err());
        assert!(RootfsPlan::from_slice(br#"{"kind":"directory","beneath":1,"path":"r"}"#).is_err());
        // a member that is not known is ignored, as in the other kinds
        let extra = br#"{"kind":"directory","beneath":"/b","path":"r","more":1}"#;
        assert_eq!(
            RootfsPlan::from_slice(extra).unwrap(),
            RootfsPlan::Directory(dir("/b", "r"))
        );
    }

    #[test]
    fn a_directory_plan_of_the_layout_without_beneath_is_refused_with_the_remedy() {
        let e = RootfsPlan::from_slice(br#"{"kind":"directory","path":"/var/lib/c/1/vfs/root"}"#)
            .unwrap_err()
            .to_string();
        assert!(e.contains("no `beneath`"), "{e}");
        assert!(
            e.contains("remove the container and create it again"),
            "{e}"
        );
    }

    #[test]
    fn the_parts_of_a_directory_plan_are_plain_paths() {
        dir("/var/lib/c/1", "vfs/root").validate().unwrap();
        dir("/b", "r").validate().unwrap();
        let long = "a/".repeat(2100) + "a";
        let name = "n".repeat(256);
        for (b, p, why) in [
            ("/", "etc", "beneath is `/`"),
            ("", "etc", "not an absolute"),
            ("b", "etc", "not an absolute"),
            ("//b", "etc", "component"),
            ("/b/", "etc", "component"),
            ("/b/../c", "etc", "component"),
            ("/b/./c", "etc", "component"),
            ("/b", "", "empty"),
            ("/b", "/etc", "not relative"),
            ("/b", "..", "component"),
            ("/b", "a/../b", "component"),
            ("/b", "./a", "component"),
            ("/b", "a//b", "component"),
            ("/b", "a/", "component"),
            ("/b", &long, "longer"),
            ("/b", &name, "component"),
            ("/b", "a\0b", "component"),
        ] {
            let e = dir(b, p).validate().expect_err(&format!("{b:?} {p:?}"));
            assert!(e.contains(why), "{b:?} {p:?}: {e}");
        }
        use std::os::unix::ffi::OsStrExt;
        let bad = Directory {
            beneath: "/b".into(),
            path: std::ffi::OsStr::from_bytes(b"a\xff").into(),
        };
        assert!(bad.validate().unwrap_err().contains("UTF-8"));
    }

    #[test]
    fn a_mount_fd_plan_is_a_kind_and_an_index_and_nothing_else() {
        let plan = RootfsPlan::MountFd(MountFd {
            server: false,
            fd_index: 2,
            idmap: false,
        });
        let v: serde_json::Value = serde_json::from_slice(&plan.to_vec().unwrap()).unwrap();
        assert_eq!(v, serde_json::json!({"kind": "mount-fd", "fd_index": 2}));
        assert_eq!(
            RootfsPlan::from_slice(&plan.to_vec().unwrap()).unwrap(),
            plan
        );
        // no index, an index that is not a number or is negative or huge, a
        // path or a number of a descriptor in its place: no plan
        for bad in [
            r#"{"kind":"mount-fd"}"#,
            r#"{"kind":"mount-fd","fd_index":"0"}"#,
            r#"{"kind":"mount-fd","fd_index":-1}"#,
            r#"{"kind":"mount-fd","fd_index":4294967296}"#,
            r#"{"kind":"mount-fd","fd":7}"#,
            r#"{"kind":"mount-fd","path":"/"}"#,
        ] {
            assert!(RootfsPlan::from_slice(bad.as_bytes()).is_err(), "{bad}");
        }
        MountFd {
            server: false,
            fd_index: 0,
            idmap: false,
        }
        .validate()
        .unwrap();
        MountFd {
            server: false,
            fd_index: MAX_MOUNT_FDS - 1,
            idmap: false,
        }
        .validate()
        .unwrap();
        let e = MountFd {
            server: false,
            fd_index: MAX_MOUNT_FDS,
            idmap: false,
        }
        .validate()
        .unwrap_err();
        assert!(e.contains("fd_index"), "{e}");
    }

    #[test]
    fn the_plan_is_written_and_read_under_its_stem() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert_eq!(file(d, ""), d.join(FILE));
        assert!(read(d, "").unwrap().is_none());
        let plan = RootfsPlan::MountFd(MountFd {
            fd_index: 1,
            idmap: true,
            server: false,
        });
        write(d, "", &plan).unwrap();
        write(d, "3.", &plan).unwrap();
        assert_eq!(read(d, "").unwrap().unwrap(), plan);
        assert_eq!(read(d, "3.").unwrap().unwrap(), plan);
        assert!(d.join("3.rootfs.json").exists());
        std::fs::write(d.join(FILE), b"{").unwrap();
        assert!(read(d, "").is_err());
    }

    #[test]
    fn a_plan_json_cannot_hold_is_an_error_not_an_empty_file() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let bad = Directory {
            beneath: std::ffi::OsStr::from_bytes(b"/s/\xff").into(),
            path: "r".into(),
        };
        let e = write(dir.path(), "", &RootfsPlan::Directory(bad)).unwrap_err();
        assert!(e.to_string().contains(FILE), "{e}");
        assert!(!file(dir.path(), "").exists());
    }
}
