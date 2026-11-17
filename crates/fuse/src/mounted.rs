// SPDX-License-Identifier: Apache-2.0
//! The root file system of an image as a mount of it shows it: what the
//! engine reads of an image whose layers it cannot read itself (the storage
//! service's, behind the descriptor of `MountImage`).  It answers the
//! lookups of [`ImageTree`] from a directory descriptor, a name at a time,
//! and nothing is read ahead.
//!
//! Every name is opened below the descriptor with `openat2`
//! (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, the
//! confinement of the monitor's lookups: [`velarx_sys::fs::open_beneath`],
//! and `RESOLVE_NO_XDEV`: the image is one mount, a mount below it is not the
//! image's), so a link of the image (to a path of the host, to `/proc/...`)
//! is data that the callers read as the name it holds
//! ([`ImageTree::resolve_following`]), never a path the kernel follows.  Only
//! a regular file has content to read ([`ImageTree::open_content`]): a FIFO
//! or a device under a name that is read is never opened.  The names it
//! keeps are bounded as an image's entries are ([`MAX_NODES`]).

use crate::view::{ImageTree, ViewNode};
use rustix::fs::FileType;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::{Arc, Mutex};
use velarx_storage::TocEntryType;
use velarx_sys::fs::{open_beneath_with, Beneath, BeneathError};

/// The most names a view keeps, the names of one directory included: the
/// entries an image may have (`velarx_content::pull::MAX_IMAGE_TOC_ENTRIES`,
/// which a test there keeps equal), so that a service that hands over more
/// costs the engine no more memory than a pulled image does.
pub const MAX_NODES: usize = 2 << 20;

/// A name below the root of the image, opened as `what` without leaving it
/// or its mount.
fn open_in(root: BorrowedFd<'_>, path: &str, what: Beneath) -> Result<OwnedFd, BeneathError> {
    open_beneath_with(
        root,
        Path::new(path),
        what,
        rustix::fs::ResolveFlags::NO_XDEV,
    )
}

#[derive(Default)]
struct Nodes {
    /// The path of each node below the root (`""` the root): a path of names
    /// that the image had when they were asked, none of them a link.
    paths: Vec<Arc<str>>,
    by_path: HashMap<Arc<str>, usize>,
}

impl Nodes {
    fn intern(&mut self, path: String) -> io::Result<usize> {
        if let Some(id) = self.by_path.get(path.as_str()) {
            return Ok(*id);
        }
        if self.paths.len() >= MAX_NODES {
            return Err(io::Error::other(format!(
                "the mounted image has more than {MAX_NODES} names"
            )));
        }
        let path: Arc<str> = path.into();
        self.paths.push(path.clone());
        let id = self.paths.len() - 1;
        self.by_path.insert(path, id);
        Ok(id)
    }
}

/// An image mounted for reading, through the descriptor of its root.
pub struct MountedImage {
    root: OwnedFd,
    nodes: Mutex<Nodes>,
}

impl MountedImage {
    /// The image whose root is the directory (or mount) `root`.  The
    /// descriptor is held until the view is dropped: a mount that nothing
    /// holds is gone.
    pub fn new(root: OwnedFd) -> io::Result<Self> {
        let st = rustix::fs::fstat(&root)?;
        if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the root of a mounted image is not a directory",
            ));
        }
        let mut nodes = Nodes::default();
        nodes.intern(String::new())?;
        Ok(Self {
            root,
            nodes: Mutex::new(nodes),
        })
    }

    fn path(&self, id: usize) -> Option<Arc<str>> {
        let nodes = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
        nodes.paths.get(id).cloned()
    }

    fn open(&self, id: usize, what: Beneath) -> io::Result<OwnedFd> {
        let path = self
            .path(id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such node"))?;
        let path = if path.is_empty() { "." } else { &path };
        Ok(open_in(self.root.as_fd(), path, what)?)
    }

    /// The extended attributes of `fd` (a regular file or a directory),
    /// base64 as a table of contents has them, the overlay's own and the SELinux
    /// label (a property of the mount, not of the image) left out.
    fn xattrs(fd: &OwnedFd) -> std::collections::HashMap<String, String> {
        use base64::Engine;
        let mut out = std::collections::HashMap::new();
        // (an `O_PATH` descriptor has no `flistxattr`: its magic link names
        // the same inode)
        let path = velarx_sys::fd::proc_str(&fd);
        let mut list = vec![0u8; 4096];
        let n = loop {
            match rustix::fs::listxattr(path.as_str(), &mut list) {
                Ok(n) => break n,
                Err(rustix::io::Errno::RANGE) if list.len() < (1 << 20) => {
                    list.resize(list.len() * 4, 0)
                }
                Err(_) => return out,
            }
        };
        for name in list[..n].split(|b| *b == 0).filter(|n| !n.is_empty()) {
            let Ok(name) = std::str::from_utf8(name) else {
                continue;
            };
            if name.starts_with("trusted.overlay.")
                || name.starts_with("user.overlay.")
                || name.starts_with("security.selinux")
            {
                continue;
            }
            let mut value = vec![0u8; 256];
            let len = loop {
                match rustix::fs::getxattr(path.as_str(), name, &mut value) {
                    Ok(n) => break Some(n),
                    Err(rustix::io::Errno::RANGE) if value.len() < (1 << 20) => {
                        value.resize(value.len() * 4, 0)
                    }
                    Err(_) => break None,
                }
            };
            if let Some(len) = len {
                out.insert(
                    name.to_string(),
                    base64::engine::general_purpose::STANDARD.encode(&value[..len]),
                );
            }
        }
        out
    }
}

impl ImageTree for MountedImage {
    fn lookup(&self, dir: usize, name: &str) -> Option<usize> {
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
            return None;
        }
        let path = {
            let nodes = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
            let parent = nodes.paths.get(dir)?;
            if parent.is_empty() {
                name.to_string()
            } else {
                format!("{parent}/{name}")
            }
        };
        if let Some(id) = self
            .nodes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .by_path
            .get(path.as_str())
        {
            return Some(*id);
        }
        match open_in(self.root.as_fd(), &path, Beneath::Path) {
            Ok(_) => self
                .nodes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .intern(path)
                .ok(),
            Err(_) => None,
        }
    }

    fn children(&self, dir: usize) -> io::Result<Vec<(String, usize)>> {
        let fd = self.open(dir, Beneath::Directory)?;
        // (a name that is not UTF-8 is not one the engine can ask for)
        let mut names: Vec<String> = velarx_base::walk::names_at_most(fd.as_fd(), MAX_NODES)?
            .into_iter()
            .filter_map(|n| n.into_string().ok())
            .collect();
        names.sort();
        let parent = self.path(dir).unwrap_or_else(|| "".into());
        let mut nodes = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
        names
            .into_iter()
            .map(|n| {
                let path = if parent.is_empty() {
                    n.clone()
                } else {
                    format!("{parent}/{n}")
                };
                Ok((n, nodes.intern(path)?))
            })
            .collect()
    }

    fn node(&self, id: usize) -> Option<ViewNode> {
        let path = self.path(id)?;
        let fd = self.open(id, Beneath::Path).ok()?;
        let st = rustix::fs::fstat(&fd).ok()?;
        let kind = FileType::from_raw_mode(st.st_mode);
        let mut e = crate::dir_entry(&path);
        e.mode = st.st_mode & 0o7777;
        e.uid = st.st_uid;
        e.gid = st.st_gid;
        e.mod_time = chrono::DateTime::from_timestamp(st.st_mtime, st.st_mtime_nsec as u32)
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true));
        e.entry_type = match kind {
            FileType::Directory => TocEntryType::Dir,
            FileType::RegularFile => TocEntryType::Reg,
            FileType::Symlink => TocEntryType::Symlink,
            FileType::Fifo => TocEntryType::Fifo,
            FileType::CharacterDevice => TocEntryType::Char,
            FileType::BlockDevice => TocEntryType::Block,
            _ => return None,
        };
        match e.entry_type {
            TocEntryType::Reg => e.size = st.st_size as u64,
            TocEntryType::Symlink => {
                // (the empty name of an `O_PATH` descriptor of the link)
                let target = rustix::fs::readlinkat(&fd, "", Vec::new()).ok()?;
                e.link_name = Some(target.to_string_lossy().into_owned());
            }
            TocEntryType::Char | TocEntryType::Block => {
                e.dev_major = Some(rustix::fs::major(st.st_rdev));
                e.dev_minor = Some(rustix::fs::minor(st.st_rdev));
            }
            _ => {}
        }
        if matches!(e.entry_type, TocEntryType::Reg | TocEntryType::Dir) {
            e.xattrs = Self::xattrs(&fd);
        }
        Some(ViewNode {
            entry: e,
            layer: 0,
            nlink: if kind == FileType::Directory {
                1
            } else {
                st.st_nlink as u32
            },
            key: (st.st_dev as usize, st.st_ino),
        })
    }

    /// Not the digests of an image: the files are read as they are.
    fn has_verity(&self) -> bool {
        false
    }

    /// The file opened below the root as a regular file only: a FIFO or a
    /// device is refused without a wait.
    fn open_content(&self, node: &ViewNode) -> Option<io::Result<File>> {
        let path = {
            let nodes = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
            let id = nodes.by_path.get(node.entry.name.as_str())?;
            nodes.paths.get(*id)?.clone()
        };
        if path.is_empty() {
            return Some(Err(io::Error::from_raw_os_error(libc::EISDIR)));
        }
        Some(
            open_in(self.root.as_fd(), &path, Beneath::File)
                .map(File::from)
                .map_err(io::Error::from),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::VIEW_ROOT;
    use rustix::fs::{Mode, OFlags};
    use std::io::Read;
    use std::os::unix::fs::{symlink, PermissionsExt};

    /// A directory laid out as a hostile image: links to files of the host,
    /// a FIFO, a big file, and a file of the host outside the root.
    fn hostile() -> (tempfile::TempDir, MountedImage) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::create_dir_all(root.join("usr/share/zoneinfo")).unwrap();
        std::fs::write(tmp.path().join("host-secret"), b"host").unwrap();
        std::fs::write(root.join("etc/group"), b"root:x:0:\n").unwrap();
        std::fs::write(root.join("usr/share/zoneinfo/UTC"), b"TZif").unwrap();
        symlink("../../host-secret", root.join("etc/escape")).unwrap();
        symlink(tmp.path().join("host-secret"), root.join("etc/absolute")).unwrap();
        symlink("/proc/self/exe", root.join("etc/magic")).unwrap();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            root.join("etc/passwd"),
            Mode::from_raw_mode(0o600),
        )
        .unwrap();
        let big = std::fs::File::create(root.join("etc/huge")).unwrap();
        big.set_len(64 << 20).unwrap();
        let mut x = std::fs::File::create(root.join("etc/exec")).unwrap();
        // not executed
        std::io::Write::write_all(&mut x, b"#!").unwrap();
        std::fs::set_permissions(
            root.join("etc/exec"),
            std::fs::Permissions::from_mode(0o4755),
        )
        .unwrap();
        std::fs::hard_link(root.join("etc/group"), root.join("etc/group2")).unwrap();
        let fd = rustix::fs::open(
            &root,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        (tmp, MountedImage::new(fd).unwrap())
    }

    #[test]
    fn a_regular_file_is_read_through_the_root() {
        let (_tmp, view) = hostile();
        let n = view.resolve("etc/group").unwrap();
        let node = view.node(n).unwrap();
        assert_eq!(node.entry.entry_type, TocEntryType::Reg);
        assert_eq!(node.entry.size, 10);
        let mut text = String::new();
        view.open_content(&node)
            .unwrap()
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "root:x:0:\n");
    }

    #[test]
    fn a_link_is_a_name_never_followed_by_the_kernel() {
        let (tmp, view) = hostile();
        for link in ["etc/escape", "etc/absolute", "etc/magic"] {
            let n = view.resolve(link).unwrap();
            let node = view.node(n).unwrap();
            assert_eq!(node.entry.entry_type, TocEntryType::Symlink, "{link}");
            assert!(node.entry.link_name.is_some());
            // (a link is not content)
            assert!(view.open_content(&node).unwrap().is_err(), "{link}");
        }
        // ... and a name below a link is not found through it
        std::os::unix::fs::symlink(tmp.path(), tmp.path().join("root/out")).unwrap();
        assert!(view.lookup(VIEW_ROOT, "out").is_some());
        assert!(view.resolve("out/host-secret").is_none());
        // the links are followed as names in the image: the one to a file
        // above the root leads to the root
        assert_eq!(view.resolve_following("etc/escape"), None);
        assert_eq!(view.resolve_following("etc/absolute"), None);
    }

    #[test]
    fn a_fifo_is_a_node_and_has_no_content() {
        let (_tmp, view) = hostile();
        let n = view.resolve("etc/passwd").unwrap();
        let node = view.node(n).unwrap();
        assert_eq!(node.entry.entry_type, TocEntryType::Fifo);
        // (refused, without waiting for a writer)
        assert!(view.open_content(&node).unwrap().is_err());
    }

    #[test]
    fn the_size_of_a_big_file_is_stated_and_the_reader_bounds_it() {
        let (_tmp, view) = hostile();
        let node = view.node(view.resolve("etc/huge").unwrap()).unwrap();
        assert_eq!(node.entry.size, 64 << 20);
        let file = view.open_content(&node).unwrap().unwrap();
        let mut buf = Vec::new();
        file.take(1024).read_to_end(&mut buf).unwrap();
        assert_eq!(buf.len(), 1024);
    }

    #[test]
    fn modes_links_and_the_children_are_those_of_the_files() {
        let (_tmp, view) = hostile();
        let node = view.node(view.resolve("etc/exec").unwrap()).unwrap();
        assert_eq!(node.entry.mode, 0o4755);
        let a = view.node(view.resolve("etc/group").unwrap()).unwrap();
        let b = view.node(view.resolve("etc/group2").unwrap()).unwrap();
        assert_eq!((a.nlink, b.nlink), (2, 2));
        assert_eq!(a.key, b.key);
        let names: Vec<String> = view
            .children(view.resolve("etc").unwrap())
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        assert!(names.iter().any(|n| n == "passwd"));
        assert!(view.lookup(VIEW_ROOT, "..").is_none());
        assert!(view.lookup(VIEW_ROOT, "etc/group").is_none());
        assert!(view.lookup(VIEW_ROOT, "").is_none());
        assert!(view.resolve("nothing").is_none());
    }

    #[test]
    fn the_root_must_be_a_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("f");
        std::fs::write(&f, b"x").unwrap();
        let fd = rustix::fs::open(&f, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).unwrap();
        assert!(MountedImage::new(fd).is_err());
    }

    /// A mount below the root is not the image's: `/proc` below the root
    /// of the host is not entered.
    #[test]
    fn a_mount_below_the_root_is_not_entered() {
        let fd = rustix::fs::open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let view = MountedImage::new(fd).unwrap();
        assert!(view.resolve("proc").is_none());
        assert!(view.resolve("proc/self/status").is_none());
        let proc_fd = rustix::fs::open(
            "/proc",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        // (the same names, from the root of that mount, are found)
        assert!(MountedImage::new(proc_fd)
            .unwrap()
            .resolve("self")
            .is_some());
    }

    #[test]
    fn a_directory_through_a_link_is_not_walked() {
        let (tmp, view) = hostile();
        std::fs::create_dir_all(tmp.path().join("elsewhere/inner")).unwrap();
        std::os::unix::fs::symlink(
            tmp.path().join("elsewhere"),
            tmp.path().join("root/linkdir"),
        )
        .unwrap();
        let link = view.resolve("linkdir").unwrap();
        // (a link is not a directory to list)
        assert!(view.children(link).is_err());
        assert!(view.resolve("linkdir/inner").is_none());
        // nor one that stays in the image: the kernel follows no link, the
        // callers resolve it as a name ([`ImageTree::resolve_following`])
        std::os::unix::fs::symlink("usr/share", tmp.path().join("root/share")).unwrap();
        let inner = view.resolve("share").unwrap();
        assert!(view.children(inner).is_err());
        assert!(view.resolve("share/zoneinfo").is_none());
        assert!(view.resolve_following("share/zoneinfo/UTC").is_some());
    }
}
