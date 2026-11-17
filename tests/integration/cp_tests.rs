// SPDX-License-Identifier: Apache-2.0
//! Copies between a container root and the host (`velarx_wire::cp`) against
//! roots that try to lead the copy out: links to host files, `..`, and a
//! root that changes while it is copied.

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{openat, Mode, OFlags};
use std::io::Read;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use velarx_wire::cp::{self, ExtractOptions, TreeWriter};

fn dir_fd(p: &Path) -> OwnedFd {
    openat(
        rustix::fs::CWD,
        p,
        OFlags::PATH | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .unwrap()
}

/// The tar of `path` resolved in `root`, as the archive endpoint writes it.
fn archive_in(root: &Path, path: &str) -> std::io::Result<Vec<u8>> {
    let root = dir_fd(root);
    let node = cp::open_in_root(root.as_fd(), path, OFlags::PATH, true)?;
    let mut b = tar::Builder::new(Vec::new());
    let name = cp::split_path(&cp::clean_path(path)).1;
    TreeWriter {
        builder: &mut b,
        ids: None,
    }
    .add_tree(node, Path::new(&name), false)?;
    b.into_inner()
}

/// Every file content of a tar.
fn contents(tar: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for e in tar::Archive::new(tar).entries().unwrap() {
        let mut e = e.unwrap();
        let mut s = String::new();
        if e.read_to_string(&mut s).is_ok() {
            out.push(s);
        }
    }
    out
}

#[test]
fn a_link_to_a_host_file_is_resolved_in_the_root() {
    let host = tempfile::tempdir().unwrap();
    std::fs::write(host.path().join("secret"), "host secret").unwrap();
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("etc")).unwrap();
    std::fs::write(root.path().join("etc/shadow"), "container shadow").unwrap();
    symlink("/etc/shadow", root.path().join("abs")).unwrap();
    symlink("../../../../../../etc/shadow", root.path().join("rel")).unwrap();
    symlink(host.path().join("secret"), root.path().join("out")).unwrap();
    for p in ["/abs", "/rel"] {
        assert_eq!(
            contents(&archive_in(root.path(), p).unwrap()),
            ["container shadow"]
        );
    }
    assert!(archive_in(root.path(), "/out").is_err());
    assert!(archive_in(root.path(), "/../../secret").is_err());
    // below the top, links are archived as links
    std::fs::create_dir(root.path().join("d")).unwrap();
    symlink(host.path().join("secret"), root.path().join("d/l")).unwrap();
    let t = archive_in(root.path(), "/d").unwrap();
    assert!(!contents(&t).iter().any(|c| c.contains("host secret")));
}

#[test]
fn copy_in_does_not_write_through_links() {
    let host = tempfile::tempdir().unwrap();
    std::fs::write(host.path().join("victim"), "keep").unwrap();
    let root = tempfile::tempdir().unwrap();
    symlink(host.path(), root.path().join("hostdir")).unwrap();
    symlink(host.path().join("victim"), root.path().join("f")).unwrap();
    let rootfd = dir_fd(root.path());

    // a destination through a link to the host is resolved in the root
    assert!(cp::open_in_root(
        rootfd.as_fd(),
        "/hostdir",
        OFlags::PATH | OFlags::DIRECTORY,
        true
    )
    .is_err());

    let mut b = tar::Builder::new(Vec::new());
    for (name, data) in [("f", &b"new"[..]), ("hostdir/victim", b"pwned")] {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        b.append_data(&mut h, name, data).unwrap();
    }
    let t = b.into_inner().unwrap();
    let dest =
        cp::open_in_root(rootfd.as_fd(), "/", OFlags::PATH | OFlags::DIRECTORY, true).unwrap();
    assert!(cp::extract(&t[..], dest.as_fd(), &ExtractOptions::default()).is_err());
    assert_eq!(std::fs::read(host.path().join("victim")).unwrap(), b"keep");
    assert_eq!(std::fs::read(root.path().join("f")).unwrap(), b"new");
}

/// A directory of the root swapped with a link to the host while files are
/// extracted below it: nothing lands on the host.
#[test]
fn extraction_races_with_a_swapped_directory() {
    let host = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let (d, moved) = (root.path().join("d"), root.path().join("d.real"));
    std::fs::create_dir(&d).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let swapper = {
        let (stop, d, moved, host) = (
            stop.clone(),
            d.clone(),
            moved.clone(),
            host.path().to_path_buf(),
        );
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if std::fs::rename(&d, &moved).is_ok() {
                    let _ = symlink(&host, &d);
                    let _ = std::fs::remove_file(&d);
                    let _ = std::fs::rename(&moved, &d);
                }
            }
        })
    };
    let mut b = tar::Builder::new(Vec::new());
    for i in 0..200 {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(1);
        h.set_mode(0o644);
        b.append_data(&mut h, format!("d/f{i}"), &b"x"[..]).unwrap();
    }
    let t = b.into_inner().unwrap();
    let base = dir_fd(root.path());
    for _ in 0..20 {
        let _ = cp::extract(&t[..], base.as_fd(), &ExtractOptions::default());
    }
    stop.store(true, Ordering::Relaxed);
    swapper.join().unwrap();
    assert_eq!(std::fs::read_dir(host.path()).unwrap().count(), 0);
}

/// A file of the root swapped with a link to a host file while the root is
/// archived: the host file is never read.
#[test]
fn archiving_races_with_a_swapped_file() {
    let host = tempfile::tempdir().unwrap();
    std::fs::write(host.path().join("secret"), "host secret").unwrap();
    let root = tempfile::tempdir().unwrap();
    let d = root.path().join("d");
    std::fs::create_dir(&d).unwrap();
    std::fs::write(d.join("f"), "fine").unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let swapper = {
        let (stop, d, secret) = (stop.clone(), d.clone(), host.path().join("secret"));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = std::fs::remove_file(d.join("f"));
                let _ = symlink(&secret, d.join("f"));
                let _ = std::fs::remove_file(d.join("f"));
                let _ = std::fs::write(d.join("f"), "fine");
            }
        })
    };
    for _ in 0..500 {
        if let Ok(t) = archive_in(root.path(), "/d") {
            assert!(!contents(&t).iter().any(|c| c.contains("host secret")));
        }
    }
    stop.store(true, Ordering::Relaxed);
    swapper.join().unwrap();
}
