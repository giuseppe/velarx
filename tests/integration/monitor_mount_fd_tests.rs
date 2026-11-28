// SPDX-License-Identifier: Apache-2.0
//! The monitor binary with a root file system that is a detached mount the
//! engine passed it (`RootfsPlan::MountFd`): the fake OCI runtime of the
//! fixture runs a command that reads the mount, and the refusals leave
//! nothing mounted.

use crate::monitor_common::*;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use velarx_fuse::plan::{MountFd, RootfsPlan};

/// A detached tmpfs (what `fsmount` makes) with the file `marker`.
fn detached_tmpfs() -> OwnedFd {
    detached_tmpfs_with(b"from the driver\n")
}

/// A detached tmpfs whose file `marker` holds `text`.
fn detached_tmpfs_with(text: &[u8]) -> OwnedFd {
    use rustix::mount::{FsMountFlags, FsOpenFlags, MountAttrFlags};
    let fs = rustix::mount::fsopen("tmpfs", FsOpenFlags::FSOPEN_CLOEXEC).unwrap();
    rustix::mount::fsconfig_create(fs.as_fd()).unwrap();
    let m = rustix::mount::fsmount(
        fs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )
    .unwrap();
    let dir = rustix::fs::openat(
        &m,
        ".",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let f = rustix::fs::openat(
        &dir,
        "marker",
        rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CREATE,
        rustix::fs::Mode::from_raw_mode(0o644),
    )
    .unwrap();
    rustix::io::write(&f, text).unwrap();
    m
}

/// A container whose root file system is the plan `plan` (the text of its
/// `rootfs.json`), mounted at `rootfs`, and whose command prints the marker
/// of the root and the descriptors it got beyond 0, 1 and 2.
fn fixture(plan: &str) -> (Fixture, std::path::PathBuf) {
    let mount_dir = tempfile::tempdir().unwrap();
    let rootfs = mount_dir.path().join("rootfs");
    // (and says which descriptors past stderr the container has: none, the
    // mounts the engine passed stay the monitor's)
    let fx = Fixture::new(&format!(
        "cat {}/marker; for n in 3 4 5 6 7 8; do [ -e /proc/$$/fd/$n ] && echo \"fd $n open\"; done; true",
        rootfs.display()
    ));
    std::fs::write(fx.bundle.join("rootfs.json"), plan).unwrap();
    let mut config = velarx_config::Config::default();
    config.storage.root = fx.dir.path().join("store");
    let image: velarx_runtime::monitor::config::ImageConfig =
        serde_json::from_value(serde_json::json!({
            "spec": fx.bundle.join("rootfs.json"),
            "overlay": fx.bundle.join("overlay"),
            "rootfs": rootfs,
            "config": serde_json::to_value(&config).unwrap(),
        }))
        .unwrap();
    let mut fx = fx;
    fx.mount_dir = Some(mount_dir);
    fx.config.image = Some(image);
    (fx, rootfs)
}

fn is_mounted(pid: u32, at: &Path) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/mountinfo"))
        .ok()?
        .lines()
        .rfind(|l| l.split(' ').nth(4) == Some(at.to_str().unwrap()))
        .map(str::to_string)
}

fn plan(index: u32) -> String {
    RootfsPlan::MountFd(MountFd {
        server: false,
        fd_index: index,
        idmap: false,
    })
    .to_vec()
    .map(|v| String::from_utf8(v).unwrap())
    .unwrap()
}

/// The container is started from the mount the engine passed: its command
/// reads the driver's file, the mount is `nodev` and private in the
/// monitor's namespace, and the descriptor the engine passed is a mount of
/// the driver's, not the one the monitor attached (which is its clone).  The
/// index counts after the descriptors of the container, and the container
/// gets none of the descriptors (the one it does not use stays the
/// monitor's).
#[test]
fn a_container_starts_from_the_mount_the_engine_passed() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let (mut fx, rootfs) = fixture(&plan(1));
        // two mounts (4, 5): the plan names the second
        fx.config.fds = fx.config.fds.with_rootfs(2);
        let other = detached_tmpfs_with(b"not this one\n");
        let mount = detached_tmpfs();
        let mut m = fx.start_monitor_with(&[other.as_fd(), mount.as_fd()]);
        assert!(m.first.ok, "{:?}", m.first.error);
        let line = is_mounted(m.child.id(), &rootfs).expect("the root is mounted");
        assert!(line.split(' ').nth(5).unwrap().contains("nodev"), "{line}");
        assert!(!line.contains(" shared:"), "{line}");
        let started = ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 });
        assert!(started.ok, "{:?}", started.error);
        let info = fx.wait_for_exit(&mut m);
        assert_eq!(info.code, 0);
        assert_eq!(fx.log_lines(), ["out F from the driver"]);
    });
}

/// What the plan names is the descriptor the engine passed and nothing else:
/// an index with no descriptor (a restart of the engine, a driver that made
/// none), a descriptor of the engine that is a directory, a file or a mount
/// point of the host are refused with the reason, and nothing stays mounted.
#[test]
fn a_plan_that_does_not_lead_to_a_detached_mount_is_refused() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let file = std::fs::File::open("/etc/hostname")
            .or_else(|_| std::fs::File::open("/proc/self/stat"))
            .unwrap();
        let dir = std::fs::File::open("/var/tmp").unwrap();
        let attached = std::fs::File::open("/proc").unwrap();
        type Case<'a> = (&'a str, u32, Option<&'a dyn AsFd>, &'a str);
        let cases: [Case; 5] = [
            ("no descriptor passed", 0, None, "create it again"),
            ("a directory", 0, Some(&dir), "not the root of a mount"),
            ("a file", 0, Some(&file), "not a directory"),
            (
                "a mount of the host",
                0,
                Some(&attached),
                "not a detached one",
            ),
            (
                "an index beyond",
                3,
                Some(&dir),
                "names the mount descriptor 3",
            ),
        ];
        for (what, index, fd, why) in cases {
            let (mut fx, rootfs) = fixture(&plan(index));
            let fds: Vec<_> = fd.map(|f| f.as_fd()).into_iter().collect();
            fx.config.fds = fx.config.fds.with_rootfs(fds.len());
            let mut m = fx.start_monitor_with(&fds);
            assert!(!m.first.ok, "{what}: started");
            let e = m.first.error.clone().unwrap();
            assert!(e.contains(why), "{what}: {e} (wanted {why:?})");
            assert!(!m.child.wait().unwrap().success(), "{what}");
            assert!(
                !rootfs.exists() || !rootfs.join("marker").exists(),
                "{what}"
            );
            // the host's mount point is where it was (this namespace is
            // the monitor's)
            assert!(is_mounted(std::process::id(), Path::new("/proc")).is_some());
        }
    });
}

/// The descriptors are counted by the engine's config, not found by number:
/// a descriptor that is open in the monitor but was not declared is not
/// reachable by an index.
#[test]
fn a_descriptor_the_engine_did_not_declare_cannot_be_named() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let (mut fx, _) = fixture(&plan(0));
        fx.config.fds = fx.config.fds.with_rootfs(0);
        let mount = detached_tmpfs();
        let mut m = fx.start_monitor_with(&[mount.as_fd()]);
        assert!(!m.first.ok);
        let e = m.first.error.clone().unwrap();
        assert!(e.contains("the engine passed 0"), "{e}");
        assert!(!m.child.wait().unwrap().success());
    });
}

/// An enforced start is refused for a mount, as for a directory.
#[test]
fn an_enforced_start_of_a_mount_is_refused() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let (mut fx, _) = fixture(&plan(0));
        fx.config.fds = fx.config.fds.with_rootfs(1);
        fx.config.image.as_mut().unwrap().enforce = true;
        let mount = detached_tmpfs();
        let mut m = fx.start_monitor_with(&[mount.as_fd()]);
        assert!(!m.first.ok);
        let e = m.first.error.clone().unwrap();
        assert!(e.contains("enforced"), "{e}");
        assert!(!m.child.wait().unwrap().success());
    });
}

/// A container that is started again (a stop and a start, a restore, an
/// engine that was restarted) is mounted from the descriptor the engine got
/// from the driver for that start: the driver made a new mount each time, and
/// the second monitor runs on the second one.  A second monitor with no
/// descriptor (the engine passed none) is refused, as the first one would be.
#[test]
fn a_container_started_again_is_mounted_from_a_fresh_descriptor() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let (mut fx, _) = fixture(&plan(0));
        fx.config.fds = fx.config.fds.with_rootfs(1);
        for text in ["first", "second", "third"] {
            // (what the driver makes at each start)
            let mount = detached_tmpfs_with(format!("{text}\n").as_bytes());
            let mut m = fx.start_monitor_with(&[mount.as_fd()]);
            assert!(m.first.ok, "{text}: {:?}", m.first.error);
            let started = ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 });
            assert!(started.ok, "{text}: {:?}", started.error);
            let info = fx.wait_for_exit(&mut m);
            assert_eq!(info.code, 0, "{text}");
            let lines = fx.log_lines();
            assert_eq!(
                lines.last().map(String::as_str),
                Some(format!("out F {text}").as_str()),
                "{lines:?}"
            );
        }
        fx.config.fds = fx.config.fds.with_rootfs(0);
        let mut m = fx.start_monitor_with(&[]);
        assert!(!m.first.ok);
        let e = m.first.error.clone().unwrap();
        assert!(e.contains("create it again"), "{e}");
        assert!(!m.child.wait().unwrap().success());
    });
}

/// What a volume of a fixture is: the plan file's text and the directory of
/// the image to mount (`subpath`).
struct Vol {
    plan: String,
    subpath: Option<&'static str>,
}

fn vol(index: u32, idmap: bool) -> Vol {
    Vol {
        plan: RootfsPlan::MountFd(MountFd {
            server: false,
            fd_index: index,
            idmap,
        })
        .to_vec()
        .map(|v| String::from_utf8(v).unwrap())
        .unwrap(),
        subpath: None,
    }
}

/// A container with the root file system `root` (the text of its plan, none
/// for one made some other way) and the image mounts `vols`: `{V0}`, `{V1}`
/// in `cmd` are their targets, which are not made before the start.
/// `mapping` is the container's id mapping, `0 100000 65536` or none.
fn volume_fixture(
    cmd: &str,
    root: Option<&str>,
    vols: &[Vol],
    mapping: bool,
) -> (Fixture, std::path::PathBuf, Vec<std::path::PathBuf>) {
    let mount_dir = tempfile::tempdir().unwrap();
    let rootfs = mount_dir.path().join("rootfs");
    let mut fx = Fixture::new("true");
    fx.mount_dir = Some(mount_dir);
    let targets: Vec<_> = (0..vols.len())
        .map(|i| fx.bundle.join(format!("imagevol/{i}")))
        .collect();
    let mut text = cmd.replace("{ROOT}", rootfs.to_str().unwrap());
    for (i, t) in targets.iter().enumerate() {
        text = text.replace(&format!("{{V{i}}}"), t.to_str().unwrap());
    }
    std::fs::write(fx.bundle.join("cmd"), text).unwrap();
    std::fs::write(fx.bundle.join("rootfs.json"), root.unwrap_or("")).unwrap();
    std::fs::create_dir_all(fx.bundle.join("imagevol")).unwrap();
    for (i, v) in vols.iter().enumerate() {
        std::fs::write(fx.bundle.join(format!("imagevol/{i}.rootfs.json")), &v.plan).unwrap();
    }
    let mut config = velarx_config::Config::default();
    config.storage.root = fx.dir.path().join("store");
    let mut image = serde_json::json!({
        "spec": fx.bundle.join("rootfs.json"),
        "overlay": fx.bundle.join("overlay"),
        "rootfs": rootfs,
        "mount_rootfs": root.is_some(),
        "config": serde_json::to_value(&config).unwrap(),
        "image_mounts": vols.iter().enumerate().map(|(i, v)| serde_json::json!({
            "spec": fx.bundle.join(format!("imagevol/{i}.rootfs.json")),
            "target": targets[i],
            "destination": format!("/data{i}"),
            "subpath": v.subpath,
        })).collect::<Vec<_>>(),
    });
    if mapping {
        let map = serde_json::json!([{"container_id": 0, "host_id": 100000, "size": 65536}]);
        image["translate"] = serde_json::json!({"uid": map, "gid": map, "squash": false});
    }
    fx.config.image = Some(serde_json::from_value(image).unwrap());
    (fx, rootfs, targets)
}

/// The mount descriptors as the monitor gets them, and the number it is told.
fn start_with(fx: &mut Fixture, mounts: &[&OwnedFd]) -> Started {
    fx.config.fds = fx.config.fds.with_rootfs(mounts.len());
    let fds: Vec<_> = mounts.iter().map(|m| m.as_fd()).collect();
    fx.start_monitor_with(&fds)
}

/// Run the container to its end and give what it printed.
fn run(fx: &Fixture, m: &mut Started) -> Vec<String> {
    let started = ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 });
    assert!(started.ok, "{:?}", started.error);
    let info = fx.wait_for_exit(m);
    assert_eq!(info.code, 0, "{:?}", fx.log_lines());
    fx.log_lines()
}

fn refused(m: &mut Started, why: &[&str]) {
    assert!(!m.first.ok, "started");
    let e = m.first.error.clone().unwrap();
    for w in why {
        assert!(e.contains(w), "{e} (wanted {w:?})");
    }
    assert!(!m.child.wait().unwrap().success());
}

/// An image mount is read only and `nodev` in the container's mount tree
/// whatever the driver's mount was, is readable, and is a mount of its own
/// (private), at a target that did not exist.  The root file system of the
/// same container stays writable.
#[test]
fn a_volume_is_attached_read_only_and_nodev_next_to_the_root() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let (mut fx, rootfs, v) = volume_fixture(
            "cat {V0}/marker; { echo x > {V0}/new; } 2>&1; echo w > {ROOT}/new && echo root-writable",
            Some(&plan(0)),
            &[vol(1, false)],
            false,
        );
        let root = detached_tmpfs_with(b"root\n");
        let volume = detached_tmpfs_with(b"volume\n");
        assert!(!v[0].exists());
        let mut m = start_with(&mut fx, &[&root, &volume]);
        assert!(m.first.ok, "{:?}", m.first.error);
        let line = is_mounted(m.child.id(), &v[0]).expect("the volume is mounted");
        let opts = line.split(' ').nth(5).unwrap();
        assert!(
            opts.split(',').any(|o| o == "ro") && opts.contains("nodev"),
            "{line}"
        );
        assert!(
            !line.contains(" shared:") && !line.contains(" master:"),
            "{line}"
        );
        let lines = run(&fx, &mut m);
        assert_eq!(lines[0], "out F volume", "{lines:?}");
        assert!(lines[1].contains("Read-only file system"), "{lines:?}");
        assert_eq!(lines.last().unwrap(), "out F root-writable", "{lines:?}");
        // (the driver's mount is writable still: it was not changed)
        rustix::fs::openat(
            &volume,
            "by-driver",
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CREATE,
            rustix::fs::Mode::from_raw_mode(0o644),
        )
        .unwrap();
        let _ = rootfs;
    });
}

/// A device node of the volume opens nothing (root makes one).
#[test]
fn a_device_node_of_a_volume_cannot_be_opened() {
    velarx_base::testing::in_child(|| {
        if !rustix::process::geteuid().is_root() || !namespace() {
            eprintln!("SKIPPED: mknod needs root");
            return;
        }
        let volume = detached_tmpfs();
        let dir = rustix::fs::openat(
            &volume,
            ".",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        rustix::fs::mknodat(
            &dir,
            "zero",
            rustix::fs::FileType::CharacterDevice,
            rustix::fs::Mode::from_raw_mode(0o666),
            rustix::fs::makedev(1, 5),
        )
        .unwrap();
        let (mut fx, _, _) = volume_fixture(
            "{ head -c1 {V0}/zero >/dev/null; } 2>&1; echo done",
            Some(&plan(0)),
            &[vol(1, false)],
            false,
        );
        let root = detached_tmpfs();
        let mut m = start_with(&mut fx, &[&root, &volume]);
        assert!(m.first.ok, "{:?}", m.first.error);
        let lines = run(&fx, &mut m);
        assert!(lines[0].contains("Permission denied"), "{lines:?}");
    });
}

/// Two image mounts and the root, each from its own descriptor.
#[test]
fn two_volumes_and_the_root_each_get_their_descriptor() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let (mut fx, _, _) = volume_fixture(
            "cat {ROOT}/marker {V0}/marker {V1}/marker",
            Some(&plan(0)),
            &[vol(1, false), vol(2, false)],
            false,
        );
        let (r, a, b) = (
            detached_tmpfs_with(b"root\n"),
            detached_tmpfs_with(b"one\n"),
            detached_tmpfs_with(b"two\n"),
        );
        let mut m = start_with(&mut fx, &[&r, &a, &b]);
        assert!(m.first.ok, "{:?}", m.first.error);
        assert_eq!(run(&fx, &mut m), ["out F root", "out F one", "out F two"]);
    });
}

/// The container gets none of the descriptors of the image mounts (they
/// stay the monitor's, closed after the clone).
#[test]
fn the_descriptors_of_the_volumes_do_not_reach_the_container() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let (mut fx, _, _) = volume_fixture(
            "cat {V0}/marker; for n in 3 4 5 6 7 8; do [ -e /proc/$$/fd/$n ] && echo \"fd $n open\"; done; true",
            Some(&plan(0)),
            &[vol(1, false), vol(2, false)],
            false,
        );
        let (r, a, b) = (
            detached_tmpfs(),
            detached_tmpfs_with(b"one\n"),
            detached_tmpfs(),
        );
        let mut m = start_with(&mut fx, &[&r, &a, &b]);
        assert!(m.first.ok, "{:?}", m.first.error);
        assert_eq!(run(&fx, &mut m), ["out F one"]);
    });
}

/// An image mount refused after the root and other image mounts were
/// attached (and one with its whole mount at the staging place of a
/// `subpath`) leaves nothing of them mounted.
#[test]
fn a_later_volume_refused_leaves_nothing_mounted() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let with_sub = {
            let m = detached_tmpfs();
            let d = rustix::fs::openat(
                &m,
                ".",
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            rustix::fs::mkdirat(&d, "sub", rustix::fs::Mode::from_raw_mode(0o755)).unwrap();
            m
        };
        let mut sub = vol(2, false);
        sub.subpath = Some("sub");
        let (mut fx, rootfs, v) = volume_fixture(
            "true",
            Some(&plan(0)),
            &[vol(1, false), sub, vol(3, false)],
            false,
        );
        let attached = std::fs::File::open("/proc").unwrap();
        let attached = attached.as_fd().try_clone_to_owned().unwrap();
        let (r, a) = (detached_tmpfs(), detached_tmpfs());
        let mut m = start_with(&mut fx, &[&r, &a, &with_sub, &attached]);
        refused(&mut m, &["image mount /data2", "not a detached one"]);
        let me = std::process::id();
        for at in [&rootfs, &v[0], &v[1], &v[2], &fx.run_dir.join("mfd1")] {
            assert!(
                is_mounted(me, at).is_none(),
                "{} still mounted",
                at.display()
            );
        }
    });
}

/// The root file system and 15 image mounts: all 16 descriptors.
#[test]
fn fifteen_volumes_and_the_root_are_the_most() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let vols: Vec<_> = (1..=15).map(|i| vol(i, false)).collect();
        let cmd: String = (0..15).map(|i| format!("cat {{V{i}}}/marker; ")).collect();
        let (mut fx, _, _) = volume_fixture(&cmd, Some(&plan(0)), &vols, false);
        let root = detached_tmpfs();
        let texts: Vec<_> = (0..15)
            .map(|i| detached_tmpfs_with(format!("v{i}\n").as_bytes()))
            .collect();
        let mut all: Vec<&OwnedFd> = vec![&root];
        all.extend(texts.iter());
        let mut m = start_with(&mut fx, &all);
        assert!(m.first.ok, "{:?}", m.first.error);
        let want: Vec<_> = (0..15).map(|i| format!("out F v{i}")).collect();
        assert_eq!(run(&fx, &mut m), want);
    });
}

/// A sixteenth image mount is refused by the monitor, before it mounts
/// anything (the config says 16 descriptors, which is all it takes).
#[test]
fn sixteen_volumes_are_refused() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let vols: Vec<_> = (0..16).map(|i| vol(i, false)).collect();
        let (mut fx, _, v) = volume_fixture("true", None, &vols, false);
        let fds: Vec<_> = (0..16).map(|_| detached_tmpfs()).collect();
        let all: Vec<&OwnedFd> = fds.iter().collect();
        let mut m = start_with(&mut fx, &all);
        refused(&mut m, &["16 image mounts", "at most 15"]);
        assert!(!v[0].exists());
    });
}

/// A volume that does not lead to a detached mount is refused with the reason
/// and its image mount's name, and nothing stays mounted or made: a
/// directory, a file, a mount of the namespace, an index the engine did not
/// pass, an index beyond 15, the root's own index.
#[test]
fn a_volume_that_is_not_a_detached_mount_is_refused() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let file = std::fs::File::open("/proc/self/stat").unwrap();
        let dir = std::fs::File::open("/var/tmp").unwrap();
        let attached = std::fs::File::open("/proc").unwrap();
        let root = detached_tmpfs();
        type Case<'a> = (&'a str, u32, Option<&'a dyn AsFd>, &'a [&'a str]);
        let cases: [Case; 7] = [
            (
                "a directory",
                1,
                Some(&dir),
                &["image mount /data0", "not the root of a mount"],
            ),
            (
                "a file",
                1,
                Some(&file),
                &["image mount /data0", "not a directory"],
            ),
            (
                "an attached mount",
                1,
                Some(&attached),
                &["image mount /data0", "not a detached one"],
            ),
            (
                "no descriptor",
                1,
                None,
                &[
                    "image mount /data0",
                    "names the mount descriptor 1",
                    "the engine passed 1",
                ],
            ),
            (
                "a place not passed",
                7,
                Some(&dir),
                &["image mount /data0", "names the mount descriptor 7"],
            ),
            (
                "a place beyond 31",
                32,
                Some(&dir),
                &["imagevol/0.rootfs.json", "fd_index 32"],
            ),
            (
                "the root's place",
                0,
                Some(&dir),
                &[
                    "image mount /data0",
                    "names the mount descriptor 0",
                    "the root file system names too",
                ],
            ),
        ];
        for (what, index, fd, why) in cases {
            let (mut fx, rootfs, v) =
                volume_fixture("true", Some(&plan(0)), &[vol(index, false)], false);
            let mut fds: Vec<&OwnedFd> = vec![&root];
            let owned = fd.map(|f| f.as_fd().try_clone_to_owned().unwrap());
            fds.extend(owned.iter());
            let mut m = start_with(&mut fx, &fds);
            refused(&mut m, why);
            assert!(!v[0].exists(), "{what}: the target was made");
            assert!(
                is_mounted(std::process::id(), &v[0]).is_none() && !rootfs.join("marker").exists(),
                "{what}"
            );
        }
    });
}

/// Which plans may go together: an image mount that is a descriptor goes
/// with a root of any kind (or none); an image mount of any other plan (a
/// directory, or the plan of a kind the monitor does not have, a `composefs`
/// one of an engine before the driver handed the mounts over) is refused,
/// whatever the root.
#[test]
fn only_a_descriptor_volume_goes_with_a_root_of_another_kind() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let beneath = tempfile::tempdir().unwrap();
        std::fs::create_dir(beneath.path().join("r")).unwrap();
        std::fs::write(beneath.path().join("r/marker"), "dir\n").unwrap();
        let directory = format!(
            r#"{{"kind":"directory","beneath":"{}","path":"r"}}"#,
            beneath.path().display()
        );
        // legal: a descriptor volume with a directory root and with no root
        for (what, root, first) in [
            ("a directory root", Some(directory.as_str()), 0u32),
            ("no root", None, 0),
        ] {
            let (mut fx, _, _) =
                volume_fixture("cat {V0}/marker", root, &[vol(first, false)], false);
            let v = detached_tmpfs_with(b"vol\n");
            let mut m = start_with(&mut fx, &[&v]);
            assert!(m.first.ok, "{what}: {:?}", m.first.error);
            assert_eq!(run(&fx, &mut m), ["out F vol"], "{what}");
        }
        // refused: a directory plan for an image mount, next to a mount-fd root
        // and next to a directory one, and the plan of a kind the monitor
        // does not have
        let dirvol = Vol {
            plan: directory.clone(),
            subpath: None,
        };
        let cfsvol = || Vol {
            plan: r#"{"kind":"composefs","layers":[],"image_id":"a"}"#.to_string(),
            subpath: None,
        };
        {
            let (mut fx, _, t) = volume_fixture("true", Some(&plan(0)), &[dirvol], false);
            let root = detached_tmpfs();
            let mut m = start_with(&mut fx, &[&root]);
            refused(&mut m, &["image mount /data0", "type=image"]);
            assert!(!t[0].exists(), "a directory image mount");
        }
        {
            let dirvol = Vol {
                plan: directory.clone(),
                subpath: None,
            };
            let (mut fx, _, _) = volume_fixture("true", Some(&directory), &[dirvol], false);
            let mut m = start_with(&mut fx, &[]);
            refused(&mut m, &["image mount /data0", "type=image"]);
        }
        for root in [Some(plan(0)), None] {
            let (mut fx, _, _) = volume_fixture("true", root.as_deref(), &[cfsvol()], false);
            let fd = detached_tmpfs();
            let mut m = start_with(&mut fx, &[&fd]);
            refused(&mut m, &["imagevol/0.rootfs.json", "composefs"]);
        }
    });
}

/// With `idmap` the owners of the files show as the host ids of the
/// container's mapping (1000 as 101000), and as they are without it; the
/// root is mapped the same way when its plan says so.  As root, on a tmpfs
/// and on the file system of `/var/tmp`.
#[test]
fn the_idmap_of_a_volume_maps_the_owners() {
    velarx_base::testing::in_child(|| {
        if !rustix::process::geteuid().is_root() || !namespace() {
            eprintln!("SKIPPED: idmapped mounts need root");
            return;
        }
        let store = tempfile::tempdir_in("/var/tmp").unwrap();
        let on_disk = |text: &[u8]| {
            let d = store.path().join(format!("{}", text.len()));
            std::fs::create_dir(&d).unwrap();
            std::fs::write(d.join("marker"), text).unwrap();
            std::os::unix::fs::chown(d.join("marker"), Some(1000), Some(1000)).unwrap();
            let clone = rustix::mount::open_tree(
                rustix::fs::CWD,
                &d,
                rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
                    | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC,
            )
            .unwrap();
            // (whether this file system takes idmapped mounts at all)
            let probe = rustix::mount::open_tree(
                rustix::fs::CWD,
                &d,
                rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
                    | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC,
            )
            .unwrap();
            let map = [(0, 100_000, 65_536)];
            let userns = velarx_runtime::userns::create_userns_for_idmap(&map, &map).unwrap();
            velarx_runtime::userns::idmap_mount(probe.as_fd(), userns.as_fd())
                .is_ok()
                .then_some(clone)
        };
        let tmpfs = {
            let m = detached_tmpfs();
            let d = rustix::fs::openat(
                &m,
                ".",
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            rustix::fs::chownat(
                &d,
                "marker",
                Some(rustix::fs::Uid::from_raw(1000)),
                Some(rustix::fs::Gid::from_raw(1000)),
                rustix::fs::AtFlags::empty(),
            )
            .unwrap();
            Some(m)
        };
        for (what, fd) in [
            ("tmpfs", tmpfs),
            ("the file system of /var/tmp", on_disk(b"xfs")),
        ] {
            let Some(fd) = fd else {
                eprintln!("SKIPPED: {what} takes no idmapped mounts");
                continue;
            };
            let (mut fx, _, _) = volume_fixture(
                "stat -c %u:%g {V0}/marker",
                Some(&plan(0)),
                &[vol(1, true)],
                true,
            );
            let root = detached_tmpfs();
            let mut m = start_with(&mut fx, &[&root, &fd]);
            assert!(m.first.ok, "{what}: {:?}", m.first.error);
            assert_eq!(run(&fx, &mut m), ["out F 101000:101000"], "{what}");
        }
        // without `idmap` the ids are the driver's
        let (mut fx, _, _) = volume_fixture(
            "stat -c %u:%g {V0}/marker",
            Some(&plan(0)),
            &[vol(1, false)],
            true,
        );
        let (root, fd) = (detached_tmpfs(), detached_tmpfs());
        rustix::fs::chownat(
            &fd,
            "marker",
            Some(rustix::fs::Uid::from_raw(1000)),
            Some(rustix::fs::Gid::from_raw(1000)),
            rustix::fs::AtFlags::empty(),
        )
        .unwrap();
        let mut m = start_with(&mut fx, &[&root, &fd]);
        assert!(m.first.ok);
        assert_eq!(run(&fx, &mut m), ["out F 1000:1000"]);
    });
}

/// The root's own plan can say `idmap` too: the same mapping on its mount.
#[test]
fn the_idmap_of_the_root_maps_the_owners() {
    velarx_base::testing::in_child(|| {
        if !rustix::process::geteuid().is_root() || !namespace() {
            eprintln!("SKIPPED: idmapped mounts need root");
            return;
        }
        let root_plan = RootfsPlan::MountFd(MountFd {
            server: false,
            fd_index: 0,
            idmap: true,
        })
        .to_vec()
        .map(|v| String::from_utf8(v).unwrap())
        .unwrap();
        let (mut fx, _, _) =
            volume_fixture("stat -c %u:%g {ROOT}/marker", Some(&root_plan), &[], true);
        let root = detached_tmpfs();
        let d = rustix::fs::openat(
            &root,
            ".",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        rustix::fs::chownat(
            &d,
            "marker",
            Some(rustix::fs::Uid::from_raw(5)),
            Some(rustix::fs::Gid::from_raw(5)),
            rustix::fs::AtFlags::empty(),
        )
        .unwrap();
        let mut m = start_with(&mut fx, &[&root]);
        assert!(m.first.ok, "{:?}", m.first.error);
        assert_eq!(run(&fx, &mut m), ["out F 100005:100005"]);
    });
}

/// An idmap that the kernel refuses fails the start, with the file system
/// and the remedy: a mount that is idmapped already, and (rootless) a
/// monitor that is not root.  And an idmap of a container with no mapping.
#[test]
fn an_idmap_that_cannot_be_made_fails_the_start_with_the_reason() {
    velarx_base::testing::in_child(|| {
        let root = rustix::process::geteuid().is_root();
        if !namespace() {
            return;
        }
        let (mut fx, _, v) = volume_fixture("true", Some(&plan(0)), &[vol(1, true)], true);
        let (r, volume) = (detached_tmpfs(), detached_tmpfs());
        if root {
            let map = [(0, 100_000, 65_536)];
            let userns = velarx_runtime::userns::create_userns_for_idmap(&map, &map).unwrap();
            if velarx_runtime::userns::idmap_mount(volume.as_fd(), userns.as_fd()).is_ok() {
                let mut m = start_with(&mut fx, &[&r, &volume]);
                refused(
                    &mut m,
                    &[
                        "image mount /data0",
                        "tmpfs",
                        "idmapped already",
                        "storage driver must deliver",
                    ],
                );
            } else {
                eprintln!("SKIPPED: tmpfs takes no idmapped mounts here");
            }
        } else {
            let mut m = start_with(&mut fx, &[&r, &volume]);
            refused(
                &mut m,
                &["image mount /data0", "tmpfs", "rootless", "`applied`"],
            );
        }
        assert!(!v[0].exists());
        // no mapping in the container: nothing to put (root or not)
        if root {
            let (mut fx, _, _) = volume_fixture("true", Some(&plan(0)), &[vol(1, true)], false);
            let (r, volume) = (detached_tmpfs(), detached_tmpfs());
            let mut m = start_with(&mut fx, &[&r, &volume]);
            refused(&mut m, &["no id mapping"]);
        }
    });
}

/// The directory `subpath` of the image is what is mounted (read only), and
/// a way out of the mount is not followed.
#[test]
fn a_volume_subpath_is_looked_up_in_the_mount() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let mk = || {
            let m = detached_tmpfs();
            let d = rustix::fs::openat(
                &m,
                ".",
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            rustix::fs::mkdirat(&d, "sub", rustix::fs::Mode::from_raw_mode(0o755)).unwrap();
            let f = rustix::fs::openat(
                &d,
                "sub/inner",
                rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CREATE,
                rustix::fs::Mode::from_raw_mode(0o644),
            )
            .unwrap();
            rustix::io::write(&f, b"inside\n").unwrap();
            rustix::fs::symlinkat("/etc", &d, "out").unwrap();
            m
        };
        let mut v = vol(1, false);
        v.subpath = Some("sub");
        let (mut fx, _, _) = volume_fixture(
            "cat {V0}/inner; { echo x > {V0}/new; } 2>&1; true",
            Some(&plan(0)),
            &[v],
            false,
        );
        let (root, volume) = (detached_tmpfs(), mk());
        let mut m = start_with(&mut fx, &[&root, &volume]);
        assert!(m.first.ok, "{:?}", m.first.error);
        let lines = run(&fx, &mut m);
        assert_eq!(lines[0], "out F inside");
        assert!(lines[1].contains("Read-only file system"), "{lines:?}");
        for bad in ["out", "missing", "../x"] {
            let mut v = vol(1, false);
            v.subpath = Some(bad);
            let (mut fx, _, t) = volume_fixture("true", Some(&plan(0)), &[v], false);
            let (root, volume) = (detached_tmpfs(), mk());
            let mut m = start_with(&mut fx, &[&root, &volume]);
            refused(&mut m, &["image mount /data0"]);
            assert!(
                !t[0].exists() || is_mounted(std::process::id(), &t[0]).is_none(),
                "{bad}"
            );
        }
    });
}

/// A volume's plan states no digest, so an enforced start is refused for it
/// as for a root.
#[test]
fn an_enforced_start_is_refused_for_a_descriptor_volume() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let (mut fx, _, _) = volume_fixture("true", Some(&plan(0)), &[vol(1, false)], false);
        fx.config.image.as_mut().unwrap().enforce = true;
        let (root, volume) = (detached_tmpfs(), detached_tmpfs());
        let mut m = start_with(&mut fx, &[&root, &volume]);
        // (the root's plan is read first and says it)
        refused(&mut m, &["enforced"]);
    });
}

/// A start as the engine makes it, through the monitor: the test driver with
/// image volumes (`VolumeFake` over composefs, its descriptors detached mounts) is
/// asked once by `start_mounts`, which checks the answer and writes the plan
/// files, and the monitor started with the descriptors it gave runs a
/// container that reads the root and both volumes, and has none of the
/// descriptors.  The root is a descriptor too, or there is none (a
/// `--rootfs`: the volumes are numbered from 0).  As root and as a user.
#[test]
fn a_container_starts_from_what_the_engine_asked_of_the_driver() {
    use std::sync::Arc;
    use velarx_core::storage_driver::conformance::VolumeFake;
    use velarx_core::storage_driver::{
        ComposefsDriver, ComposefsOptions, IdmapWay, ImageServer, MountRequest, Prefs, Purpose,
        StorageDriver, VerityAsk, Writable, WritableOptions,
    };
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let write = |dir: &dyn AsFd, text: &[u8]| {
            let f = rustix::fs::openat(
                dir,
                "marker",
                rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CREATE,
                rustix::fs::Mode::from_raw_mode(0o644),
            )
            .unwrap();
            rustix::io::write(&f, text).unwrap();
        };
        let image = velarx_db::ImageRecord {
            id: "img".into(),
            manifest_digest: velarx_types::digest::Digest::of(
                velarx_types::digest::Algorithm::Sha256,
                b"manifest",
            ),
            config_digest: velarx_types::digest::Digest::of(
                velarx_types::digest::Algorithm::Sha256,
                b"config",
            ),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: String::new(),
            is_lazy: false,
        };
        fn mount_ask<'a>(
            image: &'a velarx_db::ImageRecord,
            w: &'a Writable,
            purpose: Purpose,
        ) -> MountRequest<'a> {
            MountRequest {
                container: w,
                purpose,
                image,
                layers: &[],
                mapping: None,
                translate: None,
                idmap_mount: false,
                label: None,
                verity: VerityAsk::Off,
                volatile: false,
            }
        }
        for root_fd in [true, false] {
            let cmd = "cat {ROOT}/marker {V0}/marker {V1}/marker; for n in 3 4 5 6 7 8; do [ -e /proc/$$/fd/$n ] && echo \"fd $n open\"; done; true";
            let cmd = if root_fd {
                cmd.to_string()
            } else {
                cmd.replace("{ROOT}/marker ", "")
            };
            let (mut fx, _, _) = volume_fixture(
                &cmd,
                root_fd.then(|| plan(0)).as_deref(),
                &[vol(0, false), vol(0, false)],
                false,
            );
            let store = fx.dir.path().join("driver");
            let db = rt
                .block_on(velarx_db::Database::open(store.join("db")))
                .unwrap();
            let inner = ComposefsDriver::new(
                db,
                Arc::new(velarx_storage::FileStore::new(store.join("objects")).unwrap()),
                store.join("staging"),
                velarx_storage::VerityMode::Off,
                ComposefsOptions::new(ImageServer::new(
                    crate::common::built_binary("velarx-monitor")
                        .expect("no velarx-monitor next to the tests: cargo build --bins"),
                    store.join("run"),
                    Arc::new(velarx_config::Config::default()),
                )),
            );
            let driver: Arc<dyn StorageDriver> = Arc::new(
                VolumeFake::new(Arc::new(inner), Prefs::new(&[IdmapWay::AtCopy]), root_fd)
                    .detached(),
            );
            let w = Writable::new("c1", &fx.bundle);
            // create: the root, and the two volumes with what they show
            if root_fd {
                driver
                    .writable_create(&w, None, &WritableOptions::default(), None)
                    .unwrap();
                write(&driver.writable_root(&w).unwrap(), b"root\n");
            }
            for n in 0..2 {
                driver
                    .image_volume_create(&mount_ask(&image, &w, Purpose::Volume { index: n }))
                    .unwrap();
                let dir = rustix::fs::open(
                    VolumeFake::volume_dir(&w, n),
                    rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
                    rustix::fs::Mode::empty(),
                )
                .unwrap();
                write(&dir, format!("volume {n}\n").as_bytes());
            }
            // the start: one call, the plans written, the descriptors passed
            let fds = velarx_core::services::start_mounts(
                &*driver,
                &fx.bundle,
                &w,
                root_fd.then(|| (mount_ask(&image, &w, Purpose::Root), true)),
                (0..2)
                    .map(|n| mount_ask(&image, &w, Purpose::Volume { index: n }))
                    .collect(),
            )
            .unwrap()
            .fds;
            assert_eq!(fds.len(), if root_fd { 3 } else { 2 });
            let first = u32::from(root_fd);
            for n in 0..2u32 {
                let p =
                    velarx_fuse::plan::read(&fx.bundle.join("imagevol"), &format!("{n}.")).unwrap();
                assert_eq!(
                    p,
                    Some(RootfsPlan::MountFd(MountFd {
                        server: false,
                        fd_index: first + n,
                        idmap: false
                    })),
                    "root_fd {root_fd}"
                );
            }
            let passed: Vec<&OwnedFd> = fds.iter().map(|f| &**f).collect();
            let mut m = start_with(&mut fx, &passed);
            assert!(m.first.ok, "root_fd {root_fd}: {:?}", m.first.error);
            let mut want = vec!["out F volume 0", "out F volume 1"];
            if root_fd {
                want.insert(0, "out F root");
            }
            assert_eq!(run(&fx, &mut m), want, "root_fd {root_fd}");
        }
    });
}

fn served_plan(index: u32) -> String {
    RootfsPlan::MountFd(MountFd {
        fd_index: index,
        idmap: false,
        server: true,
    })
    .to_vec()
    .map(|b| String::from_utf8(b).unwrap())
    .unwrap()
}

/// A process that serves the mount, as the engine passes it: its pidfd
/// follows the mount's descriptor.  The monitor takes it (it names the
/// process in its log, and the cgroup it put it in), runs the container on
/// the mount, and says when the server ends.
#[test]
fn the_server_of_a_mount_is_taken_with_it() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let (mut fx, rootfs) = fixture(&served_plan(0));
        fx.config.fds = fx.config.fds.with_rootfs(2);
        let mut server = std::process::Command::new("sleep")
            .arg("600")
            .spawn()
            .unwrap();
        let pidfd = velarx_sys::pidfd::open(server.id() as i32).unwrap();
        let mount = detached_tmpfs();
        let mut m = fx.start_monitor_with(&[mount.as_fd(), pidfd.as_fd()]);
        assert!(m.first.ok, "{:?}", m.first.error);
        assert!(is_mounted(m.child.id(), &rootfs).is_some());
        let started = ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 });
        assert!(started.ok, "{:?}", started.error);
        let info = fx.wait_for_exit(&mut m);
        assert_eq!(info.code, 0);
        let log = std::fs::read_to_string(fx.run_dir.join("monitor.log")).unwrap();
        let line = format!("image server of the root file system: pid {}", server.id());
        assert!(log.contains(&line), "{log}");
        server.kill().unwrap();
        let _ = server.wait();
    });
}

/// What follows the mount must be a pidfd of a process that has not ended: a
/// descriptor of anything else, or a server that is gone, is refused with the
/// reason and nothing stays mounted; so is a mount whose digests the server
/// checks, passed with none.
#[test]
fn a_server_that_is_not_one_is_refused() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let (mut fx, rootfs) = fixture(&served_plan(0));
        fx.config.fds = fx.config.fds.with_rootfs(2);
        let (mount, other) = (detached_tmpfs(), detached_tmpfs());
        let mut m = fx.start_monitor_with(&[mount.as_fd(), other.as_fd()]);
        assert!(!m.first.ok);
        let e = m.first.error.clone().unwrap();
        assert!(e.contains("not a pidfd"), "{e}");
        assert!(!m.child.wait().unwrap().success());
        assert!(is_mounted(m.child.id(), &rootfs).is_none());
        let (mut fx, _) = fixture(&served_plan(0));
        fx.config.fds = fx.config.fds.with_rootfs(2);
        let mut gone = std::process::Command::new("true").spawn().unwrap();
        let pidfd = velarx_sys::pidfd::open(gone.id() as i32).unwrap();
        gone.wait().unwrap();
        let mount = detached_tmpfs();
        let mut m = fx.start_monitor_with(&[mount.as_fd(), pidfd.as_fd()]);
        assert!(!m.first.ok);
        let e = m.first.error.clone().unwrap();
        assert!(e.contains("ended before the container started"), "{e}");
        assert!(!m.child.wait().unwrap().success());
        let (mut fx, _) = fixture(&served_plan(0));
        fx.config.fds = fx.config.fds.with_rootfs(1);
        let mount = detached_tmpfs();
        let mut m = fx.start_monitor_with(&[mount.as_fd()]);
        assert!(!m.first.ok);
        assert!(!m.child.wait().unwrap().success());
        let (mut fx, _) = fixture(&plan(0));
        fx.config.fds = fx.config.fds.with_rootfs(1);
        fx.config.image.as_mut().unwrap().enforce = true;
        fx.config.image.as_mut().unwrap().verity = velarx_fuse::plan::VerityDone::OnOpen;
        let mount = detached_tmpfs();
        let mut m = fx.start_monitor_with(&[mount.as_fd()]);
        assert!(!m.first.ok);
        let e = m.first.error.clone().unwrap();
        assert!(e.contains("process that serves the mount"), "{e}");
        assert!(!m.child.wait().unwrap().success());
    });
}
