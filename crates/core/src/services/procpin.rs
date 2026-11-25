// SPDX-License-Identifier: Apache-2.0
//! A process of a container pinned while the engine uses it: a pidfd
//! keeps its pid from naming another process, and its root tells that it is
//! the container's.

use crate::storage_driver::{StorageDriver, Writable};
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

/// What the root of a container's process is, by how its root file system
/// was made.
#[derive(Clone, Copy)]
pub enum ContainerRoot<'a> {
    /// The root file system the driver made of the writable layer of the
    /// container (an image, or `--rootfs` with the overlay option): the root
    /// the monitor of `mon_dir` attached when it recorded one (a descriptor
    /// or a directory of the driver, which may be a new mount at every
    /// start), else the driver tells whether a process has it as its root
    /// (an overlay tells the mount of the root).
    Writable(&'a dyn StorageDriver, &'a Writable, &'a Path),
    /// A bind of this directory (`--rootfs`): the root of the process is
    /// that directory.
    Bind(&'a Path),
}

impl<'a> ContainerRoot<'a> {
    /// The root of a container made with `rootfs` (`--rootfs`), else the
    /// root file system the driver made of its writable layer `w`.
    pub fn of(
        rootfs: Option<&'a crate::container::RootfsDir>,
        driver: &'a dyn StorageDriver,
        w: &'a Writable,
        mon_dir: &'a Path,
    ) -> Self {
        match rootfs.filter(|r| !r.overlay) {
            Some(r) => Self::Bind(&r.path),
            None => Self::Writable(driver, w, mon_dir),
        }
    }
}

/// Whether the process whose root is `root` (`/proc/PID/root`) has the
/// directory `dir` as its root: a bind mount shares the inode of its source.
fn root_is_bind_of(root: &Path, dir: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let (r, d) = (std::fs::metadata(root)?, std::fs::metadata(dir)?);
    Ok((r.dev(), r.ino()) == (d.dev(), d.ino()))
}

/// Whether the process of the pidfd still runs: a pidfd is readable once
/// the process ended.
pub fn pidfd_alive(pidfd: &OwnedFd) -> io::Result<bool> {
    let mut fds = [rustix::event::PollFd::new(
        pidfd,
        rustix::event::PollFlags::IN,
    )];
    let zero = rustix::time::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    Ok(rustix::event::poll(&mut fds, Some(&zero))? == 0)
}

/// Pin the process `pid` of the container whose root is `root`: a pidfd,
/// once its root shows that it is that container's process.
pub fn pin_container_process(pid: i32, root: ContainerRoot<'_>) -> io::Result<OwnedFd> {
    pin_if_container_process(pid, root)?.ok_or_else(|| {
        io::Error::other(format!("the process {pid} is not the container's any more"))
    })
}

/// `pin_container_process` where "no such process of the container" is
/// `None` and every other failure (a record that cannot be read, a driver
/// that fails) is an error.
fn pin_if_container_process(pid: i32, root: ContainerRoot<'_>) -> io::Result<Option<OwnedFd>> {
    let Some(p) = rustix::process::Pid::from_raw(pid) else {
        return Ok(None);
    };
    let pidfd = rustix::process::pidfd_open(p, rustix::process::PidfdFlags::empty())?;
    // The root says whose process the pidfd has; /proc/PID is read after
    // the pidfd exists, and the process still runs once it was read: its
    // pid was not freed meanwhile, so what was read is that process's.
    let ours = match root {
        ContainerRoot::Writable(driver, w, mon_dir) => {
            match velarx_wire::monitor::rootid::recorded(mon_dir)? {
                Some(id) => velarx_wire::monitor::rootid::is_root(
                    Path::new(&format!("/proc/{pid}/root")),
                    &id,
                )?,
                None => match driver.is_root_of(w, Path::new(&format!("/proc/{pid}"))) {
                    Ok(ours) => ours,
                    // (a driver that cannot tell, a store behind a socket,
                    // with no record of the monitor, such as after a
                    // reboot: nothing shows that the process is the
                    // container's)
                    Err(e) if matches!(e.kind, velarx_graph::DriverErrorKind::Unsupported) => false,
                    Err(e) => return Err(e.into_io()),
                },
            }
        }
        ContainerRoot::Bind(dir) => root_is_bind_of(Path::new(&format!("/proc/{pid}/root")), dir)?,
    };
    if !ours || !pidfd_alive(&pidfd)? {
        return Ok(None);
    }
    Ok(Some(pidfd))
}

/// Whether `pid` is a running process of the container whose root is
/// `root`: false when there is no such process or it is another one that
/// took the pid.
pub fn container_process_runs(pid: i32, root: ContainerRoot<'_>) -> io::Result<bool> {
    match pin_if_container_process(pid, root) {
        Ok(found) => Ok(found.is_some()),
        // the process went, or its /proc entry is not ours to read
        Err(e)
            if matches!(
                e.raw_os_error().map(rustix::io::Errno::from_raw_os_error),
                Some(
                    rustix::io::Errno::SRCH | rustix::io::Errno::NOENT | rustix::io::Errno::ACCESS
                )
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

/// The root of the process `pid` of the container whose root is `root`
/// (`/proc/PID/root`, a descriptor): the process is pinned while it is
/// checked and the root opened, so the root of a process that took a reused
/// pid is not given.
pub fn open_container_root(pid: i32, root: ContainerRoot<'_>) -> io::Result<OwnedFd> {
    let pidfd = pin_container_process(pid, root)?;
    let dir = rustix::fs::open(
        format!("/proc/{pid}/root"),
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    if !pidfd_alive(&pidfd)? {
        return Err(io::Error::other("the process of the container exited"));
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn driver(dir: &Path) -> std::sync::Arc<dyn StorageDriver> {
        std::sync::Arc::new(crate::storage_driver::composefs::driver_for_tests(dir).await)
    }

    #[tokio::test]
    async fn a_process_that_is_not_the_container_does_not_run_it() {
        let me = std::process::id() as i32;
        let tmp = tempfile::tempdir().unwrap();
        let d = driver(tmp.path()).await;
        let w = Writable::new("nonexistent", "/nonexistent");
        let root = ContainerRoot::Writable(&*d, &w, tmp.path());
        // another process on this pid, and no process at all
        assert!(!container_process_runs(me, root).unwrap());
        assert!(!container_process_runs(i32::MAX, root).unwrap());
        assert!(!container_process_runs(me, ContainerRoot::Bind(tmp.path())).unwrap());
        // and the process whose root is the one of the container: this
        // one, for a container whose root is a bind of /
        assert!(container_process_runs(me, ContainerRoot::Bind(Path::new("/"))).unwrap());
    }

    /// A driver that cannot tell the root of a process, as the storage
    /// service's.
    struct CannotTell {
        inner: std::sync::Arc<dyn StorageDriver>,
    }

    velarx_graph::forward_storage_driver! {
        impl StorageDriver for CannotTell {
            inner: inner;
            forward: [name graph_name capabilities graph_data status pull has_layers repair remake_staged read_objects open_object objects_in_order collect release_engine_copies remove_image image_volume_create mounts image_view holds_objects leftovers check writable_create writable_paths writable_root writable_size writable_remove writable_release writable_exists diff changes apply stopped_view usage list_stores drop_store lock_unused_layers];
            fn is_root_of(&self, _w: &Writable, _proc_dir: &Path) -> velarx_graph::DriverResult<bool> {
                Err(velarx_graph::DriverError::of(
                    "test",
                    velarx_graph::DriverErrorKind::Unsupported,
                    "no mount to ask",
                ))
            }
        }
    }

    /// A process whose root the driver cannot tell and the monitor did not
    /// record (its directory went with a reboot) is not the container's:
    /// a process that took the pid after the reboot does not keep the
    /// container running.
    #[tokio::test]
    async fn a_driver_that_cannot_tell_a_root_does_not_make_a_process_the_containers() {
        let me = std::process::id() as i32;
        let tmp = tempfile::tempdir().unwrap();
        let d = CannotTell {
            inner: driver(tmp.path()).await,
        };
        let w = Writable::new("nonexistent", "/nonexistent");
        let root = ContainerRoot::Writable(&d, &w, tmp.path());
        assert!(!container_process_runs(me, root).unwrap());
        assert!(pin_container_process(me, root).is_err());
    }

    /// Only "no such process of the container" means it does not run: a
    /// record of the root that cannot be read is an error.
    #[tokio::test]
    async fn a_corrupt_root_record_is_an_error_and_not_a_stopped_container() {
        let me = std::process::id() as i32;
        let tmp = tempfile::tempdir().unwrap();
        let d = driver(tmp.path()).await;
        let w = Writable::new("nonexistent", "/nonexistent");
        let mon = tmp.path().join("mon");
        std::fs::create_dir(&mon).unwrap();
        std::fs::write(mon.join(velarx_wire::monitor::rootid::FILE), b"garbage\n").unwrap();
        let root = ContainerRoot::Writable(&*d, &w, &mon);
        let e = container_process_runs(me, root).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        // a pid that is not one is still no running process
        assert!(!container_process_runs(0, root).unwrap());
    }

    /// A root the monitor recorded is what a process is compared with, and
    /// the driver (which would say no here) is not asked.
    #[tokio::test]
    async fn the_root_the_monitor_attached_is_the_containers() {
        let me = std::process::id() as i32;
        let tmp = tempfile::tempdir().unwrap();
        let d = driver(tmp.path()).await;
        let w = Writable::new("nonexistent", "/nonexistent");
        let mon = tmp.path().join("mon");
        std::fs::create_dir(&mon).unwrap();
        let root = ContainerRoot::Writable(&*d, &w, &mon);
        velarx_wire::monitor::rootid::record(&mon, Path::new("/")).unwrap();
        assert!(container_process_runs(me, root).unwrap());
        // another root, as another container's process has
        velarx_wire::monitor::rootid::record(&mon, tmp.path()).unwrap();
        assert!(!container_process_runs(me, root).unwrap());
    }

    #[tokio::test]
    async fn this_process_is_not_a_container() {
        let pid = std::process::id() as i32;
        let tmp = tempfile::tempdir().unwrap();
        let d = driver(tmp.path()).await;
        let w = Writable::new("nonexistent", "/nonexistent");
        assert!(pin_container_process(pid, ContainerRoot::Writable(&*d, &w, tmp.path())).is_err());
        assert!(pin_container_process(0, ContainerRoot::Bind(Path::new("/x"))).is_err());
        let me = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(pid).unwrap(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap();
        assert!(pidfd_alive(&me).unwrap());
    }

    /// A pidfd tells the process ended (the old reading of its fdinfo did
    /// too, by a number to parse).
    #[test]
    fn a_pidfd_says_when_its_process_ended() {
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let fd = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(child.id() as i32).unwrap(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap();
        assert!(pidfd_alive(&fd).unwrap());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!pidfd_alive(&fd).unwrap());
    }

    /// The root of a process is a bind of a directory when it is that
    /// directory's inode (the process here has the root of the host).
    #[test]
    fn a_bind_root_is_the_inode_of_its_directory() {
        let me = std::process::id();
        let root = format!("/proc/{me}/root");
        assert!(root_is_bind_of(Path::new(&root), Path::new("/")).unwrap());
        assert!(!root_is_bind_of(Path::new(&root), Path::new("/proc")).unwrap());
    }
}
