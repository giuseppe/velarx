// SPDX-License-Identifier: Apache-2.0
//! The network namespace of the rootless bridge networks.
//!
//! Rootless, the links of the bridge networks cannot be made in the network
//! namespace of the host: they live in a namespace of their own, connected
//! to the host by pasta, that every container on a bridge network reaches
//! through its veth.  It must outlive the command that made it, and nothing
//! keeps a namespace but a process in it, a bind mount in a mount namespace
//! that lives, or an open descriptor: the mount namespace of a command ends
//! with the last process in it, and there is none that is kept alive for
//! this.  So a process lives in it: `velarx netns-holder`, which makes the
//! namespace, tells it is ready and sleeps until it is stopped (the rootless
//! network namespace is given up when no bridge in it has a port, see
//! `ContainerNetworks::release_rootless_netns_if_unused`).  It exists only
//! while bridge networks are in use, never otherwise, in a scope of its own
//! (`velarx-netns-*.scope`) when a systemd manager answers: the unit or
//! terminal of the command that started it may stop before the containers
//! of the others.
//!
//! The namespace is not pinned: who it is (device, inode and file handle,
//! like the `userns` table) and its holder (pid and start time) are in the
//! namespaces tables of the store (`velarx_nsid::store`, scope
//! [`velarx_nsid::store::ROOTLESS_NETNS`]).  Whoever needs the namespace
//! opens `/proc/PID/ns/net` of the holder: every process of the user lives
//! in the one user-namespace tree (`userns::tree`), so it may, and it
//! checks that it is the recorded one.  The pasta of the namespace runs on
//! that path and does not watch it (pasta cannot be asked to open the
//! directory of a process's descriptors): the holder stops it when it ends
//! (asked to, not killed), and whoever finds the holder gone stops it: the
//! next holder before it starts its own, the release of the namespace, the
//! sweep when the engine starts.  The holder that was killed (kill
//! -9, the out-of-memory killer, a stopped scope) while containers have
//! links there is told from a namespace that is gone by looking for a
//! process of the tree that is in the recorded namespace (the DNS server, the
//! port forwarders, the monitor of a container); the next holder is
//! started in that namespace, as podman rejoins a running container's
//! namespaces when its pause process is gone, and the bridges stay one (and
//! the pasta is started again, on the new holder).  When nothing keeps it
//! the kernel has destroyed it, the record is stale, and the next start
//! makes a new one.

use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use velarx_netkernel::rootless_netns::{
    forget_record, locate, ns_path, pasta_pid_file, write_record,
};
use velarx_nsid::tree;
use velarx_nsid::Holder;

tokio::task_local! {
    /// The holder that a future of [`in_caller_cgroup`] starts stays in the
    /// cgroup of the caller.
    static IN_CALLER_CGROUP: bool;
}

/// Run `f`, the network setup of a container; when `caller`, a holder it
/// starts stays in the cgroup of the caller (`--cgroups=disabled`: nothing
/// is made in the cgroups and no manager is asked for it).
pub async fn in_caller_cgroup<F: std::future::Future>(caller: bool, f: F) -> F::Output {
    IN_CALLER_CGROUP.scope(caller, f).await
}

/// Where a holder that is started outside [`in_caller_cgroup`] goes (a
/// setup of a container's networks that no start wraps): in the caller's
/// cgroup when the containers make none by default (`[containers] cgroups
/// = "disabled"` of the configuration).
static DEFAULT_IN_CALLER_CGROUP: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Start the holders that are not started for a container in the caller's
/// cgroup (`yes`), or in a scope of their own.
pub fn set_default_in_caller_cgroup(yes: bool) {
    DEFAULT_IN_CALLER_CGROUP.store(yes, std::sync::atomic::Ordering::Relaxed);
}

/// Whether the holder started now gets a scope of its own: not for a
/// container that makes no cgroup ([`in_caller_cgroup`]), nor, outside the
/// start of a container, when containers make none by default.
pub fn wants_own_scope() -> bool {
    !IN_CALLER_CGROUP
        .try_with(|c| *c)
        .unwrap_or_else(|_| DEFAULT_IN_CALLER_CGROUP.load(std::sync::atomic::Ordering::Relaxed))
}

/// Start the holder, if it does not live: the path of the namespace
/// (`/proc/PID/ns/net` of the holder) and whether the holder was started
/// now (a new namespace, or one that was found by other means: a pasta on
/// the path of the holder before is on a process that is gone, and must be
/// stopped before another one starts, which it would keep from making its
/// tap device).  When the holder is gone but a process of the tree keeps
/// its namespace, the new holder joins that namespace: the containers that
/// have links there stay on the same bridges.  The caller holds the lock of
/// the networks.
pub fn start(run: &Path, db: &Path, own_scope: bool) -> io::Result<(PathBuf, bool)> {
    let join = match locate(run, db, tree::members)? {
        Some(f) if f.holder => return Ok((f.path, false)),
        found => found,
    };
    if join.is_none() {
        // nothing keeps the recorded namespace: what is left of it goes
        forget_record(db)?;
    }
    // The namespace to join goes to the holder as descriptor 4: the process
    // it was found through may exit meanwhile, the descriptor keeps it.
    // (Both descriptors are moved above 10 first, so that the dup2 to 3 and
    // 4 in the child never overwrites one of them.)
    let high = |fd: std::os::fd::BorrowedFd<'_>| -> io::Result<OwnedFd> {
        Ok(rustix::io::fcntl_dupfd_cloexec(fd, 10)?)
    };
    let join_fd = join.as_ref().map(|f| high(f.ns.as_fd())).transpose()?;
    let (ready_r, ready_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    let ready_w = high(ready_w.as_fd())?;
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    // (the directory and the path only say, in `ps`, whose holder it is and
    // where the namespace was found)
    cmd.arg("netns-holder")
        .arg(run)
        .args(join.as_ref().map(|f| &f.path))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let fd = ready_w.as_raw_fd();
    let ns_fd = join_fd.as_ref().map(|f| f.as_raw_fd());
    // (both sources are above 10: dup2 never overwrites one, and clears
    // close-on-exec)
    velarx_sys::spawn::pre_exec(&mut cmd, move |child| {
        let _ = rustix::process::setsid();
        child.dup2(fd, 3)?;
        if let Some(ns) = ns_fd {
            child.dup2(ns, 4)?;
        }
        Ok(())
    });
    let mut child = cmd.spawn().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("start the holder of the network namespace: {e}"),
        )
    })?;
    drop(ready_w);
    drop(join_fd);
    let pid = child.id() as i32;
    // (the child is not reaped yet: the pidfd is its own)
    let pidfd = match velarx_sys::pidfd::open_child(pid) {
        Ok(pidfd) => pidfd,
        Err(e) => {
            // (nothing else would stop and reap it)
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    };
    let mut byte = [0u8; 1];
    let ready = std::fs::File::from(ready_r).read(&mut byte);
    if !matches!(ready, Ok(1)) {
        // (not reaped yet: the pid is still the child's)
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::other(
            "the holder of the rootless network namespace could not make it",
        ));
    }
    // (it is not for this process to wait for: it ends when stopped; a
    // failure from here on stops it, and this thread reaps it)
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    let recorded = record_holder(db, own_scope, pid);
    if recorded.is_err() {
        let _ = rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::TERM);
    }
    recorded
}

/// What `start` does once the holder `pid` made the namespace: its scope
/// and the record.
fn record_holder(db: &Path, own_scope: bool, pid: i32) -> io::Result<(PathBuf, bool)> {
    // It serves the containers of every command and unit: in a scope of its
    // own when a manager answers, so that it does not end with the cgroup of
    // the command or unit that happened to start it.  Started for a
    // container with `--cgroups=disabled` (`own_scope` false), it stays in
    // the caller's cgroup and nothing asks the manager: it ends with the
    // caller's session or unit, and the networks of the containers in it
    // with it.
    if own_scope && crate::manager::scope_manager_answers().map_err(io::Error::other)? {
        let unit = format!(
            "velarx-netns-{pid}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        );
        if let Err(e) = velarx_wire::sdbus::start_scope(
            crate::manager::system_manager().map_err(io::Error::other)?,
            &unit,
            "velarx rootless network namespace",
            &[pid as u32],
            false,
            None,
            true,
        ) {
            return Err(io::Error::new(
                e.kind(),
                format!("put the holder of the network namespace in a scope: {e}"),
            ));
        }
    }
    let gone = || io::Error::other("the holder of the network namespace is gone");
    let start = velarx_nsid::start_time(pid).ok_or_else(gone)?;
    let ns = std::fs::File::open(ns_path(pid)).map_err(|_| gone())?;
    let id = velarx_nsid::id_of(ns.as_fd()).map_err(|_| gone())?;
    write_record(
        db,
        &id,
        &Holder {
            pid,
            start,
            role: velarx_netkernel::rootless_netns::ROLE.into(),
        },
    )?;
    tree::register_holder(pid as u32, "netns");
    Ok((ns_path(pid), true))
}

/// The holder: a process in a new network namespace, loopback up, or, when
/// `join`, in the namespace of descriptor 4, which the starter
/// checked to be the one the namespaces tables record (the holder
/// before this one died: its loopback is up already).  Descriptor 3 is
/// where it says it is ready.
pub fn holder_main(run: &Path, join: bool, startup: &velarx_sys::fd::Startup) -> ! {
    let made = if join {
        // (descriptor 4 is the namespace the starter passed; setns and
        // close are the whole use of it)
        startup.adopt(4).is_some_and(|ns| {
            rustix::thread::move_into_link_name_space(
                ns.as_fd(),
                Some(rustix::thread::LinkNameSpaceType::Network),
            )
            .is_ok()
        })
    } else {
        velarx_sys::ns::unshare(rustix::thread::UnshareFlags::NEWNET).is_ok()
            && velarx_netkernel::netlink::Netlink::open()
                .and_then(|mut nl| {
                    let lo = nl.link_index("lo")?;
                    if lo > 0 {
                        nl.link_up(lo)?;
                    }
                    Ok(())
                })
                .is_ok()
    };
    // (it lives as long as bridges are used: not in the directory of the
    // command that started it, which a host would have to unmount)
    let _ = std::env::set_current_dir("/");
    // (descriptor 3 is the pipe the starter passed; the write and the close
    // are the whole use of it)
    if let Some(ready) = startup.adopt(3) {
        if made {
            let _ = rustix::io::write(&ready, &[1u8]);
        }
    }
    if !made {
        std::process::exit(1);
    }
    // It lives until it is asked to end (the release of the namespace, a
    // stopped scope, the end of the session): then the pasta of the
    // namespace, which does not watch the holder, goes with it.  A holder
    // that is killed cannot: the pasta goes with the next holder or the
    // release of the namespace.
    let signals = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP];
    if let Ok(guard) = velarx_sys::signal::SignalGuard::new(&signals) {
        if let Some(fd) = guard.fd() {
            use rustix::event::{poll, PollFd, PollFlags};
            loop {
                let mut fds = [PollFd::new(&fd, PollFlags::IN)];
                match poll(&mut fds, None) {
                    Err(rustix::io::Errno::INTR) => continue,
                    _ if guard.read().is_empty() => continue,
                    _ => break,
                }
            }
            // (only the pasta of this namespace: a holder that is late must
            // not stop the pasta of the holder that came after it)
            let me = PathBuf::from(format!("/proc/{}/ns/net", std::process::id()));
            velarx_netkernel::pasta::stop_on(&pasta_pid_file(run), &me, true);
            std::process::exit(0);
        }
    }
    velarx_sys::process::pause_forever()
}
