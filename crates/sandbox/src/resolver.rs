// SPDX-License-Identifier: Apache-2.0
//! The confinement of the process that resolves names for the pull workers
//! (`velarx_registry_lib::net::runner`).
//!
//! It has to run the name service switch of the host as an unconfined
//! process does: its modules load libraries, read their configuration
//! wherever it is, ask the resolver of the host on UDP and TCP and on UNIX
//! sockets, and may use a netlink socket.  What it can still give up it
//! gives up before it reads the first question:
//!
//! * root of the host becomes `nobody` (the sources of names serve every
//!   user); no capability, not dumpable;
//! * no file is written, made, removed or executed (Landlock, which handles
//!   every right of ABI 9: only reading, and connecting to a UNIX socket by
//!   its name, are given, beneath `/`); no signal and no abstract UNIX socket
//!   outside it;
//! * seccomp: no `execve`, no process (threads only), no namespace, no
//!   mount, no `ptrace`, no `bpf`, no module, no key, no change of identity,
//!   no `io_uring`, and none of what Landlock does not handle: the owner,
//!   mode and attributes of a file, a file by its handle;
//! * `no_new_privs`.
//!
//! What it cannot give up: reading any file (the files of the modules are
//! not known in advance), the sockets of every family, and the network (the
//! rights of TCP are not handled, as the resolver of a host may ask any
//! server any port).  It needs no other process' help, and holds nothing but
//! the descriptor it was given.
//!
//! Nothing is optional: a kernel that cannot enforce all of it does not run
//! the resolver.

use landlock::{AccessFs, ABI};
use std::path::Path;
use velarx_sys::confine as sys;
use velarx_sys::ruleset::{Handles, Must, Rules};

/// `fchmodat2`, the same number on every architecture (the libc crate
/// lacks it on some).
const SYS_FCHMODAT2: i64 = 452;
/// The calls that came after the libc crate's lists, the same number on
/// every architecture: `lsm_set_self_attr`, the `*xattrat` twins of
/// `setxattr` and `removexattr`, `file_setattr` (the flags of a file) and
/// `fchroot`.
const SYS_LSM_SET_SELF_ATTR: i64 = 460;
const SYS_SETXATTRAT: i64 = 463;
const SYS_REMOVEXATTRAT: i64 = 466;
const SYS_FILE_SETATTR: i64 = 469;
const SYS_FCHROOT: i64 = 472;

/// The system calls the resolver never makes; `EPERM`.  The sockets are not
/// among them.
const DENIED: &[i64] = &[
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    SYS_FCHROOT,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_bpf,
    libc::SYS_keyctl,
    SYS_LSM_SET_SELF_ATTR,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_mknodat,
    libc::SYS_setuid,
    libc::SYS_setgid,
    libc::SYS_setreuid,
    libc::SYS_setregid,
    libc::SYS_setresuid,
    libc::SYS_setresgid,
    libc::SYS_setfsuid,
    libc::SYS_setfsgid,
    libc::SYS_setgroups,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_reboot,
    libc::SYS_sethostname,
    libc::SYS_setdomainname,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_open_tree,
    libc::SYS_move_mount,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_mount_setattr,
    libc::SYS_kill,
    libc::SYS_pidfd_open,
    libc::SYS_pidfd_send_signal,
    libc::SYS_pidfd_getfd,
    // what Landlock does not handle: the owner, mode and attributes of a
    // file, a file by its handle, the events of a whole mount
    libc::SYS_fchmod,
    libc::SYS_fchmodat,
    SYS_FCHMODAT2,
    libc::SYS_fchown,
    libc::SYS_fchownat,
    libc::SYS_setxattr,
    libc::SYS_lsetxattr,
    libc::SYS_fsetxattr,
    libc::SYS_removexattr,
    libc::SYS_lremovexattr,
    libc::SYS_fremovexattr,
    SYS_SETXATTRAT,
    SYS_REMOVEXATTRAT,
    SYS_FILE_SETATTR,
    libc::SYS_name_to_handle_at,
    libc::SYS_open_by_handle_at,
    libc::SYS_fanotify_init,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_fork,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_vfork,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_mknod,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_chmod,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_chown,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_lchown,
];

/// The rights the resolver has beneath `/`.
fn rights() -> landlock::BitFlags<AccessFs> {
    AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::ResolveUnix
}

/// Confine the calling process.  Call it before any thread is started: the
/// filter applies to the threads that are created afterwards.
pub fn enter() -> Result<(), String> {
    // (the bounding set while root may drop it, then root's identity and
    // what is left of its capabilities)
    velarx_sys::caps::drop_bounding_except(|_| false)
        .map_err(|e| format!("capabilities of the bounding set: {e}"))?;
    super::become_nobody()?;
    super::drop_privileges()?;
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|e| format!("PR_SET_DUMPABLE: {e}"))?;
    let mut rules = Rules::new(Handles {
        abi: ABI::V9,
        net: landlock::BitFlags::empty(),
        scopes: true,
        must: Must::Everything,
    })?;
    rules.beneath(Path::new("/"), rights())?;
    rules.restrict_fully("the resolver")?;
    let filter = sys::deny_filter(DENIED, libc::EPERM as u32).map_err(|e| e.to_string())?;
    sys::seccomp_thread(&filter).map_err(|e| format!("seccomp: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A resolver can read, resolve (the host's sources need sockets and
    /// the files of the system), and not write, execute or mount.
    #[test]
    fn the_resolver_reads_and_resolves_and_changes_nothing() {
        velarx_base::testing::in_child(|| {
            let path = std::env::temp_dir().join(format!("velarx-resolver-{}", std::process::id()));
            let own = std::fs::File::create(&path).unwrap();
            std::fs::remove_file(&path).unwrap();
            enter().unwrap();
            assert!(
                std::fs::read("/etc/os-release").is_ok() || std::fs::read("/etc/passwd").is_ok()
            );
            let found = std::net::ToSocketAddrs::to_socket_addrs(&("localhost", 80)).unwrap();
            assert!(found.into_iter().any(|a| a.ip().is_loopback()));
            let dir = std::env::temp_dir();
            assert!(std::fs::File::create(dir.join("velarx-resolver-probe")).is_err());
            assert!(std::fs::create_dir(dir.join("velarx-resolver-probe-dir")).is_err());
            assert!(std::process::Command::new("/bin/true").status().is_err());
            // (nor the mode of a file of its own, which Landlock allows)
            assert!(rustix::fs::fchmod(&own, rustix::fs::Mode::from_raw_mode(0o600)).is_err());
            assert!(rustix::thread::capabilities(None)
                .is_ok_and(|c| c.effective.is_empty() && c.permitted.is_empty()));
            let mounted = rustix::mount::mount(
                "none",
                "/tmp",
                "tmpfs",
                rustix::mount::MountFlags::empty(),
                None,
            );
            assert!(mounted.is_err());
            // (threads are the one thing a runtime needs)
            assert!(std::thread::spawn(|| 1).join().is_ok());
            assert!(velarx_sys::process::fork_status(|| 0).is_err());
            // a UNIX socket and a datagram socket of the network
            use rustix::net::{AddressFamily, SocketType};
            assert!(rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None).is_ok());
            assert!(rustix::net::socket(AddressFamily::INET, SocketType::DGRAM, None).is_ok());
        });
    }
}
