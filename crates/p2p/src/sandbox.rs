// SPDX-License-Identifier: Apache-2.0
//! The confinement of `velarx-p2p`: it talks to the network
//! (libp2p: Noise, Yamux, Kademlia, gossip, mDNS) and needs nothing of the
//! machine but its sockets, its configuration and the daemon's sockets.
//! Before its runtime starts any thread it gives up:
//!
//! * `no_new_privs`, every capability, core dumps;
//! * Landlock, fail closed (a kernel without every right of the ruleset,
//!   ABI 9, does not run it): its sockets are bound before (it makes no
//!   socket, no file and no directory by name, and removes none: a process
//!   forked before removes them when it is gone); beneath the staging of the layers
//!   of the store (`<storage.root>/staging/layers`, opened before, the rule
//!   made from that descriptor) what the object contract makes (files with
//!   no name, the names of the files of a layer, its directories); it
//!   connects to no UNIX socket by name (`ResolveUnix` is granted
//!   nowhere): the store service is reached through a connector, a
//!   process forked before that passes the connections as descriptors
//!   ([`velarx_sys::connector`]); a few paths are readable (the libraries, the resolver's
//!   files, its configuration and its swarm key); no abstract
//!   UNIX socket and no signal outside its domain.  TCP is not handled:
//!   the peers listen and are dialed on ports of their choosing, libp2p
//!   binds its dialing sockets to its listening ports, and the overlay's
//!   DNS binds its own.  UDP (QUIC, mDNS, the DNS of the overlay) is not
//!   covered by Landlock at all: seccomp lets it make IPv4 and IPv6
//!   sockets, and nothing narrows their addresses.  No file it
//!   writes can grow beyond `max_incoming_mib` (`RLIMIT_FSIZE`);
//! * seccomp: an allow-list of the calls the service makes (the runtime,
//!   files, sockets, the stager's `openat2`, `linkat` and fs-verity
//!   requests, the sealed memory files of its replies), `clone` for
//!   threads only, sockets of the IPv4, IPv6, UNIX (the daemon's sockets)
//!   and netlink (the interfaces mDNS watches) families only; any other
//!   call fails with `EPERM`, a call the kernel adds later with `ENOSYS`.
//!
//! The overlay node (`velarx-p2p overlay`, [`crate::overlay_service`]) is
//! confined the same way for what it does and no more: it has no staging,
//! writes no file, connects to no UNIX socket, serves no sockets but the
//! network provider's, and makes no call of the stager (`openat2`, `linkat`,
//! fs-verity, sealed memory files, inotify on the store service's socket).
//!
//! The overlay network's privileged part (veths, routes, sysctls, packet
//! sockets, the containers' namespaces) is the overlay helper's
//! (`network::overlay_helper`), started before: the service keeps none of
//! it, it reads and writes frames on the packet sockets the helper hands
//! over.

use crate::settings::Settings;
use crate::Role;
use landlock::{AccessFs, ABI};
use std::path::{Path, PathBuf};
use velarx_config::Config;
use velarx_sandbox::{drop_privileges, net_client, READABLE};
use velarx_sys::allow::{self, Allow};

/// What the service may reach.
#[derive(Debug)]
pub struct Paths {
    /// Read
    pub readable: Vec<PathBuf>,
    /// The directories of its sockets (bound before; nothing is made or
    /// removed there once confined)
    pub sockets: Vec<PathBuf>,
    /// The staging of the layers of the store (the content role)
    pub staging: Option<PathBuf>,
}

/// What the service may read and write.
pub fn paths(role: Role, config: &Config, settings: &Settings, config_paths: &[&Path]) -> Paths {
    let mut readable: Vec<PathBuf> = READABLE.iter().map(PathBuf::from).collect();
    readable.extend(config_paths.iter().map(|p| p.to_path_buf()));
    for var in ["SSL_CERT_FILE", "SSL_CERT_DIR"] {
        if let Some(p) = std::env::var_os(var) {
            readable.push(p.into());
        }
    }
    readable.extend(settings.private_key_path.clone());
    // (the authority's files are read again when they change, and a file
    // that is replaced is a new one: its directory)
    for file in [
        &settings.ca_path,
        &settings.certificate_path,
        &settings.revocation_path,
    ]
    .into_iter()
    .flatten()
    {
        readable.extend(file.parent().map(Path::to_path_buf));
    }
    let mut sockets = Vec::new();
    let served = match role {
        Role::Content => vec![
            settings.control_socket(config),
            settings.fetcher_socket(config),
        ],
        Role::Overlay => vec![settings.network_socket(config)],
    };
    for socket in served {
        if let Some(dir) = socket.parent() {
            sockets.push(dir.to_path_buf());
        }
    }
    sockets.sort();
    sockets.dedup();
    let staging = (role == Role::Content).then(|| {
        config
            .storage
            .staging_dir()
            .join(velarx_content::pull::staged_fetch::LAYERS)
    });
    Paths {
        readable,
        sockets,
        staging,
    }
}

/// The Landlock ABI the service needs: every right of its ruleset is a must
/// (9: UNIX sockets connected to by name).
const ABI_NEEDED: ABI = ABI::V9;

fn landlock(paths: &Paths, staging: Option<std::os::fd::BorrowedFd<'_>>) -> Result<(), String> {
    use velarx_sys::ruleset::{self, Handles, Must, Rules};
    // (TCP is not handled: the peers listen and are dialed on ports of
    // their choosing; `ResolveUnix` is handled and granted nowhere: the store
    // service is reached through a connector, forked before)
    let mut rules = Rules::new(Handles {
        abi: ABI_NEEDED,
        net: Default::default(),
        scopes: true,
        must: Must::Everything,
    })?;
    for path in &paths.readable {
        // (what the system does not have cannot be used)
        rules.beneath_if_present(path, AccessFs::from_read(ABI_NEEDED))?;
    }
    // (the object contract: files with no name in `incoming/`, named with
    // `linkat` in `files/ab/`, the directories made; nothing removed)
    if let Some(staging) = staging {
        rules
            .beneath_dir(staging, ruleset::stager_rights())
            .map_err(|e| format!("the staging: {e}"))?;
    }
    rules.restrict_fully("the service").map(drop)
}

/// What the service makes: the runtime and the files and IPv4 and IPv6
/// sockets of a pull worker, the sockets it listens on and serves (UNIX,
/// the daemon's and its own) and netlink (the interfaces mDNS watches), UDP
/// in batches (QUIC), and in the directories of its sockets and the files
/// of its callers what Landlock lets it write: the files it fills (and
/// punches holes in) for a caller, its sockets, its peers file.  No process,
/// no execution, no namespace, no `kill` of anything but itself.
fn allowed(pid: u32, role: Role) -> Result<Allow, String> {
    use velarx_sys::allow::one_of;
    // (what the two roles make: the runtime, sockets of the peers' families,
    // the ones they listen on and accept, netlink for the interfaces the
    // addresses to listen on are read from; UNIX sockets for the content
    // service's calls only)
    let mut families = vec![
        libc::AF_INET as u64,
        libc::AF_INET6 as u64,
        libc::AF_NETLINK as u64,
    ];
    if role == Role::Content {
        families.push(libc::AF_UNIX as u64);
    }
    let allow = net_client(Allow::runtime(pid)?)
        .calls(&[libc::SYS_listen, libc::SYS_bind, libc::SYS_accept4])
        .when(libc::SYS_socket, one_of(0, &families));
    if role == Role::Overlay {
        return Ok(allow);
    }
    let allow = allow
        .calls(&[
            libc::SYS_pwrite64,
            libc::SYS_pwritev,
            libc::SYS_fallocate,
            libc::SYS_ftruncate,
            libc::SYS_fsync,
            libc::SYS_fdatasync,
            libc::SYS_umask,
            libc::SYS_flock,
            libc::SYS_unlinkat,
            libc::SYS_renameat,
            libc::SYS_renameat2,
            libc::SYS_mkdirat,
            libc::SYS_utimensat,
            libc::SYS_sendfile,
            libc::SYS_copy_file_range,
            libc::SYS_fadvise64,
            libc::SYS_statfs,
            libc::SYS_fstatfs,
            // (the service waits for the socket of the store service to
            // be made again: inotify on its directory)
            libc::SYS_inotify_init1,
            libc::SYS_inotify_add_watch,
            libc::SYS_inotify_rm_watch,
            // the stager: files with no name beneath the staging of a layer
            // (`openat2` BENEATH, `O_TMPFILE`), named with `linkat`
            libc::SYS_openat2,
            libc::SYS_linkat,
        ])
        // (fs-verity enabled and measured by the stager)
        .plus(
            libc::SYS_ioctl,
            one_of(
                1,
                &[
                    velarx_storage::FS_IOC_ENABLE_VERITY,
                    velarx_storage::FS_IOC_MEASURE_VERITY,
                ],
            ),
        )
        // (the sealed memory files of the replies of `Get`)
        .when(
            libc::SYS_memfd_create,
            vec![velarx_sys::allow::is_wide(
                1,
                u64::from(libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING),
            )],
        );
    // (the calls that only x86-64 has)
    #[cfg(target_arch = "x86_64")]
    let allow = allow.calls(&[
        libc::SYS_accept,
        libc::SYS_unlink,
        libc::SYS_rename,
        libc::SYS_mkdir,
    ]);
    Ok(allow)
}

fn seccomp(role: Role) -> Result<(), String> {
    allow::apply(&allowed(std::process::id(), role)?.programs()?)
}

/// Confine the service.  Call it before any thread is started (the
/// runtime): Landlock and seccomp apply to the threads created afterwards.
/// `config_paths`: the configuration files it was started with.
pub fn enter(
    role: Role,
    config: &Config,
    settings: &Settings,
    config_paths: &[&Path],
) -> Result<(), String> {
    velarx_sys::confine::require_single_thread()?;
    enter_role_thread(role, config, settings, config_paths)
}

/// Confine the calling thread and those it makes afterwards, whatever other
/// threads the process has: for the tests, whose harness runs a test on a
/// thread of its own.  The service calls [`enter`].
pub fn enter_thread(
    config: &Config,
    settings: &Settings,
    config_paths: &[&Path],
) -> Result<(), String> {
    enter_role_thread(Role::Content, config, settings, config_paths)
}

/// [`enter_thread`] for a role.
pub fn enter_role_thread(
    role: Role,
    config: &Config,
    settings: &Settings,
    config_paths: &[&Path],
) -> Result<(), String> {
    // (the trace file, when there is one, is opened before the confinement)
    velarx_base::trace::enabled();
    rustix::thread::set_no_new_privs(true).map_err(|e| format!("PR_SET_NO_NEW_PRIVS: {e}"))?;
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|e| format!("PR_SET_DUMPABLE: {e}"))?;
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|e| format!("RLIMIT_CORE: {e}"))?;
    // (the overlay node writes no file: Landlock grants it no write)
    if role == Role::Content {
        velarx_base::hardening::limit_file_size(settings.max_file_bytes(&config.pull))
            .map_err(|e| format!("RLIMIT_FSIZE: {e}"))?;
    }
    // (the overlay's DNS keeps for each container its sockets, its TCP
    // connections and the queries to the name servers open: the bounds of
    // dns_sockets times the containers of the node's subnet are more than
    // the soft limit of 1024)
    velarx_base::hardening::raise_open_files().map_err(|e| format!("RLIMIT_NOFILE: {e}"))?;
    drop_privileges()?;
    let paths = paths(role, config, settings, config_paths);
    // The directories exist before Landlock is told about them (a missing
    // path gets no rule).
    for dir in &paths.sockets {
        velarx_base::ipc::ensure_private_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    // (the staging of the store, private as the engine makes it, opened:
    // the rule is the descriptor's)
    let staging = match &paths.staging {
        Some(dir) => {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
            Some(
                rustix::fs::open(
                    dir,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|e| format!("{}: {e}", dir.display()))?,
            )
        }
        None => None,
    };
    // (no /proc once confined)
    velarx_base::ids::settle().map_err(|e| e.to_string())?;
    landlock(&paths, staging.as_ref().map(std::os::fd::AsFd::as_fd))?;
    seccomp(role)
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_sys::allow::testing::{check, check_runtime, verdicts, ALLOW, EPERM};

    /// The program of the service, evaluated: its sockets (the peers',
    /// the daemon's, netlink for mDNS), UDP in batches and the files it
    /// fills; no packet socket, no process, no execution, no mount.
    #[test]
    fn the_filters_allow_the_service_and_refuse_the_rest() {
        let verdict = verdicts(allowed(1, Role::Content).unwrap());
        check_runtime(&verdict);
        let af = |d: i32| [d as u64, 0, 0, 0, 0, 0];
        check(
            &verdict,
            &[
                (libc::SYS_socket, af(libc::AF_INET), ALLOW),
                (libc::SYS_socket, af(libc::AF_INET6), ALLOW),
                (libc::SYS_socket, af(libc::AF_UNIX), ALLOW),
                (libc::SYS_socket, af(libc::AF_NETLINK), ALLOW),
                (libc::SYS_socket, af(libc::AF_PACKET), EPERM),
                (libc::SYS_socket, af(libc::AF_VSOCK), EPERM),
                (libc::SYS_bind, [0; 6], ALLOW),
                (libc::SYS_listen, [0; 6], ALLOW),
                (libc::SYS_accept4, [0; 6], ALLOW),
                (libc::SYS_sendmmsg, [0; 6], ALLOW),
                (libc::SYS_recvmmsg, [0; 6], ALLOW),
                (libc::SYS_fallocate, [0; 6], ALLOW),
                (libc::SYS_inotify_init1, [0; 6], ALLOW),
                (libc::SYS_inotify_add_watch, [0; 6], ALLOW),
                (libc::SYS_pwritev, [0; 6], ALLOW),
                (libc::SYS_execve, [0; 6], EPERM),
                (libc::SYS_unshare, [0; 6], EPERM),
                (libc::SYS_setns, [0; 6], EPERM),
                (libc::SYS_mount, [0; 6], EPERM),
                (libc::SYS_memfd_create, [0; 6], EPERM),
                (libc::SYS_memfd_create, [0, 3, 0, 0, 0, 0], ALLOW),
                (libc::SYS_openat2, [0; 6], ALLOW),
                (libc::SYS_linkat, [0; 6], ALLOW),
                (
                    libc::SYS_ioctl,
                    [0, velarx_storage::FS_IOC_ENABLE_VERITY, 0, 0, 0, 0],
                    ALLOW,
                ),
                (libc::SYS_pidfd_send_signal, [0; 6], EPERM),
                (libc::SYS_setuid, [0; 6], EPERM),
            ],
        );
    }

    /// The overlay node's program is the content service's without the
    /// stager's calls (files, fs-verity, sealed memory, inotify): its
    /// sockets and the packets on the descriptors the helper gave it.
    #[test]
    fn the_overlay_filters_allow_the_sockets_and_nothing_of_the_stager() {
        let verdict = verdicts(allowed(1, Role::Overlay).unwrap());
        check_runtime(&verdict);
        let af = |d: i32| [d as u64, 0, 0, 0, 0, 0];
        check(
            &verdict,
            &[
                (libc::SYS_socket, af(libc::AF_INET), ALLOW),
                (libc::SYS_socket, af(libc::AF_INET6), ALLOW),
                (libc::SYS_socket, af(libc::AF_UNIX), EPERM),
                (libc::SYS_socket, af(libc::AF_NETLINK), ALLOW),
                (libc::SYS_socket, af(libc::AF_PACKET), EPERM),
                (libc::SYS_bind, [0; 6], ALLOW),
                (libc::SYS_listen, [0; 6], ALLOW),
                (libc::SYS_accept4, [0; 6], ALLOW),
                (libc::SYS_recvmsg, [0; 6], ALLOW),
                (libc::SYS_sendmsg, [0; 6], ALLOW),
                (libc::SYS_pwritev, [0; 6], EPERM),
                (libc::SYS_fallocate, [0; 6], EPERM),
                (libc::SYS_openat2, [0; 6], EPERM),
                (libc::SYS_linkat, [0; 6], EPERM),
                (libc::SYS_inotify_init1, [0; 6], EPERM),
                (libc::SYS_memfd_create, [0, 3, 0, 0, 0, 0], EPERM),
                (
                    libc::SYS_ioctl,
                    [0, velarx_storage::FS_IOC_ENABLE_VERITY, 0, 0, 0, 0],
                    EPERM,
                ),
                (libc::SYS_execve, [0; 6], EPERM),
                (libc::SYS_setns, [0; 6], EPERM),
                (libc::SYS_mount, [0; 6], EPERM),
            ],
        );
    }
}
