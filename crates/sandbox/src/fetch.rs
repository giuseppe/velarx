// SPDX-License-Identifier: Apache-2.0
//! The confinement of the processes that serve the fetcher interface: the
//! front of the registry fetcher (`velarx-registry`), the spawner that
//! starts its pull workers, and the fetcher of a directory (`velarx-dir`).
//! The registry-specific part (what the front reads for the registries, the
//! worker it starts) is `velarx_registry_lib::confine`; the directory fetcher
//! uses this module only and links no registry or HTTP code.
//!
//! The front never parses what the registries send (the frames of the
//! workers are bounds-checked), but it is the process to protect, so before
//! it serves anything it gives up what it does not need:
//!
//! * Landlock: it reads the libraries, `/proc`, the registries configuration,
//!   the certificates and the auth files, executes nothing, writes no file
//!   outside the staging it was handed, removes the socket it bound from
//!   its own directory (it makes nothing there, and removes nothing of the
//!   other services), reads and replaces the file of
//!   the registry hints in the user's cache directory (regular files there,
//!   and nothing else), makes and removes the cgroups of its pools beneath
//!   the `pulls` cgroup it was placed with (`velarx_registry_lib::net::cgroup::place`,
//!   before it confines itself), connects to no TCP port (the workers make
//!   the connections) and to no UNIX socket by name
//!   (`LANDLOCK_ACCESS_FS_RESOLVE_UNIX` is handled and granted nowhere: not
//!   the engine's socket, not a service manager's).
//! * seccomp: an allow-list with no `execve`, `execveat`, `unshare`, `fork`,
//!   no change of user or group and no process or namespace of any kind but
//!   threads.
//! * a mount namespace of its own when it is root of the initial user
//!   namespace, in which the kernel's global files (`/proc/sys`,
//!   `/proc/sysrq-trigger`, `/sys`...) are read-only
//!   ([`crate::tunables`]): Landlock cannot keep it from writing them,
//!   and its permission bits allow root to.  A failure is fatal.
//!
//! What needs `execve` is done by the spawner (`velarx_sys::spawner`), a
//! process forked before the front confines itself, as the connector is in
//! the other binaries.  The spawner is confined like the front used to be
//! when it started the workers itself: it reads what a worker reads,
//! executes the worker, writes `/dev/null` and what `/proc` has (a worker
//! writes the maps of its own user namespace there), and its filter allows
//! what the workers do while they start (they become `nobody`, unshare
//! their namespaces and confine themselves with Landlock).  The workers
//! inherit its domain and filter, and only ever add to what a worker refuses
//! for itself.  The TCP connections are not handled by the spawner's
//! domain: the domain is inherited and can only be narrowed, and each worker
//! narrows it to the ports of what it is for (its own ruleset,
//! `--connect-port`), which no ruleset of the spawner could know in advance
//! (a URL names any port).
//!
//! Landlock fails closed: every right of the ruleset is a must, and a
//! kernel without the Landlock ABI that has all of them (9: UNIX sockets
//! looked up by name, 6: scoped signals and abstract sockets, 5: device
//! ioctls, 4: TCP, 3: truncation) does not run the fetcher.
//!
//! `execve` cannot be limited to one path by seccomp (it sees a pointer):
//! the spawner is limited to its one program by what it asks for (it starts
//! the one binary it was started for, with the arguments of a worker) and by
//! Landlock (it may execute that file and the dynamic loader the kernel runs
//! for it).

use crate::tunables;
use crate::{net_client, READABLE};
use landlock::{AccessFs, AccessNet, ABI};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use velarx_storage::{FS_IOC_ENABLE_VERITY, FS_IOC_MEASURE_VERITY};
use velarx_sys::allow::{self, Allow};

/// The user a worker of a root process becomes.
const NOBODY: u64 = 65534;

/// The Landlock ABI the front needs: every right of its ruleset is of it or
/// older.
const NEWEST: ABI = velarx_sys::ruleset::NEWEST;

/// Which process of the fetcher is confined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The process that serves the interface of the registry fetcher
    Front,
    /// The one that starts its pull workers
    Spawner,
    /// The directory fetcher (`velarx-dir`)
    Dir,
    /// The directory as a pusher (`velarx-dir --push`): it writes beneath
    /// the destination directory it was handed (or, for an archive, to the
    /// file it was handed) and reads nothing but the runtime's files
    DirPush,
}

/// What a process of the fetchers may reach.
#[derive(Debug, Default, Clone)]
pub struct Reach {
    /// Read: files and directories
    pub read: Vec<PathBuf>,
    /// Execute (and read): by the spawner only
    pub execute: Vec<PathBuf>,
    /// Remove files: the directories of a socket this process bound itself
    pub remove: Vec<PathBuf>,
    /// The cgroups of the pools are made, limited and removed beneath this
    /// directory (`velarx_registry_lib::net::cgroup::Placement::dir`)
    pub cgroups: Option<PathBuf>,
    /// Read the files, make and replace regular files: the directory of
    /// the registry hints and nothing in it but that (no execute, no
    /// other kind of file, no removal of directories)
    pub state: Vec<PathBuf>,
    /// The staging of the layers of the store, open (the starter gave it):
    /// files and directories are made, written, linked and removed beneath
    /// it, and nowhere else
    pub staging: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
    /// The origin of a pull that is a directory, open (the engine handed
    /// it): read beneath it, and nowhere else but what the runtime needs
    pub origin: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
}

/// The dynamic loaders of the C libraries: executing a program is executing
/// its loader.
pub const LOADERS: &[&str] = &[
    "/lib64/ld-linux-x86-64.so.2",
    "/lib/ld-linux-aarch64.so.1",
    "/lib64/ld-linux-aarch64.so.1",
    "/lib/ld-linux-armhf.so.3",
    "/lib/ld-linux-riscv64-lp64d.so.1",
    "/lib64/ld-linux-riscv64-lp64d.so.1",
    "/lib64/ld64.so.2",
];

/// What every process of the fetcher reads: the libraries and the system's
/// files a runtime needs.  Of `/proc` only what [`READABLE`] names: its own
/// entry (`/proc/self`) and the crypto settings, not the other processes'
/// nor the kernel's files.
pub fn runtime_files() -> Vec<PathBuf> {
    READABLE.iter().map(PathBuf::from).collect()
}

/// What the directory fetcher needs: the runtime's files and the directory
/// it serves, the staging it was handed (set by the caller).
pub fn dir_reach(dir: &Path) -> Reach {
    let mut read = runtime_files();
    read.push(dir.to_path_buf());
    Reach {
        read,
        ..Reach::default()
    }
}

/// What the directory fetcher as the origin of a path needs: the runtime's
/// files; the origin it was handed (set by the caller as `origin` when it
/// is a directory: an archive is read from the file it was handed) and the
/// staging it was handed (set by the caller).
pub fn dir_origin_reach() -> Reach {
    Reach {
        read: runtime_files(),
        ..Reach::default()
    }
}

/// What the directory as a pusher needs: the runtime's files; what it
/// writes is the destination it was handed (set by the caller as `staging`,
/// and none for an archive: it writes to the file it was handed).
pub fn dir_push_reach() -> Reach {
    Reach {
        read: runtime_files(),
        ..Reach::default()
    }
}

/// Which Landlock ABI the kernel has and how much of the ruleset it
/// enforces, for the logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enforced {
    /// The ABI of the access rights asked for (the newest both the kernel
    /// and the crate know)
    pub abi: ABI,
    /// The ABI of the kernel when it is newer than the crate's
    pub kernel_abi: Option<i32>,
}

fn landlock(access: &Reach, role: Role) -> Result<Enforced, String> {
    use velarx_sys::ruleset::{self, Handles, Must, Rules};
    // (the spawner's domain is the workers': each narrows it to its own ports)
    let tcp = match role {
        Role::Spawner => AccessNet::BindTcp.into(),
        Role::Front | Role::Dir | Role::DirPush => AccessNet::BindTcp | AccessNet::ConnectTcp,
    };
    // (every right is a must: a kernel that has not all of them does not
    // run the fetcher)
    let mut rules = Rules::new(Handles {
        abi: NEWEST,
        net: tcp,
        scopes: true,
        must: Must::Everything,
    })?;
    let read = AccessFs::ReadFile | AccessFs::ReadDir;
    let execute = AccessFs::Execute | AccessFs::ReadFile;
    let state = AccessFs::ReadFile
        | AccessFs::ReadDir
        | AccessFs::WriteFile
        | AccessFs::MakeReg
        | AccessFs::RemoveFile;
    // The standard streams of the workers, and their own user namespace
    // maps (/proc/self/uid_map is the worker's, under /proc, not under the
    // front's own directory).  Another process' memory stays out of reach:
    // Landlock refuses the access to a process outside the domain.
    let null = vec![PathBuf::from("/dev/null"), PathBuf::from("/proc")];
    let cgroups: Vec<PathBuf> = access.cgroups.iter().cloned().collect();
    let cgroup = AccessFs::ReadFile
        | AccessFs::ReadDir
        | AccessFs::WriteFile
        | AccessFs::Truncate
        | AccessFs::MakeDir
        | AccessFs::RemoveDir;
    let none: Vec<PathBuf> = Vec::new();
    let (execute_at, null_at, remove_at, state_at, cgroups_at) = match role {
        Role::Spawner => (&access.execute, &null, &none, &none, &none),
        Role::Front => (&none, &none, &access.remove, &access.state, &cgroups),
        Role::Dir | Role::DirPush => (&none, &none, &none, &none, &none),
    };
    for (paths, allowed) in [
        (&access.read, read),
        (execute_at, execute),
        (null_at, AccessFs::WriteFile | AccessFs::Truncate),
        (remove_at, AccessFs::RemoveFile.into()),
        (state_at, state),
        (cgroups_at, cgroup),
    ] {
        for path in paths {
            // (what the system does not have cannot be used)
            rules.beneath_if_present(path, allowed)?;
        }
    }
    if let Some(staging) = access.staging.as_ref().filter(|_| role != Role::Spawner) {
        rules
            .beneath_dir(staging.as_fd(), ruleset::stager_rights_with_removal())
            .map_err(|e| format!("the staging: {e}"))?;
    }
    if let Some(origin) = access.origin.as_ref().filter(|_| role == Role::Dir) {
        rules
            .beneath_dir(origin.as_fd(), read)
            .map_err(|e| format!("the origin: {e}"))?;
    }
    let restricted = rules.restrict_fully("the fetcher")?;
    Ok(Enforced {
        abi: restricted.abi,
        kernel_abi: restricted.kernel_abi,
    })
}

/// The capabilities the spawner keeps: what a worker needs to start, which
/// it inherits through `execve` only from what this process has.  A worker
/// of a root process becomes `nobody` (`CAP_SETUID`, `CAP_SETGID`), and one
/// of a process that is root of a user namespace (a rootless engine) maps
/// the root of that namespace in the one it makes, which the kernel allows
/// if the process had `CAP_SETFCAP` when it made it.  An unprivileged
/// process has none of them to keep.
///
/// `CAP_DAC_READ_SEARCH` (2) stays, for reading only: the engine of a user
/// started with `sudo` has the auth files, the registries configuration and
/// the worker binary below a private home directory (mode 0700), which root
/// without it cannot even look up (a missing `~/.docker` is then "permission
/// denied", and Landlock cannot open the worker's path to allow it).
/// Landlock still decides which of them the process reads.
const SPAWNER_CAPABILITIES: [u32; 5] = [2, 6, 7, 8, 31];

/// What the front and the directory fetcher keep: that read.
const READER_CAPABILITIES: [u32; 1] = [2];

fn kept_capabilities(role: Role) -> &'static [u32] {
    match role {
        Role::Spawner => &SPAWNER_CAPABILITIES,
        Role::Front | Role::Dir | Role::DirPush => &READER_CAPABILITIES,
    }
}

/// Give up every capability but those `role` keeps (that this process has),
/// in the bounding set and in the process.
fn drop_capabilities(role: Role) -> Result<(), String> {
    use rustix::thread::CapabilitySet;
    let kept = kept_capabilities(role);
    velarx_sys::caps::drop_bounding_except(|c| kept.contains(&c))
        .map_err(|e| format!("capabilities of the bounding set: {e}"))?;
    velarx_sys::caps::clear_ambient().map_err(|e| format!("ambient capabilities: {e}"))?;
    let mut sets = rustix::thread::capabilities(None).map_err(|e| format!("capget: {e}"))?;
    let keep = CapabilitySet::from_bits_retain(kept.iter().fold(0u64, |m, c| m | 1 << c));
    sets.permitted &= keep;
    sets.effective &= sets.permitted;
    sets.inheritable = CapabilitySet::empty();
    rustix::thread::set_capabilities(None, sets).map_err(|e| format!("capset: {e}"))?;
    Ok(())
}

/// What the process of each role makes, and no more.
///
/// * The spawner: what a pull worker makes (the runtime, the files it
///   reads, IPv4 and IPv6 sockets, socket pairs) and what starting a worker
///   needs, which a worker's own list refuses once it runs: it executes,
///   becomes `nobody`, unshares its namespaces and confines itself with
///   Landlock and seccomp.  The worker starts under this filter, so it
///   holds also the calls of its start-up; it only ever adds to what it
///   refuses for itself.  The spawner stages nothing, makes no file and
///   serves no socket: it is told what to start over a socket pair.
/// * The front and the directory fetcher: the runtime, the files they read,
///   socket pairs for the connections they hand out, and the stager
///   (`openat2` beneath, `O_TMPFILE`, `linkat`, fs-verity, sealed memory
///   files).  No socket of any family (the connection they serve is a
///   descriptor they were started with, the front of a shared service
///   accepts on the listener it inherited), no `connect`, no resolver.
///   The front makes and removes the cgroups of its pools and replaces the
///   file of its hints; the directory fetcher makes the directories of the
///   staging and does neither.
fn allowed(pid: u32, role: Role) -> Result<Allow, String> {
    use velarx_sys::allow::{is, lacks, one_of};
    let nobody = |arg: u8| is(arg, NOBODY);
    // A process is started with `clone` in the namespaces of its parent:
    // the namespaces are the worker's to make, by itself.
    let new_flags = u64::from(velarx_sys::confine::CLONE_NEW_FLAGS);
    let allow = net_client(Allow::runtime(pid)?);
    if role != Role::Spawner {
        return serving(allow, role);
    }
    let allow = allow
        .calls(&[
            libc::SYS_getdents64,
            libc::SYS_getegid,
            // a worker starting
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_unshare,
            libc::SYS_setsid,
            libc::SYS_wait4,
            libc::SYS_waitid,
            libc::SYS_pidfd_open,
            libc::SYS_pidfd_send_signal,
            libc::SYS_close_range,
            libc::SYS_capget,
            libc::SYS_capset,
            libc::SYS_seccomp,
            libc::SYS_landlock_create_ruleset,
            libc::SYS_landlock_add_rule,
            libc::SYS_landlock_restrict_self,
        ])
        // (a worker sets its own limits: no other process' are touched)
        .when(libc::SYS_prlimit64, vec![velarx_sys::allow::is_wide(0, 0)])
        .when(
            libc::SYS_prctl,
            one_of(
                0,
                &[
                    libc::PR_SET_NAME as u64,
                    libc::PR_GET_NAME as u64,
                    libc::PR_GET_DUMPABLE as u64,
                    libc::PR_GET_NO_NEW_PRIVS as u64,
                    0x5356_4d41, // PR_SET_VMA
                    libc::PR_SET_NO_NEW_PRIVS as u64,
                    libc::PR_SET_DUMPABLE as u64,
                    libc::PR_SET_PDEATHSIG as u64,
                    libc::PR_CAPBSET_DROP as u64,
                    libc::PR_CAPBSET_READ as u64,
                    libc::PR_CAP_AMBIENT as u64,
                ],
            ),
        )
        // a thread, or a process in the namespaces of its parent
        .when(libc::SYS_clone, vec![lacks(0, new_flags)])
        // a worker of a root process becomes `nobody` and has no group: no
        // other user or group is to be had
        .when(libc::SYS_setuid, vec![nobody(0)])
        .when(libc::SYS_setgid, vec![nobody(0)])
        .when(
            libc::SYS_setresuid,
            vec![velarx_sys::allow::all_are(&[
                (0, NOBODY),
                (1, NOBODY),
                (2, NOBODY),
            ])],
        )
        .when(
            libc::SYS_setresgid,
            vec![velarx_sys::allow::all_are(&[
                (0, NOBODY),
                (1, NOBODY),
                (2, NOBODY),
            ])],
        )
        .when(libc::SYS_setgroups, vec![velarx_sys::allow::is_wide(0, 0)]);
    #[cfg(target_arch = "x86_64")]
    let allow = allow.calls(&[libc::SYS_arch_prctl, libc::SYS_fork, libc::SYS_vfork]);
    Ok(allow)
}

/// The list of the front and of the directory fetcher ([`allowed`]).
fn serving(allow: Allow, role: Role) -> Result<Allow, String> {
    use velarx_sys::allow::one_of;
    let allow = allow
        // (no resolver, no network: the sockets of the runtime's own
        // helpers are socket pairs)
        .without(&[
            libc::SYS_connect,
            libc::SYS_sendmmsg,
            libc::SYS_recvmmsg,
            libc::SYS_uname,
            libc::SYS_socket,
        ])
        .calls(&[
            libc::SYS_getdents64,
            libc::SYS_pread64,
            libc::SYS_fsync,
            libc::SYS_flock,
            libc::SYS_pwrite64,
            libc::SYS_pwritev,
            libc::SYS_fallocate,
            libc::SYS_ftruncate,
            libc::SYS_unlinkat,
            libc::SYS_mkdirat,
            libc::SYS_utimensat,
            libc::SYS_getegid,
        ])
        // the stager: files with no name beneath the staging (`openat2`
        // BENEATH, `O_TMPFILE`), named with `linkat`; fs-verity enabled and
        // measured (the Merkle block size follows the block size of the
        // file system: `fstatfs`); the sealed memory files of the replies
        .calls(&[libc::SYS_openat2, libc::SYS_linkat, libc::SYS_fstatfs])
        .plus(
            libc::SYS_ioctl,
            one_of(1, &[FS_IOC_ENABLE_VERITY, FS_IOC_MEASURE_VERITY]),
        )
        .when(
            libc::SYS_memfd_create,
            vec![velarx_sys::allow::is_wide(
                1,
                u64::from(libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING),
            )],
        )
        // (nothing is executed, no namespace made, no user or group taken,
        // no process started but threads)
        .when(libc::SYS_clone, vec![velarx_sys::allow::threads_only()?]);
    #[cfg(target_arch = "x86_64")]
    let allow = allow.calls(&[libc::SYS_arch_prctl, libc::SYS_unlink, libc::SYS_mkdir]);
    let allow = match role {
        // (the hints file is replaced; a shared service accepts on the
        // listener it inherited)
        Role::Front => allow.calls(&[libc::SYS_renameat, libc::SYS_renameat2, libc::SYS_accept4]),
        // (the index of a layout is replaced whole)
        Role::DirPush => allow.calls(&[libc::SYS_renameat, libc::SYS_renameat2]),
        _ => allow,
    };
    #[cfg(target_arch = "x86_64")]
    let allow = if matches!(role, Role::Front | Role::DirPush) {
        allow.calls(&[libc::SYS_rename])
    } else {
        allow
    };
    Ok(allow)
}

fn seccomp(role: Role) -> Result<(), String> {
    allow::apply(&allowed(std::process::id(), role)?.programs()?)
}

/// Confine the process as `role`.  Call it before any thread is started (the
/// runtime): Landlock and seccomp apply to the threads created afterwards.
pub fn enter(access: &Reach, role: Role) -> Result<Enforced, String> {
    velarx_sys::confine::require_single_thread()?;
    rustix::thread::set_no_new_privs(true).map_err(|e| format!("PR_SET_NO_NEW_PRIVS: {e}"))?;
    // (root of the initial user namespace: the kernel's files read-only in a
    // mount namespace of its own, which needs the capability dropped next)
    let read_only = tunables::protect_kernel_tunables()?;
    if !read_only.is_empty() {
        tracing::debug!("read-only in the front process' mount namespace: {read_only:?}");
    }
    drop_capabilities(role)?;
    // (no /proc once confined)
    velarx_base::ids::settle().map_err(|e| e.to_string())?;
    let enforced = landlock(access, role)?;
    seccomp(role)?;
    Ok(enforced)
}

/// Try, in the confined front, what its confinement allows and refuses:
/// `(what, as it should be)`.  `staging`: the staging it was given, the
/// only place it writes; `socket`: a socket bound before the confinement.
pub fn probes(staging: &std::os::fd::OwnedFd, socket: Option<&Path>) -> Vec<(String, bool)> {
    use rustix::fs::{openat, unlinkat, AtFlags, Mode, OFlags};
    use rustix::io::Errno;
    let mut out: Vec<(String, bool)> = Vec::new();
    let mut check = |what: &str, ok: bool| out.push((what.to_string(), ok));
    let make = |dir: std::os::fd::BorrowedFd<'_>, name: &str| {
        openat(
            dir,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
    };
    const PROBE: &str = ".velarx-registry-probe";
    let made = make(staging.as_fd(), PROBE);
    check("makes a file beneath the staging", made.is_ok());
    if made.is_ok() {
        check(
            "removes it",
            unlinkat(staging.as_fd(), PROBE, AtFlags::empty()).is_ok(),
        );
    }
    let next_to = make(staging.as_fd(), &format!("../{PROBE}"));
    check(
        "makes nothing next to the staging",
        next_to.as_ref().err() == Some(&Errno::ACCESS),
    );
    if next_to.is_ok() {
        let _ = unlinkat(staging.as_fd(), format!("../{PROBE}"), AtFlags::empty());
    }
    let tmp = make(rustix::fs::CWD, &format!("/tmp/{PROBE}"));
    check(
        "makes nothing in /tmp",
        tmp.as_ref().err() == Some(&Errno::ACCESS),
    );
    if tmp.is_ok() {
        let _ = rustix::fs::unlink(format!("/tmp/{PROBE}"));
    }
    out.extend(refusals(socket));
    out
}

/// What every confined process of the fetchers is refused whatever it is for:
/// `(what, as it should be)`; `socket`: a socket bound before the
/// confinement.
pub fn refusals(socket: Option<&Path>) -> Vec<(String, bool)> {
    let mut out: Vec<(String, bool)> = Vec::new();
    let mut check = |what: &str, ok: bool| out.push((what.to_string(), ok));
    // (a socket bound before the confinement, as the engine's is)
    if let Some(socket) = socket {
        let refused = std::os::unix::net::UnixStream::connect(socket)
            .err()
            .and_then(|e| e.raw_os_error());
        // (the filter has no `socket` at all: `EPERM`; Landlock refuses the
        // lookup of the name to a process that has one)
        check(
            "connects to no UNIX socket by name",
            matches!(refused, Some(libc::EACCES | libc::EPERM)),
        );
    }
    check(
        "reads nothing it does not need",
        std::fs::read("/etc/passwd")
            .err()
            .and_then(|e| e.raw_os_error())
            == Some(libc::EACCES),
    );
    // (an exec that succeeded would replace the self-test: it is refused)
    check(
        "executes nothing",
        velarx_sys::process::try_exec(c"/usr/bin/true") == libc::EPERM,
    );
    check(
        "starts no process",
        std::process::Command::new("/usr/bin/true").spawn().is_err()
            && velarx_sys::probe::clone_new_user() == Err(libc::EPERM),
    );
    check(
        "makes no namespace",
        velarx_sys::namespace::unshare(rustix::thread::UnshareFlags::NEWUSER).is_err(),
    );
    let parent = rustix::process::getppid().map_or(0, |p| p.as_raw_nonzero().get());
    check(
        "signals no process outside its domain",
        velarx_sys::probe::kill_nothing(parent) == Err(libc::EPERM),
    );
    // (the filter of the front has no socket of the network at all; the
    // Landlock rules refuse the port to the others)
    let refused = |errno: Option<i32>| errno.is_some_and(|e| e == libc::EPERM || e == libc::EACCES);
    let bound = std::net::TcpListener::bind("127.0.0.1:0")
        .err()
        .and_then(|e| e.raw_os_error());
    check("binds no TCP port", refused(bound));
    check(
        "connects to no TCP port",
        refused(
            std::net::TcpStream::connect("127.0.0.1:9")
                .err()
                .and_then(|e| e.raw_os_error()),
        ),
    );
    check(
        "mounts nothing",
        rustix::mount::mount(
            "none",
            "/tmp",
            "tmpfs",
            rustix::mount::MountFlags::empty(),
            None,
        )
        .is_err(),
    );
    let every = velarx_sys::probe::every_thread_has;
    check("seccomp on every thread", every("Seccomp", "2"));
    check("no_new_privs on every thread", every("NoNewPrivs", "1"));
    out
}

/// The name of the socket the self-tests bind in the staging, before the
/// confinement.
pub const PROBE_SOCKET: &str = ".velarx-probe.sock";

#[cfg(test)]
mod tests {
    use super::*;

    /// The program of the front process, evaluated: a pull worker's calls,
    /// the sockets it serves, and what starting a worker needs; the rest of
    /// the kernel is refused.
    #[test]
    fn the_spawner_filter_allows_a_worker_and_its_start() {
        use velarx_sys::allow::testing::{check, verdicts, ALLOW, ENOSYS, EPERM};
        let verdict = verdicts(allowed(1, Role::Spawner).unwrap());
        let af = |d: i32| [d as u64, 0, 0, 0, 0, 0];
        let id = |v: u64| [v, v, v, 0, 0, 0];
        let table: &[velarx_sys::allow::testing::Expect] = &[
            (libc::SYS_futex, [0; 6], ALLOW),
            (libc::SYS_openat, [0; 6], ALLOW),
            (libc::SYS_connect, [0; 6], ALLOW),
            // (it serves no socket and stages nothing: it is told what to
            // start over a socket pair)
            (libc::SYS_accept4, [0; 6], EPERM),
            (libc::SYS_listen, [0; 6], EPERM),
            (libc::SYS_bind, [0; 6], EPERM),
            (
                libc::SYS_socket,
                [2, libc::SOCK_STREAM as u64, 0, 0, 0, 0],
                ALLOW,
            ),
            (
                libc::SYS_socket,
                [2, libc::SOCK_DGRAM as u64, 0, 0, 0, 0],
                EPERM,
            ),
            (libc::SYS_socket, af(libc::AF_UNIX), EPERM),
            (libc::SYS_socket, af(libc::AF_NETLINK), EPERM),
            (libc::SYS_socket, af(libc::AF_PACKET), EPERM),
            // the limits of its own process only
            (libc::SYS_prlimit64, [0, 1, 0x1000, 0, 0, 0], ALLOW),
            (libc::SYS_prlimit64, [2, 1, 0x1000, 0, 0, 0], EPERM),
            // a worker starting: a process in the namespaces of its parent,
            // the program, the namespaces it makes for itself, nobody
            (
                libc::SYS_clone,
                [libc::SIGCHLD as u64, 0, 0, 0, 0, 0],
                ALLOW,
            ),
            (
                libc::SYS_clone,
                [(libc::SIGCHLD | libc::CLONE_NEWUSER) as u64, 0, 0, 0, 0, 0],
                EPERM,
            ),
            (libc::SYS_clone3, [0; 6], ENOSYS),
            (libc::SYS_execve, [0; 6], ALLOW),
            (libc::SYS_unshare, [0; 6], ALLOW),
            (libc::SYS_landlock_restrict_self, [0; 6], ALLOW),
            (libc::SYS_setresuid, id(NOBODY), ALLOW),
            (libc::SYS_setresuid, id(0), EPERM),
            (libc::SYS_setresgid, id(NOBODY), ALLOW),
            (libc::SYS_setuid, [NOBODY, 0, 0, 0, 0, 0], ALLOW),
            (libc::SYS_setuid, [0; 6], EPERM),
            (libc::SYS_setgroups, [0; 6], ALLOW),
            (libc::SYS_setgroups, [1, 0, 0, 0, 0, 0], EPERM),
            // the rest of the kernel
            (libc::SYS_mount, [0; 6], EPERM),
            (libc::SYS_setns, [0; 6], EPERM),
            (libc::SYS_ptrace, [0; 6], EPERM),
            (libc::SYS_kill, [0; 6], EPERM),
            (libc::SYS_memfd_create, [0; 6], EPERM),
            (libc::SYS_memfd_create, [0, 3, 0, 0, 0, 0], EPERM),
            (
                libc::SYS_ioctl,
                [0, FS_IOC_ENABLE_VERITY, 0, 0, 0, 0],
                EPERM,
            ),
            (libc::SYS_linkat, [0; 6], EPERM),
            (libc::SYS_openat2, [0; 6], EPERM),
            (libc::SYS_unlinkat, [0; 6], EPERM),
            (libc::SYS_renameat, [0; 6], EPERM),
            (libc::SYS_open_by_handle_at, [0; 6], EPERM),
            (libc::SYS_io_uring_setup, [0; 6], EPERM),
        ];
        check(&verdict, table);
    }

    /// The program of the directory fetcher, evaluated: the stager and the
    /// connection it was started with, no socket, no accept, no rename.
    #[test]
    fn the_directory_filter_has_no_socket_and_no_rename() {
        use velarx_sys::allow::testing::{check, verdicts, ALLOW, EPERM};
        let verdict = verdicts(allowed(1, Role::Dir).unwrap());
        let af = |d: i32| [d as u64, 0, 0, 0, 0, 0];
        let table: &[velarx_sys::allow::testing::Expect] = &[
            (libc::SYS_openat2, [0; 6], ALLOW),
            (libc::SYS_linkat, [0; 6], ALLOW),
            (libc::SYS_fstatfs, [0; 6], ALLOW),
            (libc::SYS_mkdirat, [0; 6], ALLOW),
            (libc::SYS_socketpair, af(libc::AF_UNIX), ALLOW),
            (libc::SYS_socket, af(libc::AF_UNIX), EPERM),
            (libc::SYS_accept4, [0; 6], EPERM),
            (libc::SYS_bind, [0; 6], EPERM),
            (libc::SYS_listen, [0; 6], EPERM),
            (libc::SYS_connect, [0; 6], EPERM),
            (libc::SYS_renameat, [0; 6], EPERM),
            (libc::SYS_renameat2, [0; 6], EPERM),
            (libc::SYS_execve, [0; 6], EPERM),
        ];
        check(&verdict, table);
    }

    /// The program of the front process, evaluated: it serves its sockets
    /// and stages files, and starts no program, no process and no
    /// namespace, takes no other user and opens no socket of the network.
    #[test]
    fn the_front_filter_has_no_exec_no_process_and_no_namespace() {
        use velarx_sys::allow::testing::{check, verdicts, ALLOW, ENOSYS, EPERM};
        let verdict = verdicts(allowed(1, Role::Front).unwrap());
        let af = |d: i32| [d as u64, 0, 0, 0, 0, 0];
        let thread = (libc::CLONE_THREAD
            | libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND) as u64;
        let table: &[velarx_sys::allow::testing::Expect] = &[
            (libc::SYS_futex, [0; 6], ALLOW),
            (libc::SYS_openat, [0; 6], ALLOW),
            // (a shared service accepts on the listener it inherited, and
            // binds nothing; the connection of a private one is a descriptor)
            (libc::SYS_accept4, [0; 6], ALLOW),
            (libc::SYS_listen, [0; 6], EPERM),
            (libc::SYS_bind, [0; 6], EPERM),
            (libc::SYS_connect, [0; 6], EPERM),
            (libc::SYS_sendmmsg, [0; 6], EPERM),
            (libc::SYS_renameat, [0; 6], ALLOW),
            (libc::SYS_socket, af(libc::AF_UNIX), EPERM),
            (libc::SYS_socket, af(libc::AF_INET), EPERM),
            (libc::SYS_socket, af(libc::AF_INET6), EPERM),
            (libc::SYS_socket, af(libc::AF_NETLINK), EPERM),
            (libc::SYS_clone, [thread, 0, 0, 0, 0, 0], ALLOW),
            (
                libc::SYS_clone,
                [libc::SIGCHLD as u64, 0, 0, 0, 0, 0],
                EPERM,
            ),
            (libc::SYS_clone3, [0; 6], ENOSYS),
            (libc::SYS_fork, [0; 6], EPERM),
            (libc::SYS_vfork, [0; 6], EPERM),
            (libc::SYS_execve, [0; 6], EPERM),
            (libc::SYS_execveat, [0; 6], EPERM),
            (libc::SYS_unshare, [0; 6], EPERM),
            (libc::SYS_setns, [0; 6], EPERM),
            (libc::SYS_setuid, [0; 6], EPERM),
            (libc::SYS_setresuid, [65534; 6], EPERM),
            (libc::SYS_setgroups, [0; 6], EPERM),
            (libc::SYS_wait4, [0; 6], EPERM),
            (libc::SYS_pidfd_open, [0; 6], EPERM),
            (libc::SYS_pidfd_send_signal, [0; 6], EPERM),
            (libc::SYS_landlock_restrict_self, [0; 6], EPERM),
            (libc::SYS_seccomp, [0; 6], EPERM),
            (libc::SYS_capset, [0; 6], EPERM),
            (libc::SYS_memfd_create, [0, 3, 0, 0, 0, 0], ALLOW),
            (
                libc::SYS_ioctl,
                [0, FS_IOC_ENABLE_VERITY, 0, 0, 0, 0],
                ALLOW,
            ),
            (libc::SYS_linkat, [0; 6], ALLOW),
            (libc::SYS_openat2, [0; 6], ALLOW),
            (libc::SYS_fstatfs, [0; 6], ALLOW),
            (libc::SYS_mount, [0; 6], EPERM),
            (libc::SYS_ptrace, [0; 6], EPERM),
            (libc::SYS_kill, [0; 6], EPERM),
        ];
        check(&verdict, table);
    }

    /// The paths a test child may reach: a directory it reads, one it may
    /// not, and a program it may execute.
    fn paths(dir: &Path) -> Reach {
        let read = dir.join("read");
        std::fs::create_dir_all(&read).unwrap();
        std::fs::write(read.join("registries.conf"), "x").unwrap();
        let mut access = Reach {
            read: READABLE.iter().map(PathBuf::from).collect(),
            execute: LOADERS.iter().map(PathBuf::from).collect(),
            remove: vec![],
            cgroups: None,
            state: vec![dir.join("state")],
            staging: None,
            origin: None,
        };
        std::fs::create_dir_all(dir.join("state")).unwrap();
        access.read.push(read);
        access.execute.push(PathBuf::from("/usr/bin/true"));
        access
    }

    /// What the confined spawner can and cannot do, tried in a child of the
    /// test binary: it keeps what starting a worker needs and nothing else.
    #[test]
    fn the_spawner_keeps_what_starting_a_worker_needs_and_nothing_else() {
        // (made and removed by the test process: the confined child that
        // uses it may not remove it)
        let dir = tempfile::tempdir().unwrap();
        velarx_base::testing::in_child(|| {
            let access = paths(dir.path());
            // (root keeps the capabilities it had of SPAWNER_CAPABILITIES, a
            // user none)
            let kept = rustix::thread::capabilities(None).unwrap().effective.bits()
                & SPAWNER_CAPABILITIES.iter().fold(0u64, |m, c| m | 1 << c);
            let enforced = enter(&access, Role::Spawner).expect("the spawner confines itself");
            assert!(enforced.abi >= ABI::V1);
            let mut failed = Vec::new();
            let mut check = |what: &str, ok: bool| {
                if !ok {
                    failed.push(what.to_string());
                }
            };
            check(
                "reads its configuration",
                std::fs::read(dir.path().join("read/registries.conf")).is_ok(),
            );
            check("reads the libraries", std::fs::read_dir("/usr/lib").is_ok());
            check("reads nothing else", std::fs::read("/etc/passwd").is_err());
            check(
                "writes nothing",
                std::fs::write(dir.path().join("outside"), "x").is_err()
                    && std::fs::write(dir.path().join("read/new"), "x").is_err(),
            );
            check(
                "executes the worker",
                std::process::Command::new("/usr/bin/true")
                    .status()
                    .is_ok_and(|s| s.success()),
            );
            check(
                "executes nothing else",
                std::process::Command::new("/usr/bin/id").status().is_err(),
            );
            // a child that unshares its namespaces and drops its user, as a
            // worker does, still can
            let unshared_or_refused =
                |e: &std::io::Error| matches!(e.raw_os_error(), Some(libc::EPERM | libc::ENOSPC));
            let forked = velarx_sys::process::fork_status(|| {
                let ok = match velarx_sys::namespace::unshare(
                    rustix::thread::UnshareFlags::NEWUSER | rustix::thread::UnshareFlags::NEWNS,
                ) {
                    Ok(()) => true,
                    Err(e) => unshared_or_refused(&e),
                };
                i32::from(!ok)
            });
            check("forks", forked.is_ok());
            check(
                "a child unshares its namespaces",
                forked.is_ok_and(|c| c == 0),
            );
            // the front makes none itself
            check(
                "no clone into new namespaces",
                velarx_sys::probe::clone_new_user() == Err(libc::EPERM),
            );
            check(
                "no mount",
                rustix::mount::mount(
                    "none",
                    "/tmp",
                    "tmpfs",
                    rustix::mount::MountFlags::empty(),
                    None,
                )
                .is_err(),
            );
            check("no ptrace", velarx_sys::probe::ptrace_attach(1).is_err());
            check(
                "no io_uring",
                velarx_sys::probe::io_uring_setup().err() == Some(libc::EPERM),
            );
            // the kernel's files: root of the initial user namespace had them
            // read-only made (EROFS); anyone else is refused by the permission bits
            let write_errno = |path: &str| {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(path)
                    .err()
                    .and_then(|e| e.raw_os_error())
            };
            let root = tunables::is_global_root().unwrap();
            for path in [
                "/proc/sys/kernel/printk_ratelimit",
                "/proc/sys/kernel/core_pattern",
                "/proc/sysrq-trigger",
            ] {
                check(
                    path,
                    write_errno(path) == Some(if root { libc::EROFS } else { libc::EACCES }),
                );
            }
            // (other processes' files are out of the domain's reach, and the
            // mount namespace of the host's init is the way around the above)
            check(
                "not through init's root",
                write_errno("/proc/1/root/proc/sys/kernel/core_pattern").is_some_and(|e| e != 0),
            );
            check(
                "not init's memory",
                std::fs::OpenOptions::new()
                    .write(true)
                    .open("/proc/1/mem")
                    .is_err(),
            );
            // a worker still writes the maps of its own user namespace
            let mapped = velarx_sys::process::fork_status(|| {
                let ok = match velarx_sys::namespace::unshare_user_mapped_to_root(
                    rustix::thread::UnshareFlags::NEWNS,
                ) {
                    Ok(()) => true,
                    // (a kernel that refuses user namespaces: nothing to write)
                    Err(e) => unshared_or_refused(&e),
                };
                i32::from(!ok)
            });
            check("a worker writes its maps", mapped.is_ok_and(|c| c == 0));
            // the sockets of every family a worker uses
            check(
                "an IPv4 socket",
                rustix::net::socket(
                    rustix::net::AddressFamily::INET,
                    rustix::net::SocketType::STREAM,
                    None,
                )
                .is_ok(),
            );
            check(
                "no_new_privs",
                rustix::thread::no_new_privs().unwrap_or(false),
            );
            check("a thread", velarx_sys::probe::a_thread_runs());
            // (what the kernel says of every thread, one made after it too:
            // the threads of the runtime are)
            let every = velarx_sys::probe::every_thread_has;
            check("no_new_privs on every thread", every("NoNewPrivs", "1"));
            check("seccomp on every thread", every("Seccomp", "2"));
            check(
                "no capability on any thread but the kept ones",
                every("CapEff", &format!("{kept:016x}")),
            );
            assert!(failed.is_empty(), "{failed:?}");
        });
    }

    /// What the confined front can and cannot do: it serves, keeps its hints
    /// and stages, and starts nothing, makes no namespace and connects
    /// nowhere.
    #[test]
    fn the_front_process_executes_nothing_and_starts_nothing() {
        // (made and removed by the test process: the confined child that
        // uses it may not remove it)
        let dir = tempfile::tempdir().unwrap();
        velarx_base::testing::in_child(|| {
            let access = paths(dir.path());
            let kept = rustix::thread::capabilities(None).unwrap().effective.bits()
                & READER_CAPABILITIES.iter().fold(0u64, |m, c| m | 1 << c);
            let enforced = enter(&access, Role::Front).expect("the front process confines itself");
            assert!(enforced.abi >= ABI::V1);
            let mut failed = Vec::new();
            let mut check = |what: &str, ok: bool| {
                if !ok {
                    failed.push(what.to_string());
                }
            };
            check(
                "reads its configuration",
                std::fs::read(dir.path().join("read/registries.conf")).is_ok(),
            );
            check("reads nothing else", std::fs::read("/etc/passwd").is_err());
            check(
                "writes nothing",
                std::fs::write(dir.path().join("outside"), "x").is_err()
                    && std::fs::write(dir.path().join("read/new"), "x").is_err(),
            );
            // the registry hints: files made and replaced in their directory
            let state = dir.path().join("state");
            check(
                "keeps its hints",
                std::fs::write(state.join(".tmp"), "x").is_ok()
                    && std::fs::rename(state.join(".tmp"), state.join("hints")).is_ok()
                    && std::fs::write(state.join(".tmp"), "y").is_ok()
                    && std::fs::rename(state.join(".tmp"), state.join("hints")).is_ok()
                    && std::fs::read(state.join("hints")).is_ok_and(|b| b == b"y"),
            );
            check(
                "makes nothing but files in the hints directory",
                std::fs::create_dir(state.join("d")).is_err()
                    && std::os::unix::fs::symlink("/etc/passwd", state.join("l")).is_err()
                    && std::fs::write(dir.path().join("read/new"), "x").is_err(),
            );
            // (the seccomp filter says EPERM before Landlock is asked)
            check(
                "execve is refused",
                velarx_sys::process::try_exec(c"/usr/bin/true") == libc::EPERM,
            );
            check(
                "no program is started",
                std::process::Command::new("/usr/bin/true")
                    .status()
                    .is_err(),
            );
            check(
                "no unshare",
                velarx_sys::namespace::unshare(rustix::thread::UnshareFlags::NEWUSER).is_err(),
            );
            check(
                "no clone into new namespaces",
                velarx_sys::probe::clone_new_user() == Err(libc::EPERM),
            );
            check("no fork", velarx_sys::process::fork_status(|| 0).is_err());
            // (no socket of the network: seccomp refuses it before Landlock
            // is asked for the port)
            check(
                "connects to no TCP port",
                std::net::TcpStream::connect("127.0.0.1:9")
                    .err()
                    .and_then(|e| e.raw_os_error())
                    .is_some_and(|e| e == libc::EPERM || e == libc::EACCES),
            );
            check(
                "no socket of the network",
                std::net::UdpSocket::bind("127.0.0.1:0").is_err(),
            );
            check(
                "no mount",
                rustix::mount::mount(
                    "none",
                    "/tmp",
                    "tmpfs",
                    rustix::mount::MountFlags::empty(),
                    None,
                )
                .is_err(),
            );
            check("no ptrace", velarx_sys::probe::ptrace_attach(1).is_err());
            check(
                "no io_uring",
                velarx_sys::probe::io_uring_setup().err() == Some(libc::EPERM),
            );
            check("a thread", velarx_sys::probe::a_thread_runs());
            let every = velarx_sys::probe::every_thread_has;
            check("no_new_privs on every thread", every("NoNewPrivs", "1"));
            check("seccomp on every thread", every("Seccomp", "2"));
            check(
                "no capability on any thread but the kept ones",
                every("CapEff", &format!("{kept:016x}")),
            );
            assert!(failed.is_empty(), "{failed:?}");
        });
    }

    /// The directory of the socket it bound: the front takes the socket away
    /// and cannot make anything there.
    #[test]
    fn the_front_removes_its_socket_and_makes_nothing_in_the_services_directory() {
        // (made and removed by the test process: the confined child that
        // uses it may not remove it)
        let dir = tempfile::tempdir().unwrap();
        velarx_base::testing::in_child(|| {
            let mut access = paths(dir.path());
            let services = dir.path().join("services");
            std::fs::create_dir(&services).unwrap();
            let socket = services.join("registry.sock");
            let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
            std::fs::create_dir(services.join("dir")).unwrap();
            // (the socket of another service, beside the directory of this one)
            let beside = dir.path().join("beside.sock");
            let _other = std::os::unix::net::UnixListener::bind(&beside).unwrap();
            access.remove.push(services.clone());
            enter(&access, Role::Front).expect("the front process confines itself");
            assert!(std::fs::write(services.join("new"), "x").is_err());
            assert!(std::fs::create_dir(services.join("new")).is_err());
            assert!(std::os::unix::fs::symlink("/x", services.join("link")).is_err());
            assert!(std::os::unix::net::UnixListener::bind(services.join("other.sock")).is_err());
            assert!(std::fs::rename(&socket, services.join("moved")).is_err());
            assert!(std::fs::remove_dir(services.join("dir")).is_err());
            assert!(std::fs::remove_file(&beside).is_err());
            std::fs::remove_file(&socket).expect("the front removes its socket");
        });
    }
}
