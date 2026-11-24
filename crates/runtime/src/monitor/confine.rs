// SPDX-License-Identifier: Apache-2.0
//! The threads of the monitor that read what others send confine
//! themselves when they start (docs/THREAT-MODEL.md, the monitor).
//!
//! The monitor itself cannot be confined: it forks the OCI runtime, the
//! hooks, pasta and the fetcher, and a
//! child inherits Landlock and seccomp, the container's processes too.  So
//! the confinement is of threads (`velarx_sys::confine`: the calling thread
//! and those it makes, never the rest of the process), the ones that never
//! fork:
//!
//! * [`fuse_thread`]: the FUSE session of a mount (the requests of the
//!   kernel, for the container's processes): it reads the files beneath
//!   the directories it is given (the store, the staging), nothing else,
//!   and the same calls are denied.
//! * [`fetch_thread`]: the requests for the files of an image that is being
//!   pulled (the image server's `fetch` workers, `peer-profile`, `profile`):
//!   it reads beneath the stores and the files fetched for the image (to
//!   measure what the engine staged), makes files beneath the directory of
//!   the startup profile only, looks up no unix socket by name (the
//!   connections to the engine come through a process forked before; Landlock
//!   ABI 9 and later; no TCP at all), and makes none of [`DENIED`], sockets
//!   included.
//!
//! They are a must: on a kernel without Landlock the threads do not run
//! (the pull workers need it as well).

use std::io;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use velarx_sys::confine::{self as sys, Ruleset};

/// `fchmodat2`, the same number on every architecture (the libc crate
/// lacks it on some).
const SYS_FCHMODAT2: i64 = 452;
/// The calls that came after the libc crate's lists, the same number on
/// every architecture: `quotactl_fd`, the `*xattrat` twins of `setxattr`
/// and `removexattr`, `open_tree_attr` (the new mount API) and
/// `file_setattr` (the flags of a file: immutable, append only).
const SYS_QUOTACTL_FD: i64 = 443;
const SYS_SETXATTRAT: i64 = 463;
const SYS_REMOVEXATTRAT: i64 = 466;
const SYS_OPEN_TREE_ATTR: i64 = 467;
const SYS_FILE_SETATTR: i64 = 469;

/// The system calls a confined thread never makes; `EPERM`.
const DENIED: &[i64] = &[
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_bpf,
    libc::SYS_keyctl,
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
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_acct,
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_clock_adjtime,
    libc::SYS_adjtimex,
    libc::SYS_sethostname,
    libc::SYS_setdomainname,
    libc::SYS_quotactl,
    SYS_QUOTACTL_FD,
    libc::SYS_pidfd_getfd,
    libc::SYS_pidfd_send_signal,
    libc::SYS_pidfd_open,
    libc::SYS_kill,
    // io_uring, whose operations never go through the filter
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    // the new mount API
    libc::SYS_open_tree,
    libc::SYS_move_mount,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_mount_setattr,
    SYS_OPEN_TREE_ATTR,
    // what Landlock does not handle, and a root monitor's capabilities
    // would allow: the owner, mode and attributes of any file, a file by
    // its handle, the events of a whole mount
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
    libc::SYS_syslog,
    libc::SYS_vhangup,
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
    #[cfg(target_arch = "x86_64")]
    libc::SYS_iopl,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_ioperm,
];

fn filter() -> &'static [libc::sock_filter] {
    static FILTER: OnceLock<Vec<libc::sock_filter>> = OnceLock::new();
    FILTER.get_or_init(|| {
        sys::deny_filter(DENIED, libc::EPERM as u32)
            .expect("the table of the filter makes a program")
    })
}

/// The rights beneath a directory where a fetching thread makes files (the
/// directory of the startup profile): read them, make files and
/// directories, write, truncate and remove its own temporary files.
const MAKE: u64 = sys::fs::READ_FILE
    | sys::fs::READ_DIR
    | sys::fs::WRITE_FILE
    | sys::fs::TRUNCATE
    | sys::fs::MAKE_REG
    | sys::fs::MAKE_DIR
    | sys::fs::REMOVE_FILE;

/// A Landlock domain for the calling thread: `rules` are the directories
/// and the rights beneath each; a directory that is not there is skipped
/// unless it is `needed`.
fn landlock_rules(rules: &[(&Path, u64, bool)]) -> io::Result<()> {
    landlock_scoped(rules, sys::SCOPE_ABSTRACT_UNIX | sys::SCOPE_SIGNAL)
}

/// [`landlock_rules`] with the scopes `scoped` (abstract unix sockets,
/// signals).
fn landlock_scoped(rules: &[(&Path, u64, bool)], scoped: u64) -> io::Result<()> {
    #[cfg(test)]
    if tests::NO_LANDLOCK.get() {
        return Err(io::Error::other(
            "no Landlock in this kernel (a test says so)",
        ));
    }
    let Some(ruleset) = Ruleset::new_with_scopes(scoped)? else {
        return Err(io::Error::other(
            "no Landlock in this kernel: the threads that read what others send cannot be confined",
        ));
    };
    for &(dir, access, needed) in rules {
        // (what is not there cannot be read anyway)
        let d = match std::fs::File::open(dir) {
            Ok(d) => d,
            Err(_) if !needed => continue,
            Err(e) => return Err(io::Error::new(e.kind(), format!("{}: {e}", dir.display()))),
        };
        ruleset.allow_beneath(d.as_fd(), access)?;
    }
    ruleset.restrict_thread()
}

fn landlock(read: &[PathBuf]) -> io::Result<()> {
    let rules: Vec<(&Path, u64, bool)> = read
        .iter()
        .map(|d| (d.as_path(), sys::fs::READ_FILE | sys::fs::READ_DIR, false))
        .collect();
    landlock_rules(&rules)
}

/// What a thread that fetches the files of an image being pulled reaches
/// (`fetch_thread`).
#[derive(Debug, Clone, Default)]
pub struct Fetching {
    /// Read beneath: the stores, the files fetched for the image.
    pub read: Vec<PathBuf>,
    /// Make, write and name files beneath: the directory of the startup
    /// profile.  Each must be there.
    pub make: Vec<PathBuf>,
}

/// Confine the calling thread (and those it makes) for the requests for the
/// files of an image that is being pulled: the file system of `reach` only,
/// no TCP, no process, no mount, none of [`DENIED`] (it opens no socket: its
/// connections are made by another process).
pub fn fetch_thread(reach: &Fetching) -> io::Result<()> {
    let rules: Vec<(&Path, u64, bool)> = reach
        .read
        .iter()
        .map(|d| (d.as_path(), sys::fs::READ_FILE | sys::fs::READ_DIR, false))
        .chain(reach.make.iter().map(|d| (d.as_path(), MAKE, true)))
        .collect();
    landlock_rules(&rules)?;
    sys::seccomp_thread(filter())
}

/// What the threads that record and release a container reach (the
/// files of the plan's store, events and locks).
#[derive(Debug, Clone)]
pub struct Recording {
    /// The directory of the database: `db.sqlite`, `-wal`, `-shm`, `-changes`
    pub store_dir: PathBuf,
    /// The directory of the events file, which the events are appended to and
    /// rotated in
    pub events_dir: Option<PathBuf>,
    /// The events go to the journal: its socket is reached
    pub journal: bool,
    /// The directory of the lock files of the containers
    pub mon_dir: PathBuf,
}

/// The rights over files made, written and removed in a directory (the
/// database, the events file, the locks): no directory rights beyond reading
/// its list, no links, no sockets, no devices.
const FILES: u64 = sys::fs::READ_FILE
    | sys::fs::READ_DIR
    | sys::fs::WRITE_FILE
    | sys::fs::TRUNCATE
    | sys::fs::MAKE_REG
    | sys::fs::REMOVE_FILE;

const JOURNAL_DIR: &str = "/run/systemd/journal";

fn recording_rules(r: &Recording) -> Vec<(&Path, u64, bool)> {
    let mut rules = vec![(r.store_dir.as_path(), FILES, true)];
    if let Some(d) = &r.events_dir {
        rules.push((d.as_path(), FILES, false));
    }
    if r.journal {
        rules.push((Path::new(JOURNAL_DIR), sys::fs::RESOLVE_UNIX, false));
    }
    rules.push((
        r.mon_dir.as_path(),
        sys::fs::READ_FILE | sys::fs::WRITE_FILE | sys::fs::MAKE_REG,
        false,
    ));
    rules
}

/// The calls of [`DENIED`] that remain for a thread that makes `allowed`
/// (with `keep_chmod`, the modes of files are not among them).
fn limited_denied(allowed: &[i64], keep_chmod: bool) -> Vec<i64> {
    DENIED
        .iter()
        .copied()
        .filter(|nr| !allowed.contains(nr))
        .filter(|nr| {
            !keep_chmod
                || !(*nr == libc::SYS_fchmod
                    || *nr == libc::SYS_fchmodat
                    || *nr == SYS_FCHMODAT2
                    || {
                        #[cfg(target_arch = "x86_64")]
                        {
                            *nr == libc::SYS_chmod
                        }
                        #[cfg(not(target_arch = "x86_64"))]
                        {
                            false
                        }
                    })
        })
        .collect()
}

/// The filter of a thread that makes the calls of `allowed` (of [`DENIED`])
/// only with the arguments `only` says.
fn limited_filter(
    allowed: &[i64],
    only: &'static [sys::OnlyIf],
    keep_chmod: bool,
) -> Vec<libc::sock_filter> {
    // (the tables are constants, and the tests make every one of them)
    sys::deny_filter_with(
        &limited_denied(allowed, keep_chmod),
        only,
        libc::EPERM as u32,
    )
    .expect("the table of the filter makes a program")
}

const AF_UNIX: &[sys::OnlyIf] = &[sys::OnlyIf {
    nr: libc::SYS_socket,
    arg: 0,
    values: &[libc::AF_UNIX as u32],
}];

const AF_UNIX_NETLINK: &[sys::OnlyIf] = &[
    sys::OnlyIf {
        nr: libc::SYS_socket,
        arg: 0,
        values: &[libc::AF_UNIX as u32, libc::AF_NETLINK as u32],
    },
    sys::OnlyIf {
        nr: libc::SYS_setns,
        arg: 1,
        values: &[libc::CLONE_NEWNET as u32],
    },
];

/// Confine the calling thread (and those it makes) for the thread that
/// records the events of a running container into the store: the store's
/// files, the events, the locks; unix sockets only (the journal).
pub fn record_thread(r: &Recording) -> io::Result<()> {
    landlock_rules(&recording_rules(r))?;
    sys::seccomp_thread(record_filter())
}

/// What the threads of unix sockets only make of [`DENIED`].
const UNIX_CALLS: &[i64] = &[libc::SYS_socket, libc::SYS_connect];

/// The filter of the record thread: unix sockets only.
fn record_filter() -> &'static [libc::sock_filter] {
    static FILTER: OnceLock<Vec<libc::sock_filter>> = OnceLock::new();
    FILTER.get_or_init(|| limited_filter(UNIX_CALLS, AF_UNIX, false))
}

/// What the thread of the end of a container reaches beyond [`Recording`]:
/// the run root (the networks, the pool), the
/// network lock, `/proc` (start times, command lines, the descriptors of the
/// namespaces), the directories of the unix sockets it connects to.
#[derive(Debug, Clone)]
pub struct Releasing {
    pub recording: Recording,
    pub state_dir: PathBuf,
    pub network_lock: PathBuf,
    pub unix_dirs: Vec<PathBuf>,
    /// The pods' records, for a member of a pod
    pub pods_dir: Option<PathBuf>,
}

/// Confine the calling thread for the release of a container's network and
/// the record of its exit: the files of `reach`, netlink and unix sockets,
/// `setns` into a network namespace, pidfds (pasta, the forwarder and the
/// holder of the rootless namespace are outside its domain: no signal
/// scope), no exec, no mount.
pub fn exit_thread(reach: &Releasing) -> io::Result<()> {
    let tree = sys::fs::READ_FILE
        | sys::fs::READ_DIR
        | sys::fs::WRITE_FILE
        | sys::fs::TRUNCATE
        | sys::fs::MAKE_REG
        | sys::fs::MAKE_DIR
        | sys::fs::REMOVE_FILE
        | sys::fs::REMOVE_DIR;
    let mut rules = recording_rules(&reach.recording);
    rules.push((reach.state_dir.as_path(), tree, false));
    rules.push((
        reach.network_lock.as_path(),
        sys::fs::READ_FILE | sys::fs::WRITE_FILE,
        false,
    ));
    rules.push((
        Path::new("/proc"),
        sys::fs::READ_FILE | sys::fs::READ_DIR,
        true,
    ));
    for d in &reach.unix_dirs {
        rules.push((d.as_path(), sys::fs::RESOLVE_UNIX, false));
    }
    if let Some(d) = &reach.pods_dir {
        rules.push((d.as_path(), FILES, false));
    }
    landlock_scoped(&rules, sys::SCOPE_ABSTRACT_UNIX)?;
    sys::seccomp_thread(exit_filter())
}

/// What the exit thread makes of [`DENIED`].
const EXIT_CALLS: &[i64] = &[
    libc::SYS_socket,
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_setns,
    libc::SYS_pidfd_open,
    libc::SYS_pidfd_send_signal,
];

/// The filter of the exit thread: netlink and unix sockets, `setns` into a
/// network namespace, pidfds.
fn exit_filter() -> &'static [libc::sock_filter] {
    static FILTER: OnceLock<Vec<libc::sock_filter>> = OnceLock::new();
    FILTER.get_or_init(|| limited_filter(EXIT_CALLS, AF_UNIX_NETLINK, false))
}

/// What the thread that removes a container reaches beyond [`Recording`].
#[derive(Debug, Clone)]
pub struct Removing {
    pub recording: Recording,
    /// Trees removed with what is below them
    pub trees: Vec<PathBuf>,
    /// Directories a file is removed from
    pub file_dirs: Vec<PathBuf>,
    /// The directories of the unix sockets it connects to (the storage
    /// service, which removes the layer it holds)
    pub unix_dirs: Vec<PathBuf>,
    /// The monitor is root: it has the capability to remove what a container
    /// left unreadable; else the removal makes it readable first
    pub root: bool,
}

/// Confine the calling thread for the removal of an `--rm` container: the
/// trees of its files (and the volumes it made), the rows and events; unix
/// sockets only.
pub fn remove_thread(reach: &Removing) -> io::Result<()> {
    let mut rules = recording_rules(&reach.recording);
    let tree = sys::fs::READ_FILE | sys::fs::READ_DIR | sys::fs::REMOVE_FILE | sys::fs::REMOVE_DIR;
    for t in &reach.trees {
        rules.push((t.as_path(), tree, false));
        // (the tree's own top is removed from its parent: a directory only)
        if let Some(parent) = t.parent() {
            rules.push((parent, sys::fs::REMOVE_DIR, false));
        }
    }
    for d in &reach.file_dirs {
        rules.push((d.as_path(), sys::fs::REMOVE_FILE, false));
    }
    for d in &reach.unix_dirs {
        rules.push((d.as_path(), sys::fs::RESOLVE_UNIX, false));
    }
    landlock_rules(&rules)?;
    sys::seccomp_thread(remove_filter(reach.root))
}

/// The filter of the removal thread: unix sockets only; the modes of files
/// for a monitor that is not root.
fn remove_filter(root: bool) -> &'static [libc::sock_filter] {
    static FILTER_ROOT: OnceLock<Vec<libc::sock_filter>> = OnceLock::new();
    static FILTER_USER: OnceLock<Vec<libc::sock_filter>> = OnceLock::new();
    let (cell, keep) = if root {
        (&FILTER_ROOT, false)
    } else {
        (&FILTER_USER, true)
    };
    cell.get_or_init(|| limited_filter(UNIX_CALLS, AF_UNIX, keep))
}

/// Confine the calling thread for the FUSE session of a mount: it reads
/// beneath `read`, nothing else.
pub fn fuse_thread(read: &[PathBuf]) -> io::Result<()> {
    landlock(read)?;
    sys::seccomp_thread(filter())
}

#[cfg(test)]
mod tests {
    use super::*;

    std::thread_local! {
        /// The kernel of this thread has no Landlock.
        pub(super) static NO_LANDLOCK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// A kernel without Landlock confines no thread: the thread fails to
    /// start, it does not go with its seccomp filter only.
    #[test]
    fn without_landlock_no_thread_is_confined() {
        std::thread::spawn(|| {
            NO_LANDLOCK.set(true);
            let dir = tempfile::tempdir().unwrap();
            assert!(fetch_thread(&Fetching::default()).is_err());
            assert!(fuse_thread(&[dir.path().to_path_buf()]).is_err());
            let recording = recording_in(dir.path());
            assert!(record_thread(&recording).is_err());
            assert!(exit_thread(&Releasing {
                recording: recording.clone(),
                state_dir: dir.path().to_path_buf(),
                network_lock: dir.path().join("lock"),
                unix_dirs: Vec::new(),
                pods_dir: None,
            })
            .is_err());
            assert!(remove_thread(&Removing {
                recording,
                trees: Vec::new(),
                file_dirs: Vec::new(),
                unix_dirs: Vec::new(),
                root: false,
            })
            .is_err());
            // (no filter was installed either)
            let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
            assert!(status.lines().any(|l| l == "Seccomp:\t0"), "{status}");
        })
        .join()
        .unwrap();
    }

    /// The calls of the newer kernels that do what a denied call does are
    /// denied too.
    #[test]
    fn the_filter_refuses_the_newer_twins_of_its_calls() {
        let program: Vec<_> = filter()
            .iter()
            .map(|i| seccompiler::sock_filter {
                code: i.code,
                jt: i.jt,
                jf: i.jf,
                k: i.k,
            })
            .collect();
        let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        for nr in [
            libc::SYS_setxattr,
            SYS_SETXATTRAT,
            SYS_REMOVEXATTRAT,
            SYS_FILE_SETATTR,
            libc::SYS_open_tree,
            SYS_OPEN_TREE_ATTR,
            SYS_QUOTACTL_FD,
        ] {
            assert_eq!(
                sys::seccomp_answer(&program, nr as u32, sys::ARCH, [0; 6]),
                eperm,
                "{nr}"
            );
        }
    }

    /// The length and the FNV-1a hash of the instructions of a program.
    fn fingerprint(program: &[libc::sock_filter]) -> (usize, u64) {
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for i in program {
            let mut bytes = Vec::from(i.code.to_le_bytes());
            bytes.extend([i.jt, i.jf]);
            bytes.extend(i.k.to_le_bytes());
            for b in bytes {
                hash = (hash ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
            }
        }
        (program.len(), hash)
    }

    /// The programs of the filters are what they were: any change of the
    /// generator, or of a table, shows here.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_programs_of_the_filters_are_pinned() {
        for (name, program, want) in [
            ("fuse", filter(), (200, 1670101401834716846)),
            ("record", record_filter(), (201, 16209927425034214830)),
            ("exit", exit_filter(), (199, 13994333819956319298)),
            (
                "remove (root)",
                remove_filter(true),
                (201, 16209927425034214830),
            ),
            (
                "remove (user)",
                remove_filter(false),
                (193, 16003295455940468575),
            ),
        ] {
            assert_eq!(fingerprint(program), want, "{name}");
        }
    }

    /// The program of each filter is the one of its table, and answers what
    /// the statement of `velarx_bpf_core::check` says to every call and
    /// argument that matters, as the filter of the kernel will.
    #[test]
    fn the_filters_answer_what_their_tables_say() {
        use velarx_bpf_core::{check, Insn, Table, Target};
        let target = Target {
            arch: sys::ARCH,
            x32: cfg!(target_arch = "x86_64"),
            clone: libc::SYS_clone as u32,
            clone3: libc::SYS_clone3 as u32,
        };
        let none: &[sys::OnlyIf] = &[];
        let tables = [
            ("fuse", filter(), DENIED.to_vec(), none),
            (
                "record",
                record_filter(),
                limited_denied(UNIX_CALLS, false),
                AF_UNIX,
            ),
            (
                "exit",
                exit_filter(),
                limited_denied(EXIT_CALLS, false),
                AF_UNIX_NETLINK,
            ),
            (
                "remove (root)",
                remove_filter(true),
                limited_denied(UNIX_CALLS, false),
                AF_UNIX,
            ),
            (
                "remove (user)",
                remove_filter(false),
                limited_denied(UNIX_CALLS, true),
                AF_UNIX,
            ),
        ];
        for (name, program, denied, only) in tables {
            let table = Table {
                denied: &denied,
                only,
                errno: libc::EPERM as u32,
            };
            let made: Vec<Insn> = program
                .iter()
                .map(|i| Insn {
                    code: i.code,
                    jt: i.jt,
                    jf: i.jf,
                    k: i.k,
                })
                .collect();
            assert_eq!(
                velarx_bpf_core::deny_program(&table, &target).unwrap(),
                made,
                "{name}"
            );
            let asked = check::agrees(&table, &target).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(asked > 10_000, "{name}: {asked}");
        }
    }

    /// The seccomp answer of `program` to the call `nr` with the first two
    /// arguments `a0` and `a1`.
    fn answer(program: &[libc::sock_filter], nr: i64, a0: i64, a1: i64) -> u32 {
        let program: Vec<_> = program
            .iter()
            .map(|i| seccompiler::sock_filter {
                code: i.code,
                jt: i.jt,
                jf: i.jf,
                k: i.k,
            })
            .collect();
        sys::seccomp_answer(
            &program,
            nr as u32,
            sys::ARCH,
            [a0 as u64, a1 as u64, 0, 0, 0, 0],
        )
    }

    /// Each job thread of the end of a container makes the calls its work
    /// needs, with the arguments it needs, and none of the others: no
    /// program, no mount, no internet socket, no signal by `kill`.
    #[test]
    fn the_job_threads_make_the_calls_of_their_work_only() {
        let allow = libc::SECCOMP_RET_ALLOW;
        let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        let (unix, netlink, inet, inet6, packet) = (
            i64::from(libc::AF_UNIX),
            i64::from(libc::AF_NETLINK),
            i64::from(libc::AF_INET),
            i64::from(libc::AF_INET6),
            i64::from(libc::AF_PACKET),
        );
        let (newnet, newns) = (i64::from(libc::CLONE_NEWNET), i64::from(libc::CLONE_NEWNS));
        // (what none of them makes)
        for (name, f) in [
            ("record", record_filter()),
            ("exit", exit_filter()),
            ("remove (root)", remove_filter(true)),
            ("remove (user)", remove_filter(false)),
        ] {
            for nr in [
                libc::SYS_execve,
                libc::SYS_execveat,
                libc::SYS_mount,
                libc::SYS_umount2,
                libc::SYS_kill,
                libc::SYS_ptrace,
                libc::SYS_unshare,
            ] {
                assert_eq!(answer(f, nr, 0, 0), eperm, "{name}: {nr}");
            }
            for family in [inet, inet6, packet] {
                assert_eq!(
                    answer(f, libc::SYS_socket, family, 0),
                    eperm,
                    "{name}: {family}"
                );
            }
            assert_eq!(answer(f, libc::SYS_socket, unix, 0), allow, "{name}");
            assert_eq!(answer(f, libc::SYS_connect, 3, 0), allow, "{name}");
            assert_eq!(answer(f, libc::SYS_setns, 3, newns), eperm, "{name}");
        }
        // netlink, a network namespace and pidfds: the exit thread only
        let exit = exit_filter();
        assert_eq!(answer(exit, libc::SYS_socket, netlink, 0), allow);
        assert_eq!(answer(exit, libc::SYS_bind, 3, 0), allow);
        assert_eq!(answer(exit, libc::SYS_setns, 3, newnet), allow);
        assert_eq!(answer(exit, libc::SYS_setns, 3, 0), eperm);
        assert_eq!(answer(exit, libc::SYS_pidfd_open, 1, 0), allow);
        assert_eq!(answer(exit, libc::SYS_pidfd_send_signal, 3, 15), allow);
        for (name, f) in [
            ("record", record_filter()),
            ("remove", remove_filter(false)),
        ] {
            assert_eq!(answer(f, libc::SYS_socket, netlink, 0), eperm, "{name}");
            assert_eq!(answer(f, libc::SYS_bind, 3, 0), eperm, "{name}");
            assert_eq!(answer(f, libc::SYS_setns, 3, newnet), eperm, "{name}");
            assert_eq!(
                answer(f, libc::SYS_pidfd_send_signal, 3, 15),
                eperm,
                "{name}"
            );
        }
        // modes: only the removal of a monitor that is not root, which makes
        // what the container left unreadable removable
        assert_eq!(
            answer(remove_filter(false), libc::SYS_fchmodat, 3, 0),
            allow
        );
        assert_eq!(answer(remove_filter(true), libc::SYS_fchmodat, 3, 0), eperm);
        assert_eq!(answer(record_filter(), libc::SYS_fchmodat, 3, 0), eperm);
        assert_eq!(answer(exit, libc::SYS_fchmodat, 3, 0), eperm);
    }

    /// The directories of a test of the job threads' confinement.
    fn recording_in(root: &Path) -> Recording {
        for d in ["store", "events", "mon", "elsewhere"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        Recording {
            store_dir: root.join("store"),
            events_dir: Some(root.join("events")),
            journal: false,
            mon_dir: root.join("mon"),
        }
    }

    /// The record thread makes, writes and removes the files of the store
    /// and of the events, takes the locks, and writes nothing else; it
    /// starts no program and opens no internet socket.
    #[test]
    fn a_record_thread_writes_the_store_and_the_events_only() {
        let dir = tempfile::tempdir().unwrap();
        let reach = recording_in(dir.path());
        let root = dir.path().to_path_buf();
        let abi = sys::landlock_abi();
        let got = std::thread::spawn(move || {
            record_thread(&reach).unwrap();
            let p = |s: &str| root.join(s);
            (
                std::fs::write(p("store/db.sqlite-wal"), b"w").is_ok()
                    && std::fs::remove_file(p("store/db.sqlite-wal")).is_ok(),
                std::fs::write(p("events/events.log"), b"e").is_ok()
                    && std::fs::rename(p("events/events.log"), p("events/events.log.1")).is_ok(),
                std::fs::write(p("mon/c.lock"), b"").is_ok(),
                std::fs::write(p("elsewhere/f"), b"x").is_err(),
                std::fs::create_dir(p("store/dir")).is_err(),
                std::process::Command::new("/bin/true").status().is_err(),
                std::net::TcpListener::bind("127.0.0.1:0").is_err(),
            )
        })
        .join()
        .unwrap();
        let (store, events, lock, no_elsewhere, no_dir, no_exec, no_inet) = got;
        assert!(store && events && lock && no_exec && no_inet);
        if abi > 0 {
            assert!(no_elsewhere && no_dir);
        }
    }

    /// The exit thread opens netlink sockets and writes beneath the run root,
    /// and nothing else of the file system; it starts no program and opens
    /// no internet socket.
    #[test]
    fn an_exit_thread_reaches_netlink_and_the_run_root_only() {
        let dir = tempfile::tempdir().unwrap();
        let recording = recording_in(dir.path());
        std::fs::create_dir_all(dir.path().join("state/networks")).unwrap();
        let reach = Releasing {
            recording,
            state_dir: dir.path().join("state"),
            network_lock: dir.path().join("networks.lock"),
            unix_dirs: Vec::new(),
            pods_dir: None,
        };
        let root = dir.path().to_path_buf();
        let abi = sys::landlock_abi();
        let got = std::thread::spawn(move || {
            exit_thread(&reach).unwrap();
            let p = |s: &str| root.join(s);
            let netlink = rustix::net::socket(
                rustix::net::AddressFamily::NETLINK,
                rustix::net::SocketType::RAW,
                None,
            )
            .is_ok();
            (
                netlink,
                std::fs::create_dir(p("state/networks/dns")).is_ok()
                    && std::fs::write(p("state/networks/dns/r"), b"r").is_ok()
                    && std::fs::remove_dir_all(p("state/networks/dns")).is_ok(),
                std::fs::write(p("elsewhere/f"), b"x").is_err(),
                std::fs::read_to_string("/proc/self/status").is_ok(),
                std::process::Command::new("/bin/true").status().is_err(),
                std::net::TcpListener::bind("127.0.0.1:0").is_err(),
            )
        })
        .join()
        .unwrap();
        let (netlink, state, no_elsewhere, proc, no_exec, no_inet) = got;
        assert!(netlink && state && proc && no_exec && no_inet);
        if abi > 0 {
            assert!(no_elsewhere);
        }
    }

    /// The removal thread removes the trees of the container, a directory
    /// the container made unreadable included (a monitor that is not root
    /// makes it readable first), never what a link in them points to, and
    /// nothing outside them.
    #[test]
    fn a_remove_thread_removes_its_trees_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let recording = recording_in(dir.path());
        let p = |s: &str| dir.path().join(s);
        std::fs::create_dir_all(p("bundle/rootfs/locked/inner")).unwrap();
        std::fs::write(p("bundle/rootfs/locked/inner/f"), b"f").unwrap();
        std::fs::write(p("elsewhere/target"), b"t").unwrap();
        std::os::unix::fs::symlink(p("elsewhere/target"), p("bundle/rootfs/link")).unwrap();
        std::fs::set_permissions(
            p("bundle/rootfs/locked"),
            std::fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        std::fs::write(p("elsewhere/pid"), b"1").unwrap();
        let root = rustix::process::geteuid().is_root();
        let reach = Removing {
            recording,
            trees: vec![p("bundle")],
            file_dirs: Vec::new(),
            unix_dirs: Vec::new(),
            root,
        };
        let abi = sys::landlock_abi();
        let (bundle, other) = (p("bundle"), p("elsewhere/pid"));
        let got = std::thread::spawn(move || {
            remove_thread(&reach).unwrap();
            (
                velarx_base::tree::remove_dir_all_confined(&bundle).map_err(|e| e.to_string()),
                std::fs::remove_file(&other).is_err(),
                std::process::Command::new("/bin/true").status().is_err(),
            )
        })
        .join()
        .unwrap();
        let (removed, no_other, no_exec) = got;
        assert_eq!(removed, Ok(()));
        assert!(!p("bundle").exists());
        assert_eq!(std::fs::read(p("elsewhere/target")).unwrap(), b"t");
        assert!(no_exec);
        if abi > 0 {
            assert!(no_other);
        }
    }

    /// A FUSE thread reads beneath its directories only, and opens, makes
    /// and changes nothing else.
    #[test]
    fn a_fuse_thread_reads_its_directories_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir(&store).unwrap();
        std::fs::write(store.join("object"), b"o").unwrap();
        std::fs::write(dir.path().join("secret"), b"s").unwrap();
        let secret = dir.path().join("secret");
        let landlock = sys::landlock_abi() > 0;
        let fuse = std::thread::spawn({
            let (secret, store) = (secret.clone(), store.clone());
            move || {
                fuse_thread(std::slice::from_ref(&store)).unwrap();
                (
                    std::fs::read(store.join("object")).ok(),
                    std::fs::read(&secret).is_err(),
                    std::fs::write(store.join("new"), b"n").is_err(),
                )
            }
        })
        .join()
        .unwrap();
        assert_eq!(fuse.0.as_deref(), Some(&b"o"[..]));
        if landlock {
            assert!(fuse.1 && fuse.2);
        }
        // (this thread is not confined)
        assert!(std::fs::read(&secret).is_ok());
    }

    /// A fetching thread reads beneath its directories, makes and names
    /// files beneath the directory of the profile, reaches the engine
    /// through the connector forked before it, and nothing else: no file
    /// elsewhere, no mode, no socket by name (Landlock 9), no process; the
    /// threads it makes are as confined.
    #[test]
    fn a_fetching_thread_reaches_its_directories_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = |p: &str| dir.path().join(p);
        for d in ["store", "pool", "sockets", "elsewhere"] {
            std::fs::create_dir(path(d)).unwrap();
        }
        std::fs::write(path("store/object"), b"o").unwrap();
        std::fs::write(path("secret"), b"s").unwrap();
        let ours = std::os::unix::net::UnixListener::bind(path("sockets/d.sock")).unwrap();
        let theirs = std::os::unix::net::UnixListener::bind(path("elsewhere/x.sock")).unwrap();
        let reach = Fetching {
            read: vec![path("store")],
            make: vec![path("pool")],
        };
        // (forked before the confinement, as the server's is)
        let connector =
            velarx_sys::connector::Connector::start_beside_idle_threads(&path("sockets/d.sock"))
                .unwrap();
        let abi = sys::landlock_abi();
        let got = std::thread::spawn({
            let root = dir.path().to_path_buf();
            move || {
                let path = |p: &str| root.join(p);
                fetch_thread(&reach).unwrap();
                let made = std::fs::create_dir(path("pool/ab")).is_ok()
                    && std::fs::write(path("pool/ab/.tmp"), b"f").is_ok()
                    && std::fs::rename(path("pool/ab/.tmp"), path("pool/ab/f")).is_ok();
                let no_mode = std::fs::set_permissions(
                    path("pool/ab/f"),
                    std::fs::Permissions::from_mode(0o444),
                )
                .is_err();
                // (a thread it makes is as confined)
                let child = {
                    let secret = path("secret");
                    std::thread::spawn(move || std::fs::read(secret).is_err())
                        .join()
                        .unwrap()
                };
                (
                    std::fs::read(path("store/object")).ok(),
                    made,
                    connector.connect().is_ok(),
                    (
                        std::os::unix::net::UnixStream::connect(path("sockets/d.sock")).is_err(),
                        std::os::unix::net::UnixStream::connect(path("elsewhere/x.sock")).is_err(),
                    ),
                    std::fs::read(path("secret")).is_err(),
                    std::fs::write(path("store/new"), b"n").is_err(),
                    child,
                    std::process::Command::new("/bin/true").status().is_err(),
                    no_mode,
                )
            }
        })
        .join()
        .unwrap();
        drop((ours, theirs));
        let (
            object,
            made,
            connected,
            no_other_socket,
            no_secret,
            no_store_write,
            child,
            no_exec,
            no_mode,
        ) = got;
        assert_eq!(object.as_deref(), Some(&b"o"[..]));
        assert!(made && connected && no_exec && no_mode);
        assert_eq!(std::fs::read(path("pool/ab/f")).unwrap(), b"f");
        if abi > 0 {
            assert!(no_secret && no_store_write && child);
        }
        if abi >= 9 {
            // (no socket is looked up by name: those beneath the directory
            // of the engine's neither)
            assert!(no_other_socket.0 && no_other_socket.1);
        }
    }

    /// A fetching thread opens no socket of its own, whatever the family:
    /// Landlock does not cover UDP, so the filter has to.
    #[test]
    fn a_fetching_thread_opens_no_datagram_socket() {
        use rustix::net::{AddressFamily, SocketType};
        let opened = std::thread::spawn(|| {
            fetch_thread(&Fetching::default()).unwrap();
            rustix::net::socket(AddressFamily::INET, SocketType::DGRAM, None).is_ok()
        })
        .join()
        .unwrap();
        assert!(!opened);
    }
}
