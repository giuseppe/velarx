// SPDX-License-Identifier: Apache-2.0
//! The confinement of one thread: Landlock and a seccomp filter that apply
//! to the calling thread and the threads it makes afterwards, never to the
//! rest of the process (no `SECCOMP_FILTER_FLAG_TSYNC`, no Landlock
//! flags).  A process that forks programs (the monitor of a container)
//! confines the threads that handle what others send, not itself: a child
//! process inherits the confinement of the thread that forks it.
//!
//! The raw system calls, without a library: the monitor stays small.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

const CREATE_RULESET_VERSION: u32 = 1;
const RULE_PATH_BENEATH: u32 = 1;

/// Rights of the file system of Landlock (`LANDLOCK_ACCESS_FS_*`).
pub mod fs {
    pub const EXECUTE: u64 = 1 << 0;
    pub const WRITE_FILE: u64 = 1 << 1;
    pub const READ_FILE: u64 = 1 << 2;
    pub const READ_DIR: u64 = 1 << 3;
    pub const REMOVE_DIR: u64 = 1 << 4;
    pub const REMOVE_FILE: u64 = 1 << 5;
    pub const MAKE_DIR: u64 = 1 << 7;
    pub const MAKE_REG: u64 = 1 << 8;
    /// ABI 3
    pub const TRUNCATE: u64 = 1 << 14;
    /// ABI 9: connect to (or send to) a unix socket with a path
    pub const RESOLVE_UNIX: u64 = 1 << 16;
    /// Every right of the ABI `abi` (1 and later)
    pub fn all(abi: u32) -> u64 {
        // 1: 13 rights; 2: REFER; 3: TRUNCATE; 5: IOCTL_DEV; 9: RESOLVE_UNIX
        let bits = match abi {
            0 => 0,
            1 => 13,
            2 => 14,
            3 | 4 => 15,
            5..=8 => 16,
            _ => 17,
        };
        (1u64 << bits) - 1
    }
}

/// `LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP` (ABI 4).
const NET_TCP: u64 = 0b11;
/// `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` (ABI 6).
pub const SCOPE_ABSTRACT_UNIX: u64 = 0b01;
/// `LANDLOCK_SCOPE_SIGNAL` (ABI 6): no signal, `pidfd_send_signal` included,
/// to a process outside the domain.
pub const SCOPE_SIGNAL: u64 = 0b10;
const SCOPE_ALL: u64 = SCOPE_ABSTRACT_UNIX | SCOPE_SIGNAL;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Refuse to go on when the process has a thread besides the caller's: a
/// confinement without `TSYNC` is of the calling thread and those it makes
/// afterwards, so a thread that exists already (a runtime's blocking pool,
/// a helper) would keep running unconfined.  Call it first, before any
/// part of a confinement is applied.
pub fn require_single_thread() -> Result<(), String> {
    let threads = std::fs::read_dir("/proc/self/task")
        .map_err(|e| format!("/proc/self/task: {e}"))?
        .count();
    match threads {
        1 => Ok(()),
        n => Err(format!(
            "the process has {n} threads: a confinement reaches the calling thread and those \
             made after it, not the others"
        )),
    }
}

/// The Landlock ABI of the kernel; 0 when it has none (or it is off).
pub fn landlock_abi() -> u32 {
    // SAFETY: the query of the version takes no attributes (a null pointer
    // of size 0) and returns a number, no descriptor.
    let v = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    u32::try_from(v).unwrap_or(0)
}

/// A Landlock ruleset being made, which handles every right of the file
/// system, TCP and the scopes the kernel knows: what a rule does not allow
/// is denied.
pub struct Ruleset(OwnedFd);

impl Ruleset {
    /// The ruleset; none when the kernel has no Landlock.
    pub fn new() -> io::Result<Option<Self>> {
        Self::new_with_scopes(SCOPE_ALL)
    }

    /// [`Self::new`] that scopes only what `scoped` names
    /// ([`SCOPE_ABSTRACT_UNIX`], [`SCOPE_SIGNAL`]): a thread that signals
    /// processes outside its domain through a pidfd leaves the signal scope out.
    pub fn new_with_scopes(scoped: u64) -> io::Result<Option<Self>> {
        let abi = landlock_abi();
        if abi == 0 {
            return Ok(None);
        }
        let attr = RulesetAttr {
            handled_access_fs: fs::all(abi),
            handled_access_net: if abi >= 4 { NET_TCP } else { 0 },
            scoped: if abi >= 6 { scoped & SCOPE_ALL } else { 0 },
        };
        // (a kernel that knows a shorter structure checks that what it does
        // not know is zero, which it is)
        // SAFETY: `attr` is a valid `landlock_ruleset_attr` of the size
        // given; the result is a new descriptor or an error.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const RulesetAttr,
                std::mem::size_of::<RulesetAttr>(),
                0u32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the kernel gave this descriptor and nothing else owns it.
        Ok(Some(Self(unsafe { OwnedFd::from_raw_fd(fd as i32) })))
    }

    /// Allow `access` (of [`fs`]) beneath the directory `dir`.
    pub fn allow_beneath(&self, dir: BorrowedFd<'_>, access: u64) -> io::Result<()> {
        let attr = PathBeneathAttr {
            allowed_access: access & fs::all(landlock_abi()),
            parent_fd: dir.as_raw_fd(),
        };
        // SAFETY: `attr` is a valid `landlock_path_beneath_attr` and the
        // descriptors are open for the call.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                self.0.as_raw_fd(),
                RULE_PATH_BENEATH,
                &attr as *const PathBeneathAttr,
                0u32,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Enforce the ruleset on the calling thread (`no_new_privs` first).
    pub fn restrict_thread(self) -> io::Result<()> {
        rustix::thread::set_no_new_privs(true)?;
        // SAFETY: the descriptor is the ruleset's; flags 0: this thread.
        let rc =
            unsafe { libc::syscall(libc::SYS_landlock_restrict_self, self.0.as_raw_fd(), 0u32) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

// The instructions of classic BPF that a filter needs: `BPF_LD | BPF_W |
// BPF_ABS`, and `BPF_JMP | BPF_JEQ / BPF_JGE / BPF_JSET | BPF_K`, `BPF_RET |
// BPF_K`.
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
#[cfg(any(target_arch = "x86_64", feature = "seccompiler"))]
const BPF_JGE_K: u16 = 0x35;
const BPF_JSET_K: u16 = 0x45;
const BPF_RET_K: u16 = 0x06;
const RET_ALLOW: u32 = 0x7fff_0000;

/// The flags of `clone` that make a namespace (`CLONE_NEWTIME`, 0x80,
/// included).
pub const CLONE_NEW_FLAGS: u32 = (libc::CLONE_NEWNS
    | libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET) as u32
    | 0x80;

fn op(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// The architecture of the system calls of this build (`AUDIT_ARCH_*`).
#[cfg(target_arch = "x86_64")]
pub const ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
pub const ARCH: u32 = 0xc000_00b7;

// The filter sets of the confined workers name their system calls by
// number, and a number means another call (or none) on another
// architecture: they are written and reviewed for these two only.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "the confinement (the seccomp filters of the confined workers) is written for x86_64 and \
     aarch64 only"
);

/// A filter that answers `errno` to the system calls `denied`, `EPERM` to
/// a `clone` that makes a process or a namespace (threads are allowed), `ENOSYS` to
/// `clone3` (the C library falls back to `clone`), and `EPERM` to every
/// call of another architecture or ABI (x32): the rest is allowed.
pub fn deny_filter(denied: &[i64], denied_errno: u32) -> Vec<libc::sock_filter> {
    deny_filter_with(denied, &[], denied_errno)
}

/// A call that is allowed only with some values of one argument.
#[derive(Clone, Copy, Debug)]
pub struct OnlyIf {
    /// The system call
    pub nr: i64,
    /// Which argument (0 to 5): its low word is compared
    pub arg: usize,
    /// The values it may have
    pub values: &'static [u32],
}

/// [`deny_filter`] with calls that are allowed only when the low word of an
/// argument is one of some values (`EPERM` otherwise): `socket` for
/// `AF_UNIX` alone, `setns` for a network namespace alone.  The rules come
/// before the one of `clone`.
pub fn deny_filter_with(
    denied: &[i64],
    only: &[OnlyIf],
    denied_errno: u32,
) -> Vec<libc::sock_filter> {
    let errno = |e: u32| op(BPF_RET_K, 0, 0, libc::SECCOMP_RET_ERRNO | (e & 0xffff));
    let mut p = vec![
        // seccomp_data: nr at 0, arch at 4, args at 16
        op(BPF_LD_W_ABS, 0, 0, 4),
        op(BPF_JEQ_K, 1, 0, ARCH),
        errno(libc::EPERM as u32),
        op(BPF_LD_W_ABS, 0, 0, 0),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        // x32 calls have this bit
        p.push(op(BPF_JGE_K, 0, 1, 0x4000_0000));
        p.push(errno(libc::EPERM as u32));
    }
    for &nr in denied {
        p.push(op(BPF_JEQ_K, 0, 1, nr as u32));
        p.push(errno(denied_errno));
    }
    for rule in only {
        let k = rule.values.len();
        // the call, else past the block; the argument; one jump per value
        // to the allow at the end; a refusal; the allow
        p.push(op(BPF_JEQ_K, 0, (k + 3) as u8, rule.nr as u32));
        p.push(op(BPF_LD_W_ABS, 0, 0, 16 + 8 * rule.arg as u32));
        for (j, &v) in rule.values.iter().enumerate() {
            p.push(op(BPF_JEQ_K, (k - j) as u8, 0, v));
        }
        p.push(errno(libc::EPERM as u32));
        p.push(op(BPF_RET_K, 0, 0, RET_ALLOW));
    }
    p.push(op(BPF_JEQ_K, 0, 1, libc::SYS_clone3 as u32));
    p.push(errno(libc::ENOSYS as u32));
    // clone: the flags are its first argument (the low word on both
    // little endian architectures); a thread, and no new namespace
    p.push(op(BPF_JEQ_K, 0, 4, libc::SYS_clone as u32));
    p.push(op(BPF_LD_W_ABS, 0, 0, 16));
    p.push(op(BPF_JSET_K, 1, 0, CLONE_NEW_FLAGS));
    p.push(op(BPF_JSET_K, 1, 0, libc::CLONE_THREAD as u32));
    p.push(errno(libc::EPERM as u32));
    p.push(op(BPF_RET_K, 0, 0, RET_ALLOW));
    p
}

/// What the program of a seccomp filter answers to the call `nr` of the
/// architecture `arch` with the arguments `args` (the instructions that
/// seccompiler and this module emit: the answer is the filter's return
/// value, `SECCOMP_RET_*`).  For the tests of the filters of the confined
/// workers.
#[cfg(feature = "seccompiler")]
pub fn seccomp_answer(
    program: &[seccompiler::sock_filter],
    nr: u32,
    arch: u32,
    args: [u64; 6],
) -> u32 {
    const BPF_ALU_AND_K: u16 = 0x54;
    const BPF_JGT_K: u16 = 0x25;
    const BPF_JA: u16 = 0x05;
    let (mut pc, mut a) = (0, 0u32);
    loop {
        let i = &program[pc];
        pc += 1;
        match i.code {
            BPF_LD_W_ABS => {
                a = match i.k {
                    0 => nr,
                    4 => arch,
                    k @ 16..=63 => {
                        let arg = args[(k as usize - 16) / 8];
                        if k % 8 == 4 {
                            (arg >> 32) as u32
                        } else {
                            arg as u32
                        }
                    }
                    k => panic!("a load the test does not know: {k}"),
                }
            }
            BPF_ALU_AND_K => a &= i.k,
            BPF_JEQ_K if a == i.k => pc += usize::from(i.jt),
            BPF_JGT_K if a > i.k => pc += usize::from(i.jt),
            BPF_JGE_K if a >= i.k => pc += usize::from(i.jt),
            BPF_JSET_K if a & i.k != 0 => pc += usize::from(i.jt),
            BPF_JEQ_K | BPF_JGT_K | BPF_JGE_K | BPF_JSET_K => pc += usize::from(i.jf),
            BPF_JA => pc += i.k as usize,
            BPF_RET_K => return i.k,
            code => panic!("an instruction the test does not know: {code:#x}"),
        }
    }
}

/// What the kernel answers to a call when `programs` are installed in this
/// order: the most restrictive answer of the programs, the last installed
/// one when two are alike (as the kernel decides; see [`seccomp_answer`]).
#[cfg(feature = "seccompiler")]
pub fn seccomp_verdict(
    programs: &[seccompiler::BpfProgram],
    nr: u32,
    arch: u32,
    args: [u64; 6],
) -> u32 {
    let action = |ret: u32| (ret & libc::SECCOMP_RET_ACTION_FULL) as i32;
    let mut verdict: Option<u32> = None;
    for program in programs.iter().rev() {
        let ret = seccomp_answer(program, nr, arch, args);
        if verdict.is_none_or(|v| action(ret) < action(v)) {
            verdict = Some(ret);
        }
    }
    verdict.unwrap_or(RET_ALLOW)
}

/// Install `filter` on the calling thread (`no_new_privs` first).
pub fn seccomp_thread(filter: &[libc::sock_filter]) -> io::Result<()> {
    rustix::thread::set_no_new_privs(true)?;
    let prog = libc::sock_fprog {
        len: u16::try_from(filter.len()).map_err(|_| io::Error::other("a filter too long"))?,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: `prog` points to `filter`, which lives during the call (the
    // kernel copies it); flags 0: this thread only.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0u32,
            &prog as *const libc::sock_fprog,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The program of a seccompiler filter, the calls of another ABI refused as
/// [`deny_filter`] refuses them.  seccompiler checks the architecture (a
/// call of another one, i386 or AArch32, kills the process) but not the
/// x32 calls of x86_64: they have the architecture of x86_64 and the bit
/// `0x4000_0000` in their number, so a call that a filter refuses would
/// pass as its x32 twin where the kernel has x32.
#[cfg(feature = "seccompiler")]
pub fn seccompiler_program(
    filter: seccompiler::SeccompFilter,
) -> Result<seccompiler::BpfProgram, String> {
    let program = seccompiler::BpfProgram::try_from(filter).map_err(|e| e.to_string())?;
    #[cfg(target_arch = "x86_64")]
    let program = refuse_x32(program)?;
    Ok(program)
}

/// `program` with the refusal of the x32 numbers after the check of the
/// architecture.
#[cfg(all(feature = "seccompiler", target_arch = "x86_64"))]
fn refuse_x32(mut program: seccompiler::BpfProgram) -> Result<seccompiler::BpfProgram, String> {
    let op = |code, jt, jf, k| seccompiler::sock_filter { code, jt, jf, k };
    // seccompiler's check of the architecture; what follows loads the
    // number again
    let arch = [
        op(BPF_LD_W_ABS, 0, 0, 4),
        op(BPF_JEQ_K, 1, 0, ARCH),
        op(BPF_RET_K, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
    ];
    if program.get(..arch.len()) != Some(&arch[..]) {
        return Err(
            "seccomp: the program does not start with the check of the architecture".into(),
        );
    }
    let x32 = [
        op(BPF_LD_W_ABS, 0, 0, 0),
        op(BPF_JGE_K, 0, 1, 0x4000_0000),
        op(
            BPF_RET_K,
            0,
            0,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ),
    ];
    program.splice(arch.len()..arch.len(), x32);
    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A process of one thread may confine itself; one with another thread
    /// (the harness has several) may not.
    #[test]
    fn a_confinement_wants_a_process_of_one_thread() {
        assert!(require_single_thread().is_err());
        // (a fork has the thread that forked it only)
        let child = crate::process::fork_status(|| i32::from(require_single_thread().is_err()));
        assert_eq!(child.unwrap(), 0);
    }

    /// A confined thread: no file but beneath the directory it was given,
    /// none of the denied calls, no process, and the threads it makes the
    /// same; the thread that made it is not confined.
    #[test]
    fn only_the_confined_thread_is_confined() {
        // (removed when it drops, a failed assertion included)
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let inside = dir.join("in");
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::write(inside.join("f"), b"x").unwrap();
        std::fs::write(dir.join("out"), b"y").unwrap();
        let nnp = rustix::thread::no_new_privs().unwrap();
        let confined = std::thread::spawn({
            let (dir, inside) = (dir.clone(), inside.clone());
            move || {
                let ruleset = Ruleset::new().unwrap();
                let landlock = ruleset.is_some();
                if let Some(r) = ruleset {
                    let d = std::fs::File::open(&inside).unwrap();
                    use std::os::fd::AsFd;
                    r.allow_beneath(d.as_fd(), fs::READ_FILE | fs::READ_DIR)
                        .unwrap();
                    r.restrict_thread().unwrap();
                }
                seccomp_thread(&deny_filter(&[libc::SYS_socket], libc::EPERM as u32)).unwrap();
                let socket = std::os::unix::net::UnixDatagram::unbound();
                let child = std::process::Command::new("/bin/true").status();
                let read_in = std::fs::read(inside.join("f")).is_ok();
                let read_out = std::fs::read(dir.join("out")).is_ok();
                // (a thread it makes is confined too)
                let thread_out = std::thread::spawn({
                    let dir = dir.clone();
                    move || std::fs::read(dir.join("out")).is_ok()
                })
                .join()
                .unwrap();
                (
                    landlock,
                    socket.is_err(),
                    child.is_err(),
                    read_in,
                    read_out,
                    thread_out,
                )
            }
        })
        .join()
        .unwrap();
        let (landlock, no_socket, no_child, read_in, read_out, thread_out) = confined;
        assert!(no_socket, "a socket was made");
        assert!(no_child, "a process was made");
        assert!(read_in);
        if landlock {
            assert!(!read_out, "a file outside was read");
            assert!(!thread_out, "a thread of the confined thread read outside");
        }
        // the others are not confined (nor given no_new_privs: the set-user-ID
        // helpers that they start keep working)
        assert_eq!(rustix::thread::no_new_privs().unwrap(), nnp);
        if !nnp {
            let status = std::process::Command::new("grep")
                .args(["NoNewPrivs", "/proc/self/status"])
                .output()
                .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&status.stdout).trim(),
                "NoNewPrivs:\t0"
            );
        }
        assert!(std::fs::read(dir.join("out")).is_ok());
        assert!(std::os::unix::net::UnixDatagram::unbound().is_ok());
    }

    #[test]
    fn the_rights_of_an_abi_are_those_it_has() {
        assert_eq!(fs::all(0), 0);
        assert_eq!(fs::all(1), 0x1fff);
        assert_eq!(fs::all(3), 0x7fff);
        assert_eq!(fs::all(9), 0x1ffff);
    }

    /// The hand-written filter: `clone` for threads only, without a
    /// namespace, `clone3` answered with `ENOSYS`.
    #[cfg(feature = "seccompiler")]
    #[test]
    fn the_deny_filter_lets_threads_through_and_no_namespace() {
        let program: Vec<_> = deny_filter(&[libc::SYS_unshare], libc::EPERM as u32)
            .into_iter()
            .map(|i| seccompiler::sock_filter {
                code: i.code,
                jt: i.jt,
                jf: i.jf,
                k: i.k,
            })
            .collect();
        let answer = |nr: i64, flags: i32| {
            seccomp_answer(&program, nr as u32, ARCH, [flags as u64, 0, 0, 0, 0, 0])
        };
        let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        let thread = libc::CLONE_VM | libc::CLONE_FILES | libc::CLONE_SIGHAND | libc::CLONE_THREAD;
        assert_eq!(answer(libc::SYS_clone, thread), RET_ALLOW);
        assert_eq!(answer(libc::SYS_clone, libc::SIGCHLD), eperm);
        for ns in [libc::CLONE_NEWUSER, libc::CLONE_NEWNS, libc::CLONE_NEWNET] {
            assert_eq!(answer(libc::SYS_clone, thread | ns), eperm);
        }
        assert_eq!(
            answer(libc::SYS_clone3, 0),
            libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32
        );
        assert_eq!(answer(libc::SYS_unshare, 0), eperm);
        assert_eq!(answer(libc::SYS_getpid, 0), RET_ALLOW);
    }

    /// A call allowed with some values of an argument only.
    #[cfg(feature = "seccompiler")]
    #[test]
    fn a_call_allowed_with_some_arguments_only() {
        const ONLY: &[OnlyIf] = &[
            OnlyIf {
                nr: libc::SYS_socket,
                arg: 0,
                values: &[libc::AF_UNIX as u32, libc::AF_NETLINK as u32],
            },
            OnlyIf {
                nr: libc::SYS_setns,
                arg: 1,
                values: &[libc::CLONE_NEWNET as u32],
            },
        ];
        let program: Vec<_> = deny_filter_with(&[libc::SYS_unshare], ONLY, libc::EPERM as u32)
            .into_iter()
            .map(|i| seccompiler::sock_filter {
                code: i.code,
                jt: i.jt,
                jf: i.jf,
                k: i.k,
            })
            .collect();
        let answer = |nr: i64, a0: i32, a1: i32| {
            seccomp_answer(
                &program,
                nr as u32,
                ARCH,
                [a0 as u64, a1 as u64, 0, 0, 0, 0],
            )
        };
        let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        for (family, ok) in [
            (libc::AF_UNIX, true),
            (libc::AF_NETLINK, true),
            (libc::AF_INET, false),
            (libc::AF_INET6, false),
            (libc::AF_PACKET, false),
        ] {
            let want = if ok { RET_ALLOW } else { eperm };
            assert_eq!(answer(libc::SYS_socket, family, 0), want, "family {family}");
        }
        assert_eq!(answer(libc::SYS_setns, 5, libc::CLONE_NEWNET), RET_ALLOW);
        assert_eq!(answer(libc::SYS_setns, 5, libc::CLONE_NEWNS), eperm);
        assert_eq!(answer(libc::SYS_setns, 5, 0), eperm);
        // the rules after them still apply
        assert_eq!(answer(libc::SYS_unshare, 0, 0), eperm);
        assert_eq!(answer(libc::SYS_getpid, 0, 0), RET_ALLOW);
        assert_eq!(
            answer(libc::SYS_clone, libc::SIGCHLD, 0),
            eperm,
            "a process is not made"
        );
    }

    /// A call that a seccompiler filter refuses is refused as its x32 twin
    /// too, and a call of another architecture kills the process.
    #[cfg(feature = "seccompiler")]
    #[test]
    fn a_seccompiler_program_refuses_the_calls_of_another_abi() {
        use seccompiler::{SeccompAction, SeccompFilter, TargetArch};
        let nr = libc::SYS_unshare;
        let filter = SeccompFilter::new(
            [(nr, Vec::new())].into_iter().collect(),
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            TargetArch::try_from(std::env::consts::ARCH).unwrap(),
        )
        .unwrap();
        let program = seccompiler_program(filter).unwrap();
        let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        assert_eq!(seccomp_answer(&program, nr as u32, ARCH, [0; 6]), eperm);
        assert_eq!(
            seccomp_answer(&program, libc::SYS_getpid as u32, ARCH, [0; 6]),
            RET_ALLOW
        );
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            seccomp_answer(&program, nr as u32 | 0x4000_0000, ARCH, [0; 6]),
            eperm
        );
        // i386, AArch32
        for other in [0x4000_0003, 0x4000_0028] {
            assert_eq!(
                seccomp_answer(&program, nr as u32, other, [0; 6]),
                libc::SECCOMP_RET_KILL_PROCESS
            );
        }
    }

    /// The numbers the filter sets of the confined workers write as digits
    /// (io_uring, the new mount API, Landlock) are the same on every
    /// architecture they are written for: the value of the matching `libc`
    /// constant.  The calls that exist on x86_64 only (`fork`, `open`, ...)
    /// are named by their constant behind `#[cfg(target_arch = "x86_64")]`
    /// instead.
    #[test]
    fn the_numbers_written_as_digits_are_the_libc_constants() {
        assert_eq!(libc::SYS_io_uring_setup, 425);
        assert_eq!(libc::SYS_io_uring_enter, 426);
        assert_eq!(libc::SYS_io_uring_register, 427);
        assert_eq!(libc::SYS_open_tree, 428);
        assert_eq!(libc::SYS_move_mount, 429);
        assert_eq!(libc::SYS_fsopen, 430);
        assert_eq!(libc::SYS_fsconfig, 431);
        assert_eq!(libc::SYS_fsmount, 432);
        assert_eq!(libc::SYS_fspick, 433);
        assert_eq!(libc::SYS_mount_setattr, 442);
        assert_eq!(libc::SYS_landlock_create_ruleset, 444);
        assert_eq!(libc::SYS_landlock_add_rule, 445);
        assert_eq!(libc::SYS_landlock_restrict_self, 446);
        // `fchmodat2` (452) is written as a number in the monitor's filter
        // (`SYS_FCHMODAT2`): the libc crate lacks the constant on aarch64
        // (0.2.191), although the kernel's asm-generic table, which aarch64
        // implements, gives it the same number.
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(libc::SYS_fchmodat2, 452);
        }
    }
}
