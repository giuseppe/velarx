// SPDX-License-Identifier: Apache-2.0
//! Seccomp allow-lists for the confined helpers.
//!
//! A deny-list lets through every call it does not name: the calls of the
//! kernels of tomorrow, `memfd_create` with an executable mapping, every
//! `prctl` and `ioctl` there is, `fcntl(F_SETOWN)` with `O_ASYNC`, which can
//! signal another process of the same user.  An [`Allow`] names the calls a
//! helper makes and the arguments of the ones that could do more; the rest
//! fails with `EPERM`, a number past the table of the kernel with `ENOSYS`
//! (so that a library falls back, as it does on an older kernel), and
//! `clone3`, whose flags a filter cannot see, with `ENOSYS` too (the C
//! library falls back to `clone`).
//!
//! [`Allow::runtime`] is what every helper of velarx has in common: a
//! process of threads on tokio, glibc, OpenSSL and the compression
//! libraries.  The helpers add their own sockets and files to it.  The
//! system calls are named by `libc::SYS_*`, so that a call that an
//! architecture does not have (`open`, `poll`, `epoll_wait`, `dup2`...) is
//! under `cfg(target_arch = "x86_64")`, as the sets of both architectures
//! are written for.

use crate::confine::{ARCH, CLONE_NEW_FLAGS};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use std::collections::BTreeMap;

/// The first system call number the filters answer `ENOSYS` to: the table
/// of the kernels known when this was written ends below it, so a call
/// beyond is one that a newer kernel added (or an old one lacks), and the
/// answer a library expects of a kernel that does not have it.
pub const TABLE_END: u32 = 471;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_JGE_K: u16 = 0x35;
const BPF_RET_K: u16 = 0x06;

/// An allow-list: the calls, each with the rules that make it allowed (none:
/// always; several: one of them).
#[derive(Default, Clone)]
pub struct Allow {
    rules: BTreeMap<i64, Vec<SeccompRule>>,
}

fn rule(conditions: Vec<SeccompCondition>) -> Result<SeccompRule, String> {
    SeccompRule::new(conditions).map_err(|e| e.to_string())
}

fn cond(arg: u8, len: SeccompCmpArgLen, op: SeccompCmpOp, value: u64) -> SeccompCondition {
    SeccompCondition::new(arg, len, op, value).expect("an argument number below 6")
}

/// The rule: argument `arg` (32 bits) is `value`.
pub fn is(arg: u8, value: u64) -> SeccompRule {
    rule(vec![cond(
        arg,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        value,
    )])
    .expect("a rule of one condition")
}

/// The rules: argument `arg` (32 bits) is one of `values`.
pub fn one_of(arg: u8, values: &[u64]) -> Vec<SeccompRule> {
    values.iter().map(|v| is(arg, *v)).collect()
}

/// The rule: argument `arg` (32 bits) has none of the bits `mask`.
pub fn lacks(arg: u8, mask: u64) -> SeccompRule {
    rule(vec![cond(
        arg,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(mask),
        0,
    )])
    .expect("a rule of one condition")
}

/// The rule: each argument `arg` (32 bits) of `args` is its `value`.
pub fn all_are(args: &[(u8, u64)]) -> SeccompRule {
    rule(
        args.iter()
            .map(|(arg, value)| cond(*arg, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, *value))
            .collect(),
    )
    .expect("conditions")
}

/// The rule: argument `arg` (32 bits) has all the bits `mask`.
pub fn has(arg: u8, mask: u64) -> SeccompRule {
    rule(vec![cond(
        arg,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(mask),
        mask,
    )])
    .expect("a rule of one condition")
}

/// The rule: argument `arg` (64 bits) is `value`.
pub fn is_wide(arg: u8, value: u64) -> SeccompRule {
    rule(vec![cond(
        arg,
        SeccompCmpArgLen::Qword,
        SeccompCmpOp::Eq,
        value,
    )])
    .expect("a rule of one condition")
}

impl Allow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow `calls` whatever their arguments.
    pub fn calls(mut self, calls: &[i64]) -> Self {
        for nr in calls {
            self.rules.insert(*nr, Vec::new());
        }
        self
    }

    /// Allow `nr` also when one of `rules` holds (the rules it has stay;
    /// a call allowed always stays so).
    pub fn plus(mut self, nr: i64, rules: Vec<SeccompRule>) -> Self {
        match self.rules.get_mut(&nr) {
            Some(have) if have.is_empty() => {}
            Some(have) => have.extend(rules),
            None => {
                self.rules.insert(nr, rules);
            }
        }
        self
    }

    /// Allow `nr` when one of `rules` holds.
    pub fn when(mut self, nr: i64, rules: Vec<SeccompRule>) -> Self {
        self.rules.insert(nr, rules);
        self
    }

    /// Whether `nr` is allowed, with its rules.
    pub fn get(&self, nr: i64) -> Option<&Vec<SeccompRule>> {
        self.rules.get(&nr)
    }

    /// The calls allowed.
    pub fn numbers(&self) -> Vec<i64> {
        self.rules.keys().copied().collect()
    }

    /// Take away `calls`.
    pub fn without(mut self, calls: &[i64]) -> Self {
        for nr in calls {
            self.rules.remove(nr);
        }
        self
    }

    /// What every helper makes: memory, threads (no process, no namespace),
    /// signals to itself (`kill` and `tgkill` with its own pid), time, its
    /// own ids, random bytes, descriptors it has (not the ones that make
    /// files or sockets), and the queries and options of sockets it has.  `pid`: the process, which may signal
    /// itself (`abort`).
    ///
    /// * `mmap` and `mprotect` make memory executable only for a mapping of
    ///   a file, which loading a library (the name service modules the
    ///   resolver loads when it first needs them) does: no anonymous
    ///   executable memory, which a payload needs;
    /// * `ioctl` is the set of non-blocking, close-on-exec, the size of a
    ///   pipe and the queries of a terminal; `fcntl` has no `F_SETOWN`,
    ///   `F_SETSIG` or `O_ASYNC`; `prctl` names threads;
    /// * `prlimit64` reads limits only.
    pub fn runtime(pid: u32) -> Result<Self, String> {
        let exec = libc::PROT_EXEC as u64;
        let mut a = Self::new().calls(&[
            // memory
            libc::SYS_brk,
            libc::SYS_munmap,
            libc::SYS_mremap,
            libc::SYS_madvise,
            // threads
            libc::SYS_futex,
            libc::SYS_set_robust_list,
            libc::SYS_rseq,
            libc::SYS_set_tid_address,
            libc::SYS_gettid,
            libc::SYS_sched_yield,
            libc::SYS_sched_getaffinity,
            libc::SYS_exit,
            libc::SYS_exit_group,
            // signals
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_sigaltstack,
            // what the kernel calls in place of a sleep, a wait or a poll
            // with a timeout that a stop (SIGSTOP, a frozen cgroup, a
            // tracer) interrupted: refused, the sleep fails with `EPERM`
            libc::SYS_restart_syscall,
            // time
            libc::SYS_clock_gettime,
            libc::SYS_clock_getres,
            libc::SYS_gettimeofday,
            libc::SYS_nanosleep,
            libc::SYS_clock_nanosleep,
            // who it is
            libc::SYS_getpid,
            libc::SYS_getppid,
            libc::SYS_getuid,
            libc::SYS_geteuid,
            libc::SYS_getgid,
            libc::SYS_getegid,
            libc::SYS_getrandom,
            // descriptors it has
            libc::SYS_close,
            libc::SYS_dup,
            libc::SYS_dup3,
            libc::SYS_pipe2,
            libc::SYS_eventfd2,
            libc::SYS_epoll_create1,
            libc::SYS_epoll_ctl,
            libc::SYS_epoll_pwait,
            libc::SYS_ppoll,
            libc::SYS_read,
            libc::SYS_readv,
            libc::SYS_write,
            libc::SYS_writev,
            libc::SYS_pread64,
            libc::SYS_lseek,
            libc::SYS_fstat,
            libc::SYS_newfstatat,
            libc::SYS_statx,
            // sockets it has
            libc::SYS_getsockopt,
            libc::SYS_setsockopt,
            libc::SYS_getsockname,
            libc::SYS_getpeername,
            libc::SYS_shutdown,
            libc::SYS_recvfrom,
            libc::SYS_sendto,
            libc::SYS_recvmsg,
            libc::SYS_sendmsg,
        ]);
        #[cfg(target_arch = "x86_64")]
        {
            a = a.calls(&[
                libc::SYS_dup2,
                libc::SYS_pipe,
                libc::SYS_poll,
                libc::SYS_epoll_wait,
            ]);
        }
        // executable memory is a mapping of a file
        a = a
            .when(
                libc::SYS_mmap,
                vec![lacks(2, exec), lacks(3, libc::MAP_ANONYMOUS as u64)],
            )
            .when(libc::SYS_mprotect, vec![lacks(2, exec)])
            .when(libc::SYS_pkey_mprotect, vec![lacks(2, exec)])
            .when(
                libc::SYS_ioctl,
                one_of(
                    1,
                    &[
                        libc::FIONBIO,
                        libc::FIONREAD,
                        libc::FIOCLEX,
                        libc::FIONCLEX,
                        libc::TCGETS,
                        libc::TIOCGWINSZ,
                        TCGETS2,
                    ],
                ),
            )
            .when(libc::SYS_fcntl, fcntl_rules()?)
            .when(
                libc::SYS_prctl,
                one_of(
                    0,
                    &[
                        libc::PR_SET_NAME as u64,
                        libc::PR_GET_NAME as u64,
                        PR_SET_VMA,
                    ],
                ),
            )
            .when(libc::SYS_prlimit64, vec![is_wide(2, 0)])
            .when(libc::SYS_tgkill, vec![is_wide(0, u64::from(pid))])
            .when(libc::SYS_kill, vec![is_wide(0, u64::from(pid))])
            .when(libc::SYS_clone, vec![threads_only()?]);
        Ok(a)
    }

    /// The programs to install, in this order: the allow-list (`EPERM` for
    /// the rest, the process is killed on another architecture) and the
    /// filter that answers `ENOSYS` to the numbers past [`TABLE_END`] and to
    /// `clone3`.  Call [`apply`] on each.
    pub fn programs(self) -> Result<Vec<BpfProgram>, String> {
        // (the second program is installed under the first: a filter can
        // only take away)
        let this = self
            .when(
                libc::SYS_seccomp,
                vec![is(0, libc::SECCOMP_SET_MODE_FILTER as u64)],
            )
            .plus(
                libc::SYS_prctl,
                vec![is(0, libc::PR_SET_NO_NEW_PRIVS as u64)],
            );
        let arch = TargetArch::try_from(std::env::consts::ARCH).map_err(|e| e.to_string())?;
        let filter = SeccompFilter::new(
            this.rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            arch,
        )
        .map_err(|e| e.to_string())?;
        Ok(vec![
            crate::confine::seccompiler_program(filter)?,
            unknown_calls(),
        ])
    }
}

/// `TCGETS2`: the terminal query of the C libraries since 2.42.
const TCGETS2: u64 = 0x802c_542a;

/// `PR_SET_VMA`: the name of a memory area (the C library names the
/// stacks of threads).
const PR_SET_VMA: u64 = 0x5356_4d41;

/// `fcntl`: the flags and duplicates of descriptors, the sizes of pipes and
/// the seals and locks of the files a helper has; `F_SETFL` without
/// `O_ASYNC` (a descriptor that signals), and no `F_SETOWN` or `F_SETSIG`.
fn fcntl_rules() -> Result<Vec<SeccompRule>, String> {
    use SeccompCmpArgLen::Dword;
    use SeccompCmpOp::{Eq, MaskedEq};
    let mut rules = one_of(
        1,
        &[
            libc::F_GETFD as u64,
            libc::F_SETFD as u64,
            libc::F_GETFL as u64,
            libc::F_DUPFD as u64,
            libc::F_DUPFD_CLOEXEC as u64,
            libc::F_GETPIPE_SZ as u64,
            libc::F_SETPIPE_SZ as u64,
            libc::F_ADD_SEALS as u64,
            libc::F_GET_SEALS as u64,
            libc::F_GETLK as u64,
            libc::F_SETLK as u64,
            libc::F_SETLKW as u64,
            libc::F_OFD_GETLK as u64,
            libc::F_OFD_SETLK as u64,
            libc::F_OFD_SETLKW as u64,
        ],
    );
    rules.push(rule(vec![
        cond(1, Dword, Eq, libc::F_SETFL as u64),
        cond(2, Dword, MaskedEq(libc::O_ASYNC as u64), 0),
    ])?);
    Ok(rules)
}

/// The rule of `clone` for a thread: `CLONE_THREAD`, and no namespace
/// (a child process would outlive the helper).
pub fn threads_only() -> Result<SeccompRule, String> {
    use SeccompCmpArgLen::Qword;
    use SeccompCmpOp::MaskedEq;
    rule(vec![
        cond(
            0,
            Qword,
            MaskedEq(libc::CLONE_THREAD as u64),
            libc::CLONE_THREAD as u64,
        ),
        cond(0, Qword, MaskedEq(u64::from(CLONE_NEW_FLAGS)), 0),
    ])
}

/// The filter that answers `ENOSYS` to `clone3` and to every number past
/// [`TABLE_END`] (the calls of the x32 interface too), and allows the
/// rest; the other architectures are refused by the allow-list.
fn unknown_calls() -> BpfProgram {
    let op = |code, jt, jf, k| seccompiler::sock_filter { code, jt, jf, k };
    let errno = |e: i32| op(BPF_RET_K, 0, 0, libc::SECCOMP_RET_ERRNO | e as u32);
    vec![
        op(BPF_LD_W_ABS, 0, 0, 4),
        op(BPF_JEQ_K, 1, 0, ARCH),
        op(BPF_RET_K, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
        op(BPF_LD_W_ABS, 0, 0, 0),
        op(BPF_JGE_K, 0, 1, TABLE_END),
        errno(libc::ENOSYS),
        op(BPF_JEQ_K, 0, 1, libc::SYS_clone3 as u32),
        errno(libc::ENOSYS),
        op(BPF_RET_K, 0, 0, 0x7fff_0000),
    ]
}

/// Install `programs` (from [`Allow::programs`]) on the calling thread and
/// the threads it makes.
pub fn apply(programs: &[BpfProgram]) -> Result<(), String> {
    for program in programs {
        seccompiler::apply_filter(program).map_err(|e| format!("seccomp: {e}"))?;
    }
    Ok(())
}

/// Tables for the tests of the filters of the helpers.
pub mod testing {
    use super::*;

    pub const EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    pub const ENOSYS: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
    pub const ALLOW: u32 = 0x7fff_0000;

    /// What the kernel answers to a call and its arguments, when the
    /// programs of `allow` are installed.
    pub fn verdicts(allow: Allow) -> impl Fn(i64, [u64; 6]) -> u32 {
        let programs = allow.programs().expect("the programs");
        move |nr, args| crate::confine::seccomp_verdict(&programs, nr as u32, ARCH, args)
    }

    /// A call, its arguments and what the filters answer to it.
    pub type Expect = (i64, [u64; 6], u32);

    /// Check each row of `table` against `verdict` (the answer of the
    /// installed programs to a call and its arguments).
    pub fn check(verdict: &dyn Fn(i64, [u64; 6]) -> u32, table: &[Expect]) {
        for (nr, args, want) in table {
            let got = verdict(*nr, *args);
            assert_eq!(
                got, *want,
                "call {nr} with {args:x?}: {got:#x}, not {want:#x}"
            );
        }
    }

    /// The part every helper has: [`Allow::runtime`] with `pid` 1.
    pub fn check_runtime(verdict: &dyn Fn(i64, [u64; 6]) -> u32) {
        let none = [0u64; 6];
        let args = |a: &[u64]| {
            let mut v = [0u64; 6];
            v[..a.len()].copy_from_slice(a);
            v
        };
        let thread = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID) as u64;
        let exec = libc::PROT_EXEC as u64;
        let rw = (libc::PROT_READ | libc::PROT_WRITE) as u64;
        let anon = (libc::MAP_ANONYMOUS | libc::MAP_PRIVATE) as u64;
        let file = libc::MAP_PRIVATE as u64;
        let mut table: Vec<Expect> = Allow::runtime(1)
            .unwrap()
            .numbers()
            .into_iter()
            .filter(|nr| {
                Allow::runtime(1)
                    .unwrap()
                    .get(*nr)
                    .is_some_and(|r| r.is_empty())
            })
            .map(|nr| (nr, none, ALLOW))
            .collect();
        table.extend([
            // threads, not processes or namespaces
            (libc::SYS_clone, args(&[thread]), ALLOW),
            (libc::SYS_clone, args(&[libc::SIGCHLD as u64]), EPERM),
            (libc::SYS_clone3, none, ENOSYS),
            // memory: no executable memory that is not a file
            (libc::SYS_mmap, args(&[0, 4096, rw, anon]), ALLOW),
            (libc::SYS_mmap, args(&[0, 4096, rw | exec, file]), ALLOW),
            (libc::SYS_mmap, args(&[0, 4096, rw | exec, anon]), EPERM),
            (libc::SYS_mprotect, args(&[0, 4096, rw]), ALLOW),
            (libc::SYS_mprotect, args(&[0, 4096, rw | exec]), EPERM),
            (libc::SYS_pkey_mprotect, args(&[0, 4096, rw | exec]), EPERM),
            // descriptors and processes
            (libc::SYS_ioctl, args(&[0, libc::FIONBIO]), ALLOW),
            (libc::SYS_ioctl, args(&[0, 0x5412]), EPERM), // TIOCSTI
            (libc::SYS_ioctl, args(&[0, 0x541c]), EPERM), // TIOCLINUX
            (libc::SYS_ioctl, args(&[0, 0x1234_5678]), EPERM),
            (libc::SYS_fcntl, args(&[0, libc::F_GETFD as u64]), ALLOW),
            (libc::SYS_fcntl, args(&[0, libc::F_SETFL as u64, 0]), ALLOW),
            (
                libc::SYS_fcntl,
                args(&[0, libc::F_SETFL as u64, libc::O_ASYNC as u64]),
                EPERM,
            ),
            (libc::SYS_fcntl, args(&[0, libc::F_SETOWN as u64, 1]), EPERM),
            (libc::SYS_fcntl, args(&[0, 10u64, 1]), EPERM),
            (libc::SYS_prctl, args(&[libc::PR_SET_NAME as u64]), ALLOW),
            (
                libc::SYS_prctl,
                args(&[libc::PR_SET_DUMPABLE as u64]),
                EPERM,
            ),
            (libc::SYS_prctl, args(&[libc::PR_SET_SECCOMP as u64]), EPERM),
            (libc::SYS_prlimit64, none, ALLOW),
            (libc::SYS_prlimit64, args(&[0, 0, 0x1000]), EPERM),
            // a signal to itself only, and never a kill
            (libc::SYS_tgkill, args(&[1]), ALLOW),
            (libc::SYS_tgkill, args(&[2]), EPERM),
            (libc::SYS_kill, args(&[1]), ALLOW),
            (libc::SYS_kill, args(&[2]), EPERM),
            (libc::SYS_kill, none, EPERM),
            // what the kernel interface of tomorrow is: ENOSYS, as on an
            // older kernel; the calls of the table the helpers never make
            // are EPERM
            (TABLE_END as i64, none, ENOSYS),
            (1000, none, ENOSYS),
            (0x4000_0000 | libc::SYS_read, none, ENOSYS),
            (libc::SYS_ptrace, none, EPERM),
            (libc::SYS_bpf, none, EPERM),
            (libc::SYS_setns, none, EPERM),
            (libc::SYS_process_madvise, none, EPERM),
            (libc::SYS_kcmp, none, EPERM),
            (libc::SYS_move_pages, none, EPERM),
            (libc::SYS_mq_open, none, EPERM),
            (libc::SYS_shmget, none, EPERM),
            (libc::SYS_pidfd_open, none, EPERM),
        ]);
        check(verdict, &table);
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{check_runtime, verdicts};
    use super::*;

    #[test]
    fn the_runtime_table() {
        check_runtime(&verdicts(Allow::runtime(1).unwrap()));
    }

    /// The programs installed for real on a thread of the test: the calls
    /// of the runtime work, the others fail before the kernel looks at
    /// their arguments (`mount` and `ptrace` would fail with `EFAULT` and
    /// `ESRCH`), and the kernel's restart of an interrupted sleep is let
    /// through (`EINTR` when nothing is to be restarted).
    #[test]
    fn installed_the_programs_refuse_what_is_not_listed() {
        use crate::probe::syscall_ints;
        let programs = Allow::runtime(std::process::id())
            .unwrap()
            .programs()
            .unwrap();
        assert_eq!(programs.len(), 2);
        assert!(programs.iter().all(|p| p.len() > 4));
        let got = std::thread::spawn(move || {
            rustix::thread::set_no_new_privs(true).unwrap();
            apply(&programs).unwrap();
            let (r, w) = rustix::pipe::pipe().unwrap();
            let wrote = rustix::io::write(&w, b"x");
            let mut buf = [0u8; 1];
            let read = rustix::io::read(&r, &mut buf);
            let pid = std::process::id() as usize;
            let call = |nr: i64, args: [usize; 6]| syscall_ints(nr, args).err();
            (
                wrote.ok(),
                read.ok(),
                call(libc::SYS_mount, [0; 6]),
                call(
                    libc::SYS_ptrace,
                    [libc::PTRACE_ATTACH as usize, 0x7fff_fff0, 0, 0, 0, 0],
                ),
                call(libc::SYS_kill, [pid, 0, 0, 0, 0, 0]),
                call(libc::SYS_kill, [1, 0, 0, 0, 0, 0]),
                call(libc::SYS_clone3, [0; 6]),
                call(i64::from(TABLE_END) + 9, [0; 6]),
                call(libc::SYS_restart_syscall, [0; 6]),
            )
        })
        .join()
        .unwrap();
        assert_eq!(
            got,
            (
                Some(1),
                Some(1),
                Some(libc::EPERM),
                Some(libc::EPERM),
                None,
                Some(libc::EPERM),
                Some(libc::ENOSYS),
                Some(libc::ENOSYS),
                Some(libc::EINTR),
            )
        );
    }
}
