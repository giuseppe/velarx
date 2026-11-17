// SPDX-License-Identifier: Apache-2.0
//! Commands that start other programs.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

/// The proof of being in a forked child before it executes another program
/// (or, for a child that goes on, right after the fork): the process has one
/// thread of control and nothing else of it runs, so a descriptor may be
/// used, closed or replaced by its number.  Only [`pre_exec`] and the
/// functions that fork ([`crate::process::fork_single_threaded`] and the
/// others) make one, and it is handed to the child by reference, so it does
/// not outlive the child's code.
///
/// Its methods are the system calls on numbers that are async-signal-safe:
/// they allocate nothing and take no lock.  It is neither `Send` nor `Sync`:
/// the claim is about the one thread of the child.  A child that goes on
/// after its set-up gives it up (drops it) before it opens anything of its
/// own.
#[derive(Debug)]
pub struct InChild {
    _one_thread: std::marker::PhantomData<*const ()>,
}

/// The most descriptors [`InChild::close_all_but`] keeps.
pub const MAX_KEPT_FDS: usize = 8;

/// The most descriptors [`InChild::place_fds`] moves.
pub const MAX_PLACED_FDS: usize = 80;

impl InChild {
    pub(crate) fn new() -> Self {
        Self {
            _one_thread: std::marker::PhantomData,
        }
    }

    /// Close the descriptor `raw` (an error is ignored).
    pub fn close(&self, raw: i32) {
        // SAFETY: close takes an integer; nothing else of the child uses it.
        unsafe {
            libc::close(raw);
        }
    }

    /// Close every descriptor from `first` to `last` (both included).
    pub fn close_range(&self, first: u32, last: u32) {
        crate::fd::close_range(first, last);
    }

    /// Close every descriptor above the standard streams but those of
    /// `keep` (at most [`MAX_KEPT_FDS`]; no allocation).
    pub fn close_all_but(&self, keep: &[i32]) {
        let mut sorted = [i32::MAX; MAX_KEPT_FDS];
        let n = keep.len().min(MAX_KEPT_FDS);
        sorted[..n].copy_from_slice(&keep[..n]);
        sorted[..n].sort_unstable();
        let mut first = 3u32;
        for &fd in &sorted[..n] {
            let fd = fd as u32;
            if fd >= first {
                if fd > first {
                    crate::fd::close_range(first, fd - 1);
                }
                first = fd + 1;
            }
        }
        crate::fd::close_range(first, u32::MAX);
    }

    /// Close every descriptor from `first` on (one system call).
    pub fn close_from(&self, first: u32) {
        crate::fd::close_range(first, u32::MAX);
    }

    /// Mark every descriptor from `first` on close-on-exec (one system call:
    /// closing them would also close the pipe through which
    /// `Command::spawn` learns that the exec failed).
    pub fn cloexec_from(&self, first: u32) {
        // SAFETY: close_range takes integers and touches no memory; the
        // CLOEXEC flag closes nothing now.
        unsafe {
            libc::syscall(
                libc::SYS_close_range,
                first,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            );
        }
    }

    /// Clear the close-on-exec flag of `fd` (and its other descriptor flags).
    pub fn clear_cloexec(&self, fd: i32) -> io::Result<()> {
        // SAFETY: fcntl with F_SETFD takes integers.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// `dup2(from, to)`: `to` is `from`'s file, without close-on-exec.
    pub fn dup2(&self, from: i32, to: i32) -> io::Result<()> {
        // SAFETY: dup2 takes two integers.
        if unsafe { libc::dup2(from, to) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// A copy of `fd` with close-on-exec set, numbered `min` or above.
    pub fn dup_cloexec_from(&self, fd: i32, min: i32) -> io::Result<i32> {
        // SAFETY: fcntl with F_DUPFD_CLOEXEC takes integers.
        let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, min) };
        if new < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(new)
    }

    /// Put `fds` at `first`, `first + 1`, ..., without close-on-exec.  They
    /// are moved above the targets first, so that one at the target number
    /// of another is not lost.  Only fcntl, dup2 and close.
    pub fn place_fds(&self, fds: &[i32], first: i32) -> io::Result<()> {
        let mut parked = [0i32; MAX_PLACED_FDS];
        if fds.len() > parked.len() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        for (i, &fd) in fds.iter().enumerate() {
            parked[i] = self.dup_cloexec_from(fd, first + fds.len() as i32)?;
        }
        for (i, &p) in parked[..fds.len()].iter().enumerate() {
            self.dup2(p, first + i as i32)?;
            self.close(p);
        }
        Ok(())
    }

    /// Unblock all signals, for a child that is going to exec.
    pub fn unblock_signals(&self) -> io::Result<()> {
        // SAFETY: a full empty set is valid; sigprocmask only reads it.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            if libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

/// Run `f` in the child of `cmd` between the fork and the exec.  It may
/// only call async-signal-safe functions (the methods of [`InChild`],
/// [`crate::signal`] and of `rustix`, on integers and on memory the closure
/// owns): no allocation, no lock, no printing.
pub fn pre_exec<F>(cmd: &mut Command, mut f: F)
where
    F: FnMut(&InChild) -> io::Result<()> + Send + Sync + 'static,
{
    // SAFETY: the contract above is the one `pre_exec` asks for; the
    // closure is `Send + Sync + 'static`, so it owns what it uses.  The
    // token it gets is true: this runs in the child.
    unsafe {
        cmd.pre_exec(move || f(&InChild::new()));
    }
}

/// Make `fd` the descriptor 3 of the process `cmd` starts and mark every
/// descriptor above it close-on-exec.  `fd` must stay open until the
/// command is spawned (else the spawn fails or passes what has its number).
pub fn pass_as_fd3(cmd: &mut Command, fd: i32) {
    pre_exec(cmd, move |child| {
        if fd == 3 {
            child.clear_cloexec(3)?;
        } else {
            child.dup2(fd, 3)?;
        }
        child.cloexec_from(4);
        Ok(())
    });
}

/// [`pass_as_fd3`], and `others` as 4, 5, ...; the descriptors above are
/// closed on exec.  All must stay open until the command is spawned.
pub fn pass_fds(cmd: &mut Command, fd: i32, others: Vec<i32>) {
    pre_exec(cmd, move |child| {
        // out of the way of 3 and the places of the others first
        let parked = child.dup_cloexec_from(fd, 4 + others.len() as i32)?;
        child.place_fds(&others, 4)?;
        child.dup2(parked, 3)?;
        child.close(parked);
        child.cloexec_from(4 + others.len() as u32);
        Ok(())
    });
}

/// The program, arguments and environment of an `exec`, with the pointer
/// arrays made before the fork so that the child allocates nothing.
pub struct ExecArgs {
    argv: Vec<*const libc::c_char>,
    envp: Vec<*const libc::c_char>,
    // (the strings the pointers point to)
    _strings: (Vec<CString>, Vec<CString>),
}

impl ExecArgs {
    pub fn new(argv: Vec<CString>, envp: Vec<CString>) -> Self {
        let pointers = |v: &[CString]| -> Vec<*const libc::c_char> {
            v.iter()
                .map(|c| c.as_ptr())
                .chain([std::ptr::null()])
                .collect()
        };
        Self {
            argv: pointers(&argv),
            envp: pointers(&envp),
            _strings: (argv, envp),
        }
    }

    /// `execveat` of the open file `exe` (`AT_EMPTY_PATH`: no path is looked
    /// up): it returns only when it failed, with the error.
    /// Async-signal-safe.
    pub fn exec_fd(&self, exe: i32) -> io::Error {
        // SAFETY: the pointer arrays end in a null pointer and point to
        // NUL-terminated strings that live as long as `self`; the empty
        // path is a NUL-terminated literal.
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                exe,
                c"".as_ptr(),
                self.argv.as_ptr(),
                self.envp.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
        }
        io::Error::last_os_error()
    }

    /// `execvpe` of `program`: it returns only when it failed, with the
    /// error.  Async-signal-safe.
    pub fn exec(&self, program: &std::ffi::CStr) -> io::Error {
        // SAFETY: the pointer arrays end in a null pointer and point to
        // NUL-terminated strings that live as long as `self`.
        unsafe { libc::execvpe(program.as_ptr(), self.argv.as_ptr(), self.envp.as_ptr()) };
        io::Error::last_os_error()
    }
}

#[repr(C)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// Fork (`clone3` with `CLONE_INTO_CGROUP`: the child starts in the cgroup
/// `cgroup`, a descriptor of its directory), as `std::process::Command`
/// does: the signals are blocked until the child has its own mask, which
/// is empty with `SIGPIPE` the default again.  The child runs `child`
/// and ends with the status it returns (`_exit`: no destructor, no
/// `atexit`).  `child` may only make async-signal-safe calls.  Returns the
/// pid.
pub fn fork_into_cgroup<F: FnOnce(&InChild) -> i32>(
    cgroup: BorrowedFd<'_>,
    child: F,
) -> io::Result<u32> {
    let args = CloneArgs {
        flags: CLONE_INTO_CGROUP,
        pidfd: 0,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: u64::from(cgroup.as_raw_fd() as u32),
    };
    // SAFETY: sigset_t is plain data for which all zeroes is valid; the
    // calls fill local values.
    let before = unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        let mut before: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_SETMASK, &all, &mut before);
        before
    };
    // SAFETY: clone3 without CLONE_VM is a fork; `args` is a valid
    // structure of the size given; the child below makes only
    // async-signal-safe calls (those of `child`, by contract), and ends in
    // `_exit`.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &args as *const CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if pid == 0 {
        // SAFETY: in the child: signal and pthread_sigmask on local values
        // (async-signal-safe), and `_exit` never returns.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            let mut none: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut none);
            libc::pthread_sigmask(libc::SIG_SETMASK, &none, std::ptr::null_mut());
        }
        let status = child(&InChild::new());
        crate::process::exit_now(status);
    }
    let error = io::Error::last_os_error();
    // SAFETY: restores the mask saved above.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &before, std::ptr::null_mut()) };
    if pid < 0 {
        return Err(error);
    }
    Ok(pid as u32)
}

#[cfg(test)]
mod tests {
    #[test]
    fn exec_of_a_missing_program_is_an_error() {
        let args = super::ExecArgs::new(vec![c"x".into()], vec![]);
        let e = args.exec(c"/nonexistent/velarx-test");
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
    }

    /// The methods of the child's token do what they say: the descriptors
    /// land on their numbers, and what is above is closed on exec.
    #[test]
    fn the_token_places_and_closes_descriptors_in_the_child() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        let mut a = tempfile::tempfile().unwrap();
        let mut b = tempfile::tempfile().unwrap();
        a.write_all(b"a").unwrap();
        b.write_all(b"b").unwrap();
        for f in [&mut a, &mut b] {
            std::io::Seek::rewind(f).unwrap();
        }
        let (a, b) = (a.as_raw_fd(), b.as_raw_fd());
        let mut cmd = std::process::Command::new("/bin/sh");
        // 3 and 4 are the files, 5 is not open
        cmd.args([
            "-c",
            "cat <&3; cat <&4; if cat <&5 2>/dev/null; then exit 1; fi",
        ]);
        super::pass_fds(&mut cmd, a, vec![b]);
        let out = cmd.output().unwrap();
        assert_eq!(out.stdout, b"ab");
    }

    /// A forked child keeps the descriptors it is told to and no other
    /// above the standard streams.
    #[test]
    fn a_child_keeps_the_descriptors_it_is_told_to_and_no_others() {
        use std::os::fd::AsRawFd;
        let open = || std::fs::File::open("/dev/null").unwrap();
        let (a, b, c, d) = (open(), open(), open(), open());
        let fds = [a.as_raw_fd(), b.as_raw_fd(), c.as_raw_fd(), d.as_raw_fd()];
        let (keep, gone) = ([fds[3], fds[1]], [fds[0], fds[2]]);
        let pid = crate::process::fork_beside_idle_threads(|child| {
            child.close_all_but(&keep);
            i32::from(
                keep.iter().any(|&fd| !crate::fd::is_open(fd))
                    || gone.iter().any(|&fd| crate::fd::is_open(fd)),
            )
        })
        .unwrap();
        let status = rustix::process::waitpid(
            rustix::process::Pid::from_raw(pid),
            rustix::process::WaitOptions::empty(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(status.1.exit_status(), Some(0));
    }

    #[test]
    fn the_closure_runs_before_the_exec_and_can_fail_it() {
        let mut ok = std::process::Command::new("/bin/true");
        super::pre_exec(&mut ok, |_| Ok(()));
        assert!(ok.status().unwrap().success());
        let mut bad = std::process::Command::new("/bin/true");
        super::pre_exec(&mut bad, |_| {
            Err(std::io::Error::from_raw_os_error(libc::EPERM))
        });
        assert_eq!(bad.status().unwrap_err().raw_os_error(), Some(libc::EPERM));
    }
}
