// SPDX-License-Identifier: Apache-2.0
//! The calls the self-tests of the sandboxes make to see them refused.

use std::os::fd::{FromRawFd, OwnedFd};

/// A system call with integer arguments: `Err(errno)`, or what it
/// returned.  Not public: a call by number with any integers can close or
/// replace a descriptor, or unmap memory; the probes below are the calls
/// the self-tests make, each with arguments that cannot.
pub(crate) fn syscall_ints(nr: i64, args: [usize; 6]) -> Result<isize, i32> {
    // SAFETY: private; every caller passes harmless numbers, no address and
    // no descriptor (see each one).
    let r = unsafe { libc::syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]) };
    if r < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        Ok(r as isize)
    }
}

/// `kill(pid, 0)`: `Ok` when a signal could be sent to `pid` (`-1`: to
/// every process this one may signal), else the errno.  Nothing is sent.
pub fn kill_nothing(pid: i32) -> Result<(), i32> {
    // (signal 0: only the permission is checked)
    syscall_ints(libc::SYS_kill, [pid as usize, 0, 0, 0, 0, 0]).map(drop)
}

/// `tgkill(tgid, tid, 0)`: [`kill_nothing`] for a thread.
pub fn tgkill_nothing(tgid: i32, tid: i32) -> Result<(), i32> {
    // (signal 0: only the permission is checked)
    syscall_ints(libc::SYS_tgkill, [tgid as usize, tid as usize, 0, 0, 0, 0]).map(drop)
}

/// `bpf` with command 0 and no attributes: `Ok` when the kernel looked at
/// it (it fails then, with `EFAULT`, `EINVAL`...: anything but `EPERM` is
/// the call let through), else the errno.
pub fn bpf_nothing() -> Result<(), i32> {
    // (command 0, a null attribute pointer, size 0: nothing is made)
    syscall_ints(libc::SYS_bpf, [0; 6]).map(drop)
}

/// `clone(CLONE_NEWUSER | SIGCHLD)` without a stack (a fork into a new
/// user namespace): `Ok` when it was allowed, else the errno.  A child
/// that is made ends at once and is reaped.
pub fn clone_new_user() -> Result<(), i32> {
    let flags = (libc::CLONE_NEWUSER | libc::SIGCHLD) as usize;
    match syscall_ints(libc::SYS_clone, [flags, 0, 0, 0, 0, 0])? {
        0 => crate::process::exit_now(0),
        pid => {
            let _ = crate::process::wait_exit_code(pid as i32);
            Ok(())
        }
    }
}

/// `io_uring_setup(1, params)` with a zeroed parameter block: the
/// descriptor, or the errno.
pub fn io_uring_setup() -> Result<OwnedFd, i32> {
    let mut params = [0u8; 120];
    // SAFETY: the parameter block is a local array of the size of
    // `struct io_uring_params`, which the kernel fills.
    let r = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1, params.as_mut_ptr()) };
    if r < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    // SAFETY: the kernel returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(r as i32) })
}

/// `ptrace(PTRACE_ATTACH, pid)`: `Ok` when it was allowed, else the errno.
pub fn ptrace_attach(pid: i32) -> Result<(), i32> {
    // SAFETY: PTRACE_ATTACH takes a pid and no address.
    let r = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0) };
    if r < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        Ok(())
    }
}

/// `ptrace(PTRACE_TRACEME)`: `Ok` when it was allowed, else the errno.
pub fn ptrace_traceme() -> Result<(), i32> {
    // SAFETY: PTRACE_TRACEME takes no address and no pid.
    let r = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) };
    if r < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        Ok(())
    }
}

/// Whether this process can make a thread that runs: it makes one the first
/// time, which then stays (parked) for as long as the process lives, so
/// that the listing of the threads ([`status_of_every_thread`]) has another
/// thread than the caller's to look at, and no thread of the probes ends
/// while it is read: the kernel ends a listing of `/proc/PID/task` at the
/// thread it has just listed when that one ends meanwhile, and the threads
/// after it are not in it.
pub fn a_thread_runs() -> bool {
    static RAN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *RAN.get_or_init(|| {
        let (ran, told) = std::sync::mpsc::channel::<i32>();
        let made = std::thread::Builder::new().spawn(move || {
            let _ = ran.send(1 + 1);
            loop {
                std::thread::park();
            }
        });
        made.is_ok() && told.recv() == Ok(2)
    })
}

/// The value of the field `name` of the status of every thread of this
/// process (`Seccomp`, `NoNewPrivs`, `CapEff`: what the kernel says of each
/// task), the one of [`a_thread_runs`] alive meanwhile: a confinement of the
/// process is of every thread, those made after it too.  `None` for a task
/// whose status has no such field.  The caller makes no thread end while
/// this reads (see [`a_thread_runs`]).
pub fn status_of_every_thread(name: &str) -> Vec<Option<String>> {
    let _ = a_thread_runs();
    let field = format!("{name}:");
    std::fs::read_dir("/proc/self/task")
        .into_iter()
        .flatten()
        .flatten()
        // (a task that ended meanwhile has no status: it is no thread)
        .filter_map(|task| std::fs::read_to_string(task.path().join("status")).ok())
        .map(|status| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(field.as_str()))
                .map(|v| v.trim().to_string())
        })
        .collect()
}

/// Whether every thread of this process (`status_of_every_thread`), and
/// more than one, has `value` in its field `name`.
pub fn every_thread_has(name: &str, value: &str) -> bool {
    let values = status_of_every_thread(name);
    values.len() > 1 && values.iter().all(|v| v.as_deref() == Some(value))
}

#[cfg(test)]
mod tests {
    /// Each thread is seen, the one made for it too; a thread confined
    /// alone is not the process.
    #[test]
    fn the_status_of_every_thread_is_read() {
        let values = super::status_of_every_thread("NoNewPrivs");
        assert!(values.len() > 1, "{values:?}");
        assert!(values.iter().all(Option::is_some), "{values:?}");
        assert!(super::status_of_every_thread("NoSuchField")
            .iter()
            .all(Option::is_none));
        if rustix::thread::no_new_privs().unwrap() {
            return eprintln!("skipped: this process has no_new_privs already");
        }
        let confined = std::thread::spawn(|| {
            rustix::thread::set_no_new_privs(true).unwrap();
            super::every_thread_has("NoNewPrivs", "1")
        });
        assert!(!confined.join().unwrap());
    }
}
