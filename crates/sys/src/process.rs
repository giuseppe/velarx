// SPDX-License-Identifier: Apache-2.0
//! Processes: fork, exit, signals, the environment and the argument area.

use std::ffi::CStr;
use std::io;

use crate::spawn::InChild;

/// The effective user of the process.
pub fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Drop the whole environment of the process (`clearenv`).  Call it in a
/// process with one thread, as no other thread may read the environment
/// meanwhile.
pub fn clear_environment() {
    // SAFETY: clearenv has no arguments; the single thread of the caller is
    // the only one that reads the environment, by the contract above.
    unsafe {
        libc::clearenv();
    }
}

/// Write `title` over the memory `[start, end)` of this process, padded
/// with NULs and cut to leave the last byte NUL: the area of its arguments
/// and environment as `/proc/self/stat` reports it.  A range that is not
/// inside one writable mapping of the process (`/proc/self/maps`) is left
/// alone.
pub fn overwrite_memory(start: usize, end: usize, title: &[u8]) {
    if end <= start || !mapped_writable(start, end) {
        return;
    }
    // SAFETY: the range lies inside one writable mapping of this process
    // (checked in `mapped_writable`), and the caller is the only code that
    // reads or writes the argument area at this time.
    let area = unsafe { std::slice::from_raw_parts_mut(start as *mut u8, end - start) };
    let n = title.len().min(area.len() - 1);
    area[..n].copy_from_slice(&title[..n]);
    area[n..].fill(0);
}

/// Whether `[start, end)` is inside one mapping of this process that is
/// writable.
fn mapped_writable(start: usize, end: usize) -> bool {
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return false;
    };
    maps.lines().any(|l| {
        let mut f = l.split_whitespace();
        let (Some(range), Some(perms)) = (f.next(), f.next()) else {
            return false;
        };
        let Some((a, b)) = range.split_once('-') else {
            return false;
        };
        match (usize::from_str_radix(a, 16), usize::from_str_radix(b, 16)) {
            (Ok(a), Ok(b)) => a <= start && end <= b && perms.starts_with("rw"),
            _ => false,
        }
    })
}

/// Which side of a fork this is.
#[derive(Debug)]
pub enum Fork {
    /// The new process, with the proof that it may use descriptor numbers.
    Child(InChild),
    /// The process that forked, with the pid of the child.
    Parent(i32),
}

/// The number of threads of this process.
pub fn thread_count() -> io::Result<usize> {
    Ok(std::fs::read_dir("/proc/self/task")?.count())
}

/// Fail unless this process has a single thread.  A `fork` of a process with
/// other threads leaves the child with the locks they held (the allocator's,
/// the standard output's) taken for good: its child may only call
/// async-signal-safe functions until it executes another program.  `what`
/// names the fork in the error.
pub fn ensure_single_threaded(what: &str) -> io::Result<()> {
    match thread_count()? {
        1 => Ok(()),
        n => Err(io::Error::other(format!(
            "{what}: the process has {n} threads, it has to fork with one"
        ))),
    }
}

fn fork_now() -> io::Result<Fork> {
    // SAFETY: fork takes no argument and touches no memory of this
    // process.  What the child may do afterwards is the contract of the
    // public functions that call this one.
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(Fork::Child(InChild::new())),
        pid => Ok(Fork::Parent(pid)),
    }
}

/// Fork a process that has a single thread (checked: the error names `what`),
/// so that the child may do anything, allocate and take locks included.
pub fn fork_single_threaded(what: &str) -> io::Result<Fork> {
    ensure_single_threaded(what)?;
    fork_now()
}

/// [`fork_single_threaded`] for a process that cannot count its threads (it
/// cannot read `/proc`, being confined): the caller knows it has one.
pub fn fork_known_single_threaded() -> io::Result<Fork> {
    fork_now()
}

/// Fork a process that may have other threads: `child` runs in the new
/// process and must only call async-signal-safe functions (system calls on
/// integers and on memory made before the fork: no allocation, no lock, no
/// `std::io` printing); the child ends with the code it returns (`_exit`:
/// no destructor runs).  The pid of the child.
pub fn fork_async_signal_safe(child: impl FnOnce(&InChild) -> i32) -> io::Result<i32> {
    match fork_now()? {
        Fork::Child(token) => exit_now(child(&token)),
        Fork::Parent(pid) => Ok(pid),
    }
}

/// Fork from a thread of a process whose other threads are known to hold
/// nothing (the main thread of a unit test binary waits for the thread that
/// runs the test): `child` runs in the new process, which has that one
/// thread and may do anything, and its result is the code the process ends
/// with (no destructor runs).  The pid of the child.
pub fn fork_beside_idle_threads(child: impl FnOnce(&InChild) -> i32) -> io::Result<i32> {
    match fork_now()? {
        Fork::Child(token) => exit_now(child(&token)),
        Fork::Parent(pid) => Ok(pid),
    }
}

/// End this process at once (`_exit`): no destructor runs, nothing is
/// flushed.  For a forked child that must not run the code of its parent.
pub fn exit_now(code: i32) -> ! {
    // SAFETY: _exit takes an integer and does not return.
    unsafe { libc::_exit(code) }
}

/// Run `f` when the process ends by `exit` or by returning from `main`
/// (`atexit`; not at `_exit` or a signal).  The calls add up, run last in
/// first out.
pub fn at_exit(f: extern "C" fn()) {
    // SAFETY: atexit takes a function that has no arguments and no result.
    unsafe {
        libc::atexit(f);
    }
}

/// Wait until a signal ends the process or runs its handler (`pause`).
pub fn pause() {
    // SAFETY: pause takes no argument.
    unsafe {
        libc::pause();
    }
}

/// Stop until a signal ends the process or runs its handler, forever.
pub fn pause_forever() -> ! {
    loop {
        // SAFETY: pause takes no argument; it returns after a handler ran.
        unsafe { libc::pause() };
    }
}

/// Wait for the child `pid` to end: its exit code, or 128 plus the number of
/// the signal that ended it.
pub fn wait_exit_code(pid: i32) -> io::Result<i32> {
    let pid = rustix::process::Pid::from_raw(pid)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ECHILD))?;
    loop {
        match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty()) {
            Ok(Some((_, status))) => {
                return Ok(match status.exit_status() {
                    Some(code) => code,
                    None => 128 + status.terminating_signal().unwrap_or(0),
                })
            }
            Ok(None) => continue,
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

/// Become the user `uid` and the group `gid` for good (real, effective and
/// saved ids), with no supplementary group.  The first call that fails ends
/// it with its error: the process keeps the ids it had then.
pub fn become_user_and_group(uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: setgroups takes a size and a list that is not read when the
    // size is zero.
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: setresgid takes three integers.
    if unsafe { libc::setresgid(gid, gid, gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: setresuid takes three integers.
    if unsafe { libc::setresuid(uid, uid, uid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Send the signal number `signum` (any the kernel has, `0` to probe) to the
/// process `pid` (a negative `pid` is a process group, as in `kill(2)`).
pub fn kill(pid: i32, signum: i32) -> io::Result<()> {
    // SAFETY: kill takes two integers.
    if unsafe { libc::kill(pid, signum) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Fork a child that runs `body` and exits with the code it returns, and
/// wait for it: its exit code, or the error of the `fork`.  A child that
/// ends by a signal is code `128 + signal`.  For the self-tests of the
/// sandboxes, whose forks are refused by the filter or whose children only
/// make system calls: `body` must not rely on locks or the allocator of a
/// process with other threads.
pub fn fork_status(body: impl FnOnce() -> i32) -> std::io::Result<i32> {
    // SAFETY: the child runs `body` and `_exit`s; it never returns into the
    // caller, and the calls of the self-tests it makes are system calls.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid == 0 {
        let code = body();
        // SAFETY: _exit ends the child at once, running nothing of the parent.
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    // SAFETY: waitpid on the child made above, into a local integer.
    while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
    Ok(if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        128 + libc::WTERMSIG(status)
    })
}

/// `execve(path)` with no arguments and no environment, for a sandbox that
/// must refuse it: what the call returns is its errno (it returns only when
/// it failed).
pub fn try_exec(path: &CStr) -> i32 {
    let argv = [path.as_ptr(), std::ptr::null()];
    // SAFETY: execve with a NUL-terminated path, a NULL-terminated argv that
    // outlives the call and an empty environment; it returns only on error.
    unsafe {
        libc::execve(path.as_ptr(), argv.as_ptr(), std::ptr::null());
    }
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_process_with_a_second_thread_does_not_fork_one() {
        let (stop, wait) = std::sync::mpsc::channel::<()>();
        let (up, started) = std::sync::mpsc::channel::<()>();
        let t = std::thread::spawn(move || {
            up.send(()).unwrap();
            let _ = wait.recv();
        });
        started.recv().unwrap();
        assert!(fork_single_threaded("test").is_err());
        stop.send(()).unwrap();
        t.join().unwrap();
    }

    #[test]
    fn a_child_ends_with_its_code() {
        let pid = fork_async_signal_safe(|_| 7).unwrap();
        let (_, status) = rustix::process::waitpid(
            rustix::process::Pid::from_raw(pid),
            rustix::process::WaitOptions::empty(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(status.exit_status(), Some(7));
    }

    #[test]
    fn kill_of_nothing_probes() {
        assert!(kill(std::process::id() as i32, 0).is_ok());
        assert!(kill(std::process::id() as i32, 9999).is_err());
    }

    #[test]
    fn a_range_that_is_not_mapped_is_not_written() {
        super::overwrite_memory(8, 64, b"x");
    }

    #[test]
    fn a_writable_buffer_is_overwritten() {
        let mut buf = vec![b'a'; 16];
        let start = buf.as_mut_ptr() as usize;
        super::overwrite_memory(start, start + 16, b"hello");
        assert_eq!(&buf[..6], b"hello\0");
        assert!(buf[6..].iter().all(|&b| b == 0));
    }
}
