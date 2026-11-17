// SPDX-License-Identifier: Apache-2.0
//! Signals: dispositions, the mask, routing to a thread, signal descriptors
//! and the exited children of a process.

use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

/// Ignore the signal `signum` in this process (`SIG_IGN`).
pub fn ignore(signum: i32) {
    // SAFETY: signal with SIG_IGN installs no handler, so no code can run
    // in a signal context; an invalid number only makes the call fail.
    unsafe {
        libc::signal(signum, libc::SIG_IGN);
    }
}

/// Block the signals `signals` in this thread (and the threads it starts).
pub fn block(signals: &[i32]) -> io::Result<()> {
    // SAFETY: an all-zero sigset_t is valid storage for sigemptyset to
    // initialise, and sigaddset/pthread_sigmask only read it.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for &s in signals {
            libc::sigaddset(&mut set, s);
        }
        if libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Unblock the signals `signals` in this thread.
pub fn unblock(signals: &[i32]) -> io::Result<()> {
    // SAFETY: as in `block`.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for &s in signals {
            libc::sigaddset(&mut set, s);
        }
        if libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Put the default disposition back for the signal `signum` (`SIG_DFL`).
pub fn set_default(signum: i32) {
    // SAFETY: signal with SIG_DFL installs no handler; an invalid number only
    // makes the call fail.
    unsafe {
        libc::signal(signum, libc::SIG_DFL);
    }
}

/// Put the default disposition back for every signal that has a handler of
/// this process (a signal that is ignored stays ignored).  For a process
/// forked from one that installed handlers of its own (the signal driver of
/// a runtime writes a byte to a descriptor number of its parent): the
/// handler would run in the child with the number of a descriptor the child
/// may have closed and opened again for something else.
pub fn reset_handlers() {
    for signum in 1..=64 {
        // SAFETY: sigaction with a null new action only reads the
        // disposition into a zeroed structure (a signal the kernel does
        // not have only makes the call fail).
        let handled = unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            libc::sigaction(signum, std::ptr::null(), &mut old) == 0
                && old.sa_sigaction != libc::SIG_DFL
                && old.sa_sigaction != libc::SIG_IGN
        };
        if handled {
            set_default(signum);
        }
    }
}

/// Make the signal `signum` interrupt a blocking call (`pause`, a read) and
/// do nothing else: a handler that is empty, installed without `SA_RESTART`.
pub fn wake_on(signum: i32) {
    extern "C" fn wake(_: libc::c_int) {}
    // SAFETY: an all-zero sigaction is valid (empty mask, no flags); the
    // handler does nothing, so it is async-signal-safe.
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = wake as extern "C" fn(libc::c_int) as usize;
        libc::sigaction(signum, &act, std::ptr::null_mut());
    }
}

/// Signals blocked and read through a descriptor; the mask is restored
/// when the guard is dropped.  The mask is the thread's: in a process with
/// other threads (the engine of a command), a signal one of them takes is
/// sent on to the thread of the guard by a handler, instead of having its
/// default action.
pub struct SignalGuard {
    fd: Option<OwnedFd>,
    old: libc::sigset_t,
    routes: Vec<Route>,
}

/// The handler of a signal before a guard routed it, and the thread it
/// went to.
struct Route {
    sig: i32,
    action: libc::sigaction,
    tid: i32,
}

/// The thread each signal is routed to (0: none), and its process.
static ROUTE_TID: [std::sync::atomic::AtomicI32; 65] =
    [const { std::sync::atomic::AtomicI32::new(0) }; 65];
static ROUTE_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn route_signal(sig: libc::c_int) {
    use std::sync::atomic::Ordering::Relaxed;
    // SAFETY: getpid, syscall(tgkill), signal and raise are
    // async-signal-safe; errno is kept for the interrupted thread.
    unsafe {
        let errno = *libc::__errno_location();
        let pid = libc::getpid();
        let tid = ROUTE_TID.get(sig as usize).map_or(0, |t| t.load(Relaxed));
        if tid == 0 || pid != ROUTE_PID.load(Relaxed) {
            // (a child forked with the handler: the default action)
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        } else {
            libc::syscall(libc::SYS_tgkill, pid, tid, sig);
        }
        *libc::__errno_location() = errno;
    }
}

impl SignalGuard {
    /// Block `signals` for the process.  With no signals there is no
    /// descriptor.
    pub fn new(signals: &[i32]) -> io::Result<Self> {
        // SAFETY: sigset_t is plain data, initialised by sigemptyset below.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let mut old: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: `set` and `old` are valid sigset_t for these calls; the
        // new descriptor is owned by nothing else.
        unsafe {
            libc::sigemptyset(&mut set);
            for &s in signals {
                libc::sigaddset(&mut set, s);
            }
            libc::sigemptyset(&mut old);
            if libc::sigprocmask(libc::SIG_BLOCK, &set, &mut old) != 0 {
                return Err(io::Error::last_os_error());
            }
            if signals.is_empty() {
                return Ok(Self {
                    fd: None,
                    old,
                    routes: Vec::new(),
                });
            }
            let fd = libc::signalfd(-1, &set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
            if fd < 0 {
                let e = io::Error::last_os_error();
                libc::sigprocmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
                return Err(e);
            }
            let mut guard = Self {
                fd: Some(OwnedFd::from_raw_fd(fd)),
                old,
                routes: Vec::new(),
            };
            guard.route(signals);
            Ok(guard)
        }
    }

    /// Send `signals` that another thread takes to this one.
    fn route(&mut self, signals: &[i32]) {
        use std::sync::atomic::Ordering::Relaxed;
        let tid = rustix::thread::gettid().as_raw_nonzero().get();
        ROUTE_PID.store(rustix::process::getpid().as_raw_nonzero().get(), Relaxed);
        for &sig in signals {
            let Some(slot) = ROUTE_TID.get(sig as usize) else {
                continue;
            };
            let before = slot.swap(tid, Relaxed);
            // SAFETY: a sigaction made from zeroes and filled; the handler
            // only calls async-signal-safe functions.
            unsafe {
                let mut act: libc::sigaction = std::mem::zeroed();
                act.sa_sigaction = route_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
                act.sa_flags = libc::SA_RESTART;
                libc::sigemptyset(&mut act.sa_mask);
                let mut action: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(sig, &act, &mut action) == 0 {
                    self.routes.push(Route {
                        sig,
                        action,
                        tid: before,
                    });
                } else {
                    slot.store(before, Relaxed);
                }
            }
        }
    }

    pub fn fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.fd.as_ref().map(|f| f.as_fd())
    }

    /// The signals that arrived.
    pub fn read(&self) -> Vec<i32> {
        self.fd.as_ref().map(read_signals).unwrap_or_default()
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        // SAFETY: restores the handlers and the mask saved by `new`.
        unsafe {
            for r in self.routes.iter().rev() {
                libc::sigaction(r.sig, &r.action, std::ptr::null_mut());
                ROUTE_TID[r.sig as usize].store(r.tid, std::sync::atomic::Ordering::Relaxed);
            }
            libc::sigprocmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut());
        }
    }
}

/// The signals waiting on a descriptor made by a `SignalGuard`.
pub fn read_signals(fd: &OwnedFd) -> Vec<i32> {
    let mut out = Vec::new();
    loop {
        // SAFETY: an all-zero signalfd_siginfo is valid; read fills at most
        // its size.
        let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
        // SAFETY: the buffer is `info`, live for the call, and the length is
        // its size; the descriptor is open for as long as `fd` is borrowed.
        let n = unsafe {
            libc::read(
                fd.as_raw_fd(),
                (&mut info as *mut libc::signalfd_siginfo).cast(),
                std::mem::size_of::<libc::signalfd_siginfo>(),
            )
        };
        if n != std::mem::size_of::<libc::signalfd_siginfo>() as isize {
            break;
        }
        out.push(info.ssi_signo as i32);
    }
    out
}

/// Send `sig` to the process behind a pidfd.
pub fn pidfd_send_signal<Fd: AsFd>(pidfd: Fd, sig: i32) -> io::Result<()> {
    if !(1..=64).contains(&sig) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    // SAFETY: pidfd_send_signal with a valid descriptor, no siginfo, no flags.
    let r = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_fd().as_raw_fd(),
            sig,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The pid of a child that has exited and is not reaped yet, without
/// reaping it.
pub fn peek_zombie() -> Option<i32> {
    // SAFETY: an all-zero siginfo_t is valid for waitid to fill in.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: waitid with P_ALL and a valid siginfo_t.
    let r = unsafe {
        libc::waitid(
            libc::P_ALL,
            0,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if r != 0 {
        return None;
    }
    // SAFETY: filled in by a successful waitid.
    let pid = unsafe { info.si_pid() };
    (pid > 0).then_some(pid)
}

/// Send `signum` to the thread `tid` of this process.
pub fn tgkill(tid: i32, signum: i32) -> io::Result<()> {
    // SAFETY: tgkill takes the ids of a process and a thread and a signal
    // number; it reads no memory of this process.
    let r = unsafe { libc::syscall(libc::SYS_tgkill, libc::getpid(), tid, signum) };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Raise `signum` on the calling thread.
pub fn raise(signum: i32) {
    // SAFETY: raise takes a signal number; what the handler does is the
    // caller's business.
    unsafe {
        libc::raise(signum);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn dispositions_can_be_changed() {
        // (SIGURG: ignored by default, nothing of the test process uses it)
        super::wake_on(libc::SIGURG);
        super::set_default(libc::SIGURG);
        super::block(&[libc::SIGURG]).unwrap();
        super::unblock(&[libc::SIGURG]).unwrap();
    }

    /// A forked process has no handler of its parent's (they would run
    /// with the descriptor numbers of the parent), and keeps what the
    /// parent ignores.
    #[test]
    fn the_handlers_are_reset_and_the_ignored_signals_stay_so() {
        let code = crate::process::fork_status(|| {
            super::wake_on(libc::SIGUSR1);
            super::ignore(libc::SIGUSR2);
            super::reset_handlers();
            let disposition = |signum| {
                // SAFETY: reads the disposition into a zeroed structure.
                let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
                // SAFETY: a null new action changes nothing.
                unsafe { libc::sigaction(signum, std::ptr::null(), &mut old) };
                old.sa_sigaction
            };
            i32::from(
                disposition(libc::SIGUSR1) != libc::SIG_DFL
                    || disposition(libc::SIGUSR2) != libc::SIG_IGN,
            )
        })
        .unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn a_signal_is_blocked() {
        // (SIGURG is ignored by default)
        super::block(&[libc::SIGURG]).unwrap();
    }

    #[test]
    fn a_signal_is_ignored() {
        // (a signal that nothing else of the test process uses)
        super::ignore(libc::SIGXFSZ);
    }
}
