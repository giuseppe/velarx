// SPDX-License-Identifier: Apache-2.0
//! The process that starts the programs of a process that confines itself
//! ([`Spawner`]).
//!
//! A process that may execute nothing and make no namespace once it is
//! confined forks a spawner before the confinement (as the [`Connector`]
//! does for connections), and asks it for each program it needs.  What
//! crosses the socket between them (a socket of messages, one message for
//! each request):
//!
//! * a request: the number of the program, its arguments and its
//!   environment, the write end of a life pipe and the descriptors the program
//!   gets as 0, 1, 2 and so on; the reply: its process id, or why it cannot
//!   be started.  The spawner starts the programs it was given (open
//!   before the fork, executed through the descriptor: no path is looked up
//!   after the start), with the arguments and the variables that program's
//!   checks accept, nothing else;
//! * the life pipe: the caller holds its read end ([`Child`]) for as long as
//!   it holds the program (a pipe, not a socket: a confined caller may make
//!   no socket); when it closes it (or ends) the spawner kills the program,
//!   and when the program ends the spawner writes its wait status (4 bytes)
//!   to it.  The caller is not the parent of the program and
//!   signals none.
//!
//! The spawner confines itself with what the caller gives it (it runs in
//! the new process before it serves, and an error from it is the start's:
//! it serves nothing unconfined); the programs inherit that and add what
//! each narrows itself to.  It ends with the caller.
//!
//! [`Connector`]: crate::connector::Connector

use std::ffi::CString;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::Mutex;

/// The most programs running at once in one spawner.
const MAX_RUNNING: usize = 256;

/// The longest request.
const MAX_REQUEST: usize = 16 << 10;

/// The most descriptors a program is given (0, 1, 2 and eight more).
pub const MAX_FDS: usize = 11;

/// The number of the lowest descriptor the spawner's own descriptors are
/// moved to in the child before the program's are placed.
const PARKED: i32 = 64;

/// A program the spawner may start.
pub struct Program {
    /// The first of its arguments (its name)
    pub name: String,
    /// The program, open (`O_PATH` or read-only) before the fork
    pub exe: OwnedFd,
    /// Whether the arguments (after the name) are the ones this program is
    /// started with
    pub check: fn(&[String]) -> bool,
    /// Whether a variable of the environment of this name is passed
    pub env: fn(&str) -> bool,
    /// The program is a script: it keeps `exe` open through the exec, as
    /// its interpreter reads it by `/dev/fd`
    script: bool,
    /// What the child of a request does (in its own process, after the
    /// fork, with its descriptors placed) before it executes the program:
    /// the confinement that is for this program and not for the spawner
    setup: Option<ChildSetup>,
}

/// What the child of a request does before it executes its program.
pub type ChildSetup = Box<dyn Fn() -> io::Result<()>>;

impl Program {
    /// This program's child runs `setup` before the exec (an error from it
    /// is the error of the spawn).
    pub fn with_setup(mut self, setup: impl Fn() -> io::Result<()> + 'static) -> Self {
        self.setup = Some(Box::new(setup));
        self
    }

    /// The program `exe`, called `name`.
    pub fn new(
        name: &str,
        exe: OwnedFd,
        check: fn(&[String]) -> bool,
        env: fn(&str) -> bool,
    ) -> Self {
        let mut head = [0u8; 2];
        let script = rustix::fs::open(
            crate::fd::proc_str(&exe),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .and_then(|f| rustix::io::read(&f, &mut head))
        .is_ok_and(|n| n == 2 && &head == b"#!");
        Self {
            name: name.to_string(),
            exe,
            check,
            env,
            script,
            setup: None,
        }
    }

    /// The program at `path`.
    pub fn open(
        name: &str,
        path: &std::path::Path,
        check: fn(&[String]) -> bool,
        env: fn(&str) -> bool,
    ) -> io::Result<Self> {
        let exe = rustix::fs::open(
            path,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        Ok(Self::new(name, exe, check, env))
    }
}

/// The spawner of a process: its end of the socket.
pub struct Spawner {
    requests: Mutex<OwnedFd>,
}

impl std::fmt::Debug for Spawner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Spawner").finish()
    }
}

/// A program the spawner started, as its caller holds it.  Dropping it ends
/// the program.
#[derive(Debug)]
pub struct Child {
    pid: u32,
    life: OwnedFd,
}

impl Child {
    /// The process id, in the spawner's namespace (for logs only).
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// How the program ended, as long as it takes.
    pub fn wait(&self) -> io::Result<ExitStatus> {
        let mut status = [0u8; 4];
        let mut life = std::fs::File::from(self.life.try_clone()?);
        life.read_exact(&mut status)?;
        Ok(ExitStatus::from_raw(i32::from_ne_bytes(status)))
    }

    /// The life pipe, for a caller that waits in its own reactor: it is
    /// readable (4 bytes, the wait status in native order) when the program
    /// ends.  Closing it ends the program.
    pub fn into_life(self) -> OwnedFd {
        self.life
    }
}

fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
    use rustix::net::{AddressFamily, SocketFlags, SocketType};
    Ok(rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?)
}

// The replies
const READY: u8 = 0;
const STARTED: u8 = 1;
const FAILED: u8 = 2;

impl Spawner {
    /// Fork the spawner of `programs`.  `confine` runs in the new process
    /// before it serves, given the programs (for the rules that name them),
    /// and an error from it is this one's.  The process
    /// must have one thread.
    pub fn start(
        programs: Vec<Program>,
        confine: impl FnOnce(&[Program]) -> Result<(), String>,
    ) -> Result<Self, String> {
        let (ours, theirs) = pair().map_err(|e| format!("the spawner: {e}"))?;
        match crate::process::fork_single_threaded("the spawner") {
            Err(e) => Err(format!("cannot fork the spawner: {e}")),
            Ok(crate::process::Fork::Child(child)) => {
                drop(ours);
                let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(&child, theirs, programs, confine)
                }))
                .unwrap_or(70);
                crate::process::exit_now(code)
            }
            Ok(crate::process::Fork::Parent(_)) => {
                drop((theirs, programs));
                let mut buf = [0u8; 1024];
                let got = crate::scm::recv(&ours, &mut buf, 0, rustix::net::RecvFlags::empty())
                    .map_err(|e| format!("the spawner: {e}"))?;
                match buf[..got.bytes].split_first() {
                    Some((&READY, _)) => Ok(Self {
                        requests: Mutex::new(ours),
                    }),
                    Some((&FAILED, why)) => Err(String::from_utf8_lossy(why).into_owned()),
                    _ => Err("the spawner ended before it was ready".into()),
                }
            }
        }
    }

    /// [`Spawner::start`] for the main thread of a test binary, which waits
    /// for the thread that runs the test.
    pub fn start_beside_idle_threads(
        programs: Vec<Program>,
        confine: impl FnOnce(&[Program]) -> Result<(), String>,
    ) -> Result<Self, String> {
        let (ours, theirs) = pair().map_err(|e| format!("the spawner: {e}"))?;
        // (the closure runs in the child only: the parent drops its copy of
        // the descriptors with the closure)
        crate::process::fork_beside_idle_threads(move |child| {
            run(child, theirs, programs, confine)
        })
        .map_err(|e| format!("cannot fork the spawner: {e}"))?;
        let mut buf = [0u8; 1024];
        let got = crate::scm::recv(&ours, &mut buf, 0, rustix::net::RecvFlags::empty())
            .map_err(|e| format!("the spawner: {e}"))?;
        match buf[..got.bytes].split_first() {
            Some((&READY, _)) => Ok(Self {
                requests: Mutex::new(ours),
            }),
            Some((&FAILED, why)) => Err(String::from_utf8_lossy(why).into_owned()),
            _ => Err("the spawner ended before it was ready".into()),
        }
    }

    /// Start `program` (its index in the list given) with `args` (after its
    /// name) and the variables `env`; it gets `fds` as its descriptors 0, 1,
    /// 2, ... (at most [`MAX_FDS`]).  Blocks until the spawner has started
    /// it or refused.
    pub fn spawn(
        &self,
        program: usize,
        args: &[String],
        env: &[(String, String)],
        fds: &[BorrowedFd<'_>],
    ) -> io::Result<Child> {
        if fds.len() > MAX_FDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("more than {MAX_FDS} descriptors for a program"),
            ));
        }
        let program = u8::try_from(program)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "no such program"))?;
        let mut body = vec![program];
        for list in [
            args.iter()
                .map(|a| a.as_bytes().to_vec())
                .collect::<Vec<_>>(),
            env.iter()
                .map(|(k, v)| format!("{k}={v}").into_bytes())
                .collect(),
        ] {
            body.extend_from_slice(&(list.len() as u16).to_le_bytes());
            for item in list {
                if item.contains(&0) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "a NUL in an argument or a variable",
                    ));
                }
                body.extend_from_slice(&item);
                body.push(0);
            }
        }
        if body.len() > MAX_REQUEST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the request is too long",
            ));
        }
        let (life, their_life) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
        let mut sent: Vec<BorrowedFd<'_>> = vec![their_life.as_fd()];
        sent.extend_from_slice(fds);
        let requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        crate::scm::send(&*requests, &body, &sent)?;
        drop(their_life);
        // (a reply carries no descriptor: a plain read, which a confined
        // caller whose filter has no `recvmsg` may make)
        let mut buf = [0u8; 1024];
        let got = loop {
            match rustix::io::read(&*requests, &mut buf) {
                Err(rustix::io::Errno::INTR) => {}
                r => break r?,
            }
        };
        match buf[..got].split_first() {
            Some((&STARTED, pid)) if pid.len() == 4 => Ok(Child {
                pid: u32::from_le_bytes([pid[0], pid[1], pid[2], pid[3]]),
                life,
            }),
            Some((&FAILED, why)) => {
                Err(io::Error::other(String::from_utf8_lossy(why).into_owned()))
            }
            _ => Err(io::Error::other("the spawner is gone")),
        }
    }
}

/// A program the spawner holds.
struct Held {
    pid: rustix::process::Pid,
    pidfd: OwnedFd,
    life: OwnedFd,
    /// The kill was sent (the caller let the program go)
    killed: bool,
}

fn reap(h: &Held) -> i32 {
    loop {
        match rustix::process::waitpid(Some(h.pid), rustix::process::WaitOptions::empty()) {
            Ok(Some((_, status))) => return status.as_raw(),
            Err(rustix::io::Errno::INTR) => {}
            _ => return 0,
        }
    }
}

/// What the forked spawner does: confine itself, say so, serve.
fn run(
    child: &crate::spawn::InChild,
    requests: OwnedFd,
    programs: Vec<Program>,
    confine: impl FnOnce(&[Program]) -> Result<(), String>,
) -> i32 {
    // (no handler of the caller's: the one of a runtime's signal driver
    // writes a byte to the descriptor it knew, which is closed here and may
    // be a program's socket when a signal comes)
    crate::signal::reset_handlers();
    // (nothing of the caller but the socket and the programs: its
    // listeners, its credentials...)
    let mut keep: Vec<i32> = vec![requests.as_raw_fd()];
    keep.extend(programs.iter().map(|p| p.exe.as_raw_fd()));
    if keep.len() > crate::spawn::MAX_KEPT_FDS {
        let _ = crate::scm::send(
            &requests,
            &[&[FAILED][..], b"too many programs"].concat(),
            &[],
        );
        return 1;
    }
    child.close_all_but(&keep);
    if let Err(why) = confine(&programs) {
        let _ = crate::scm::send(
            &requests,
            &[
                &[FAILED][..],
                format!("the spawner cannot confine itself: {why}").as_bytes(),
            ]
            .concat(),
            &[],
        );
        return 1;
    }
    let _ = crate::scm::send(&requests, &[READY], &[]);
    serve(&requests, &programs)
}

fn serve(requests: &OwnedFd, programs: &[Program]) -> i32 {
    use rustix::event::{poll, PollFd, PollFlags};
    let mut held: Vec<Held> = Vec::new();
    loop {
        let mut fds = vec![PollFd::new(requests, PollFlags::IN)];
        for h in &held {
            fds.push(PollFd::new(&h.pidfd, PollFlags::IN));
            // (a program that was killed has no life to watch any more: its pipe
            // is not asked about again)
            fds.push(PollFd::from_borrowed_fd(
                h.life.as_fd(),
                // (a pipe whose reader is gone: an error condition, always
                // reported)
                PollFlags::empty(),
            ));
        }
        if poll(&mut fds, None).is_err_and(|e| e != rustix::io::Errno::INTR) {
            return 1;
        }
        let ready: Vec<PollFlags> = fds.iter().map(PollFd::revents).collect();
        let at = |i: usize, f: PollFlags| ready[i].intersects(f);
        let mut ended = Vec::new();
        for (i, h) in held.iter_mut().enumerate() {
            if at(1 + 2 * i, PollFlags::IN | PollFlags::HUP) {
                ended.push(i);
            } else if !h.killed && at(2 + 2 * i, PollFlags::ERR | PollFlags::HUP) {
                h.killed = true;
                let _ = rustix::process::pidfd_send_signal(&h.pidfd, rustix::process::Signal::KILL);
            }
        }
        // (from the last: the indices of the others stay)
        for i in ended.into_iter().rev() {
            let gone = held.remove(i);
            let status = reap(&gone);
            let _ = rustix::io::write(&gone.life, &status.to_ne_bytes());
        }
        if at(0, PollFlags::HUP | PollFlags::ERR) {
            // (the caller is gone: its programs go with it)
            for h in &held {
                let _ = rustix::process::pidfd_send_signal(&h.pidfd, rustix::process::Signal::KILL);
            }
            for h in &held {
                reap(h);
            }
            return 0;
        }
        if at(0, PollFlags::IN) {
            match request(requests, programs, held.len()) {
                Ok(Some(h)) => held.push(h),
                Ok(None) => {}
                Err(_) => return 1,
            }
        }
    }
}

/// The arguments and the variables of a request.
/// What a request asks: the program, its arguments and its variables.
type Asked = (usize, Vec<String>, Vec<(String, String)>);

fn parse(body: &[u8]) -> Option<Asked> {
    let (&program, mut rest) = body.split_first()?;
    let mut lists = Vec::new();
    for _ in 0..2 {
        let (n, tail) = rest.split_first_chunk::<2>()?;
        rest = tail;
        let mut items = Vec::new();
        for _ in 0..u16::from_le_bytes(*n) {
            let end = rest.iter().position(|&b| b == 0)?;
            items.push(String::from_utf8(rest[..end].to_vec()).ok()?);
            rest = &rest[end + 1..];
        }
        lists.push(items);
    }
    if !rest.is_empty() {
        return None;
    }
    let env = lists.pop()?;
    let args = lists.pop()?;
    let env = env
        .into_iter()
        .map(|e| {
            e.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect::<Option<Vec<_>>>()?;
    Some((usize::from(program), args, env))
}

/// Serve one request: `Ok(Some)` a program started, `Ok(None)` one refused
/// (and told so); an error: the socket is broken.
fn request(requests: &OwnedFd, programs: &[Program], running: usize) -> io::Result<Option<Held>> {
    let mut buf = vec![0u8; MAX_REQUEST];
    let got = crate::scm::recv(
        requests,
        &mut buf,
        1 + MAX_FDS,
        rustix::net::RecvFlags::empty(),
    )?;
    if got.bytes == 0 && got.fds.is_empty() {
        return Ok(None);
    }
    let refuse = |why: &str| {
        crate::scm::send(requests, &[&[FAILED][..], why.as_bytes()].concat(), &[]).map(|()| None)
    };
    let Some((index, args, env)) = parse(&buf[..got.bytes]) else {
        return refuse("not a request");
    };
    let mut fds = got.fds.into_iter();
    let Some(life) = fds.next() else {
        return refuse("a request carries a life pipe");
    };
    let given: Vec<OwnedFd> = fds.collect();
    if running >= MAX_RUNNING {
        return refuse(&format!("{MAX_RUNNING} programs are running"));
    }
    let Some(program) = programs.get(index) else {
        return refuse("no such program");
    };
    if !(program.check)(&args) {
        return refuse(&format!("not the arguments of {}", program.name));
    }
    if let Some((name, _)) = env.iter().find(|(name, _)| !(program.env)(name)) {
        return refuse(&format!("{} does not get {name}", program.name));
    }
    let to_c = |s: &str| CString::new(s).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL));
    let (argv, envp) = match (
        std::iter::once(program.name.as_str())
            .chain(args.iter().map(String::as_str))
            .map(to_c)
            .collect::<io::Result<Vec<_>>>(),
        env.iter()
            .map(|(k, v)| to_c(&format!("{k}={v}")))
            .collect::<io::Result<Vec<_>>>(),
    ) {
        (Ok(a), Ok(e)) => (a, e),
        _ => return refuse("a NUL in an argument"),
    };
    let exec = crate::spawn::ExecArgs::new(argv, envp);
    let (errno_read, errno_write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    let raws: Vec<i32> = given.iter().map(AsRawFd::as_raw_fd).collect();
    let (exe, errno, script, setup) = (
        program.exe.as_raw_fd(),
        errno_write.as_raw_fd(),
        program.script,
        program.setup.as_ref(),
    );
    let pid = match crate::process::fork_known_single_threaded() {
        Err(e) => return refuse(&format!("cannot fork {}: {e}", program.name)),
        Ok(crate::process::Fork::Child(child)) => {
            let _failed = (|| -> io::Error {
                // (the program's own descriptors are placed over the low
                // numbers: what the spawner holds goes out of their way)
                let exe = match child.dup_cloexec_from(exe, PARKED) {
                    Ok(fd) => fd,
                    Err(e) => return e,
                };
                let errno = match child.dup_cloexec_from(errno, PARKED) {
                    Ok(fd) => fd,
                    Err(e) => return e,
                };
                if let Err(e) = child.place_fds(&raws, 0) {
                    return e;
                }
                child.cloexec_from(raws.len() as u32);
                if script {
                    if let Err(e) = child.clear_cloexec(exe) {
                        return e;
                    }
                }
                if rustix::process::set_parent_process_death_signal(Some(
                    rustix::process::Signal::KILL,
                ))
                .is_err()
                {
                    return io::Error::from_raw_os_error(libc::EPERM);
                }
                if let Err(e) = child.unblock_signals() {
                    return e;
                }
                if let Some(Err(e)) = setup.map(|f| f()) {
                    let code = e.raw_os_error().unwrap_or(libc::EIO).to_ne_bytes();
                    // SAFETY: write of 4 bytes of a local array to a
                    // descriptor number that is open in this process.
                    unsafe { libc::write(errno, code.as_ptr().cast(), code.len()) };
                    return e;
                }
                let e = exec.exec_fd(exe);
                // (the pipe is closed by the exec when it worked: an end of
                // file is the success)
                let code = e.raw_os_error().unwrap_or(libc::EIO).to_ne_bytes();
                // SAFETY: write of 4 bytes of a local array to a descriptor
                // number that is open in this process.
                unsafe { libc::write(errno, code.as_ptr().cast(), code.len()) };
                e
            })();
            crate::process::exit_now(127)
        }
        Ok(crate::process::Fork::Parent(pid)) => pid,
    };
    drop(errno_write);
    drop(given);
    let mut why = [0u8; 4];
    if let Ok(4) = rustix::io::read(&errno_read, &mut why) {
        let _ = rustix::process::waitpid(
            rustix::process::Pid::from_raw(pid),
            rustix::process::WaitOptions::empty(),
        );
        return refuse(&format!(
            "cannot start {}: {}",
            program.name,
            io::Error::from_raw_os_error(i32::from_ne_bytes(why))
        ));
    }
    let pid_typed = rustix::process::Pid::from_raw(pid).ok_or_else(|| io::Error::other("pid 0"))?;
    let pidfd = match crate::pidfd::open_child(pid) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = rustix::process::kill_process(pid_typed, rustix::process::Signal::KILL);
            let _ =
                rustix::process::waitpid(Some(pid_typed), rustix::process::WaitOptions::empty());
            return refuse(&format!("cannot hold {}: {e}", program.name));
        }
    };
    crate::scm::send(
        requests,
        &[&[STARTED][..], &(pid as u32).to_le_bytes()].concat(),
        &[],
    )?;
    Ok(Some(Held {
        pid: pid_typed,
        pidfd,
        life,
        killed: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn any(_: &[String]) -> bool {
        true
    }
    fn no_variable(_: &str) -> bool {
        false
    }
    fn only_x(name: &str) -> bool {
        name == "X"
    }
    fn only_dash_c(args: &[String]) -> bool {
        args.first().map(String::as_str) == Some("-c")
    }

    fn sh(check: fn(&[String]) -> bool, env: fn(&str) -> bool) -> Program {
        Program::open("sh", std::path::Path::new("/bin/sh"), check, env).unwrap()
    }

    fn pipe() -> (std::fs::File, std::fs::File) {
        let (r, w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        (r.into(), w.into())
    }

    /// The descriptors given are the program's 0, 1 and 2 in the order
    /// given, its arguments and variables are the ones asked for, and how
    /// it ended is the wait status.
    #[test]
    fn descriptors_arguments_and_status_reach_the_program() {
        let spawner =
            Spawner::start_beside_idle_threads(vec![sh(any, only_x)], |_| Ok(())).unwrap();
        let (stdin_r, mut stdin_w) = pipe();
        let (mut out_r, out_w) = pipe();
        let (mut err_r, err_w) = pipe();
        let child = spawner
            .spawn(
                0,
                &[
                    "-c".into(),
                    "read a <&0; echo \"$a $X $0\" >&1; echo oops >&2; exit 3".into(),
                ],
                &[("X".into(), "ex".into())],
                &[stdin_r.as_fd(), out_w.as_fd(), err_w.as_fd()],
            )
            .unwrap();
        drop((stdin_r, out_w, err_w));
        stdin_w.write_all(b"hello\n").unwrap();
        let (mut out, mut err) = (String::new(), String::new());
        out_r.read_to_string(&mut out).unwrap();
        err_r.read_to_string(&mut err).unwrap();
        assert_eq!(out, "hello ex sh\n");
        assert_eq!(err, "oops\n");
        assert_eq!(child.wait().unwrap().code(), Some(3));
    }

    /// What the program's checks refuse is refused, and the spawner goes on.
    #[test]
    fn a_refused_request_is_an_error_and_the_next_one_is_served() {
        let spawner =
            Spawner::start_beside_idle_threads(vec![sh(only_dash_c, no_variable)], |_| Ok(()))
                .unwrap();
        let null = std::fs::File::open("/dev/null").unwrap();
        let fds = [null.as_fd(), null.as_fd(), null.as_fd()];
        let refused = spawner.spawn(0, &["-s".into()], &[], &fds).unwrap_err();
        assert!(
            refused.to_string().contains("not the arguments"),
            "{refused}"
        );
        let refused = spawner
            .spawn(
                0,
                &["-c".into(), "true".into()],
                &[("Y".into(), "1".into())],
                &fds,
            )
            .unwrap_err();
        assert!(refused.to_string().contains("does not get Y"), "{refused}");
        assert!(spawner.spawn(1, &["-c".into()], &[], &fds).is_err());
        let child = spawner
            .spawn(0, &["-c".into(), "exit 0".into()], &[], &fds)
            .unwrap();
        assert!(child.wait().unwrap().success());
    }

    /// A program that cannot be executed is the error of the spawn.
    #[test]
    fn a_program_that_cannot_start_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("data");
        std::fs::write(&file, b"not a program").unwrap();
        let program = Program::open("data", &file, any, no_variable).unwrap();
        let spawner = Spawner::start_beside_idle_threads(vec![program], |_| Ok(())).unwrap();
        let err = spawner.spawn(0, &[], &[], &[]).unwrap_err();
        assert!(err.to_string().contains("cannot start data"), "{err}");
    }

    /// Dropping the child ends the program: the end of file of a pipe it
    /// held is the only signal, no sleeping.
    #[test]
    fn dropping_the_child_kills_the_program() {
        let spawner =
            Spawner::start_beside_idle_threads(vec![sh(any, no_variable)], |_| Ok(())).unwrap();
        let (stdin_r, _stdin_w) = pipe();
        let (mut out_r, out_w) = pipe();
        let child = spawner
            .spawn(
                0,
                &["-c".into(), "echo up; read a".into()],
                &[],
                &[stdin_r.as_fd(), out_w.as_fd(), out_w.as_fd()],
            )
            .unwrap();
        drop((stdin_r, out_w));
        let mut up = [0u8; 3];
        out_r.read_exact(&mut up).unwrap();
        drop(child);
        // (the program holds the one write end: its end is the end of file)
        let mut rest = Vec::new();
        out_r.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    }

    /// The program is executed through its descriptor: the file may be gone
    /// from its path.
    #[test]
    fn no_path_is_looked_up_after_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("copy-of-true");
        // (written by another process: a spawner that another test forks
        // from this one while it held the file open for writing would keep
        // that descriptor, and the program could not be executed, ETXTBSY)
        assert!(std::process::Command::new("cp")
            .arg("/bin/true")
            .arg(&copy)
            .status()
            .unwrap()
            .success());
        let program = Program::open("true", &copy, any, no_variable).unwrap();
        let spawner = Spawner::start_beside_idle_threads(vec![program], |_| Ok(())).unwrap();
        std::fs::remove_file(&copy).unwrap();
        let child = spawner.spawn(0, &[], &[], &[]).unwrap();
        assert!(child.wait().unwrap().success());
    }

    /// With the rules of [`crate::ruleset::Rules::execute_only`] for the one
    /// program, what that program starts is refused by the kernel, and the
    /// program itself still runs.
    #[test]
    #[cfg(feature = "landlock")]
    fn an_exec_of_another_file_is_refused_by_landlock() {
        use crate::ruleset::{AccessFs, Rules};
        let program = sh(any, no_variable);
        let confine = |programs: &[Program]| {
            let mut rules = Rules::execute_only()?;
            for p in programs {
                rules.program(p.exe.as_fd(), AccessFs::Execute.into())?;
            }
            rules.restrict_fully("the test spawner").map(|_| ())
        };
        let spawner = Spawner::start_beside_idle_threads(vec![program], confine).unwrap();
        let null = std::fs::File::open("/dev/null").unwrap();
        let fds = [null.as_fd(), null.as_fd(), null.as_fd()];
        let own = spawner
            .spawn(0, &["-c".into(), "exit 0".into()], &[], &fds)
            .unwrap();
        assert!(own.wait().unwrap().success());
        // (126: the shell found /bin/true and could not execute it)
        let other = spawner
            .spawn(0, &["-c".into(), "/bin/true".into()], &[], &fds)
            .unwrap();
        assert_eq!(other.wait().unwrap().code(), Some(126));
    }
}
