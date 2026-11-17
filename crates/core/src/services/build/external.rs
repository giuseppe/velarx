// SPDX-License-Identifier: Apache-2.0
//! The xz and bzip2 archives of ADD: they are extracted by the system
//! programs (`xz -dc`, `bzip2 -dc`), not by a library the engine carries for
//! a corner case.  gzip, zstd and plain tar are read in the process.
//!
//! The program is found once, at an absolute path below `/usr` or `/bin`
//! (no `PATH`: the directories of the user are not searched), and run with
//! an argument vector (no shell) and an empty environment (`LC_ALL=C`).  The
//! archive is written to its standard input and the tar stream is read from
//! its standard output, as the bytes come: nothing is kept in a file.
//! Standard error is read, and its last bytes are in the error of a
//! program that fails.
//!
//! The decompressor is confined by Landlock: it reads below `/usr`, `/lib`,
//! `/lib64` and `/bin` and the loader cache, executes the one program, and
//! can write nowhere, open no TCP connection or unix socket and signal
//! nobody (the pipes it was given are all it has).  A seccomp filter refuses
//! it a new process or namespace, sockets, ptrace, bpf, io_uring and the
//! like.  It has no capability and cannot gain any (`no_new_privs`).  Where
//! Landlock is not there the program is not run: the error says so.
//!
//! The confined worker (`worker`) cannot execute a program: its filter has no
//! `execve`.  Before it confines itself it starts a spawner
//! (`velarx_sys::spawner`), a small process of its own that is confined as
//! above, and asks it over a socket to run the program with the three pipes
//! sent as descriptors; the child it gets tells how the program ended.  The
//! spawner dies with the worker, and so does the program with the spawner.
//! The seccomp filter is applied to each program before its exec.

use rustix::event::{poll, PollFd, PollFlags};
use rustix::fs::{fcntl_setfl, OFlags};
use rustix::io::Errno;
use std::io::{self, Read};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use thiserror::Error;

/// Where the programs are looked for, in this order.
const PROGRAM_DIRS: [&str; 2] = ["/usr/bin", "/bin"];
/// What the decompressor reads below (not executes).
const READ_DIRS: [&str; 4] = ["/usr", "/lib", "/lib64", "/bin"];
const LOADER_CACHE: &str = "/etc/ld.so.cache";
/// The last bytes of the standard error that an error carries.
const TAIL: usize = 2048;
const CHUNK: usize = 64 * 1024;

/// Why an archive could not be extracted by a system program.
#[derive(Debug, Error)]
pub enum ExternalError {
    #[error(
        "cannot extract the {format} archive: `{program}` is not installed in /usr/bin or /bin \
         (ADD extracts {format} archives with the system program; install the {package} package)"
    )]
    Missing {
        format: &'static str,
        program: &'static str,
        package: &'static str,
    },
    #[error("`{program} -dc` exited with status {code}{}", stderr_of(.stderr))]
    Failed {
        program: PathBuf,
        code: i32,
        stderr: String,
    },
    #[error("`{program} -dc` was killed by signal {signal}{}", stderr_of(.stderr))]
    Signaled {
        program: PathBuf,
        signal: i32,
        stderr: String,
    },
    #[error("cannot run `{program} -dc`: {reason}")]
    Spawn { program: PathBuf, reason: String },
}

fn stderr_of(s: &str) -> String {
    if s.is_empty() {
        String::new()
    } else {
        format!(": {s}")
    }
}

impl ExternalError {
    fn into_io(self) -> io::Error {
        io::Error::other(self)
    }
}

/// One of the programs.
#[derive(Clone, Debug)]
pub struct Tool {
    pub format: &'static str,
    pub program: &'static str,
    pub package: &'static str,
    /// Where it was found; none when it is not installed.
    pub path: Option<PathBuf>,
}

/// The programs that extract the formats read in a separate process.
#[derive(Clone, Debug)]
pub struct Programs(Vec<Tool>);

impl Programs {
    /// Look for them below `/usr/bin` and `/bin`.
    pub fn system() -> Self {
        Self::with(find("xz"), find("bzip2"))
    }

    /// With the paths given (the tests').
    pub fn with(xz: Option<PathBuf>, bzip2: Option<PathBuf>) -> Self {
        Self(vec![
            Tool {
                format: "xz",
                program: "xz",
                package: "xz",
                path: xz,
            },
            Tool {
                format: "bzip2",
                program: "bzip2",
                package: "bzip2",
                path: bzip2,
            },
        ])
    }

    fn get(&self, format: &str) -> Option<(usize, &Tool)> {
        self.0.iter().enumerate().find(|(_, t)| t.format == format)
    }

    fn paths(&self) -> Vec<&Path> {
        self.0.iter().filter_map(|t| t.path.as_deref()).collect()
    }

    pub fn any(&self) -> bool {
        !self.paths().is_empty()
    }
}

/// The program `name` of the system: a regular file, executable, that nobody
/// but the owner can write, that is below `/usr` or `/bin` once the links
/// are followed.
fn find(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    for dir in PROGRAM_DIRS {
        let Ok(real) = Path::new(dir).join(name).canonicalize() else {
            continue;
        };
        if !(real.starts_with("/usr/") || real.starts_with("/bin/")) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&real) else {
            continue;
        };
        let mode = meta.permissions().mode();
        if meta.is_file() && mode & 0o111 != 0 && mode & 0o022 == 0 {
            return Some(real);
        }
    }
    None
}

/// What the seccomp filter of a decompressor refuses (with `EPERM`), on top
/// of a new process or namespace (`deny_filter`): it reads a pipe and writes
/// two, nothing of this is its work.
const DENIED_CALLS: [i64; 21] = [
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept4,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_io_uring_setup,
    libc::SYS_userfaultfd,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_mount,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
];

/// The decompressors of a process: the programs and the spawner that runs
/// them (`velarx_sys::spawner`).
pub struct Decompressors {
    programs: Programs,
    /// The spawner, or why there is none (the programs are not run without
    /// the confinement)
    spawner: Result<velarx_sys::spawner::Spawner, String>,
    /// Where each tool of `programs` is in the spawner's list
    slots: Vec<Option<usize>>,
}

static GLOBAL: OnceLock<Decompressors> = OnceLock::new();

/// What a decompressor reads below, executes and may do: Landlock for the
/// spawner (the programs inherit it) and seccomp for each program.
fn confine(
    programs: &[velarx_sys::spawner::Program],
    extra_exec: &[PathBuf],
) -> Result<(), String> {
    use velarx_sys::ruleset::{AccessFs, AccessNet, Handles, Must, Rules, NEWEST};
    let _ = velarx_sys::caps::drop_all();
    rustix::thread::set_no_new_privs(true).map_err(|e| format!("no_new_privs: {e}"))?;
    let mut rules = Rules::new(Handles {
        abi: NEWEST,
        net: AccessNet::BindTcp | AccessNet::ConnectTcp,
        scopes: true,
        must: Must::Files,
    })?;
    for dir in READ_DIRS.iter().copied().chain([LOADER_CACHE]) {
        rules.beneath_if_present(Path::new(dir), AccessFs::ReadFile | AccessFs::ReadDir)?;
    }
    let rights = AccessFs::ReadFile | AccessFs::Execute;
    for p in programs {
        rules.program(p.exe.as_fd(), rights)?;
    }
    for p in extra_exec {
        let fd = rustix::fs::open(
            p,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| format!("{}: {e}", p.display()))?;
        rules.program(fd.as_fd(), rights)?;
    }
    rules.restrict().map(|_| ())
}

impl Decompressors {
    /// The programs started by a spawner forked now, which has to be
    /// beside nothing (single threaded, or `idle`: the main thread of a test
    /// binary).  `confined`: with Landlock and seccomp, which the tests do
    /// not want where they run a script of their own; `extra_exec`: more
    /// files the confined program may execute (the interpreter of a script).
    fn start(programs: Programs, confined: bool, extra_exec: Vec<PathBuf>, idle: bool) -> Self {
        let mut slots = Vec::new();
        let mut list = Vec::new();
        let mut failure = None;
        for tool in &programs.0 {
            let Some(path) = &tool.path else {
                slots.push(None);
                continue;
            };
            match velarx_sys::spawner::Program::open(
                tool.program,
                path,
                |a| a == ["-dc"],
                |n| n == "LC_ALL",
            ) {
                Ok(program) => {
                    slots.push(Some(list.len()));
                    list.push(if confined {
                        let filter =
                            velarx_sys::confine::deny_filter(&DENIED_CALLS, libc::EPERM as u32);
                        program.with_setup(move || velarx_sys::confine::seccomp_thread(&filter))
                    } else {
                        program
                    });
                }
                Err(e) => {
                    slots.push(None);
                    failure = Some(format!("{}: {e}", path.display()));
                }
            }
        }
        let spawner = match failure {
            Some(why) => Err(why),
            None if list.is_empty() => Err("no program".into()),
            None => {
                let confine = move |p: &[velarx_sys::spawner::Program]| {
                    if confined {
                        confine(p, &extra_exec)
                    } else {
                        Ok(())
                    }
                };
                if idle {
                    velarx_sys::spawner::Spawner::start_beside_idle_threads(list, confine)
                } else {
                    velarx_sys::spawner::Spawner::start(list, confine)
                }
            }
        };
        Self {
            programs,
            spawner,
            slots,
        }
    }

    /// For the tests: [`Decompressors::start`] beside the threads of the
    /// test binary.
    #[cfg(test)]
    fn direct(programs: Programs, confined: bool, extra_exec: Vec<PathBuf>) -> Self {
        Self::start(programs, confined, extra_exec, true)
    }

    /// Start the spawner of a worker, which has to be single threaded and
    /// not confined yet, and make it the one `decompress` uses.
    pub fn start_for_worker() -> Result<(), String> {
        let programs = Programs::system();
        let started = Self::start(programs, true, Vec::new(), false);
        GLOBAL
            .set(started)
            .map_err(|_| "the decompressor spawner is already started".to_string())
    }

    /// The tar stream that the program for `format` makes of `input`.
    pub fn run<'a>(
        &'a self,
        format: &str,
        input: impl Read + 'a,
    ) -> io::Result<Box<dyn Read + 'a>> {
        let (index, tool) = self
            .programs
            .get(format)
            .ok_or_else(|| io::Error::other(format!("no decompressor for {format}")))?;
        let Some(path) = tool.path.clone() else {
            return Err(ExternalError::Missing {
                format: tool.format,
                program: tool.program,
                package: tool.package,
            }
            .into_io());
        };
        let spawn_error = |reason: String| {
            ExternalError::Spawn {
                program: path.clone(),
                reason,
            }
            .into_io()
        };
        let (child_in, to_child) = std::io::pipe().map_err(|e| spawn_error(e.to_string()))?;
        let (from_child, child_out) = std::io::pipe().map_err(|e| spawn_error(e.to_string()))?;
        let (errors, child_err) = std::io::pipe().map_err(|e| spawn_error(e.to_string()))?;
        let to_child: OwnedFd = to_child.into();
        let from_child: OwnedFd = from_child.into();
        let errors: OwnedFd = errors.into();
        for fd in [&to_child, &from_child, &errors] {
            fcntl_setfl(fd, OFlags::NONBLOCK).map_err(|e| spawn_error(e.to_string()))?;
        }
        let spawner = self
            .spawner
            .as_ref()
            .map_err(|why| spawn_error(why.clone()))?;
        let slot = self.slots.get(index).copied().flatten().ok_or_else(|| {
            spawn_error("the program is not one the spawner was started with".into())
        })?;
        let waiter = spawner
            .spawn(
                slot,
                &["-dc".to_string()],
                &[("LC_ALL".to_string(), "C".to_string())],
                &[child_in.as_fd(), child_out.as_fd(), child_err.as_fd()],
            )
            .map_err(|e| spawn_error(e.to_string()))?;
        drop((child_in, child_out, child_err));
        Ok(Box::new(Stream {
            input: Box::new(input),
            chunk: vec![0; CHUNK].into_boxed_slice(),
            len: 0,
            sent: 0,
            input_done: false,
            to_child: Some(to_child),
            from_child: Some(from_child),
            errors: Some(errors),
            tail: Vec::new(),
            path,
            waiter: Some(waiter),
            done: false,
        }))
    }
}

/// The tar stream of the archive `input` of `format` (`xz` or `bzip2`),
/// made by the system program: in the spawner of the worker, or here.
pub fn decompress<'a>(format: &str, input: impl Read + 'a) -> io::Result<Box<dyn Read + 'a>> {
    GLOBAL
        .get()
        .ok_or_else(|| io::Error::other("the decompressor spawner is not started"))?
        .run(format, input)
}

/// What a program writes is read as the decompressed stream while the
/// archive is written to it, in one thread: what can be moved is moved.
struct Stream<'a> {
    input: Box<dyn Read + 'a>,
    chunk: Box<[u8]>,
    len: usize,
    sent: usize,
    input_done: bool,
    to_child: Option<OwnedFd>,
    from_child: Option<OwnedFd>,
    errors: Option<OwnedFd>,
    tail: Vec<u8>,
    path: PathBuf,
    waiter: Option<velarx_sys::spawner::Child>,
    done: bool,
}

impl Stream<'_> {
    fn note_errors(&mut self, bytes: &[u8]) {
        self.tail.extend_from_slice(bytes);
        if self.tail.len() > TAIL {
            let cut = self.tail.len() - TAIL;
            self.tail.drain(..cut);
        }
    }

    fn drain_errors(&mut self) {
        let mut buf = [0u8; 1024];
        while let Some(fd) = &self.errors {
            match rustix::io::read(fd, &mut buf) {
                Ok(0) => self.errors = None,
                Ok(n) => self.note_errors(&buf[..n]),
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => {
                    // the program has not closed it yet
                    let mut p = [PollFd::new(fd, PollFlags::IN)];
                    let _ = poll(&mut p, None);
                }
                Err(_) => self.errors = None,
            }
        }
    }

    /// How the program ended.
    fn wait(&mut self) -> io::Result<()> {
        let stderr = String::from_utf8_lossy(&self.tail).trim().to_string();
        let program = self.path.clone();
        let Some(child) = self.waiter.take() else {
            return Ok(());
        };
        let status = child.wait().map_err(|e| {
            ExternalError::Spawn {
                program: program.clone(),
                reason: format!("the spawner is gone: {e}"),
            }
            .into_io()
        })?;
        match (
            status.code(),
            std::os::unix::process::ExitStatusExt::signal(&status),
        ) {
            (Some(0), _) => Ok(()),
            (Some(code), _) => Err(ExternalError::Failed {
                program,
                code,
                stderr,
            }
            .into_io()),
            (_, Some(signal)) => Err(ExternalError::Signaled {
                program,
                signal,
                stderr,
            }
            .into_io()),
            _ => Err(ExternalError::Spawn {
                program,
                reason: "it ended in no way known".into(),
            }
            .into_io()),
        }
    }
}
impl Read for Stream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.sent == self.len && !self.input_done {
                self.sent = 0;
                self.len = self.input.read(&mut self.chunk)?;
                if self.len == 0 {
                    self.input_done = true;
                    self.to_child = None;
                }
            }
            let Some(out) = &self.from_child else {
                // (a program that closed its output reads no more)
                self.to_child = None;
                self.drain_errors();
                self.done = true;
                return self.wait().map(|()| 0);
            };
            let mut fds = vec![PollFd::new(out, PollFlags::IN)];
            let err_at = self.errors.as_ref().map(|e| {
                fds.push(PollFd::new(e, PollFlags::IN));
                fds.len() - 1
            });
            let in_at = match &self.to_child {
                Some(w) if self.sent < self.len => {
                    fds.push(PollFd::new(w, PollFlags::OUT));
                    Some(fds.len() - 1)
                }
                _ => None,
            };
            match poll(&mut fds, None) {
                Ok(_) | Err(Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
            let ready = |i: usize| !fds[i].revents().is_empty();
            let (out_ready, err_ready, in_ready) = (
                ready(0),
                err_at.is_some_and(ready),
                in_at.is_some_and(ready),
            );
            if err_ready {
                let mut b = [0u8; 1024];
                match rustix::io::read(self.errors.as_ref().expect("polled"), &mut b) {
                    Ok(0) => self.errors = None,
                    Ok(n) => self.note_errors(&b[..n]),
                    Err(_) => {}
                }
            }
            if in_ready {
                match rustix::io::write(
                    self.to_child.as_ref().expect("polled"),
                    &self.chunk[self.sent..self.len],
                ) {
                    Ok(n) => self.sent += n,
                    Err(Errno::AGAIN | Errno::INTR) => {}
                    Err(_) => {
                        // the program stopped reading: its end says why
                        self.to_child = None;
                        self.input_done = true;
                        self.sent = self.len;
                    }
                }
            }
            if out_ready {
                match rustix::io::read(self.from_child.as_ref().expect("polled"), &mut *buf) {
                    Ok(0) => self.from_child = None,
                    Ok(n) => return Ok(n),
                    Err(Errno::AGAIN | Errno::INTR) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
}

impl Drop for Stream<'_> {
    fn drop(&mut self) {
        // The program sees its pipes close and ends; its status is read so
        // that nothing is left unread, or a zombie.
        self.to_child = None;
        self.from_child = None;
        self.errors = None;
        // (the life socket of the program closes with the child: the spawner
        // ends it and reaps it)
        self.waiter = None;
    }
}

/// `ok`, xz compressed (the self-test of the worker, the tests).
pub const XZ_OK: [u8; 68] = [
    0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x04, 0xc0, 0x06, 0x02,
    0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0xcb, 0xc2, 0x4c,
    0x01, 0x00, 0x01, 0x6f, 0x6b, 0x00, 0x00, 0x00, 0x03, 0xc0, 0x44, 0x80, 0x3f, 0x3f, 0x67, 0x80,
    0x00, 0x01, 0x22, 0x02, 0x27, 0x92, 0x3a, 0x69, 0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x04, 0x59, 0x5a,
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        velarx_base::testing::write_script(&p, body);
        p
    }

    fn fake(path: PathBuf) -> Decompressors {
        Decompressors::direct(Programs::with(Some(path), None), false, Vec::new())
    }

    fn run(s: &Decompressors, input: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        s.run("xz", input)?.read_to_end(&mut out).map(|_| out)
    }

    fn typed(e: &io::Error) -> &ExternalError {
        e.get_ref()
            .and_then(|e| e.downcast_ref())
            .expect("a typed error")
    }

    #[test]
    fn the_output_of_the_program_is_the_stream() {
        let d = tempfile::tempdir().unwrap();
        let s = fake(script(d.path(), "xz", "cat"));
        let big = vec![7u8; 5 << 20];
        assert_eq!(run(&s, &big).unwrap(), big);
    }

    #[test]
    fn a_failure_is_typed_with_the_end_of_its_standard_error() {
        let d = tempfile::tempdir().unwrap();
        let s = fake(script(
            d.path(),
            "xz",
            "cat > /dev/null; echo first >&2; echo xz: corrupt >&2; exit 3",
        ));
        let e = run(&s, b"data").unwrap_err();
        let ExternalError::Failed { code, stderr, .. } = typed(&e) else {
            panic!("{e}")
        };
        assert_eq!(*code, 3);
        assert_eq!(stderr, "first\nxz: corrupt");
    }

    #[test]
    fn the_standard_error_is_bounded() {
        let d = tempfile::tempdir().unwrap();
        let s = fake(script(
            d.path(),
            "xz",
            "cat > /dev/null; i=0; while [ $i -lt 3000 ]; do echo line$i >&2; i=$((i+1)); done; echo END >&2; exit 1",
        ));
        let e = run(&s, b"x").unwrap_err();
        let ExternalError::Failed { stderr, .. } = typed(&e) else {
            panic!("{e}")
        };
        assert!(
            stderr.len() <= TAIL && stderr.ends_with("END"),
            "{}",
            stderr.len()
        );
    }

    #[test]
    fn a_signal_is_typed() {
        let d = tempfile::tempdir().unwrap();
        let s = fake(script(d.path(), "xz", "cat > /dev/null; kill -9 $$"));
        let e = run(&s, b"x").unwrap_err();
        assert!(
            matches!(typed(&e), ExternalError::Signaled { signal: 9, .. }),
            "{e}"
        );
    }

    #[test]
    fn a_program_that_is_not_installed_is_named_with_the_fix() {
        let s = Decompressors::direct(Programs::with(None, None), false, Vec::new());
        for (format, program) in [("xz", "xz"), ("bzip2", "bzip2")] {
            let e = s.run(format, &b"x"[..]).err().unwrap();
            assert!(
                matches!(typed(&e), ExternalError::Missing { program: p, .. } if *p == program),
                "{e}"
            );
            let text = e.to_string();
            assert!(
                text.contains(program) && text.contains("install the"),
                "{text}"
            );
        }
    }

    #[test]
    fn a_program_that_cannot_start_is_typed() {
        let s = fake(PathBuf::from("/nonexistent/xz"));
        let e = s.run("xz", &b"x"[..]).err().unwrap();
        assert!(matches!(typed(&e), ExternalError::Spawn { .. }), "{e}");
    }

    #[test]
    fn a_program_that_does_not_read_its_input_does_not_hang() {
        let d = tempfile::tempdir().unwrap();
        let s = fake(script(d.path(), "xz", "echo done; exit 0"));
        let big = vec![1u8; 8 << 20];
        assert_eq!(run(&s, &big).unwrap(), b"done\n");
    }

    #[test]
    fn a_stream_dropped_early_ends_the_program() {
        let d = tempfile::tempdir().unwrap();
        let s = fake(script(d.path(), "xz", "yes"));
        let mut stream = s.run("xz", std::io::empty()).unwrap();
        let mut b = [0u8; 16];
        stream.read_exact(&mut b).unwrap();
        // (the program writes forever: the drop closes the pipe, it ends)
        drop(stream);
    }

    fn landlock_here() -> bool {
        velarx_sys::confine::landlock_abi() > 0
    }

    /// The program is confined: what it may not read or write is refused,
    /// what it may read below /usr is not.
    #[test]
    fn the_program_cannot_read_outside_usr_or_write_anywhere() {
        if !landlock_here() {
            eprintln!("no Landlock: skipped");
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let outside = d.path().join("secret");
        std::fs::write(&outside, "secret\n").unwrap();
        let probe = |action: &str, confined: bool| -> io::Result<Vec<u8>> {
            let sh = Path::new("/usr/bin/sh").canonicalize().unwrap();
            let p = script(
                d.path(),
                "xz",
                &format!("cat_in() {{ read -r x < \"$1\"; }}\n{action}"),
            );
            let s = Decompressors::direct(Programs::with(Some(p), None), confined, vec![sh]);
            run(&s, b"x")
        };
        // (shell built-ins only: the program has no other to execute)
        assert_eq!(
            probe("cat_in /usr/bin/sh && echo allowed", true).unwrap(),
            b"allowed\n"
        );
        let probe_file = "/var/tmp/velarx-external-probe";
        for denied in [
            format!("cat_in {}", outside.display()),
            "cat_in /etc/passwd".to_string(),
            format!("echo x > {}/new", d.path().display()),
            format!("echo x > {}", outside.display()),
            format!("echo x > {probe_file}"),
            // (a subshell is a new process: the filter refuses it)
            "( : )".to_string(),
        ] {
            let action = format!("{denied} && echo allowed; exit 0");
            // (without the confinement the same action is done)
            assert_eq!(
                probe(&action, false).unwrap(),
                b"allowed\n",
                "`{denied}` is not possible even unconfined"
            );
            let _ = std::fs::remove_file(probe_file);
            std::fs::remove_file(d.path().join("new")).ok();
            std::fs::write(&outside, "secret\n").unwrap();
            // (refused: the shell goes on, or ends where it cannot fork)
            let confined = probe(&action, true);
            assert!(
                matches!(&confined, Ok(o) if o.is_empty())
                    || matches!(&confined, Err(e) if matches!(typed(e), ExternalError::Failed { .. })),
                "`{denied}` was allowed: {confined:?}"
            );
            assert!(!Path::new(probe_file).exists());
        }
        assert!(!d.path().join("new").exists());
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "secret\n");
    }

    #[test]
    fn a_program_other_than_the_one_is_not_executed() {
        if !landlock_here() {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let marker = d.path().join("ran");
        let sh = Path::new("/usr/bin/sh").canonicalize().unwrap();
        // (/usr/bin/touch is readable, not executable by the program; the
        // shell replaces itself, the filter refuses it a new process)
        let p = script(
            d.path(),
            "xz",
            &format!("exec /usr/bin/touch {}", marker.display()),
        );
        let unconfined =
            Decompressors::direct(Programs::with(Some(p.clone()), None), false, vec![]);
        assert_eq!(run(&unconfined, b"x").unwrap(), b"");
        assert!(marker.exists(), "touch does not run even unconfined");
        std::fs::remove_file(&marker).unwrap();
        let s = Decompressors::direct(Programs::with(Some(p), None), true, vec![sh]);
        let e = run(&s, b"x").unwrap_err();
        assert!(matches!(typed(&e), ExternalError::Failed { .. }), "{e}");
        assert!(!marker.exists());
    }

    fn real(format: &str) -> Option<(Decompressors, &'static str)> {
        let programs = Programs::system();
        let (_, t) = programs.get(format)?;
        t.path.as_ref()?;
        let name = if format == "xz" { "xz" } else { "bzip2" };
        Some((Decompressors::direct(programs, true, Vec::new()), name))
    }

    #[test]
    fn the_system_programs_extract_confined() {
        if !landlock_here() {
            return;
        }
        for (format, archive) in [
            ("xz", XZ_OK.as_slice()),
            ("bzip2", ARCHIVE_BZIP2.as_slice()),
        ] {
            let Some((s, _)) = real(format) else {
                eprintln!("{format} is not installed: skipped");
                continue;
            };
            let mut out = Vec::new();
            s.run(format, archive)
                .unwrap()
                .read_to_end(&mut out)
                .unwrap();
            assert_eq!(out, b"ok", "{format}");
            // a corrupt archive is the program's failure
            let mut bad = archive.to_vec();
            let n = bad.len();
            bad[n / 2] ^= 0xff;
            bad[n / 2 + 1] ^= 0xff;
            let e = s
                .run(format, &bad[..])
                .unwrap()
                .read_to_end(&mut Vec::new())
                .unwrap_err();
            assert!(
                matches!(typed(&e), ExternalError::Failed { .. }),
                "{format}: {e}"
            );
        }
    }

    const ARCHIVE_BZIP2: [u8; 37] = [
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xa4, 0xc4, 0xf1, 0x36, 0x00,
        0x00, 0x00, 0x81, 0x00, 0x00, 0x08, 0xa0, 0x00, 0x21, 0x00, 0x82, 0xb1, 0x77, 0x24, 0x53,
        0x85, 0x09, 0x0a, 0x4c, 0x4f, 0x13, 0x60,
    ];
}
