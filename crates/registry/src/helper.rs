// SPDX-License-Identifier: Apache-2.0
//! The credential helper runner: a process that runs `docker-credential-NAME
//! get` for a process that cannot (the fetcher confines itself
//! with Landlock and seccomp, and a helper needs its own files, its
//! interpreter, the network and the session bus).
//!
//! [`HelperRunner::start`] forks the runner before the confinement and keeps
//! it on a socket pair.  What crosses the socket, in frames of a 32 bit
//! length and JSON:
//!
//! * a request: its number, the auth file the asker found the registry in
//!   (it has to be one of the auth files of this process:
//!   [`auth::default_auth_files`]) and the registry;
//! * the reply: the number of the request, the credentials (or none), or why
//!   there are none.  The asker takes only the reply to the request it made:
//!   a late reply to an earlier one it gave up waiting for is dropped, never
//!   taken for the credentials of another registry.
//!
//! A request that is not JSON of that form, or longer than the limit, ends
//! the runner: only a broken asker sends one.
//!
//! The asker never names a helper or a server: the runner reads the file
//! itself and takes the `credHelpers` entry for the registry, else
//! `credsStore`, as [`AuthConfig`](super::AuthConfig) does; a registry the
//! file names no helper for is refused.  The helper has to be a name that
//! `valid_helper_name` accepts, only `get` is run, the answer is capped and
//! the helper has a time limit.
//!
//! The runner has the privileges the asker had when it forked (same user,
//! same environment, so `HOME` and the search path are the user's), with no
//! new privileges for itself and the helpers.  It serves one request at a
//! time, keeps no descriptor but the socket, and ends with the asker: at the
//! end of the socket, taking the helper it may be running along (the
//! runner and its helpers are one process group).

use super::auth::{self, HelperAnswer, HelperLimits};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

/// Largest request: a path and a registry.
const MAX_REQUEST: usize = 64 << 10;

/// Largest reply: the answer of a helper, capped at 1 MiB, as JSON.
const MAX_REPLY: usize = 4 << 20;

/// Longest registry name.
const MAX_REGISTRY: usize = 512;

/// What the asker waits for a reply beyond the time of the helper.
const SLACK: Duration = Duration::from_secs(30);

#[derive(Serialize, Deserialize)]
struct Request {
    id: u64,
    file: PathBuf,
    registry: String,
}

#[derive(Serialize, Deserialize)]
struct Reply {
    id: u64,
    answer: Answer,
}

#[derive(Serialize, Deserialize)]
enum Answer {
    Credentials(HelperAnswer),
    Failed(String),
}

fn read_frame(from: &mut impl Read, max: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut head = [0u8; 4];
    let mut got = 0;
    while got < head.len() {
        match from.read(&mut head[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let len = u32::from_be_bytes(head) as usize;
    if len > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("a frame of {len} bytes"),
        ));
    }
    let mut body = vec![0u8; len];
    from.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_frame(to: &mut impl Write, body: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(body.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too big"))?;
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(body);
    to.write_all(&frame)
}

/// A registry name as an auth file writes one: printable ASCII, no
/// space.
fn valid_registry(registry: &str) -> bool {
    !registry.is_empty()
        && registry.len() <= MAX_REGISTRY
        && registry.bytes().all(|b| b.is_ascii_graphic())
}

/// The runner, as its asker holds it.
pub struct HelperRunner {
    /// The socket and the number of the last request.
    stream: Mutex<(UnixStream, u64)>,
    pid: libc::pid_t,
}

impl std::fmt::Debug for HelperRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperRunner")
            .field("pid", &self.pid)
            .finish()
    }
}

impl HelperRunner {
    /// Fork the runner.  Call it before the confinement and before any
    /// thread is started: the runner uses the allocator and its own
    /// threads, which a child of a process with other threads cannot do
    /// safely (the start is refused then).
    pub fn start() -> Result<Self, String> {
        Self::start_with(HelperLimits::default())
    }

    pub(crate) fn start_with(limits: HelperLimits) -> Result<Self, String> {
        let (front, runner) = UnixStream::pair()
            .map_err(|e| format!("cannot make the socket of the credential helper runner: {e}"))?;
        front
            .set_read_timeout(Some(limits.timeout + SLACK))
            .map_err(|e| format!("cannot set up the credential helper runner: {e}"))?;
        // (the process has a single thread, checked above, so the child may
        // allocate and start threads; it only runs `run_forked`, which ends
        // in `_exit` and never returns into the code of the parent)
        match velarx_sys::process::fork_single_threaded("credential helper runner") {
            Err(e) => Err(format!("cannot fork the credential helper runner: {e}")),
            Ok(velarx_sys::process::Fork::Child(child)) => {
                drop(front);
                run_forked(child, OwnedFd::from(runner), limits)
            }
            Ok(velarx_sys::process::Fork::Parent(pid)) => Ok(Self {
                stream: Mutex::new((front, 0)),
                pid,
            }),
        }
    }

    /// The process id of the runner.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// The credentials the helper that `file` (one of the auth files)
    /// names for `registry` gives; none when it has none.
    pub(crate) fn get(&self, file: &Path, registry: &str) -> Result<HelperAnswer, String> {
        let mut guard = self.stream.lock().unwrap_or_else(|e| e.into_inner());
        let (stream, last) = &mut *guard;
        *last += 1;
        let id = *last;
        let request = serde_json::to_vec(&Request {
            id,
            file: file.to_path_buf(),
            registry: registry.to_string(),
        })
        .map_err(|e| e.to_string())?;
        write_frame(stream, &request).map_err(|e| self.gone(&e.to_string()))?;
        loop {
            let reply = read_frame(stream, MAX_REPLY)
                .map_err(|e| self.gone(&e.to_string()))?
                .ok_or_else(|| self.gone("end of the socket"))?;
            let reply: Reply = serde_json::from_slice(&reply)
                .map_err(|e| format!("invalid reply of the credential helper runner: {e}"))?;
            // (a reply to a request whose wait timed out comes late: not ours)
            if reply.id != id {
                continue;
            }
            return match reply.answer {
                Answer::Credentials(c) => Ok(c),
                Answer::Failed(why) => Err(why),
            };
        }
    }

    /// The error for a runner that does not answer, with how it ended if
    /// it did.
    fn gone(&self, why: &str) -> String {
        let ended = rustix::process::Pid::from_raw(self.pid)
            .and_then(|pid| {
                rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG)
                    .ok()
                    .flatten()
            })
            .map(|(_, status)| status);
        let how = match ended {
            None => String::new(),
            Some(status) => match status.terminating_signal() {
                Some(signal) => format!(" (it was killed by signal {signal})"),
                None => format!(
                    " (it exited with status {})",
                    status.exit_status().unwrap_or(0)
                ),
            },
        };
        format!(
            "the credential helper runner (process {}) does not answer{how}: {why}; \
             credential helpers cannot run until the fetcher is started again \
             (it is confined and cannot run them itself)",
            self.pid
        )
    }
}

impl Drop for HelperRunner {
    fn drop(&mut self) {
        // (the child ends at once: it sees the end of the socket)
        let stream = self.stream.get_mut().unwrap_or_else(|e| e.into_inner());
        let _ = stream.0.shutdown(std::net::Shutdown::Both);
        if let Some(pid) = rustix::process::Pid::from_raw(self.pid) {
            let _ = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty());
        }
    }
}

/// What the forked child does; it never returns.
fn run_forked(child: velarx_sys::spawn::InChild, sock: OwnedFd, limits: HelperLimits) -> ! {
    let code = std::panic::catch_unwind(move || serve(child, sock, limits)).unwrap_or(70);
    velarx_sys::process::exit_now(code)
}

/// The descriptors, the group and the privileges of the runner; the reason
/// when one of them cannot be set (every request is then answered with it).
fn prepare(child: velarx_sys::spawn::InChild, sock: BorrowedFd<'_>) -> Result<(), String> {
    let sock = sock.as_raw_fd();
    let fail = |what: &str, e: std::io::Error| format!("{what}: {e}");
    let null = rustix::fs::open(
        c"/dev/null",
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| fail("cannot close the standard input", e.into()))?;
    child
        .dup2(null.as_raw_fd(), 0)
        .map_err(|e| fail("cannot close the standard input", e))?;
    drop(null);
    // nothing of the asker but the socket (its listening socket, its
    // credentials...)
    child.close_range(3, (sock - 1).max(2) as u32);
    child.close_from(sock as u32 + 1);
    rustix::process::setpgid(None, None)
        .map_err(|e| fail("cannot make its own process group", e.into()))?;
    rustix::thread::set_no_new_privs(true)
        .map_err(|e| fail("cannot set no_new_privs", e.into()))?;
    Ok(())
}

/// One thread that waits for the end of the socket and then kills the
/// group: a helper that is running goes with the runner.
fn watch_socket(sock: OwnedFd) {
    let _ = std::thread::Builder::new()
        .name("asker-gone".into())
        .spawn(move || {
            let mut fds = [rustix::event::PollFd::new(
                &sock,
                rustix::event::PollFlags::RDHUP,
            )];
            loop {
                let n = rustix::event::poll(&mut fds, None).unwrap_or(0);
                if n > 0 {
                    // the group this made its own in `prepare`
                    let _ =
                        rustix::process::kill_current_process_group(rustix::process::Signal::KILL);
                }
            }
        });
}

fn serve(child: velarx_sys::spawn::InChild, sock: OwnedFd, limits: HelperLimits) -> i32 {
    let setup = prepare(child, sock.as_fd());
    if setup.is_ok() {
        // (a descriptor of its own, made after `prepare` closed the others)
        if let Ok(watch) = sock.try_clone() {
            watch_socket(watch);
        }
    }
    let mut stream = UnixStream::from(sock);
    loop {
        let request = match read_frame(&mut stream, MAX_REQUEST) {
            Ok(Some(r)) => r,
            Ok(None) => return 0,
            Err(_) => return 1,
        };
        // (only a broken asker sends what is not a request)
        let Ok(request) = serde_json::from_slice::<Request>(&request) else {
            return 1;
        };
        let answer = match &setup {
            Ok(()) => answer(&request, limits),
            Err(why) => Answer::Failed(format!("the credential helper runner: {why}")),
        };
        let reply = Reply {
            id: request.id,
            answer,
        };
        let out = serde_json::to_vec(&reply).unwrap_or_default();
        if write_frame(&mut stream, &out).is_err() {
            return 1;
        }
    }
}

fn answer(request: &Request, limits: HelperLimits) -> Answer {
    if !valid_registry(&request.registry) {
        return Answer::Failed("invalid registry name".into());
    }
    let files = match auth::default_auth_files() {
        Ok(files) => files,
        Err(e) => return Answer::Failed(e.to_string()),
    };
    if !files.contains(&request.file) {
        return Answer::Failed(format!(
            "`{}` is not an auth file of this process",
            request.file.display()
        ));
    }
    match auth::helper_credentials(&request.file, &request.registry, limits) {
        Ok(c) => Answer::Credentials(c),
        Err(e) => Answer::Failed(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A world for the runner: the helpers `scripts` (name, shell body) in
    /// the search path, the auth file `config` as the only one (the
    /// environment of the process: run in a child).
    fn world(dir: &Path, config: &str, scripts: &[(&str, &str)]) -> PathBuf {
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        for (name, body) in scripts {
            let p = bin.join(format!("docker-credential-{name}"));
            velarx_base::testing::write_script(&p, body);
        }
        let file = dir.join("config.json");
        std::fs::write(&file, config).unwrap();
        // child-only
        std::env::set_var("PATH", format!("{}:/usr/bin:/bin", bin.display()));
        // child-only
        std::env::set_var("REGISTRY_AUTH_FILE", &file);
        file
    }

    const GOOD: &str = r#"read s; echo "{\"Username\":\"u\",\"Secret\":\"secret-of-$s\"}""#;

    /// Wait until `fd` is readable (a pidfd: the process ended).
    fn ended(fd: &OwnedFd) {
        let mut p = [rustix::event::PollFd::new(fd, rustix::event::PollFlags::IN)];
        // (the limit only keeps a broken runner from hanging the test)
        let limit = rustix::event::Timespec {
            tv_sec: 30,
            tv_nsec: 0,
        };
        let n = rustix::event::poll(&mut p, Some(&limit)).unwrap();
        assert_eq!(n, 1, "the process did not end");
    }

    fn pidfd(pid: i32) -> OwnedFd {
        rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(pid).unwrap(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap()
    }

    #[test]
    fn the_runner_gives_the_credentials_of_the_helper_the_file_names() {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let file = world(
                dir.path(),
                r#"{"credsStore": "fake", "credHelpers": {"other.io": "second"}}"#,
                &[
                    ("fake", GOOD),
                    ("second", r#"echo '{"Username":"<token>","Secret":"t"}'"#),
                ],
            );
            let runner = HelperRunner::start().unwrap();
            // the store is asked for the server as the registry is written
            let c = runner.get(&file, "r.io:5000").unwrap().credentials.unwrap();
            assert_eq!(c, crate::Credentials::basic("u", "secret-of-r.io:5000"));
            let t = runner.get(&file, "other.io").unwrap().credentials.unwrap();
            assert_eq!(t.identity_token.as_deref(), Some("t"));
            let hub = runner
                .get(&file, "registry-1.docker.io")
                .unwrap()
                .credentials
                .unwrap();
            assert_eq!(hub.password, "secret-of-https://index.docker.io/v1/");
        });
    }

    /// How many times the helper `script` ran for `lookups` lookups of
    /// `r.io` by one configuration, with the runner or in this process.
    fn helper_runs(script: &str, lookups: usize, with_runner: bool) -> usize {
        let dir = tempfile::tempdir().unwrap();
        let count = dir.path().join("count");
        world(
            dir.path(),
            r#"{"credsStore": "fake"}"#,
            &[(
                "fake",
                &format!("echo run >> {}\nread s\n{script}", count.display()),
            )],
        );
        let mut auth = auth::AuthConfig::load().unwrap();
        if with_runner {
            auth = auth.with_helper_runner(std::sync::Arc::new(HelperRunner::start().unwrap()));
        }
        for _ in 0..lookups {
            let c = auth.lookup("r.io", "x").unwrap();
            assert_eq!(c.unwrap().password, "p");
        }
        std::fs::read_to_string(count).unwrap().lines().count()
    }

    const NO_EXPIRY: &str = r#"echo '{"Username":"u","Secret":"p"}'"#;

    #[test]
    fn an_answer_is_kept_for_the_next_lookups() {
        velarx_base::testing::in_child(|| {
            assert_eq!(helper_runs(NO_EXPIRY, 3, false), 1);
            assert_eq!(helper_runs(NO_EXPIRY, 3, true), 1);
        });
    }

    #[test]
    fn an_answer_is_kept_until_its_expiry() {
        velarx_base::testing::in_child(|| {
            let at = |secs: i64| {
                let t = chrono::Utc::now() + chrono::Duration::seconds(secs);
                format!(
                    r#"echo '{{"Username":"u","Secret":"p","ExpiresAt":"{}"}}'"#,
                    t.to_rfc3339()
                )
            };
            assert_eq!(helper_runs(&at(3600), 3, true), 1);
            // expired, or about to: asked again every time
            assert_eq!(helper_runs(&at(-60), 3, true), 3);
            assert_eq!(helper_runs(&at(2), 3, false), 3);
        });
    }

    #[test]
    fn the_runner_refuses_what_the_file_does_not_name() {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let file = world(
                dir.path(),
                r#"{"credHelpers": {"r.io": "fake"}}"#,
                &[("fake", GOOD)],
            );
            let runner = HelperRunner::start().unwrap();
            assert!(runner.get(&file, "r.io").unwrap().credentials.is_some());
            let e = runner.get(&file, "other.io").unwrap_err();
            assert!(e.contains("no credential helper is configured"), "{e}");
            // a file that is not one of the auth files of the process
            let other = dir.path().join("other.json");
            std::fs::write(&other, r#"{"credsStore": "fake"}"#).unwrap();
            let e = runner.get(&other, "r.io").unwrap_err();
            assert!(e.contains("not an auth file"), "{e}");
            for bad in ["", "a b", "r.io\n", &"x".repeat(MAX_REGISTRY + 1)] {
                assert!(runner.get(&file, bad).is_err(), "{bad:?}");
            }
            // still serving
            assert!(runner.get(&file, "r.io").unwrap().credentials.is_some());
        });
    }

    #[test]
    fn a_name_that_is_a_path_is_never_run() {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let marker = dir.path().join("ran");
            let file = world(
                dir.path(),
                r#"{"credHelpers": {"a.io": "../x", "b.io": "a/b", "c.io": ".."}, "credsStore": "/bin/sh"}"#,
                &[],
            );
            velarx_base::testing::write_script(
                &dir.path().join("docker-credential-x"),
                &format!("touch {}", marker.display()),
            );
            let runner = HelperRunner::start().unwrap();
            for registry in ["a.io", "b.io", "c.io", "d.io"] {
                let e = runner.get(&file, registry).unwrap_err();
                assert!(e.contains("invalid credential helper name"), "{e}");
            }
            assert!(!marker.exists());
        });
    }

    #[test]
    fn an_answer_over_the_cap_is_refused() {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let file = world(
                dir.path(),
                r#"{"credsStore": "big"}"#,
                &[("big", "/usr/bin/head -c 100000 /dev/zero")],
            );
            let runner = HelperRunner::start_with(HelperLimits {
                max_output: 100,
                ..HelperLimits::default()
            })
            .unwrap();
            let e = runner.get(&file, "r.io").unwrap_err();
            assert!(e.contains("too big"), "{e}");
        });
    }

    #[test]
    fn a_helper_that_does_not_answer_is_stopped() {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let file = world(
                dir.path(),
                r#"{"credsStore": "hang"}"#,
                &[("hang", "exec /usr/bin/sleep 3600")],
            );
            let runner = HelperRunner::start_with(HelperLimits {
                timeout: Duration::from_millis(100),
                ..HelperLimits::default()
            })
            .unwrap();
            let e = runner.get(&file, "r.io").unwrap_err();
            assert!(e.contains("timed out"), "{e}");
        });
    }

    #[test]
    fn the_runner_ends_when_the_front_is_killed() {
        velarx_base::testing::in_child(|| {
            let (ready_r, ready_w) = rustix::pipe::pipe().unwrap();
            let (go_r, go_w) = rustix::pipe::pipe().unwrap();
            let front = match velarx_sys::process::fork_known_single_threaded().unwrap() {
                velarx_sys::process::Fork::Child(_) => {
                    let runner = HelperRunner::start().unwrap();
                    let pid = runner.pid();
                    rustix::io::write(&ready_w, &pid.to_ne_bytes()).unwrap();
                    let mut b = [0u8; 1];
                    let _ = rustix::io::read(&go_r, &mut b);
                    // no destructor: the end of the socket is the whole signal
                    let _ = rustix::process::kill_process(
                        rustix::process::getpid(),
                        rustix::process::Signal::KILL,
                    );
                    velarx_sys::process::exit_now(1)
                }
                velarx_sys::process::Fork::Parent(front) => front,
            };
            let mut pid = [0u8; 4];
            assert_eq!(rustix::io::read(&ready_r, &mut pid).unwrap(), 4);
            let watch = pidfd(i32::from_ne_bytes(pid));
            rustix::io::write(&go_w, b"x").unwrap();
            ended(&watch);
            let status = rustix::process::waitpid(
                rustix::process::Pid::from_raw(front),
                rustix::process::WaitOptions::empty(),
            )
            .unwrap()
            .unwrap()
            .1;
            assert!(status.terminating_signal().is_some());
        });
    }

    #[test]
    fn a_helper_that_is_running_ends_with_the_front() {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let fifo = dir.path().join("pid");
            rustix::fs::mknodat(
                rustix::fs::CWD,
                &fifo,
                rustix::fs::FileType::Fifo,
                rustix::fs::Mode::from_raw_mode(0o600),
                0,
            )
            .unwrap();
            let file = world(
                dir.path(),
                r#"{"credsStore": "hang"}"#,
                &[(
                    "hang",
                    &format!("echo $$ > {}\nexec /usr/bin/sleep 3600", fifo.display()),
                )],
            );
            let runner = std::sync::Arc::new(HelperRunner::start().unwrap());
            // (the asker holds the stream while it waits: the socket is
            // ended through a descriptor of its own, as the asker's death)
            let closer = runner.stream.lock().unwrap().0.try_clone().unwrap();
            let asker = {
                let runner = runner.clone();
                std::thread::spawn(move || runner.get(&file, "r.io"))
            };
            let helper: i32 = std::fs::read_to_string(&fifo)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let helper = pidfd(helper);
            let own = pidfd(runner.pid());
            closer.shutdown(std::net::Shutdown::Both).unwrap();
            ended(&helper);
            ended(&own);
            assert!(asker.join().unwrap().is_err());
        });
    }

    /// What a compromised front sends: a frame of its own making.
    fn raw(runner: &HelperRunner, body: &[u8]) -> std::io::Result<Option<Vec<u8>>> {
        let mut guard = runner.stream.lock().unwrap();
        write_frame(&mut guard.0, body)?;
        read_frame(&mut guard.0, MAX_REPLY)
    }

    fn failed(reply: Option<Vec<u8>>) -> String {
        let reply: Reply = serde_json::from_slice(&reply.expect("a reply")).unwrap();
        match reply.answer {
            Answer::Failed(why) => why,
            Answer::Credentials(c) => panic!("credentials given: {c:?}"),
        }
    }

    /// The exit status of the runner, once it ended.
    fn exit_status(runner: &HelperRunner) -> i32 {
        ended(&pidfd(runner.pid()));
        let status = rustix::process::waitpid(
            rustix::process::Pid::from_raw(runner.pid()),
            rustix::process::WaitOptions::empty(),
        )
        .unwrap()
        .unwrap()
        .1;
        status.exit_status().expect("the runner exited")
    }

    #[test]
    fn crafted_requests_of_a_compromised_front_are_refused() {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let file = world(dir.path(), r#"{"credsStore": "fake"}"#, &[("fake", GOOD)]);
            let runner = HelperRunner::start().unwrap();
            let link = dir.path().join("link.json");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            let sub = dir.path().join("sub");
            std::fs::create_dir(&sub).unwrap();
            // auth files that are not the process's, or that name it in
            // another way than the list does
            let files = [
                PathBuf::from("config.json"),
                link,
                sub.join("../config.json"),
                PathBuf::from("/etc/passwd"),
                PathBuf::from(""),
            ];
            for (n, f) in files.iter().enumerate() {
                let body = serde_json::json!({"id": n, "file": f, "registry": "r.io"});
                let why = failed(raw(&runner, body.to_string().as_bytes()).unwrap());
                assert!(why.contains("not an auth file"), "{f:?}: {why}");
            }
            // registries that would add to what the helper reads, or that
            // are not names
            for bad in ["r.io\nx", "r.io\0", " r.io", "r.io x", "", "é.io"] {
                let body = serde_json::json!({"id": 1, "file": file, "registry": bad});
                let body = body.to_string();
                let why = failed(raw(&runner, body.as_bytes()).unwrap());
                assert!(why.contains("invalid registry"), "{bad:?}: {why}");
            }
            // the helper reads the registry and nothing else
            let c = runner.get(&file, "r.io").unwrap().credentials.unwrap();
            assert_eq!(c.password, "secret-of-r.io");
            // what is not a request ends the runner (no reply, no helper)
            assert!(raw(&runner, br#"{"file": "x"}"#).unwrap().is_none());
            assert_eq!(exit_status(&runner), 1);
            std::mem::forget(runner);
        });
    }

    #[test]
    fn a_frame_over_the_limit_ends_the_runner_before_it_is_read() {
        velarx_base::testing::in_child(|| {
            let runner = HelperRunner::start().unwrap();
            {
                let mut guard = runner.stream.lock().unwrap();
                // a length of 4 GiB, and no body: the runner does not wait
                // for one (nor allocates it)
                guard.0.write_all(&u32::MAX.to_be_bytes()).unwrap();
                let mut b = [0u8; 1];
                assert_eq!(guard.0.read(&mut b).unwrap(), 0);
            }
            assert_eq!(exit_status(&runner), 1);
            std::mem::forget(runner);
        });
    }

    #[test]
    fn a_late_reply_is_never_taken_for_the_next_request() {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let file = world(
                dir.path(),
                r#"{"credsStore": "slow"}"#,
                &[(
                    "slow",
                    r#"read s; [ "$s" = slow.io ] && /usr/bin/sleep 1; echo "{\"Username\":\"u\",\"Secret\":\"secret-of-$s\"}""#,
                )],
            );
            let runner = HelperRunner::start().unwrap();
            let timeout = |t| {
                runner
                    .stream
                    .lock()
                    .unwrap()
                    .0
                    .set_read_timeout(Some(t))
                    .unwrap()
            };
            // the asker stops waiting for the first answer
            timeout(Duration::from_millis(100));
            assert!(runner.get(&file, "slow.io").is_err());
            timeout(Duration::from_secs(60));
            // the answer for slow.io comes first: it is not the one of fast.io
            let c = runner.get(&file, "fast.io").unwrap().credentials.unwrap();
            assert_eq!(c.password, "secret-of-fast.io");
        });
    }

    #[test]
    fn a_runner_that_cannot_answer_says_why() {
        velarx_base::testing::in_child(|| {
            let runner = HelperRunner::start().unwrap();
            let pid = runner.pid();
            let _ = rustix::process::kill_process(
                rustix::process::Pid::from_raw(pid).unwrap(),
                rustix::process::Signal::KILL,
            );
            let e = runner.get(Path::new("/x/config.json"), "r.io").unwrap_err();
            assert!(e.contains("does not answer"), "{e}");
            assert!(e.contains("confined"), "{e}");
        });
    }
}
