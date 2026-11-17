// SPDX-License-Identifier: Apache-2.0
//! pasta for rootless networks: user mode networking in the namespace of
//! the container, with the published ports forwarded from the host.
//!
//! pasta configures the namespace and daemonizes; its pid is in a file.
//! The daemon keeps an eye on it (`Supervisor`) and starts it again if it
//! dies while the container runs; the teardown stops it and waits until it
//! is gone, so that a restart of the container can bind the ports again.

use std::collections::HashMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, warn};
use velarx_netkernel::pasta::{exiting_pidfd, namespace_id, open_namespace, pasta_pidfd, read_pid};
use velarx_wire::addr::{PortSpec, Proto};

/// The address of the DNS forwarder of pasta in the container.
pub const PASTA_DNS: &str = "169.254.1.1";
/// The address of the host in the container (host.containers.internal).
pub const PASTA_HOST: &str = "169.254.1.2";

/// The latest release of pasta, the one rootless containers need: an older
/// pasta is refused (`require_pasta`).
pub const PASTA_RELEASE: &str = "2026_10_02";

/// How long `pasta --version` may take.
const VERSION_TIMEOUT: Duration = Duration::from_secs(5);

/// The directories pasta is looked for in: the `$PATH` of the engine.
fn search_path() -> std::ffi::OsString {
    #[cfg(test)]
    if let Some(p) = tests::SEARCH_PATH.with(|p| p.borrow().clone()) {
        return p;
    }
    std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into())
}

pub fn find_pasta() -> Option<PathBuf> {
    std::env::split_paths(&search_path())
        .map(|d| d.join("pasta"))
        .find(|p| p.is_file())
}

/// pasta of [`PASTA_RELEASE`] or later, or the error that says why there is
/// none: none in the directories searched (`NoPasta`), or the one found is
/// older or does not tell its release (`OldPasta`).  Rootless networking is
/// pasta: no other way out is taken.
pub fn require_pasta() -> Result<PathBuf, velarx_netkernel::error::NetworkError> {
    let Some(path) = find_pasta() else {
        return Err(velarx_netkernel::error::NetworkError::NoPasta {
            searched: std::env::split_paths(&search_path())
                .map(|d| d.display().to_string())
                .collect::<Vec<_>>()
                .join(":"),
            minimum: PASTA_RELEASE,
        });
    };
    let said = version_of(&path);
    if release_of(&said).is_some_and(|r| Some(r) >= release_of(PASTA_RELEASE)) {
        return Ok(path);
    }
    Err(velarx_netkernel::error::NetworkError::OldPasta {
        path: path.display().to_string(),
        said: said.to_string(),
        minimum: PASTA_RELEASE,
    })
}

/// The first line of `PATH --version` (empty when it does not run, fails or
/// does not answer in time).  It is asked once for the file at PATH as it
/// is (its device, inode and time: a pasta updated in place is asked
/// again); a pasta that gives no answer is asked again the next time.
fn version_of(path: &Path) -> Arc<str> {
    use std::os::unix::fs::MetadataExt;
    type Key = (PathBuf, u64, u64, i64, i64);
    static KNOWN: Mutex<Vec<(Key, Arc<str>)>> = Mutex::new(Vec::new());
    let Ok(meta) = std::fs::metadata(path) else {
        return "".into();
    };
    let key: Key = (
        path.to_path_buf(),
        meta.dev(),
        meta.ino(),
        meta.mtime(),
        meta.mtime_nsec(),
    );
    let known =
        |all: &Vec<(Key, Arc<str>)>| all.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone());
    if let Some(v) = known(&KNOWN.lock().unwrap_or_else(|e| e.into_inner())) {
        return v;
    }
    // (not under the lock: a slow pasta holds up no other)
    let mut command = Command::new(path);
    command.arg("--version");
    let Some(out) = velarx_sys::pipe::output_within(command, VERSION_TIMEOUT) else {
        return "".into();
    };
    let line: Arc<str> = out.lines().next().unwrap_or("").trim().into();
    let mut all = KNOWN.lock().unwrap_or_else(|e| e.into_inner());
    if known(&all).is_none() {
        all.push((key, line.clone()));
    }
    line
}

/// The release (year, month, day) a pasta version names: the first date of
/// it, as upstream writes it (`2026_10_02`) or as a package version does
/// (`0^20261002.g...`, `0.0~git20261002...`).  None when it names none.
fn release_of(version: &str) -> Option<(u32, u32, u32)> {
    let b = version.as_bytes();
    let digits = |at: usize, n: usize| -> Option<u32> {
        let s = b.get(at..at + n)?;
        s.iter()
            .all(u8::is_ascii_digit)
            .then(|| std::str::from_utf8(s).ok()?.parse().ok())?
    };
    let date = |y: u32, m: u32, d: u32| {
        ((2000..=9999).contains(&y) && (1..=12).contains(&m) && (1..=31).contains(&d))
            .then_some((y, m, d))
    };
    (0..b.len())
        .filter(|&i| b[i].is_ascii_digit() && (i == 0 || !b[i - 1].is_ascii_digit()))
        .find_map(|i| {
            let (y, end) = (digits(i, 4)?, i + 4);
            let found = if b.get(end) == Some(&b'_') {
                date(y, digits(end + 1, 2)?, digits(end + 4, 2)?)
                    .filter(|_| b.get(end + 3) == Some(&b'_'))
                    .map(|r| (r, end + 6))
            } else {
                date(y, digits(end, 2)?, digits(end + 2, 2)?).map(|r| (r, end + 4))
            };
            // (the date ends where its digits end)
            found
                .filter(|(_, e)| !b.get(*e).is_some_and(u8::is_ascii_digit))
                .map(|(r, _)| r)
        })
}

/// The options of `--network pasta:OPTIONS` that take a value; none
/// names a file (pasta runs as root for a rootful daemon).
const VALUE_OPTIONS: &[&str] = &[
    "-a",
    "--address",
    "-n",
    "--netmask",
    "-g",
    "--gateway",
    "-i",
    "--interface",
    "-o",
    "--outbound",
    "--outbound-if4",
    "--outbound-if6",
    "-D",
    "--dns",
    "-S",
    "--search",
    "--dns-forward",
    "-m",
    "--mtu",
    "-t",
    "--tcp-ports",
    "-u",
    "--udp-ports",
    "-T",
    "--tcp-ns",
    "-U",
    "--udp-ns",
    "--map-host-loopback",
    "--map-guest-addr",
];

/// The options without a value that may be given.
const FLAG_OPTIONS: &[&str] = &[
    "-4",
    "--ipv4-only",
    "-6",
    "--ipv6-only",
    "--no-tcp",
    "--no-udp",
    "--no-icmp",
    "--no-dhcp",
    "--no-ndp",
    "--no-dhcpv6",
    "--no-ra",
    "--no-map-gw",
    "--map-gw",
    "--no-dhcp-dns",
    "--no-dhcp-search",
];

/// Refuse the options of `--network pasta:OPTIONS` that are not known to be
/// harmless: files (`--pcap`, `--log-file`, `--pid`...), namespaces, and a
/// bare word, which pasta would run as a command.
pub fn check_options(options: &[String]) -> Result<(), String> {
    let mut it = options.iter();
    while let Some(o) = it.next() {
        let (name, inline) = match o.split_once('=') {
            Some((n, _)) if n.starts_with("--") => (n, true),
            _ => (o.as_str(), false),
        };
        if VALUE_OPTIONS.contains(&name) {
            if !inline {
                let v = it
                    .next()
                    .ok_or_else(|| format!("the pasta option `{name}` needs a value"))?;
                if v.starts_with('-') && !v[1..].starts_with(|c: char| c.is_ascii_digit()) {
                    return Err(format!("invalid value `{v}` for the pasta option `{name}`"));
                }
            }
        } else if !(FLAG_OPTIONS.contains(&name) && !inline) {
            return Err(format!("the pasta option `{o}` is not allowed"));
        }
    }
    Ok(())
}

/// How pasta is run for a container, and what the container sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PastaPlan {
    pub argv: Vec<String>,
    /// host.containers.internal.
    pub host_address: String,
    pub nameserver: String,
}

/// The command line of pasta: the published ports (`-t`/`-u`), the MAC
/// address, the DNS forwarder, the host address, and the options of
/// `--network pasta:OPTS` last.
pub fn plan(
    pasta: &Path,
    ports: &[PortSpec],
    mac: Option<&str>,
    options: &[String],
    as_root: bool,
) -> PastaPlan {
    let mut a: Vec<String> = vec![pasta.to_string_lossy().into_owned()];
    // As root pasta switches to nobody before it opens the namespace, which
    // is in a directory only root can enter.
    if as_root {
        a.extend(["--runas".into(), "0".into()]);
    }
    a.push("--config-net".into());
    if let Some(mac) = mac {
        a.extend(["--ns-mac-addr".into(), mac.to_string()]);
    }
    a.push("--quiet".into());
    a.extend(["--dns-forward".into(), PASTA_DNS.into()]);
    // As podman's: the gateway is not the host (`--map-gw`, which is no
    // option of pasta, asks for it), and 169.254.1.2 is the address of
    // the container's namespace on the host (`--map-guest-addr`), not the
    // loopback of the host: a service of the user bound to 127.0.0.1 is not
    // reachable from the container (`--map-host-loopback` opens it)
    let map_gw = options.iter().any(|o| o == "--map-gw");
    let guest_addr = option_value(options, "--map-guest-addr");
    if !map_gw {
        a.push("--no-map-gw".into());
    }
    if guest_addr.is_none() {
        a.extend(["--map-guest-addr".into(), PASTA_HOST.into()]);
    }
    let (mut tcp, mut udp) = (false, false);
    for p in ports {
        let span = |port: u16| {
            if p.range > 1 {
                format!("{}-{}", port, u32::from(port) + u32::from(p.range) - 1)
            } else {
                port.to_string()
            }
        };
        let host = match p.host_ip {
            Some(ip) => format!("{ip}/"),
            None => String::new(),
        };
        let spec = format!("{host}{}:{}", span(p.host_port), span(p.container_port));
        let flag = match p.proto {
            Proto::Tcp => {
                tcp = true;
                "-t"
            }
            Proto::Udp => {
                udp = true;
                "-u"
            }
            // (refused before, with the other checks of the ports)
            Proto::Sctp => continue,
        };
        a.extend([flag.into(), spec]);
    }
    if !tcp {
        a.extend(["-t".into(), "none".into()]);
    }
    if !udp {
        a.extend(["-u".into(), "none".into()]);
    }
    a.extend(["-T".into(), "none".into(), "-U".into(), "none".into()]);
    a.extend(
        options
            .iter()
            .filter(|o| !o.is_empty() && *o != "--map-gw")
            .cloned(),
    );
    PastaPlan {
        argv: a,
        host_address: guest_addr.unwrap_or(PASTA_HOST).into(),
        nameserver: option_value(options, "--dns-forward")
            .unwrap_or(PASTA_DNS)
            .into(),
    }
}

/// The value of the last `NAME VALUE` or `NAME=VALUE` option of the user.
fn option_value<'a>(options: &'a [String], name: &str) -> Option<&'a str> {
    let mut found = None;
    let mut it = options.iter();
    while let Some(o) = it.next() {
        if o == name {
            found = it.next().map(String::as_str);
        } else if let Some(v) = o.strip_prefix(name).and_then(|v| v.strip_prefix('=')) {
            found = Some(v);
        }
    }
    found
}

/// Run pasta on the network namespace NETNS; it daemonizes once the
/// namespace is configured and writes its pid to PID_FILE.
///
/// pasta ends by itself, by default, when the path of its namespace is
/// deleted (a bound file, or the entry of a process that ended in procfs):
/// for that it opens the directory of the path, which a policy may deny it
/// on the entry of another process (`netns dir open: Permission denied`:
/// SELinux on the directory `/proc/PID/fd` of a monitor).  So it does not
/// watch the path (`--no-netns-quit`), and its end is explicit:
///
/// * a container's pasta: the teardown of the container (the end of its
///   process, `rm`, the cleanup command of its monitor, an engine that
///   finds the monitor lost).  After a `kill -9` of the monitor with no
///   engine running, the pasta and the ports it published stay until the
///   next command looks at the container, or `rm`; so they do when an
///   engine dies between this and the start of the container (until `rm`).
/// * the pasta of the rootless network namespace: the holder when it is
///   asked to end, else the next holder (before it starts its own), the
///   release of the namespace and the start of an engine.
pub fn start(argv: &[String], netns: &Path, pid_file: &Path, log_file: &Path) -> io::Result<()> {
    let (prog, args) = argv
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no pasta"))?;
    let _ = std::fs::remove_file(pid_file);
    let log = std::fs::File::create(log_file)?;
    let status = Command::new(prog)
        .args(args)
        .arg("--no-netns-quit")
        .arg("--netns")
        .arg(netns)
        .arg("--pid")
        .arg(pid_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .status()?;
    if status.success() {
        if let Some(pid) = read_pid(pid_file) {
            velarx_nsid::tree::register_holder(pid.as_raw_nonzero().get() as u32, "pasta");
        }
        return Ok(());
    }
    let mut msg = String::new();
    if let Ok(f) = std::fs::File::open(log_file) {
        let _ = f.take(4096).read_to_string(&mut msg);
    }
    Err(io::Error::other(format!("pasta failed: {}", msg.trim())))
}

/// One pasta to keep running.
struct Watched {
    argv: Vec<String>,
    netns: PathBuf,
    pid_file: PathBuf,
    log_file: PathBuf,
    /// The namespace NETNS was when the watch began, held open: pasta is
    /// started again only on that one, never on one that was pinned on the
    /// path since (device and inode)
    namespace: Option<(std::fs::File, (u64, u64))>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    /// Readable once `unwatch` asked the thread to end
    ended: Arc<std::os::fd::OwnedFd>,
}

/// The thread that watches one pasta, and how to end it.
struct Watch {
    stop: Arc<std::sync::atomic::AtomicBool>,
    ended: Arc<std::os::fd::OwnedFd>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Watch {
    /// End the thread and wait for it (it returns at once, or when the pasta
    /// it was starting is up): after that no pasta is started for the
    /// container, and the teardown that follows stops the last one.
    fn end(mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = rustix::io::write(&*self.ended, &1u64.to_ne_bytes());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Starts pasta again when it dies while its container runs.
#[derive(Default)]
pub struct Supervisor {
    watched: Mutex<HashMap<String, Watch>>,
}

impl Supervisor {
    /// Watch the pasta of the container ID from a thread: restart it (at
    /// most a few times a minute) until `unwatch`.
    pub fn watch(
        &self,
        id: &str,
        argv: Vec<String>,
        netns: &Path,
        pid_file: &Path,
        log_file: &Path,
    ) {
        let ended = match rustix::event::eventfd(
            0,
            rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
        ) {
            Ok(fd) => Arc::new(fd),
            Err(e) => {
                warn!("cannot supervise pasta: {e}");
                return;
            }
        };
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let w = Watched {
            argv,
            netns: netns.to_path_buf(),
            pid_file: pid_file.to_path_buf(),
            log_file: log_file.to_path_buf(),
            namespace: open_namespace(netns),
            stop: stop.clone(),
            ended: ended.clone(),
        };
        // (the watch it replaces ends first: never two that start pasta)
        self.unwatch(id);
        let name = id.to_string();
        let spawned = std::thread::Builder::new()
            .name("pasta-watch".into())
            .spawn(move || supervise(&name, w));
        match spawned {
            Ok(thread) => {
                let old = self
                    .watched
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        id.to_string(),
                        Watch {
                            stop,
                            ended,
                            thread: Some(thread),
                        },
                    );
                // (one that a concurrent watch put in meanwhile)
                if let Some(old) = old {
                    old.end();
                }
            }
            Err(e) => warn!("cannot supervise pasta: {e}"),
        }
    }

    /// Whether the pasta of the container ID is watched.
    #[cfg(test)]
    pub(super) fn is_watched(&self, id: &str) -> bool {
        self.watched
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(id)
    }

    /// Stop watching: the teardown stops pasta.  Returns once the thread
    /// that restarts it has ended.
    pub fn unwatch(&self, id: &str) {
        let watch = self
            .watched
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        if let Some(watch) = watch {
            watch.end();
        }
    }
}

/// Wait until the process of `pasta` exited (true) or `ended` is readable
/// (false), with no timer.
fn exited_before_end(pasta: &std::os::fd::OwnedFd, ended: &std::os::fd::OwnedFd) -> bool {
    use rustix::event::{poll, PollFd, PollFlags};
    loop {
        let mut fds = [
            PollFd::new(pasta, PollFlags::IN),
            PollFd::new(ended, PollFlags::IN),
        ];
        match poll(&mut fds, None) {
            Ok(_) => {
                if !fds[1].revents().is_empty() {
                    return false;
                }
                if !fds[0].revents().is_empty() {
                    return true;
                }
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return false,
        }
    }
}

fn supervise(id: &str, w: Watched) {
    use std::sync::atomic::Ordering;
    let mut restarts: Vec<std::time::Instant> = Vec::new();
    loop {
        if w.stop.load(Ordering::SeqCst) {
            return;
        }
        // (a pasta that is exiting is waited for: its tap device would keep
        // the next one from making its own; one that died before the watch
        // looked for it is gone as well)
        if let Some(fd) = pasta_pidfd(&w.pid_file).or_else(|| exiting_pidfd(&w.pid_file)) {
            if !exited_before_end(&fd, &w.ended) {
                return;
            }
        }
        // (a pasta that died leaves its pid file; `stop` removes it before
        // it stops pasta)
        if w.stop.load(Ordering::SeqCst)
            || !w.pid_file.exists()
            || namespace_id(&w.netns) != w.namespace.as_ref().map(|n| n.1)
        {
            return;
        }
        let now = std::time::Instant::now();
        restarts.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        if restarts.len() >= 5 {
            warn!("pasta of {id} keeps dying, not restarting it");
            return;
        }
        restarts.push(now);
        debug!("pasta of {id} exited, starting it again");
        if let Err(e) = start(&w.argv, &w.netns, &w.pid_file, &w.log_file) {
            warn!("cannot restart pasta of {id}: {e}");
            return;
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::ffi::OsString;
    use velarx_netkernel::pasta::{is_pasta_of, is_running, stop, stop_on, wait_exit};

    thread_local! {
        /// The `$PATH` pasta is looked for in by the test of this thread
        /// (the environment is the process's, shared by the tests).
        pub(in crate::network) static SEARCH_PATH: RefCell<Option<OsString>> =
            const { RefCell::new(None) };
    }

    /// Look for pasta in DIRS only, in this thread.
    pub(in crate::network) fn search_in(dirs: &[&Path]) {
        let path = std::env::join_paths(dirs).unwrap();
        SEARCH_PATH.with(|p| *p.borrow_mut() = Some(path));
    }

    /// Without pasta in the directories searched, the error is typed, names
    /// what was searched and the release needed; a `pasta` in one of them is
    /// found.
    #[test]
    fn a_missing_pasta_is_a_typed_error_that_names_the_search() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        search_in(&[a.path(), b.path()]);
        let Err(velarx_netkernel::error::NetworkError::NoPasta { searched, minimum }) =
            require_pasta()
        else {
            panic!("pasta found in two empty directories");
        };
        assert_eq!(
            searched,
            format!("{}:{}", a.path().display(), b.path().display())
        );
        assert_eq!(minimum, PASTA_RELEASE);
        let text = require_pasta().unwrap_err().to_string();
        assert!(text.contains("cannot find `pasta`"), "{text}");
        assert!(text.contains(&searched), "{text}");
        assert!(text.contains(PASTA_RELEASE), "{text}");
        assert!(text.contains("--network none"), "{text}");
        fake_version(b.path(), "pasta 2026_10_02.cba3570");
        assert_eq!(require_pasta().unwrap(), b.path().join("pasta"));
    }

    /// A pasta in DIR whose `--version` prints LINE (and what pasta prints
    /// after it).
    pub(in crate::network) fn fake_version(dir: &Path, line: &str) {
        velarx_base::testing::write_script(
            &dir.join("pasta"),
            &format!("printf '%s\\n' '{line}' 'Copyright Red Hat'"),
        );
    }

    /// The release is read from what pasta prints of itself, whatever
    /// packaged it; a pasta older than the release needed, or one that names
    /// no release, is refused with what it said; the release needed and any
    /// later one are taken.
    #[test]
    fn the_release_of_pasta_is_required() {
        for (said, ok) in [
            ("pasta 2026_10_02.cba3570", true),
            ("pasta 0^20261002.gcba3570-1.fc44.x86_64", true),
            ("pasta 0.0~git20261002.cba3570-1", true),
            ("pasta 2027_01_15.0123456", true),
            ("pasta 2026_11_20", true),
            ("pasta 2026_09_30.1234567", false),
            ("pasta 0^20250121.g4f2c8e7-2.fc42.x86_64", false),
            ("pasta 0.0~git20240220.1e6f92b-1", false),
            ("pasta unknown version", false),
            ("pasta git", false),
            ("pasta 12345678", false),
            ("", false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            search_in(&[dir.path()]);
            fake_version(dir.path(), said);
            match require_pasta() {
                Ok(p) => {
                    assert!(ok, "{said:?} was taken");
                    assert_eq!(p, dir.path().join("pasta"));
                }
                Err(e) => {
                    assert!(!ok, "{said:?}: {e}");
                    let velarx_netkernel::error::NetworkError::OldPasta {
                        ref path,
                        said: ref found,
                        minimum,
                    } = e
                    else {
                        panic!("{said:?}: {e}");
                    };
                    assert_eq!(path, &dir.path().join("pasta").display().to_string());
                    assert_eq!(found, said);
                    assert_eq!(minimum, PASTA_RELEASE);
                    let text = e.to_string();
                    assert!(text.contains(PASTA_RELEASE), "{text}");
                    assert!(text.contains("--network none"), "{text}");
                }
            }
        }
        // a pasta that cannot be run says nothing: refused
        let dir = tempfile::tempdir().unwrap();
        search_in(&[dir.path()]);
        std::fs::write(dir.path().join("pasta"), "").unwrap();
        assert!(matches!(
            require_pasta(),
            Err(velarx_netkernel::error::NetworkError::OldPasta { ref said, .. }) if said.is_empty()
        ));
    }

    /// A pasta is asked its version once, and again when it is replaced.
    #[test]
    fn the_version_of_pasta_is_asked_once_per_file() {
        let dir = tempfile::tempdir().unwrap();
        search_in(&[dir.path()]);
        let count = dir.path().join("count");
        velarx_base::testing::write_script(
            &dir.path().join("pasta"),
            &format!("echo x >> {}\necho pasta 2026_10_02", count.display()),
        );
        require_pasta().unwrap();
        require_pasta().unwrap();
        assert_eq!(std::fs::read_to_string(&count).unwrap().lines().count(), 1);
        // (replaced: a new file, as a package update does; the old one is
        // kept so that its inode is not the new one's)
        std::fs::rename(dir.path().join("pasta"), dir.path().join("old")).unwrap();
        fake_version(dir.path(), "pasta 2026_09_30");
        assert!(require_pasta().is_err());
    }

    /// The supervisor waits for the exit of pasta or for the end of the
    /// watch, whichever comes first, with no timer: `unwatch` ends it at
    /// once.
    #[test]
    fn the_wait_for_pasta_ends_with_the_process_or_the_watch() {
        let eventfd = || {
            rustix::event::eventfd(
                0,
                rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
            )
            .unwrap()
        };
        let pidfd = |c: &std::process::Child| {
            rustix::process::pidfd_open(
                rustix::process::Pid::from_raw(c.id() as i32).unwrap(),
                rustix::process::PidfdFlags::empty(),
            )
            .unwrap()
        };
        // the watch ends while the process runs
        let mut sleeper = Command::new("sleep").arg("30").spawn().unwrap();
        let (fd, ended) = (pidfd(&sleeper), Arc::new(eventfd()));
        let (tx, rx) = std::sync::mpsc::channel();
        let waiting = {
            let ended = ended.clone();
            std::thread::spawn(move || tx.send(exited_before_end(&fd, &ended)).unwrap())
        };
        assert!(rx.try_recv().is_err(), "it waits");
        rustix::io::write(&*ended, &1u64.to_ne_bytes()).unwrap();
        assert!(!rx.recv().unwrap());
        waiting.join().unwrap();
        // the process exits while the watch goes on
        let (fd, ended) = (pidfd(&sleeper), eventfd());
        let (tx, rx) = std::sync::mpsc::channel();
        let waiting = std::thread::spawn(move || tx.send(exited_before_end(&fd, &ended)).unwrap());
        sleeper.kill().unwrap();
        sleeper.wait().unwrap();
        assert!(rx.recv().unwrap());
        waiting.join().unwrap();
    }

    /// A pasta that is not a real one: a copy of the shell named `pasta`,
    /// that holds on a fifo, started by a script that writes the pid file as
    /// pasta does.  Each start is told on the fifo `started`.
    pub(in crate::network) struct FakePasta {
        _dir: tempfile::TempDir,
        pub argv: Vec<String>,
        pub netns: PathBuf,
        pub pid_file: PathBuf,
        pub log_file: PathBuf,
        started: std::fs::File,
    }

    impl FakePasta {
        pub fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path();
            // (copied by a process of its own, and the launcher is read by
            // the shell, not executed: a fork of another test of this process
            // that held either open for writing would make the exec fail
            // with ETXTBSY)
            velarx_base::testing::copy_program(Path::new("/bin/sh"), &p.join("pasta"));
            for fifo in ["started", "hold"] {
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    p.join(fifo),
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::from_raw_mode(0o600),
                    0,
                )
                .unwrap();
            }
            let launch = p.join("launch");
            std::fs::write(
                &launch,
                format!(
                    "while [ $# -gt 0 ]; do\n\
                     case $1 in --netns) ns=$2;; --pid) pid=$2;; esac; shift\n\
                     done\n\
                     mkfifo {d}/ready\n\
                     PIDFILE=$pid {d}/pasta -c 'echo $$ > \"$PIDFILE\"; echo > {d}/ready; \
                     echo > {d}/started; read x < {d}/hold' --pid \"$pid\" --netns \"$ns\" &\n\
                     read x < {d}/ready; rm {d}/ready\n",
                    d = p.display()
                ),
            )
            .unwrap();
            let netns = p.join("netns");
            std::fs::write(&netns, "").unwrap();
            // (read and write: opening it never waits, and a read waits for a line)
            let started = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(p.join("started"))
                .unwrap();
            Self {
                argv: vec!["/bin/sh".into(), launch.to_string_lossy().into_owned()],
                pid_file: p.join("pid"),
                log_file: p.join("log"),
                netns,
                started,
                _dir: dir,
            }
        }

        pub fn start(&self) {
            start(&self.argv, &self.netns, &self.pid_file, &self.log_file).unwrap();
            self.wait_started();
        }

        /// Wait for the next start of the pasta (30 s at most: a start
        /// that never comes fails the test).
        pub fn wait_started(&self) {
            use rustix::event::{poll, PollFd, PollFlags};
            let limit = rustix::event::Timespec {
                tv_sec: 30,
                tv_nsec: 0,
            };
            let mut fds = [PollFd::new(&self.started, PollFlags::IN)];
            assert!(
                poll(&mut fds, Some(&limit)).unwrap() > 0,
                "pasta was not started again"
            );
            let mut line = [0u8; 1];
            (&self.started).read_exact(&mut line).unwrap();
        }

        /// Whether a start is told, now.
        pub fn started_now(&self) -> bool {
            use rustix::event::{poll, PollFd, PollFlags};
            let mut fds = [PollFd::new(&self.started, PollFlags::IN)];
            poll(&mut fds, Some(&rustix::event::Timespec::default())).unwrap() > 0
        }

        /// Kill the pasta that runs, and wait until it is gone.
        pub fn kill(&self) {
            let pid = read_pid(&self.pid_file).unwrap();
            let fd =
                rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap();
            rustix::process::pidfd_send_signal(&fd, rustix::process::Signal::KILL).unwrap();
            assert!(wait_exit(&fd, Duration::from_secs(30)));
        }
    }

    /// The fake pasta that runs goes with the test, one that failed too.
    impl Drop for FakePasta {
        fn drop(&mut self) {
            if let Some(fd) = pasta_pidfd(&self.pid_file) {
                let _ = rustix::process::pidfd_send_signal(&fd, rustix::process::Signal::KILL);
            }
        }
    }

    /// `supervise` on a thread of its own: the channel tells when it returned.
    fn supervise_on_thread(
        fake: &FakePasta,
        ended: &Arc<std::os::fd::OwnedFd>,
    ) -> std::sync::mpsc::Receiver<()> {
        let w = Watched {
            argv: fake.argv.clone(),
            netns: fake.netns.clone(),
            pid_file: fake.pid_file.clone(),
            log_file: fake.log_file.clone(),
            namespace: open_namespace(&fake.netns),
            stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            ended: ended.clone(),
        };
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            supervise("c", w);
            let _ = tx.send(());
        });
        rx
    }

    fn eventfd() -> Arc<std::os::fd::OwnedFd> {
        Arc::new(
            rustix::event::eventfd(
                0,
                rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
            )
            .unwrap(),
        )
    }

    /// A pasta that dies while its container runs is started again, and the
    /// watch goes on until `unwatch`, after which a pasta that goes is not
    /// started again.
    #[test]
    fn a_pasta_that_dies_during_the_run_is_started_again() {
        let fake = FakePasta::new();
        let supervisor = Supervisor::default();
        fake.start();
        supervisor.watch(
            "c",
            fake.argv.clone(),
            &fake.netns,
            &fake.pid_file,
            &fake.log_file,
        );
        fake.kill();
        fake.wait_started();
        fake.kill();
        fake.wait_started();
        // (`unwatch` returns once the thread ended: nothing starts pasta
        // after it)
        supervisor.unwatch("c");
        fake.kill();
        assert!(!fake.started_now(), "pasta was started again");
    }

    /// The pasta of the last run of a container is stopped, and its
    /// namespace file removed, by the cleanup command of its monitor (another
    /// process), and the next run pins a new namespace on the path.  The
    /// watch of the last run, that learns of the exit after the new
    /// namespace is pinned, must start nothing: a pasta on the new namespace
    /// would make the tap device that the pasta of the new run needs.
    #[test]
    fn a_watch_does_not_start_pasta_on_the_namespace_of_the_next_run() {
        let fake = FakePasta::new();
        fake.start();
        let ended = eventfd();
        let done = supervise_on_thread(&fake, &ended);
        // the next run pins another namespace on the path (the old file
        // is kept until the new one is there: another inode)
        let next = fake.netns.with_extension("next");
        std::fs::write(&next, "").unwrap();
        std::fs::rename(&next, &fake.netns).unwrap();
        fake.kill();
        done.recv_timeout(Duration::from_secs(30))
            .expect("the watch of the last run ended");
        assert!(!fake.started_now(), "pasta was started on the next run");
    }

    /// A pasta that `stop` stopped is not started again, whoever watches it:
    /// the engine watches the pasta that the cleanup command of a monitor, a
    /// process of its own, stops.
    #[test]
    fn a_watch_does_not_start_a_stopped_pasta_again() {
        let fake = FakePasta::new();
        fake.start();
        let ended = eventfd();
        let done = supervise_on_thread(&fake, &ended);
        stop(&fake.pid_file, true);
        done.recv_timeout(Duration::from_secs(30))
            .expect("the watch ended");
        assert!(!fake.started_now(), "pasta was started again");
    }

    /// The same, when the pin is gone altogether.
    #[test]
    fn a_watch_does_not_start_pasta_without_its_namespace() {
        let fake = FakePasta::new();
        fake.start();
        let ended = eventfd();
        let done = supervise_on_thread(&fake, &ended);
        std::fs::remove_file(&fake.netns).unwrap();
        fake.kill();
        done.recv_timeout(Duration::from_secs(30))
            .expect("the watch ended");
        assert!(!fake.started_now(), "pasta was started again");
    }

    /// A pid file that names another process (a reused pid) is never
    /// signalled.
    #[test]
    fn stop_signals_only_its_pasta() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("p.pid");
        let mut other = Command::new("sleep").arg("30").spawn().unwrap();
        std::fs::write(&pid_file, other.id().to_string()).unwrap();
        stop(&pid_file, true);
        assert!(other.try_wait().unwrap().is_none(), "a stranger was killed");
        assert!(!pid_file.exists());
        let _ = other.kill();
        let _ = other.wait();
        assert!(!is_pasta_of(std::process::id() as i32, Path::new("/x")));
    }

    #[test]
    fn options() {
        let o = |v: &[&str]| check_options(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert!(o(&["--ipv4-only", "-a", "10.0.2.0", "--mtu=1400", "-t", "8080"]).is_ok());
        for bad in [
            &["--pcap", "/etc/shadow"][..],
            &["-l", "/root/x"],
            &["--log-file=/root/x"],
            &["--pid", "/etc/passwd"],
            &["--netns", "/proc/1/ns/net"],
            &["--runas", "1000"],
            &["sh"],
            &["-a"],
            &["-a", "--pcap"],
            &["--no-tcp=1"],
        ] {
            assert!(o(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn nameserver_follows_dns_forward() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(option_value(&v(&["--ipv4-only"]), "--dns-forward"), None);
        assert_eq!(
            option_value(&v(&["--dns-forward", "198.51.100.1"]), "--dns-forward"),
            Some("198.51.100.1")
        );
        assert_eq!(
            option_value(&v(&["--dns-forward=10.1.1.1", "-4"]), "--dns-forward"),
            Some("10.1.1.1")
        );
        assert_eq!(option_value(&v(&["--dns-forward"]), "--dns-forward"), None);
    }

    #[test]
    fn command_line() {
        let ports = vec![
            PortSpec::parse("8080:80").unwrap(),
            PortSpec::parse("127.0.0.1:9000-9001:90-91/udp").unwrap(),
        ];
        let p = plan(
            Path::new("/usr/bin/pasta"),
            &ports,
            Some("02:42:00:00:00:01"),
            &["--ipv4-only".into()],
            true,
        );
        let a = p.argv.join(" ");
        assert_eq!(
            a,
            "/usr/bin/pasta --runas 0 --config-net --ns-mac-addr 02:42:00:00:00:01 --quiet \
             --dns-forward 169.254.1.1 --no-map-gw --map-guest-addr 169.254.1.2 \
             -t 8080:80 -u 127.0.0.1/9000-9001:90-91 -T none -U none --ipv4-only"
        );
        assert_eq!(p.host_address, PASTA_HOST);
        // --map-gw is podman's name for keeping the mapping of the gateway:
        // no option of pasta, and the host stays the guest address
        let p = plan(Path::new("pasta"), &[], None, &["--map-gw".into()], false);
        assert!(!p.argv.iter().any(|a| a.contains("map-gw")), "{:?}", p.argv);
        assert_eq!(p.host_address, PASTA_HOST);
    }

    #[test]
    fn the_host_is_not_the_loopback_nor_the_gateway_unless_asked() {
        let plan = |opts: &[&str]| {
            let o: Vec<String> = opts.iter().map(|s| s.to_string()).collect();
            plan(Path::new("pasta"), &[], None, &o, false)
        };
        // as podman's defaults: no gateway mapping, the namespace's own
        // address as 169.254.1.2, and no --map-host-loopback
        let a = plan(&[]).argv.join(" ");
        assert!(
            a.contains("--no-map-gw --map-guest-addr 169.254.1.2"),
            "{a}"
        );
        assert!(!a.contains("--map-host-loopback"), "{a}");
        // --map-gw is podman's name for keeping pasta's mapping of the
        // gateway: no pasta option
        let a = plan(&["--map-gw"]).argv.join(" ");
        assert!(!a.contains("--no-map-gw") && !a.contains("--map-gw"), "{a}");
        // an address of the user's own
        let p = plan(&["--map-guest-addr", "169.254.9.9"]);
        let a = p.argv.join(" ");
        assert_eq!(a.matches("--map-guest-addr").count(), 1, "{a}");
        assert_eq!(p.host_address, "169.254.9.9");
        assert_eq!(
            p.argv.join(" "),
            "pasta --config-net --quiet --dns-forward 169.254.1.1 --no-map-gw -t none -u none \
             -T none -U none --map-guest-addr 169.254.9.9"
        );
    }

    /// A holder that ends late must not stop the pasta that a newer holder
    /// started: the pid file names it, but it is not on the namespace of
    /// the old holder.
    #[test]
    fn a_pasta_of_another_namespace_is_not_stopped() {
        let fake = FakePasta::new();
        fake.start();
        let old_holder = fake.netns.with_extension("old");
        assert!(!stop_on(&fake.pid_file, &old_holder, true));
        assert!(is_running(&fake.pid_file), "the new pasta was stopped");
        assert!(fake.pid_file.exists(), "the pid file of the new pasta went");
        // its own namespace: stopped, and the file with it
        assert!(stop_on(&fake.pid_file, &fake.netns, true));
        assert!(!is_running(&fake.pid_file));
        assert!(!fake.pid_file.exists());
        // nothing is there any more
        assert!(!stop_on(&fake.pid_file, &fake.netns, true));
    }

    /// The pid file that was rewritten for another pasta since the identity
    /// was checked stays.
    #[test]
    fn a_stranger_in_the_pid_file_is_not_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("p.pid");
        let mut other = Command::new("sleep").arg("30").spawn().unwrap();
        std::fs::write(&pid_file, other.id().to_string()).unwrap();
        assert!(!stop_on(&pid_file, Path::new("/x"), true));
        assert!(other.try_wait().unwrap().is_none());
        assert!(pid_file.exists());
        let _ = other.kill();
        let _ = other.wait();
    }

    /// pasta opens the directory of its `--netns` path to watch it: where it
    /// may not (a policy denies it, here the mode of the directory), it joins
    /// the namespace all the same, and keeps running until it is stopped.
    #[test]
    fn pasta_joins_a_namespace_whose_directory_it_cannot_open() {
        velarx_base::testing::in_child(|| {
            use rustix::mount::{
                mount_bind, mount_change, unmount, MountPropagationFlags, UnmountFlags,
            };
            use rustix::thread::UnshareFlags;
            use std::os::unix::fs::PermissionsExt;
            let Ok(prog) = require_pasta() else {
                eprintln!("SKIPPED: no pasta");
                return;
            };
            let uid = rustix::process::getuid().as_raw();
            let gid = rustix::process::getgid().as_raw();
            if velarx_sys::ns::unshare(
                UnshareFlags::NEWUSER | UnshareFlags::NEWNET | UnshareFlags::NEWNS,
            )
            .is_err()
            {
                eprintln!("SKIPPED: no user and network namespace for this user");
                return;
            }
            std::fs::write("/proc/self/setgroups", "deny").unwrap();
            std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).unwrap();
            std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).unwrap();
            let dir = tempfile::tempdir().unwrap();
            // the namespace by a path in a directory that can be searched,
            // not read
            let ns_dir = dir.path().join("ns");
            std::fs::create_dir(&ns_dir).unwrap();
            // (bound on a file, as the engine pins one: the SELinux policy
            // of pasta does not let it follow a link in a temporary directory)
            let netns = ns_dir.join("net");
            std::fs::write(&netns, "").unwrap();
            mount_change(
                "/",
                MountPropagationFlags::REC | MountPropagationFlags::PRIVATE,
            )
            .unwrap();
            mount_bind("/proc/self/ns/net", &netns).unwrap();
            std::fs::set_permissions(&ns_dir, std::fs::Permissions::from_mode(0o311)).unwrap();
            let (pid_file, log_file) = (dir.path().join("pid"), dir.path().join("log"));
            let plan = plan(&prog, &[], None, &[], true);
            start(&plan.argv, &netns, &pid_file, &log_file).unwrap();
            assert!(is_running(&pid_file));
            stop(&pid_file, true);
            assert!(!is_running(&pid_file));
            std::fs::set_permissions(&ns_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            unmount(&netns, UnmountFlags::DETACH).unwrap();
        });
    }
}
