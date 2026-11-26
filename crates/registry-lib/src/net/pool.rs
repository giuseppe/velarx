// SPDX-License-Identifier: Apache-2.0
//! The daemon's side of the pull workers: processes started when a pull
//! needs them, each answering one request at a time.
//!
//! The daemon trusts nothing a worker says: lengths are bounded before
//! anything is allocated, the bytes of an answer are limited by what was
//! asked, and every digest is checked by the caller.

use super::proto::{
    json, parse, read_bytes, read_header, write_data, write_frame, write_frame_with_fd, ChunkSpec,
    Done, ErrorKind, ErrorMsg, Header, Kind, LayerTrailer, Request,
};
use crate::net::ranges::PieceSink;
use bytes::Bytes;
use reqwest::StatusCode;
use std::collections::HashMap;
use std::ops::Range;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::debug;
use velarx_content::pull::net::origin::{UrlError, UrlTrailer};
use velarx_content::pull::ranges::{Piece, RangesError};
use velarx_registry::netpolicy::Resolver;
use velarx_registry::target::EndpointSpec;
use velarx_sys::spawner::Spawner;
use velarx_types::digest::{Algorithm, Digest};
use velarx_types::{printable, ImageError, ImageResult};

use velarx_content::list::ENVIRONMENT;

/// Size of the buffers of the socket to a worker.
const SOCKET_BUFFER: usize = 4 * 1024 * 1024;

/// How long a worker may take to send the next message of a request (the
/// network has its own timeouts: this is for a worker that hangs).
const MESSAGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// How long the payload of a message may take to arrive once its header did.
const PAYLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long a worker may take to say it is ready.
pub(crate) const START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a worker whose socket closed may take to exit.
pub(crate) const WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Longest message of a worker shown.
const MAX_MESSAGE: usize = 1024;

/// The arguments of a worker the spawner starts: `pull-worker`, and its
/// flags.
fn valid_args(args: &[String]) -> bool {
    let mut it = args.iter().map(String::as_str);
    if it.next() != Some("pull-worker") {
        return false;
    }
    while let Some(arg) = it.next() {
        match arg {
            "--require-userns" | "--self-test" => {}
            "--connect-port" => {
                if it.next().is_none_or(|p| p.parse::<u16>().is_err()) {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

/// The program the spawner of a fetcher starts: its own binary as a pull
/// worker, with the arguments of `pull-worker` and the variables the workers
/// keep, nothing else.
pub fn worker_program(exe: &std::path::Path) -> std::io::Result<velarx_sys::spawner::Program> {
    velarx_sys::spawner::Program::open(&exe.to_string_lossy(), exe, valid_args, |name| {
        ENVIRONMENT.contains(&name)
    })
}

/// A worker the spawner started, as the front holds it.  Dropping it ends
/// the worker.  The front is not its parent and signals none: its life
/// socket tells how it ended.
pub struct Worker {
    pub pid: u32,
    stderr: Option<tokio::net::unix::pipe::Receiver>,
    life: tokio::net::unix::pipe::Receiver,
}

impl Worker {
    /// The worker's standard error (once).
    pub fn take_stderr(&mut self) -> Option<tokio::net::unix::pipe::Receiver> {
        self.stderr.take()
    }

    /// How the worker ended, as long as it takes.
    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        use std::os::unix::process::ExitStatusExt;
        use tokio::io::AsyncReadExt;
        let mut status = [0u8; 4];
        self.life.read_exact(&mut status).await?;
        Ok(std::process::ExitStatus::from_raw(i32::from_ne_bytes(
            status,
        )))
    }
}

/// Start a worker with `args` and the variables `env`, its standard input
/// `stdin`, its standard output and error one pipe the front reads, and
/// `names`, the channel on which it asks for names, as the descriptor 3.
pub async fn start_worker(
    spawner: &Arc<Spawner>,
    args: Vec<String>,
    env: Vec<(String, String)>,
    stdin: std::os::fd::OwnedFd,
    names: std::os::fd::OwnedFd,
) -> std::io::Result<Worker> {
    let spawner = spawner.clone();
    let (pipe_read, pipe_write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    let child = tokio::task::spawn_blocking(move || {
        use std::os::fd::AsFd;
        spawner.spawn(
            0,
            &args,
            &env,
            &[
                stdin.as_fd(),
                pipe_write.as_fd(),
                pipe_write.as_fd(),
                names.as_fd(),
            ],
        )
    })
    .await
    .map_err(std::io::Error::other)??;
    let pid = child.pid();
    Ok(Worker {
        pid,
        stderr: Some(tokio::net::unix::pipe::Receiver::from_owned_fd(pipe_read)?),
        life: tokio::net::unix::pipe::Receiver::from_owned_fd(child.into_life())?,
    })
}

struct Conn {
    stream: UnixStream,
    /// The worker: dropped with the connection, it ends it
    worker: Option<Worker>,
    /// The last bytes the worker wrote to its standard error
    tail: Arc<Mutex<Vec<u8>>>,
    /// The kills for memory of the cgroup before the worker was put in it
    kills_before: u64,
}

pub struct Pool {
    /// What starts the workers
    spawner: Arc<Spawner>,
    endpoints: Vec<EndpointSpec>,
    /// The TCP ports its workers may connect to ([`connect_ports`])
    ports: Vec<u16>,
    /// For each brokered endpoint, the pool of the one worker that has its
    /// credentials and answers the `Authorization` of its requests.
    auth: Vec<Option<Arc<Pool>>>,
    idle: Mutex<Vec<Conn>>,
    slots: Arc<Semaphore>,
    max_workers: usize,
    /// Where the registry sent the blobs its workers asked for (the signed
    /// URLs of its CDN), told to the workers that ask for them next
    redirects: Mutex<HashMap<Digest, (String, std::time::Instant)>>,
    /// Workers being made ready (a request that finds no slot free takes
    /// one of them once it is idle)
    warming: std::sync::atomic::AtomicUsize,
    /// Where the workers run, if they are confined
    confinement: std::sync::OnceLock<super::cgroup::Confinement>,
    /// The user's hints about the registries, kept as the workers find out
    hints: std::sync::OnceLock<Arc<velarx_registry::hints::HintStore>>,
    /// Where the lines for the user go (the log when there is none)
    warning: std::sync::OnceLock<Warn>,
    warned: Mutex<Vec<String>>,
    /// The CDN host told to the hints (once)
    cdn_told: Mutex<HashMap<usize, String>>,
    /// The schemes the insecure endpoints were found to speak, told to the
    /// next workers
    schemes: Mutex<HashMap<String, velarx_registry::target::Scheme>>,
    /// Whether the workers must have a user namespace (`[pull]
    /// require_userns`)
    require_userns: std::sync::atomic::AtomicBool,
    /// What resolves the names the workers ask for (this process' own
    /// resolver if none was given)
    names: std::sync::OnceLock<Arc<dyn Resolver>>,
}

/// The TCP ports of HTTPS and HTTP: a registry named without a port, the
/// hosts it sends the client to (its token service, the CDN of its blobs).
const WEB_PORTS: [u16; 2] = [443, 80];

/// The port `authority` (`host:port`, `[v6]:port`, `host`) names.
pub(crate) fn authority_port(authority: &str) -> Option<u16> {
    let rest = match authority.strip_prefix('[') {
        Some(v6) => v6.split_once(']')?.1,
        None => match authority.rsplit_once(':') {
            Some((host, _)) if host.contains(':') => return None,
            Some(_) => &authority[authority.rfind(':')?..],
            None => return None,
        },
    };
    rest.strip_prefix(':')?.parse().ok().filter(|p| *p != 0)
}

/// The ports of the proxies of the environment the workers get
/// ([`ENVIRONMENT`]).
fn proxy_ports() -> Vec<u16> {
    ENVIRONMENT
        .iter()
        .filter(|n| {
            n.to_ascii_lowercase().ends_with("_proxy") && !n.eq_ignore_ascii_case("no_proxy")
        })
        .filter_map(|n| std::env::var(n).ok())
        .filter(|v| !v.is_empty())
        .filter_map(|v| {
            let url = if v.contains("://") {
                v
            } else {
                format!("http://{v}")
            };
            reqwest::Url::parse(&url).ok()?.port_or_known_default()
        })
        .collect()
}

/// The ports the workers of `endpoints` are sent to: of each endpoint and
/// of what its hint names (the token service, the host of its blobs).
fn endpoint_ports(endpoints: &[EndpointSpec]) -> impl Iterator<Item = u16> + '_ {
    endpoints.iter().flat_map(|e| {
        let hint = e.hint.as_ref();
        let realm = hint.and_then(|h| match &h.auth {
            velarx_registry::hints::Auth::Bearer { realm, .. } => {
                reqwest::Url::parse(realm).ok()?.port_or_known_default()
            }
            _ => None,
        });
        let cdn = hint.and_then(|h| authority_port(h.cdn.as_deref()?));
        [authority_port(&e.host), realm, cdn].into_iter().flatten()
    })
}

/// The TCP ports a worker for `endpoints` may connect to (its Landlock
/// rules): 443 and 80, the ports the endpoints and their hints name, those
/// of the proxies.  A registry that sends the client to a host on
/// another port (a token service, a CDN) the hints do not know is not
/// reached.
pub fn connect_ports(endpoints: &[EndpointSpec]) -> Vec<u16> {
    let mut ports: Vec<u16> = WEB_PORTS.to_vec();
    ports.extend(endpoint_ports(endpoints));
    ports.extend(proxy_ports());
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Takes a line for the person who pulls.
pub type Warn = Arc<dyn Fn(String) + Send + Sync>;

/// Lines of workers shown for a pool: a worker is not trusted to fill a
/// terminal.
const WARNINGS_SHOWN: usize = 4;

/// How long the address a worker was sent to for a blob is given to the
/// others (the signed URLs of the CDNs of registries last minutes), and how
/// many blobs are kept.
const REDIRECT_KEPT: Duration = Duration::from_secs(120);
const REDIRECTS_KEPT: usize = 64;

/// Whether a worker without a user namespace was already reported.
static NO_USERNS_TOLD: std::sync::Once = std::sync::Once::new();

fn worker_failed(msg: impl std::fmt::Display) -> ImageError {
    ImageError::Registry(format!("pull worker: {msg}"))
}

/// Keep the last bytes a worker writes to its standard error.
pub(crate) async fn keep_tail(
    mut stderr: impl tokio::io::AsyncRead + Unpin,
    tail: Arc<Mutex<Vec<u8>>>,
) {
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 1024];
    while let Ok(n @ 1..) = stderr.read(&mut buf).await {
        let mut t = tail.lock().unwrap();
        t.extend_from_slice(&buf[..n]);
        let excess = t.len().saturating_sub(MAX_MESSAGE);
        t.drain(..excess);
    }
}

/// A signal by its name and number.
pub(crate) fn signal_name(signal: i32) -> String {
    let name = match signal {
        libc::SIGABRT => "SIGABRT",
        libc::SIGKILL => "SIGKILL",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGBUS => "SIGBUS",
        libc::SIGTERM => "SIGTERM",
        libc::SIGSYS => "SIGSYS",
        _ => return format!("signal {signal}"),
    };
    format!("signal {signal} ({name})")
}

/// `e`, `who` (a worker, the job) that is gone, with how it ended and its
/// last words.
pub(crate) fn describe_stop(
    who: &str,
    e: ImageError,
    status: Result<std::io::Result<std::process::ExitStatus>, tokio::time::error::Elapsed>,
    tail: &Mutex<Vec<u8>>,
) -> ImageError {
    use std::os::unix::process::ExitStatusExt;
    let how = match status {
        Ok(Ok(s)) => match (s.code(), s.signal()) {
            (Some(c), _) => format!("exited with status {c}"),
            (_, Some(sig)) => format!("was killed by {}", signal_name(sig)),
            _ => s.to_string(),
        },
        Ok(Err(err)) => format!("could not be waited for: {err}"),
        Err(_) => "did not end".to_string(),
    };
    let said = printable(String::from_utf8_lossy(&tail.lock().unwrap()).trim());
    let ImageError::Registry(msg) = e else {
        return e;
    };
    if said.is_empty() {
        ImageError::Registry(format!("{msg} (the {who} {how})"))
    } else {
        ImageError::Registry(format!("{msg} (the {who} {how}: {said})"))
    }
}

fn lost(e: std::io::Error) -> ImageError {
    worker_failed(format!("lost: {e}"))
}

impl Pool {
    /// A pool of at most `max_workers` workers, started by `spawner`, talking
    /// to `endpoints`.
    pub fn new(
        spawner: Arc<Spawner>,
        endpoints: Vec<EndpointSpec>,
        max_workers: usize,
    ) -> Arc<Self> {
        let ports = connect_ports(&endpoints);
        Self::with_ports(spawner, endpoints, max_workers, ports)
    }

    /// A pool of one worker for the requests to `authority` (`host[:port]`
    /// of a URL or of a registry to log in to), which may connect to its
    /// port only (`default_port` when it names none), besides those of the
    /// proxies ([`connect_ports`]).
    pub fn for_authority(
        spawner: Arc<Spawner>,
        authority: &str,
        default_ports: &[u16],
    ) -> Arc<Self> {
        let mut ports = match authority_port(authority) {
            Some(p) => vec![p],
            None => default_ports.to_vec(),
        };
        ports.extend(proxy_ports());
        ports.sort_unstable();
        ports.dedup();
        Self::with_ports(spawner, Vec::new(), 1, ports)
    }

    fn with_ports(
        spawner: Arc<Spawner>,
        endpoints: Vec<EndpointSpec>,
        max_workers: usize,
        ports: Vec<u16>,
    ) -> Arc<Self> {
        Arc::new(Self {
            spawner,
            endpoints,
            ports,
            auth: Vec::new(),
            idle: Mutex::new(Vec::new()),
            slots: Arc::new(Semaphore::new(max_workers.max(1))),
            max_workers: max_workers.max(1),
            redirects: Mutex::default(),
            warming: std::sync::atomic::AtomicUsize::new(0),
            confinement: std::sync::OnceLock::new(),
            hints: std::sync::OnceLock::new(),
            warning: std::sync::OnceLock::new(),
            warned: Mutex::new(Vec::new()),
            cdn_told: Mutex::default(),
            schemes: Mutex::default(),
            require_userns: std::sync::atomic::AtomicBool::new(false),
            names: std::sync::OnceLock::new(),
        })
    }

    /// Resolve the names the workers of this pool, and of the pools that hold
    /// the credentials for it, ask for with `names` (a process that cannot
    /// resolve them itself has another do it).
    pub fn use_names(&self, names: Arc<dyn Resolver>) {
        let _ = self.names.set(names.clone());
        for pool in self.auth.iter().flatten() {
            pool.use_names(names.clone());
        }
    }

    /// Keep what the workers find out about the registries in `store`.
    pub fn set_hints(&self, store: Option<Arc<velarx_registry::hints::HintStore>>) {
        if let Some(store) = store {
            let _ = self.hints.set(store);
        }
        for pool in self.auth.iter().flatten() {
            pool.set_hints(self.hints.get().cloned());
        }
    }

    /// Give the lines the workers have for the user (a hint that did not
    /// work) to `warn`, once: a second call changes nothing.
    pub fn on_warning(&self, warn: Warn) {
        for pool in self.auth.iter().flatten() {
            pool.on_warning(warn.clone());
        }
        let _ = self.warning.set(warn);
    }

    /// What a worker found out: its warnings go to the user, once, and
    /// the hints of its registries are kept.
    fn absorb(&self, notices: velarx_registry::hints::Notices) {
        if notices.is_empty() {
            return;
        }
        if let Some(store) = self.hints.get() {
            let known: Vec<&str> = self.endpoints.iter().map(|e| e.host.as_str()).collect();
            store.apply(&notices.hints, &known);
        }
        for (host, scheme) in notices.schemes {
            if self.endpoints.iter().any(|e| e.insecure && e.host == host) {
                self.schemes.lock().unwrap().insert(host, scheme);
            }
        }
        for line in notices.warnings {
            let line = printable(line.trim());
            {
                let mut warned = self.warned.lock().unwrap();
                if warned.len() >= WARNINGS_SHOWN || warned.contains(&line) {
                    continue;
                }
                warned.push(line.clone());
            }
            match self.warning.get() {
                Some(warn) => warn(line),
                None => tracing::warn!("{line}"),
            }
        }
    }

    async fn spawn(&self) -> ImageResult<Conn> {
        let spawned_at = std::time::Instant::now();
        let (mine, theirs) = std::os::unix::net::UnixStream::pair().map_err(lost)?;
        mine.set_nonblocking(true).map_err(lost)?;
        let theirs: OwnedFd = theirs.into();
        // (the names the worker asks for are resolved here, for as long as
        // it holds its end)
        let (names, names_theirs) = std::os::unix::net::UnixStream::pair().map_err(lost)?;
        names.set_nonblocking(true).map_err(lost)?;
        let names = UnixStream::from_std(names).map_err(lost)?;
        let resolver = self
            .names
            .get()
            .cloned()
            .unwrap_or_else(|| Arc::new(super::runner::System));
        tokio::spawn(async move {
            let served = super::resolve::serve(names, resolver, super::resolve::MAX_IN_FLIGHT);
            if let Err(e) = served.await {
                debug!("The names of a pull worker are no longer resolved: {e}");
            }
        });
        if let Some(c) = self.confinement.get() {
            c.check().await.map_err(worker_failed)?;
        }
        let mut args = vec!["pull-worker".to_string()];
        if self
            .require_userns
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            args.push("--require-userns".into());
        }
        args.extend(
            self.ports
                .iter()
                .flat_map(|p| ["--connect-port".to_string(), p.to_string()]),
        );
        let env = ENVIRONMENT
            .iter()
            .filter_map(|name| {
                let value = std::env::var(name).ok()?;
                Some(((*name).to_string(), value))
            })
            .collect();
        let mut worker = start_worker(&self.spawner, args, env, theirs, names_theirs.into())
            .await
            .map_err(|e| worker_failed(e.to_string()))?;
        let stderr_tail = Arc::new(Mutex::new(Vec::new()));
        if let Some(stderr) = worker.take_stderr() {
            tokio::spawn(keep_tail(stderr, stderr_tail.clone()));
        }
        let kills_before = self
            .confinement
            .get()
            .map_or(0, super::cgroup::Confinement::memory_kills);
        if let Some(c) = self.confinement.get() {
            let pid = worker.pid;
            // (the worker has not read anything yet: it waits for a request)
            if let Err(e) = c.adopt(pid).await {
                if c.required() {
                    return Err(worker_failed(format!("cannot put it in its cgroup: {e}")));
                }
                debug!("Cannot put the pull worker {pid} in a cgroup: {e}");
            }
        }
        let mut stream = UnixStream::from_std(mine).map_err(lost)?;
        // Frames of a few hundred KiB: the default buffers (208 KiB) make a
        // chunk wait for the other side several times.
        for set in [
            rustix::net::sockopt::set_socket_send_buffer_size,
            rustix::net::sockopt::set_socket_recv_buffer_size,
        ] {
            let _ = set(&stream, SOCKET_BUFFER);
        }

        // A worker for URLs: no registry to greet; a worker that could not
        // confine itself answers the first request with why.
        if self.endpoints.is_empty() {
            return Ok(Conn {
                stream,
                worker: Some(worker),
                tail: stderr_tail,
                kills_before,
            });
        }
        let hello = Request::Hello {
            endpoints: self.endpoints_for_a_worker(),
        };
        let started = async {
            write_frame(
                &mut stream,
                Kind::Request,
                &json(&hello).map_err(lost)?,
                &[],
            )
            .await
            .map_err(lost)?;
            let header = read_header(&mut stream, 0).await.map_err(lost)?;
            let body = read_bytes(&mut stream, header.json_len)
                .await
                .map_err(lost)?;
            match header.kind {
                Kind::Reply => {
                    let r: super::proto::HelloReply = parse(&body).map_err(lost)?;
                    if !r.userns {
                        NO_USERNS_TOLD.call_once(|| {
                            tracing::warn!(
                                "the pull workers run without a user namespace of their own \
                                 (the kernel refuses one): Landlock, seccomp, no capability \
                                 only; [pull] require_userns = true refuses that"
                            )
                        });
                    }
                    Ok(())
                }
                Kind::Error => Err(error_of(&body)),
                _ => Err(worker_failed("unexpected answer to hello")),
            }
        };
        let started = tokio::time::timeout(START_TIMEOUT, started)
            .await
            .map_err(|_| worker_failed("it did not start"))
            .and_then(|r| r);
        if let Err(e) = started {
            // (a worker that stopped before it answered: how, and what it
            // said, which a "connection reset" does not)
            let status = tokio::time::timeout(WAIT_TIMEOUT, worker.wait()).await;
            return Err(describe_stop("worker", e, status, &stderr_tail));
        }
        debug!("Pull worker started in {:?}", spawned_at.elapsed());
        Ok(Conn {
            stream,
            worker: Some(worker),
            tail: stderr_tail,
            kills_before,
        })
    }

    /// Have the workers of this pool, and of the pools that hold the
    /// credentials for it, refuse to run without a user namespace of their
    /// own.
    pub fn require_userns(&self, required: bool) {
        self.require_userns
            .store(required, std::sync::atomic::Ordering::Relaxed);
        for pool in self.auth.iter().flatten() {
            pool.require_userns(required);
        }
    }

    /// Run the workers of this pool, and of the pools that hold the
    /// credentials for it, under the limits of `config`.
    pub fn confine(self: &Arc<Self>, config: &velarx_config::PullConfig) {
        self.require_userns(config.require_userns);
        let _ = self
            .confinement
            .set(super::cgroup::Confinement::new(config));
        for pool in self.auth.iter().flatten() {
            pool.confine(config);
        }
    }

    /// Have `n` workers (at most the pool's) idle or getting ready in the
    /// background: each connects to the registry and takes its token, so
    /// that the requests that follow find workers that have.
    pub fn warm(self: &Arc<Self>, n: usize) {
        use std::sync::atomic::Ordering::Relaxed;
        let have = self.idle.lock().unwrap().len() + self.warming.load(Relaxed);
        for _ in have..n.min(self.max_workers) {
            self.warming.fetch_add(1, Relaxed);
            let pool = self.clone();
            tokio::spawn(async move {
                if let Err(e) = pool.warm_one().await {
                    debug!("Cannot warm a pull worker: {e}");
                }
                pool.warming.fetch_sub(1, Relaxed);
            });
        }
    }

    /// Where the blobs of the registry come from, as far as it is known:
    /// where the registry sent a blob in this pull, else the hint of the
    /// registry (the scheme and `host[:port]`).  Never the registry itself.
    fn cdn(&self) -> Option<(String, String)> {
        let registry = self.endpoints.first().filter(|e| e.hints)?;
        let told = self
            .redirects
            .lock()
            .unwrap()
            .values()
            .filter(|(_, at)| at.elapsed() < REDIRECT_KEPT)
            .max_by_key(|(_, at)| *at)
            .and_then(|(url, _)| reqwest::Url::parse(url).ok())
            .filter(|url| matches!(url.scheme(), "https" | "http"))
            .and_then(|url| Some((url.scheme().to_string(), authority_of(&url)?)))
            .filter(|(_, cdn)| *cdn != registry.host);
        told.or_else(|| {
            let hint = registry.hint.as_ref()?;
            Some((hint.transport.clone(), hint.cdn.clone()?))
        })
        .filter(|(_, cdn)| *cdn != registry.host)
    }

    /// The endpoints a worker is told about: the hint of the first has the
    /// CDN this pool knows, the insecure ones the scheme a worker found.
    fn endpoints_for_a_worker(&self) -> Vec<EndpointSpec> {
        let mut endpoints = self.endpoints.clone();
        let schemes = self.schemes.lock().unwrap();
        for e in &mut endpoints {
            e.scheme = schemes.get(&e.host).copied();
        }
        drop(schemes);
        if let (Some(first), Some((scheme, cdn))) = (endpoints.first_mut(), self.cdn()) {
            let hint = first
                .hint
                .get_or_insert_with(|| velarx_registry::hints::Hint {
                    transport: if first.insecure {
                        scheme
                    } else {
                        "https".into()
                    },
                    auth: velarx_registry::hints::Auth::None,
                    cdn: None,
                });
            hint.cdn = Some(cdn);
        }
        endpoints
    }

    /// A worker of its own, ready for requests: it goes to the idle ones
    /// while it still holds its slot, so that a request waiting for a slot
    /// finds it.
    async fn warm_one(self: &Arc<Self>) -> ImageResult<()> {
        let slot = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| worker_failed("shut down"))?;
        // a worker that went idle while this one waited for its slot is
        // ready already: no more processes than slots
        if !self.idle.lock().unwrap().is_empty() {
            return Ok(());
        }
        let conn = self.spawn().await?;
        let mut x = self.start(conn, slot, (&Request::Warm, None), 0, 0).await?;
        match x.next().await {
            Ok(Event::Reply(_)) => Ok(()),
            Ok(Event::Data { .. }) => Err(worker_failed("data for a warm-up")),
            Err(f) => Err(f.into()),
        }
    }

    /// A pool whose workers hold no credentials: `endpoints` has the
    /// brokered endpoints without them, `auth` the spec with its
    /// credentials of each brokered endpoint, given to a worker of its own
    /// that answers the `Authorization` the others ask the daemon for
    /// ([`RegistryClient::brokered_specs`]).
    ///
    /// [`RegistryClient::brokered_specs`]: velarx_registry::client::RegistryClient::brokered_specs
    pub fn new_brokered(
        spawner: Arc<Spawner>,
        endpoints: Vec<EndpointSpec>,
        auth: Vec<Option<EndpointSpec>>,
        max_workers: usize,
    ) -> Arc<Self> {
        let auth = auth
            .into_iter()
            .map(|spec| spec.map(|s| Pool::new(spawner.clone(), vec![s], 1)))
            .collect();
        let ports = connect_ports(&endpoints);
        Arc::new(Self {
            spawner,
            endpoints,
            ports,
            auth,
            idle: Mutex::new(Vec::new()),
            slots: Arc::new(Semaphore::new(max_workers.max(1))),
            max_workers: max_workers.max(1),
            redirects: Mutex::default(),
            warming: std::sync::atomic::AtomicUsize::new(0),
            confinement: std::sync::OnceLock::new(),
            hints: std::sync::OnceLock::new(),
            warning: std::sync::OnceLock::new(),
            warned: Mutex::new(Vec::new()),
            cdn_told: Mutex::default(),
            schemes: Mutex::default(),
            require_userns: std::sync::atomic::AtomicBool::new(false),
            names: std::sync::OnceLock::new(),
        })
    }

    /// The `Authorization` of the endpoint of this pool (a pool of the
    /// worker that has its credentials).
    pub async fn authorize(
        self: &Arc<Self>,
        actions: &str,
        refresh: bool,
    ) -> ImageResult<super::proto::AuthReply> {
        let request = Request::Authorize {
            actions: actions.to_string(),
            refresh,
        };
        let mut x = self.begin(&request, 0, 0).await?;
        match x.next().await? {
            Event::Reply(body) => parse(&body).map_err(lost),
            Event::Data { .. } => Err(worker_failed("data for an authorization")),
        }
    }

    /// The answer to a worker's question about the `Authorization` of a
    /// brokered endpoint.  The worker is not trusted: an endpoint that is
    /// not brokered, and anything but pulling, are refused.
    fn answer_auth<'a>(
        self: &'a Arc<Self>,
        body: &'a [u8],
    ) -> futures::future::BoxFuture<'a, super::proto::AuthReply> {
        // boxed and Send by its type: the worker of the credentials is
        // another pool, but the compiler sees a cycle
        Box::pin(async move {
            let refused = |why: &str| super::proto::AuthReply {
                header: None,
                error: Some(why.to_string()),
                ..Default::default()
            };
            let Ok(ask) = parse::<super::proto::AuthRequest>(body) else {
                return refused("invalid authorization request");
            };
            if ask.actions != "pull" {
                return refused("only pulls are brokered");
            }
            let Some(Some(auth)) = self.auth.get(ask.endpoint) else {
                return refused("not a brokered endpoint");
            };
            match auth.authorize(&ask.actions, ask.refresh).await {
                Ok(mut r) => {
                    // (taken in by the pool of that worker)
                    r.notices = Default::default();
                    r
                }
                Err(e) => refused(&e.to_string()),
            }
        })
    }

    /// Send a request to a worker.  At most `budget` bytes of data are
    /// accepted for it, in frames of at most `max_frame`.
    pub async fn begin(
        self: &Arc<Self>,
        request: &Request,
        max_frame: usize,
        budget: u64,
    ) -> ImageResult<Exchange> {
        self.begin_with(request, None, max_frame, budget).await
    }

    /// [`begin`](Self::begin) with a descriptor that goes with the request
    /// (the file a request that says `file` is about).
    pub async fn begin_with(
        self: &Arc<Self>,
        request: &Request,
        file: Option<std::os::fd::BorrowedFd<'_>>,
        max_frame: usize,
        budget: u64,
    ) -> ImageResult<Exchange> {
        let slot = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| worker_failed("shut down"))?;
        let idle = self.idle.lock().unwrap().pop();
        let conn = match idle {
            Some(c) => c,
            None => self.spawn().await?,
        };
        self.start(conn, slot, (request, file), max_frame, budget)
            .await
    }

    /// Where a worker was sent for the blob `digest` not long ago.
    fn redirect_for(&self, digest: &Digest) -> Option<String> {
        let redirects = self.redirects.lock().unwrap();
        let (url, at) = redirects.get(digest)?;
        (at.elapsed() < REDIRECT_KEPT).then(|| url.clone())
    }

    /// The endpoint `endpoint` (a mirror may be one of the fallbacks) sent a
    /// blob to `url`: its host is kept as the CDN of that endpoint when it is
    /// another host.
    fn note_cdn(&self, endpoint: usize, url: &str) {
        let (Some(store), Some(registry)) = (self.hints.get(), self.endpoints.get(endpoint)) else {
            return;
        };
        let Ok(url) = reqwest::Url::parse(url) else {
            return;
        };
        let (Some(host), true) = (url.host_str(), matches!(url.scheme(), "https" | "http")) else {
            return;
        };
        let cdn = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        if cdn == registry.host {
            return;
        }
        let mut told = self.cdn_told.lock().unwrap();
        if told.get(&endpoint) == Some(&cdn) {
            return;
        }
        let transport = if registry.insecure {
            url.scheme()
        } else {
            "https"
        };
        store.learn_cdn(&registry.host, transport, &cdn);
        told.insert(endpoint, cdn);
    }

    /// A worker was sent to `url` for the blob `digest` by the endpoint
    /// number `endpoint`.  Only what the first endpoint sent is where the
    /// next workers connect in advance and go for that blob.
    fn note_redirect(self: &Arc<Self>, digest: &Digest, url: String, endpoint: usize) {
        self.note_cdn(endpoint, &url);
        if endpoint != 0 {
            return;
        }
        {
            let mut redirects = self.redirects.lock().unwrap();
            if redirects.len() >= REDIRECTS_KEPT && !redirects.contains_key(digest) {
                redirects.retain(|_, (_, at)| at.elapsed() < REDIRECT_KEPT);
                if redirects.len() >= REDIRECTS_KEPT {
                    return;
                }
            }
            redirects.insert(*digest, (url.clone(), std::time::Instant::now()));
        }
    }

    /// Send the request on `conn`, which holds `slot` until the exchange
    /// ends.
    async fn start(
        self: &Arc<Self>,
        mut conn: Conn,
        slot: OwnedSemaphorePermit,
        (request, file): (&Request, Option<std::os::fd::BorrowedFd<'_>>),
        max_frame: usize,
        budget: u64,
    ) -> ImageResult<Exchange> {
        let digest = blob_of(request).copied();
        if let Some(digest) = &digest {
            if let Some(url) = self.redirect_for(digest) {
                let told = Request::Redirect {
                    digest: *digest,
                    url,
                };
                write_frame(
                    &mut conn.stream,
                    Kind::Request,
                    &json(&told).map_err(lost)?,
                    &[],
                )
                .await
                .map_err(lost)?;
            }
        }
        let json = json(request).map_err(lost)?;
        match file {
            Some(fd) => write_frame_with_fd(&mut conn.stream, fd, Kind::Request, &json).await,
            None => write_frame(&mut conn.stream, Kind::Request, &json, &[]).await,
        }
        .map_err(lost)?;
        Ok(Exchange {
            digest,
            conn: Some(conn),
            pool: self.clone(),
            _slot: slot,
            max_frame,
            budget,
            clean: false,
            pending: None,
        })
    }
}

/// `host[:port]` of an address.
fn authority_of(url: &reqwest::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

/// The blob a request asks for.
fn blob_of(request: &Request) -> Option<&Digest> {
    match request {
        Request::Blob { digest, .. }
        | Request::Ranges { digest, .. }
        | Request::Chunks { digest, .. } => Some(digest),
        _ => None,
    }
}

/// A message of a worker, shown on a terminal.
fn error_of(body: &[u8]) -> ImageError {
    match parse::<ErrorMsg>(body) {
        Ok(e) => worker_failed(printable(
            &e.message.chars().take(MAX_MESSAGE).collect::<String>(),
        )),
        Err(_) => worker_failed("invalid error message"),
    }
}

/// What a worker answered.
pub enum Event {
    /// A frame of data; its payload is read with [`Exchange::payload`].
    Data { tag: usize, offset: u64, len: usize },
    /// The request is done.
    Reply(Vec<u8>),
}

/// Why an exchange failed.
pub enum Failure {
    /// The server refuses the ranges.
    Rejected(StatusCode),
    /// The server cannot give the ranges: the blob is asked whole.
    WholeBlob,
    /// What was asked is not there (404); an error for who needs it.
    Missing(ImageError),
    /// The body is longer than the limit of the request.
    TooLarge(ImageError),
    Error(ImageError),
}

impl From<ImageError> for Failure {
    fn from(e: ImageError) -> Self {
        Failure::Error(e)
    }
}

impl From<Failure> for RangesError {
    fn from(f: Failure) -> Self {
        match f {
            Failure::Rejected(s) => RangesError::Rejected(s.as_u16()),
            Failure::WholeBlob => RangesError::WholeBlob,
            Failure::Missing(e) | Failure::TooLarge(e) | Failure::Error(e) => RangesError::Other(e),
        }
    }
}

impl From<Failure> for ImageError {
    fn from(f: Failure) -> Self {
        match f {
            Failure::Rejected(s) => worker_failed(format!("the registry answered {s}")),
            Failure::WholeBlob => worker_failed("the registry cannot give the ranges of the blob"),
            Failure::Missing(e) | Failure::TooLarge(e) | Failure::Error(e) => e,
        }
    }
}

/// A request in progress.  The worker goes back to the pool when the
/// request ended with a reply or an error and the exchange is dropped; in
/// any other case it is killed.
pub struct Exchange {
    /// The blob the request is about, to learn where the registry sent it
    digest: Option<Digest>,
    conn: Option<Conn>,
    pool: Arc<Pool>,
    _slot: OwnedSemaphorePermit,
    max_frame: usize,
    budget: u64,
    clean: bool,
    /// The header of a data frame whose payload was not read.
    pending: Option<Header>,
}

impl Drop for Exchange {
    fn drop(&mut self) {
        if self.clean {
            if let Some(conn) = self.conn.take() {
                self.pool.idle.lock().unwrap().push(conn);
            }
        }
    }
}

impl Exchange {
    fn stream(&mut self) -> ImageResult<&mut UnixStream> {
        self.conn
            .as_mut()
            .map(|c| &mut c.stream)
            .ok_or_else(|| worker_failed("the exchange is over"))
    }

    pub async fn next(&mut self) -> Result<Event, Failure> {
        if self.pending.is_some() {
            return Err(worker_failed("a frame was not read").into());
        }
        let max_frame = self.max_frame;
        let (header, body) = loop {
            let stream = self.stream()?;
            let header = match tokio::time::timeout(MESSAGE_TIMEOUT, read_header(stream, max_frame))
                .await
                .map_err(|_| worker_failed("it does not answer"))?
            {
                Ok(h) => h,
                Err(e) => return Err(self.died(e).await.into()),
            };
            let stream = self.stream()?;
            let body =
                match tokio::time::timeout(PAYLOAD_TIMEOUT, read_bytes(stream, header.json_len))
                    .await
                    .map_err(|_| worker_failed("it stopped in the middle of a message"))?
                {
                    Ok(b) => b,
                    Err(e) => return Err(self.died(e).await.into()),
                };
            if header.kind != Kind::AuthRequest {
                break (header, body);
            }
            if header.payload_len != 0 {
                return Err(worker_failed("an authorization request with data").into());
            }
            // the worker waits for the answer before it goes on
            let reply = self.pool.answer_auth(&body).await;
            let stream = self.stream()?;
            write_frame(stream, Kind::AuthReply, &json(&reply).map_err(lost)?, &[])
                .await
                .map_err(lost)?;
        };
        match header.kind {
            Kind::Data => {
                let len = header.payload_len as u64;
                if len > self.budget {
                    return Err(worker_failed("it sent more than was asked").into());
                }
                self.budget -= len;
                self.pending = Some(header);
                Ok(Event::Data {
                    tag: header.tag,
                    offset: header.offset,
                    len: header.payload_len,
                })
            }
            Kind::Reply => {
                if header.payload_len != 0 {
                    return Err(worker_failed("a reply with data").into());
                }
                if let Ok(done) = parse::<Done>(&body) {
                    self.pool.absorb(done.notices);
                    if let (Some(digest), Some(url)) = (&self.digest, done.redirect) {
                        self.pool.note_redirect(digest, url, done.redirect_endpoint);
                    }
                }
                self.clean = true;
                Ok(Event::Reply(body))
            }
            Kind::Error => {
                self.clean = true;
                if let Ok(e) = parse::<ErrorMsg>(&body) {
                    self.pool.absorb(e.notices);
                }
                match parse::<ErrorMsg>(&body) {
                    Ok(ErrorMsg {
                        kind: ErrorKind::Rejected,
                        status: Some(s),
                        ..
                    }) => match StatusCode::from_u16(s) {
                        Ok(s) => Err(Failure::Rejected(s)),
                        Err(_) => Err(worker_failed("invalid status").into()),
                    },
                    Ok(ErrorMsg {
                        kind: ErrorKind::WholeBlob,
                        ..
                    }) => Err(Failure::WholeBlob),
                    Ok(ErrorMsg {
                        kind: ErrorKind::Missing,
                        ..
                    }) => Err(Failure::Missing(error_of(&body))),
                    Ok(ErrorMsg {
                        kind: ErrorKind::Unauthorized,
                        message,
                        ..
                    }) => Err(ImageError::Unauthorized(format!(
                        "pull worker: {}",
                        printable(&message.chars().take(MAX_MESSAGE).collect::<String>())
                    ))
                    .into()),
                    Ok(ErrorMsg {
                        kind: ErrorKind::Forbidden,
                        message,
                        ..
                    }) => Err(ImageError::Forbidden(format!(
                        "pull worker: {}",
                        printable(&message.chars().take(MAX_MESSAGE).collect::<String>())
                    ))
                    .into()),
                    Ok(ErrorMsg {
                        kind: ErrorKind::RegistryNotFound,
                        message,
                        ..
                    }) => Err(ImageError::RegistryNotFound(format!(
                        "pull worker: {}",
                        printable(&message.chars().take(MAX_MESSAGE).collect::<String>())
                    ))
                    .into()),
                    Ok(ErrorMsg {
                        kind: ErrorKind::TooLarge,
                        ..
                    }) => Err(Failure::TooLarge(error_of(&body))),
                    Ok(ErrorMsg {
                        kind: ErrorKind::Contradicted,
                        message,
                        ..
                    }) => Err(ImageError::Contradicted(format!(
                        "pull worker: {}",
                        printable(&message.chars().take(MAX_MESSAGE).collect::<String>())
                    ))
                    .into()),
                    _ => Err(error_of(&body).into()),
                }
            }
            Kind::Request | Kind::AuthReply | Kind::AuthRequest => {
                Err(worker_failed("it sent a request").into())
            }
        }
    }

    /// The payload of the data frame [`next`](Self::next) announced.
    pub async fn payload(&mut self) -> ImageResult<Vec<u8>> {
        let header = self
            .pending
            .take()
            .ok_or_else(|| worker_failed("no data to read"))?;
        match tokio::time::timeout(
            PAYLOAD_TIMEOUT,
            read_bytes(self.stream()?, header.payload_len),
        )
        .await
        .map_err(|_| worker_failed("it stopped in the middle of a message"))?
        {
            Ok(data) => Ok(data),
            Err(e) => Err(self.died(e).await),
        }
    }

    /// The error of a worker that cannot be read from: why it is gone, from
    /// the kernel's account of its cgroup, or how it ended and its last words.
    async fn died(&mut self, e: std::io::Error) -> ImageError {
        let lost = lost(e);
        // (the end of its socket: it is gone, or about to be)
        let Some(conn) = self.conn.as_mut() else {
            return lost;
        };
        let (tail, before) = (conn.tail.clone(), conn.kills_before);
        let Some(worker) = conn.worker.as_mut() else {
            return lost;
        };
        let status = tokio::time::timeout(WAIT_TIMEOUT, worker.wait()).await;
        if let Some(why) = self
            .pool
            .confinement
            .get()
            .and_then(|c| c.killed_for_memory(before))
        {
            return worker_failed(why);
        }
        describe_stop("worker", lost, status, &tail)
    }
}

impl Pool {
    /// `url`, None when the server answers 404.
    pub async fn url_opt(
        self: &Arc<Self>,
        url: &str,
        limit: u64,
        min_speed: velarx_registry::speed::Speed,
        sink: &mut (dyn FnMut(&[u8]) -> std::io::Result<()> + Send),
    ) -> Result<Option<UrlTrailer>, UrlError> {
        let request = Request::Url {
            url: url.to_string(),
            limit,
            min_speed,
        };
        let mut x = self
            .begin(&request, velarx_content::pull::stream::FRAME_SIZE, limit)
            .await?;
        let mut at = 0u64;
        loop {
            let event = match x.next().await {
                Ok(e) => e,
                Err(Failure::Missing(_)) => return Ok(None),
                Err(Failure::TooLarge(_)) => return Err(UrlError::TooLarge(limit)),
                Err(e) => return Err(ImageError::from(e).into()),
            };
            match event {
                Event::Data { tag, offset, len } => {
                    if tag != 0 || offset != at {
                        return Err(worker_failed("data out of order").into());
                    }
                    let data = x.payload().await?;
                    sink(&data).map_err(ImageError::Io)?;
                    at += len as u64;
                }
                Event::Reply(body) => {
                    let t: UrlTrailer = parse(&body).map_err(lost)?;
                    if t.size != at {
                        return Err(worker_failed("the size does not match the data").into());
                    }
                    return Ok(Some(t));
                }
            }
        }
    }

    /// The `tags/list` answer of the repository of the pool.
    pub async fn tags(self: &Arc<Self>, max: u64) -> ImageResult<Bytes> {
        let mut x = self.begin(&Request::Tags, max as usize, max).await?;
        Ok(Bytes::from(x.one_blob().await?))
    }

    /// A search of the registry of the pool: whether the body is the v1
    /// answer, and the body.
    pub async fn search(
        self: &Arc<Self>,
        needle: &str,
        n: usize,
        docker: bool,
        limit: u64,
    ) -> ImageResult<(bool, Bytes)> {
        let request = Request::Search {
            needle: needle.to_string(),
            n,
            docker,
            limit,
        };
        let mut x = self.begin(&request, limit as usize, limit).await?;
        let mut body = None;
        loop {
            match x.next().await? {
                Event::Data {
                    tag: 0, offset: 0, ..
                } if body.is_none() => {
                    body = Some(x.payload().await?);
                }
                Event::Data { .. } => return Err(worker_failed("more than one answer")),
                Event::Reply(r) => {
                    let r: super::proto::SearchReply = parse(&r).map_err(lost)?;
                    let body = body.ok_or_else(|| worker_failed("no answer"))?;
                    return Ok((r.v1, Bytes::from(body)));
                }
            }
        }
    }

    /// Send REQUEST and then SIZE bytes that NEXT gives (from the offset it
    /// is given, at most MAX_PIECE bytes a call), and the worker's reply.
    /// The worker may answer before the bytes ended only with an error;
    /// it is never reused after an error here (it ends).
    async fn push_exchange(
        self: &Arc<Self>,
        request: &Request,
        size: u64,
        max_piece: usize,
        next: &mut (dyn FnMut(u64) -> futures::future::BoxFuture<'static, std::io::Result<Bytes>>
                  + Send),
    ) -> ImageResult<Vec<u8>> {
        let mut x = self.begin(request, 0, 0).await?;
        let (answer, all_sent) = {
            let stream = x.stream()?;
            let (mut rd, mut wr) = stream.split();
            let send = async {
                let mut at = 0u64;
                while at < size {
                    let piece = next(at).await.map_err(ImageError::Io)?;
                    if piece.is_empty() || piece.len() > max_piece || at + piece.len() as u64 > size
                    {
                        return Err(ImageError::Layer(format!(
                            "the data to push is not the {size} bytes announced"
                        )));
                    }
                    write_data(&mut wr, Kind::Data, &[], 0, at, &piece)
                        .await
                        .map_err(lost)?;
                    at += piece.len() as u64;
                }
                Ok::<(), ImageError>(())
            };
            let recv = async {
                let header = read_header(&mut rd, 0).await.map_err(lost)?;
                let body =
                    tokio::time::timeout(PAYLOAD_TIMEOUT, read_bytes(&mut rd, header.json_len))
                        .await
                        .map_err(|_| worker_failed("it stopped in the middle of a message"))?
                        .map_err(lost)?;
                Ok::<_, ImageError>((header.kind, body))
            };
            tokio::pin!(send, recv);
            tokio::select! {
                r = &mut recv => (r, false),
                s = &mut send => {
                    if let Err(e) = s {
                        // A worker that failed says why before it goes.
                        match tokio::time::timeout(std::time::Duration::from_secs(5), &mut recv)
                            .await
                        {
                            Ok(Ok(answer)) => (Ok(answer), false),
                            _ => return Err(e),
                        }
                    } else {
                    let r = tokio::time::timeout(MESSAGE_TIMEOUT, &mut recv)
                        .await
                        .map_err(|_| worker_failed("it does not answer"))?;
                    (r, true)
                    }
                }
            }
        };
        match answer? {
            (Kind::Reply, body) if all_sent => {
                x.clean = true;
                Ok(body)
            }
            (Kind::Reply, _) => Err(worker_failed("it answered before the data ended")),
            (Kind::Error, body) => Err(error_of(&body)),
            _ => Err(worker_failed("unexpected answer to a push")),
        }
    }

    /// Whether the registry of the pool has the blob DIGEST.
    pub async fn blob_exists(self: &Arc<Self>, digest: &Digest) -> ImageResult<bool> {
        let request = Request::BlobExists { digest: *digest };
        let mut x = self.begin(&request, 0, 0).await?;
        match x.next().await? {
            Event::Reply(body) => Ok(parse::<super::proto::ExistsReply>(&body)
                .map_err(lost)?
                .exists),
            Event::Data { .. } => Err(worker_failed("data for a blob check")),
        }
    }

    /// Mount the blob DIGEST from the repository FROM of the registry:
    /// false when the registry did not.
    pub async fn mount(self: &Arc<Self>, digest: &Digest, from: &str) -> ImageResult<bool> {
        let request = Request::Mount {
            digest: *digest,
            from: from.to_string(),
        };
        let mut x = self.begin(&request, 0, 0).await?;
        match x.next().await? {
            Event::Reply(body) => Ok(parse::<super::proto::MountReply>(&body)
                .map_err(lost)?
                .mounted),
            Event::Data { .. } => Err(worker_failed("data for a mount")),
        }
    }

    /// Upload the blob DIGEST of SIZE bytes that NEXT gives, in pieces of
    /// CHUNK bytes to the registry.
    pub async fn upload(
        self: &Arc<Self>,
        digest: &Digest,
        size: u64,
        chunk: u64,
        next: &mut (dyn FnMut(u64) -> futures::future::BoxFuture<'static, std::io::Result<Bytes>>
                  + Send),
    ) -> ImageResult<()> {
        let request = Request::Upload {
            digest: *digest,
            size,
            chunk: chunk.clamp(1, super::proto::MAX_UPLOAD_CHUNK),
        };
        self.push_exchange(
            &request,
            size,
            velarx_content::pull::stream::FRAME_SIZE,
            next,
        )
        .await?;
        Ok(())
    }

    /// Put the manifest BODY as REFERENCE: the digest of what was put,
    /// checked to be the one of BODY.
    pub async fn put_manifest(
        self: &Arc<Self>,
        reference: &str,
        media_type: &str,
        body: Bytes,
        alg: Algorithm,
    ) -> ImageResult<Digest> {
        let size = body.len() as u64;
        if size > super::proto::MAX_PUT_MANIFEST {
            return Err(ImageError::Manifest(format!(
                "a manifest of {size} bytes is too large to push"
            )));
        }
        let request = Request::PutManifest {
            reference: reference.to_string(),
            media_type: media_type.to_string(),
            size,
            alg,
        };
        let mut once = Some(body.clone());
        let mut next = move |_at: u64| {
            let piece = once.take().unwrap_or_default();
            Box::pin(async move { Ok(piece) })
                as futures::future::BoxFuture<'static, std::io::Result<Bytes>>
        };
        let reply = self
            .push_exchange(&request, size, size as usize, &mut next)
            .await?;
        let r: super::proto::ManifestReply = parse(&reply).map_err(lost)?;
        let ours = Digest::of(alg, &body);
        if !(r.digest == ours || (r.digest.alg() != alg && r.digest.verify(&body))) {
            return Err(ImageError::DigestMismatch {
                expected: ours.to_string(),
                actual: r.digest.to_string(),
            });
        }
        Ok(ours)
    }

    /// The blob DIGEST of SIZE bytes as the registry has it, given to SINK
    /// in order.
    pub async fn blob(
        self: &Arc<Self>,
        digest: &Digest,
        size: u64,
        sink: &mut (dyn FnMut(&[u8]) -> std::io::Result<()> + Send),
    ) -> ImageResult<()> {
        let request = Request::Blob {
            digest: *digest,
            size,
        };
        let mut x = self
            .begin(&request, velarx_content::pull::stream::FRAME_SIZE, size)
            .await?;
        let mut at = 0u64;
        loop {
            match x.next().await? {
                Event::Data { tag, offset, len } => {
                    if tag != 0 || offset != at {
                        return Err(worker_failed("data out of order"));
                    }
                    let data = x.payload().await?;
                    sink(&data).map_err(ImageError::Io)?;
                    at += len as u64;
                }
                Event::Reply(_) if at == size => return Ok(()),
                Event::Reply(_) => return Err(worker_failed("the blob is short")),
            }
        }
    }

    /// Whether the registry HOST accepts the credentials of ACCESS: why
    /// not (`Unauthorized`: it refused them) if not.
    pub async fn login(
        self: &Arc<Self>,
        host: &str,
        access: &velarx_registry::auth::RegistryAccess,
        tls_verify: bool,
    ) -> ImageResult<()> {
        let request = Request::Login {
            host: host.to_string(),
            tls_verify,
            access: access.clone(),
        };
        let mut x = self.begin(&request, 0, 0).await?;
        match x.next().await? {
            Event::Reply(body) => {
                let r: super::proto::LoginReply = parse(&body).map_err(lost)?;
                match r.failure {
                    None => Ok(()),
                    Some(why) if r.unauthorized => Err(ImageError::Unauthorized(why)),
                    Some(why) => Err(ImageError::Registry(why)),
                }
            }
            Event::Data { .. } => Err(worker_failed("data for a login")),
        }
    }

    /// A manifest by tag or digest, and the digest of its bytes.
    pub async fn manifest(
        self: &Arc<Self>,
        reference: &str,
        max: u64,
    ) -> ImageResult<(Bytes, Digest)> {
        let mut x = self
            .begin(
                &Request::Manifest {
                    reference: reference.to_string(),
                },
                max as usize,
                max,
            )
            .await?;
        let body = x.one_blob().await?;
        let digest = velarx_registry::target::manifest_digest(reference, &body)?;
        Ok((Bytes::from(body), digest))
    }

    /// `manifest`, None when the registry does not have it (404).
    pub async fn manifest_opt(
        self: &Arc<Self>,
        reference: &str,
        max: u64,
    ) -> ImageResult<Option<(Bytes, Digest)>> {
        let mut x = self
            .begin(
                &Request::Manifest {
                    reference: reference.to_string(),
                },
                max as usize,
                max,
            )
            .await?;
        let mut body = None;
        loop {
            let event = match x.next().await {
                Ok(e) => e,
                Err(Failure::Missing(_)) => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            match event {
                Event::Data { .. } if body.is_some() => {
                    return Err(worker_failed("more data than expected"))
                }
                Event::Data { .. } => body = Some(x.payload().await?),
                Event::Reply(_) => break,
            }
        }
        let body = body.ok_or_else(|| worker_failed("it sent nothing"))?;
        let digest = velarx_registry::target::manifest_digest(reference, &body)?;
        Ok(Some((Bytes::from(body), digest)))
    }

    /// Ranges of a blob, handed to `sink` as they arrive.
    pub async fn ranges(
        self: &Arc<Self>,
        digest: &Digest,
        ranges: &[Range<u64>],
        file: Option<&std::fs::File>,
        sink: &mut PieceSink<'_>,
    ) -> Result<(), RangesError> {
        let budget: u64 = ranges.iter().map(|r| r.end - r.start).sum();
        let request = Request::Ranges {
            digest: *digest,
            ranges: ranges.iter().map(|r| (r.start, r.end)).collect(),
            file: file.is_some(),
        };
        let mut x = self
            .begin_with(
                &request,
                file.map(AsFd::as_fd),
                super::proto::MAX_JSON,
                budget,
            )
            .await
            .map_err(RangesError::Other)?;
        loop {
            match x.next().await? {
                Event::Data { tag, offset, len } => {
                    let range = ranges.get(tag).ok_or_else(|| {
                        RangesError::Other(worker_failed("data for a range that was not asked"))
                    })?;
                    let end = offset.checked_add(len as u64);
                    if offset < range.start || end.is_none_or(|e| e > range.end) {
                        return Err(RangesError::Other(worker_failed(
                            "data out of the range asked",
                        )));
                    }
                    let data = x.payload().await?;
                    sink(Piece {
                        range: tag,
                        offset,
                        data: Bytes::from(data),
                    })
                    .await?;
                }
                Event::Reply(_) => return Ok(()),
            }
        }
    }

    /// The chunks of ranges of a blob, decompressed, as they come.
    pub async fn chunks(
        self: &Arc<Self>,
        digest: &Digest,
        ranges: &[Range<u64>],
        members: &[Vec<ChunkSpec>],
        max_chunk: usize,
        file: Option<&std::fs::File>,
    ) -> ImageResult<ChunkStream> {
        let budget: u64 = members.iter().flatten().map(|c| c.size).sum();
        let request = Request::Chunks {
            digest: *digest,
            ranges: ranges.iter().map(|r| (r.start, r.end)).collect(),
            chunks: members.to_vec(),
            file: file.is_some(),
        };
        Ok(ChunkStream {
            exchange: self
                .begin_with(&request, file.map(AsFd::as_fd), max_chunk, budget)
                .await?,
            sizes: members.iter().flatten().map(|c| (c.idx, c.size)).collect(),
            seen: std::collections::HashSet::new(),
        })
    }

    /// A layer, decompressed: the frames and then what the compressed bytes
    /// were.
    pub async fn layer(
        self: &Arc<Self>,
        digest: &Digest,
        size: i64,
        max_uncompressed: u64,
    ) -> ImageResult<LayerFrames> {
        let x = self
            .begin(
                &Request::Layer {
                    digest: *digest,
                    size,
                    max_uncompressed,
                },
                velarx_content::pull::stream::FRAME_SIZE,
                max_uncompressed,
            )
            .await?;
        Ok(LayerFrames {
            exchange: Some(x),
            trailer: None,
            progress: 0,
        })
    }
}

/// The chunks a worker sends.
pub struct ChunkStream {
    exchange: Exchange,
    sizes: std::collections::HashMap<usize, u64>,
    seen: std::collections::HashSet<usize>,
}

impl ChunkStream {
    /// The index and the size of the next chunk, whose bytes are read with
    /// [`payload`](Self::payload); `None` when the worker is done.
    pub async fn next(&mut self) -> Result<Option<(usize, usize)>, RangesError> {
        match self.exchange.next().await? {
            Event::Data { tag, len, .. } => {
                let expected = self.sizes.get(&tag).copied().ok_or_else(|| {
                    RangesError::Other(worker_failed("a chunk that was not asked"))
                })?;
                if len as u64 != expected || !self.seen.insert(tag) {
                    return Err(RangesError::Other(worker_failed(
                        "a chunk of the wrong size, or twice",
                    )));
                }
                Ok(Some((tag, len)))
            }
            Event::Reply(_) => Ok(None),
        }
    }

    pub async fn payload(&mut self) -> ImageResult<Vec<u8>> {
        self.exchange.payload().await
    }
}

impl Exchange {
    /// The one data frame of a request that has one, then the reply.
    async fn one_blob(&mut self) -> ImageResult<Vec<u8>> {
        let mut body = None;
        loop {
            match self.next().await.map_err(ImageError::from)? {
                Event::Data { .. } if body.is_some() => {
                    return Err(worker_failed("more data than expected"))
                }
                Event::Data { .. } => body = Some(self.payload().await?),
                Event::Reply(_) => {
                    return body.ok_or_else(|| worker_failed("it sent nothing"));
                }
            }
        }
    }
}

/// The frames of a layer.
pub struct LayerFrames {
    exchange: Option<Exchange>,
    trailer: Option<LayerTrailer>,
    progress: u64,
}

impl LayerFrames {
    /// The next piece of the uncompressed layer; `None` at the end.
    pub async fn next(&mut self) -> ImageResult<Option<Bytes>> {
        let Some(x) = self.exchange.as_mut() else {
            return Ok(None);
        };
        match x.next().await.map_err(ImageError::from)? {
            Event::Data { offset, .. } => {
                self.progress = offset;
                Ok(Some(Bytes::from(x.payload().await?)))
            }
            Event::Reply(body) => {
                self.trailer = Some(parse(&body).map_err(lost)?);
                self.exchange = None;
                Ok(None)
            }
        }
    }

    /// How many compressed bytes the worker says it had read when it sent
    /// the last frame: to show progress, nothing else.
    pub fn progress(&self) -> u64 {
        self.progress
    }

    /// What the worker says the compressed bytes were, once the frames ended.
    pub fn trailer(&self) -> Option<&LayerTrailer> {
        self.trailer.as_ref()
    }
}

#[cfg(test)]
impl Pool {
    /// The body of an http(s) URL, given to SINK in order, at most LIMIT
    /// bytes (a pool for URLs: no endpoints).
    pub async fn url(
        self: &Arc<Self>,
        url: &str,
        limit: u64,
        sink: &mut (dyn FnMut(&[u8]) -> std::io::Result<()> + Send),
    ) -> ImageResult<UrlTrailer> {
        self.url_opt(url, limit, Default::default(), sink)
            .await
            .map_err(worker_failed)?
            .ok_or_else(|| worker_failed(format!("{url}: 404 Not Found")))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::process::Stdio;
    use tokio::process::Command;

    /// A spawner of nothing: the pools of these tests start no worker.
    fn spawner() -> Arc<Spawner> {
        static NONE: std::sync::OnceLock<Arc<Spawner>> = std::sync::OnceLock::new();
        NONE.get_or_init(|| {
            Arc::new(Spawner::start_beside_idle_threads(Vec::new(), |_| Ok(())).unwrap())
        })
        .clone()
    }

    /// `[pull] require_userns` is the policy of the pool it confines and of
    /// the pools that hold its credentials, not of the other pools.
    #[test]
    fn the_pools_of_the_credentials_require_a_user_namespace_too() {
        let required = |p: &Pool| p.require_userns.load(std::sync::atomic::Ordering::Relaxed);
        let spec = endpoint("registry.example");
        let pool = Pool::new_brokered(spawner(), Vec::new(), vec![Some(spec)], 1);
        let other = Pool::new(spawner(), Vec::new(), 1);
        // (no limits: no cgroup is made for the workers)
        let config = velarx_config::PullConfig {
            require_userns: true,
            memory_max_mib: 0,
            memory_high_mib: 0,
            pids_max: 0,
            ..Default::default()
        };
        pool.confine(&config);
        assert!(required(&pool));
        let auth: Vec<_> = pool.auth.iter().flatten().collect();
        assert!(!auth.is_empty());
        assert!(auth.iter().all(|p| required(p)));
        assert!(!required(&other));
    }

    #[tokio::test]
    async fn a_worker_gets_only_what_is_brokered() {
        // no worker is started: these are refused before
        let pool = Pool::new_brokered(spawner(), Vec::new(), vec![None], 1);
        let ask = |body: &str| {
            let pool = pool.clone();
            let body = body.to_string();
            async move {
                pool.answer_auth(body.as_bytes())
                    .await
                    .error
                    .unwrap_or_default()
            }
        };
        assert_eq!(ask("not json").await, "invalid authorization request");
        assert_eq!(
            ask(r#"{"endpoint":0,"actions":"pull,push","refresh":false}"#).await,
            "only pulls are brokered"
        );
        assert_eq!(
            ask(r#"{"endpoint":0,"actions":"pull","refresh":false}"#).await,
            "not a brokered endpoint"
        );
        assert_eq!(
            ask(r#"{"endpoint":7,"actions":"pull","refresh":false}"#).await,
            "not a brokered endpoint"
        );
    }
    use crate::net::proto::{write_data, ErrorKind};
    use tokio::io::AsyncReadExt;

    /// A pool with one idle worker that is a task of the test: it reads the
    /// request and runs `script` on the socket.
    pub(crate) async fn pool_with<F, Fut>(script: F) -> Arc<Pool>
    where
        F: FnOnce(UnixStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let pool = Pool::new(spawner(), Vec::new(), 2);
        let (mine, theirs) = UnixStream::pair().unwrap();
        tokio::spawn(async move {
            let mut theirs = theirs;
            let h = read_header(&mut theirs, 0).await.unwrap();
            read_bytes(&mut theirs, h.json_len).await.unwrap();
            script(theirs).await;
        });
        pool.idle.lock().unwrap().push(Conn {
            stream: mine,
            worker: None,
            tail: Arc::default(),
            kills_before: 0,
        });
        pool
    }

    fn reply() -> Vec<u8> {
        b"{}".to_vec()
    }

    #[tokio::test]
    async fn test_a_worker_that_sends_more_than_asked_is_refused_and_not_reused() {
        let pool = pool_with(|mut w| async move {
            write_data(&mut w, Kind::Data, &[], 0, 0, &[7u8; 100])
                .await
                .unwrap();
            write_frame(&mut w, Kind::Reply, &reply(), &[])
                .await
                .unwrap();
        })
        .await;
        let err = pool
            .blob(&crate::sha256(b"aa"), 10, &mut |_| Ok(()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("pull worker"), "{err}");
        assert!(
            pool.idle.lock().unwrap().is_empty(),
            "a bad worker is killed"
        );
    }

    /// A worker that fails in the middle of an upload ends the push, and
    /// the daemon stops sending; a reply before the data ended is refused.
    #[tokio::test]
    async fn test_a_failed_upload_stops_the_push() {
        let pool = pool_with(|mut w| async move {
            let e = br#"{"kind":"failed","status":null,"message":"PATCH refused"}"#;
            write_frame(&mut w, Kind::Error, e, &[]).await.unwrap();
        })
        .await;
        let mut next = |_at: u64| {
            Box::pin(async { Ok(Bytes::from(vec![1u8; 1024])) })
                as futures::future::BoxFuture<'static, std::io::Result<Bytes>>
        };
        let err = pool
            .upload(&crate::sha256(b"aa"), 1 << 30, 1 << 20, &mut next)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("PATCH refused"), "{err}");
        assert!(pool.idle.lock().unwrap().is_empty());
        let pool = pool_with(|mut w| async move {
            write_frame(&mut w, Kind::Reply, b"{}", &[]).await.unwrap();
        })
        .await;
        let err = pool
            .upload(&crate::sha256(b"aa"), 1 << 30, 1 << 20, &mut next)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("before the data ended"), "{err}");
        // More than the announced size from the daemon's side: refused
        // before it is sent.
        let pool = pool_with(|_w| std::future::pending::<()>()).await;
        let mut big = |_at: u64| {
            Box::pin(async { Ok(Bytes::from(vec![1u8; 100])) })
                as futures::future::BoxFuture<'static, std::io::Result<Bytes>>
        };
        let err = pool
            .upload(&crate::sha256(b"aa"), 50, 1 << 20, &mut big)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not the 50 bytes"), "{err}");
    }

    #[tokio::test]
    async fn test_a_url_comes_in_order_and_whole() {
        let pool = pool_with(|mut w| async move {
            write_data(&mut w, Kind::Data, &[], 0, 0, b"hel")
                .await
                .unwrap();
            write_data(&mut w, Kind::Data, &[], 0, 3, b"lo")
                .await
                .unwrap();
            let t = br#"{"size":5,"last_modified":"Wed, 21 Oct 2015 07:28:00 GMT"}"#;
            write_frame(&mut w, Kind::Reply, t, &[]).await.unwrap();
        })
        .await;
        let mut got = Vec::new();
        let t = pool
            .url("http://x/y", 10, &mut |b| {
                got.extend_from_slice(b);
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!((got.as_slice(), t.size), (&b"hello"[..], 5));
        assert!(t.last_modified.is_some());
        // Out of order, or a size that is not what came: refused.
        for (second, size) in [(4u64, 5u64), (3, 6)] {
            let pool = pool_with(move |mut w| async move {
                write_data(&mut w, Kind::Data, &[], 0, 0, b"hel")
                    .await
                    .unwrap();
                write_data(&mut w, Kind::Data, &[], 0, second, b"lo")
                    .await
                    .unwrap();
                let t = format!("{{\"size\":{size}}}");
                write_frame(&mut w, Kind::Reply, t.as_bytes(), &[])
                    .await
                    .unwrap();
            })
            .await;
            assert!(pool.url("http://x/y", 10, &mut |_| Ok(())).await.is_err());
        }
        // More than the limit: refused.
        let pool = pool_with(|mut w| async move {
            write_data(&mut w, Kind::Data, &[], 0, 0, &[1u8; 20])
                .await
                .unwrap();
        })
        .await;
        assert!(pool.url("http://x/y", 10, &mut |_| Ok(())).await.is_err());
    }

    #[tokio::test]
    async fn test_a_good_worker_goes_back_to_the_pool() {
        let pool = pool_with(|mut w| async move {
            write_data(&mut w, Kind::Data, &[], 0, 0, b"manifest")
                .await
                .unwrap();
            write_frame(&mut w, Kind::Reply, &reply(), &[])
                .await
                .unwrap();
        })
        .await;
        let (body, digest) = pool.manifest("latest", 100).await.unwrap();
        assert_eq!(&body[..], b"manifest");
        // The digest is the one of the bytes, whatever the worker says.
        assert_eq!(digest, crate::sha256(b"manifest"));
        assert_eq!(pool.idle.lock().unwrap().len(), 1);
    }

    /// The workers of a pool that is dropped end, though their parent is
    /// the spawner and not the process of the pool.
    #[test]
    fn the_workers_of_a_dropped_pool_end() {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let exe = dir.path().join("worker");
            velarx_base::testing::write_script(&exe, "exec sleep 60");
            let spawner =
                Arc::new(Spawner::start(vec![worker_program(&exe).unwrap()], |_| Ok(())).unwrap());
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let pool = Pool::new(spawner, Vec::new(), 1);
                    let conn = pool.spawn().await.unwrap();
                    let pid = conn.worker.as_ref().unwrap().pid as i32;
                    let held = velarx_sys::pidfd::open(pid).unwrap();
                    pool.idle.lock().unwrap().push(conn);
                    drop(pool);
                    assert!(
                        velarx_sys::pidfd::wait_exit(&held, Duration::from_secs(10)).unwrap(),
                        "the worker runs on"
                    );
                });
        });
    }

    fn endpoint(host: &str) -> EndpointSpec {
        EndpointSpec {
            host: host.into(),
            repository: "r".into(),
            insecure: false,
            allow_private: false,
            credentials: None,
            certs: Default::default(),
            brokered: false,
            hint: None,
            hints: true,
            min_speed: Default::default(),
            scheme: None,
        }
    }

    /// What a worker found out about the registry reaches the user and the
    /// hints, and nothing it says about another registry does.
    #[tokio::test]
    async fn test_what_a_worker_found_out_is_shown_and_kept() {
        use velarx_registry::hints::{Auth, HintStore, Note, Notices};
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(HintStore::at(dir.path().join("hints")));
        let pool = Pool::new(spawner(), vec![endpoint("registry.example")], 2);
        pool.set_hints(Some(store.clone()));
        let lines = Arc::new(Mutex::new(Vec::new()));
        let seen = lines.clone();
        pool.on_warning(Arc::new(move |l| seen.lock().unwrap().push(l)));
        let (mine, theirs) = UnixStream::pair().unwrap();
        tokio::spawn(async move {
            let mut w = theirs;
            let h = read_header(&mut w, 0).await.unwrap();
            read_bytes(&mut w, h.json_len).await.unwrap();
            let auth = |registry: &str| Note::Auth {
                registry: registry.into(),
                transport: "https".into(),
                auth: Auth::Bearer {
                    realm: format!("https://{registry}/token"),
                    service: None,
                },
            };
            let done = Done {
                notices: Notices {
                    warnings: vec!["registry.example: \x1b[2Jthe hint did not work\n".into(); 3],
                    hints: vec![auth("other.example"), auth("registry.example")],
                    ..Default::default()
                },
                ..Default::default()
            };
            write_frame(&mut w, Kind::Reply, &json(&done).unwrap(), &[])
                .await
                .unwrap();
        });
        pool.idle.lock().unwrap().push(Conn {
            stream: mine,
            worker: None,
            tail: Arc::default(),
            kills_before: 0,
        });
        let mut x = pool.begin(&Request::Warm, 0, 0).await.unwrap();
        assert!(matches!(x.next().await, Ok(Event::Reply(_))));
        let lines = lines.lock().unwrap();
        assert_eq!(lines.len(), 1, "the same line is shown once: {lines:?}");
        assert!(
            !lines[0].contains('\x1b') && !lines[0].contains('\n'),
            "{lines:?}"
        );
        assert!(store.get("other.example").is_none());
        assert_eq!(
            store.get("registry.example").unwrap().auth,
            Auth::Bearer {
                realm: "https://registry.example/token".into(),
                service: None
            }
        );
    }

    #[tokio::test]
    async fn test_a_worker_cannot_fill_the_terminal() {
        let pool = Pool::new(spawner(), vec![endpoint("registry.example")], 2);
        let lines = Arc::new(Mutex::new(Vec::new()));
        let seen = lines.clone();
        pool.on_warning(Arc::new(move |l| seen.lock().unwrap().push(l)));
        for i in 0..100 {
            pool.absorb(velarx_registry::hints::Notices {
                warnings: vec![format!("line {i}")],
                ..Default::default()
            });
        }
        assert_eq!(lines.lock().unwrap().len(), WARNINGS_SHOWN);
    }

    /// The scheme a worker found an insecure endpoint to speak is told to
    /// the next workers; what it says of a secure endpoint or of another
    /// registry is not.
    #[test]
    fn test_the_scheme_a_worker_found_is_told_to_the_next() {
        use velarx_registry::target::Scheme;
        let insecure = EndpointSpec {
            insecure: true,
            ..endpoint("mirror.example:5000")
        };
        let pool = Pool::new(spawner(), vec![insecure, endpoint("registry.example")], 2);
        pool.absorb(velarx_registry::hints::Notices {
            schemes: ["mirror.example:5000", "registry.example", "other.example"]
                .map(|h| (h.to_string(), Scheme::Http))
                .into(),
            ..Default::default()
        });
        let told: Vec<_> = pool
            .endpoints_for_a_worker()
            .into_iter()
            .map(|e| e.scheme)
            .collect();
        assert_eq!(told, [Some(Scheme::Http), None]);
    }

    /// The host the blobs are sent to is kept for the registry, once.
    #[test]
    fn test_the_cdn_of_a_registry_is_kept() {
        use velarx_registry::hints::HintStore;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(HintStore::at(dir.path().join("hints")));
        let pool = Pool::new(spawner(), vec![endpoint("registry.example")], 2);
        pool.set_hints(Some(store.clone()));
        pool.note_redirect(
            &crate::sha256(b"aa"),
            "https://registry.example/blob".into(),
            0,
        );
        assert!(
            store.get("registry.example").is_none(),
            "its own host is no CDN"
        );
        pool.note_redirect(
            &crate::sha256(b"aa"),
            "https://cdn.example:8443/blob?sig=x".into(),
            0,
        );
        assert_eq!(
            store.get("registry.example").unwrap().cdn.as_deref(),
            Some("cdn.example:8443")
        );
    }

    /// A redirect of a fallback is the CDN of that endpoint, not of the first.
    #[test]
    fn test_the_cdn_of_a_fallback_is_not_the_first_ones() {
        use velarx_registry::hints::HintStore;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(HintStore::at(dir.path().join("hints")));
        let pool = Pool::new(
            spawner(),
            vec![endpoint("registry.example"), endpoint("mirror.example")],
            2,
        );
        pool.set_hints(Some(store.clone()));
        pool.note_redirect(&crate::sha256(b"aa"), "https://cdn.mirror/blob".into(), 1);
        assert!(store.get("registry.example").is_none());
        assert_eq!(
            store.get("mirror.example").unwrap().cdn.as_deref(),
            Some("cdn.mirror")
        );
        assert_eq!(pool.cdn(), None, "the workers do not connect to it");
        assert_eq!(pool.redirect_for(&crate::sha256(b"aa")), None);
        assert!(pool.endpoints_for_a_worker()[0].hint.is_none());
        // the first endpoint's own redirect is still its own
        pool.note_redirect(&crate::sha256(b"aa"), "https://cdn.first/blob".into(), 0);
        assert_eq!(
            store.get("registry.example").unwrap().cdn.as_deref(),
            Some("cdn.first")
        );
        assert_eq!(
            store.get("mirror.example").unwrap().cdn.as_deref(),
            Some("cdn.mirror")
        );
    }

    /// Where workers connect in advance: where the registry sent a blob in
    /// this pull before the hint, never the registry itself, nothing without
    /// hints.
    #[test]
    fn test_the_cdn_to_connect_to_in_advance() {
        use velarx_registry::hints::{Auth, Hint};
        let cdn = |p: &Arc<Pool>| p.cdn().map(|(s, c)| format!("{s}://{c}"));
        let mut spec = endpoint("registry.example");
        spec.hint = Some(Hint {
            transport: "https".into(),
            auth: Auth::None,
            cdn: Some("cdn.example".into()),
        });
        let pool = Pool::new(spawner(), vec![spec.clone()], 2);
        assert_eq!(cdn(&pool).as_deref(), Some("https://cdn.example"));
        pool.note_redirect(
            &crate::sha256(b"aa"),
            "https://other.example:8443/b?sig=1".into(),
            0,
        );
        assert_eq!(cdn(&pool).as_deref(), Some("https://other.example:8443"));
        let told = pool.endpoints_for_a_worker();
        assert_eq!(
            told[0].hint.as_ref().unwrap().cdn.as_deref(),
            Some("other.example:8443"),
            "the workers that start next are told where the blobs came from"
        );
        let own = Pool::new(spawner(), vec![spec.clone()], 2);
        own.note_redirect(
            &crate::sha256(b"aa"),
            "https://registry.example/b".into(),
            0,
        );
        assert_eq!(
            cdn(&own).as_deref(),
            Some("https://cdn.example"),
            "the registry's own address is no CDN"
        );
        spec.hints = false;
        let off = Pool::new(spawner(), vec![spec.clone()], 2);
        off.note_redirect(&crate::sha256(b"aa"), "https://other.example/b".into(), 0);
        assert_eq!(cdn(&off), None);
        assert_eq!(off.endpoints_for_a_worker()[0].hint, spec.hint);
        spec.hints = true;
        spec.hint.as_mut().unwrap().cdn = Some("registry.example".into());
        let same = Pool::new(spawner(), vec![spec], 2);
        assert_eq!(cdn(&same), None);
        // no hint at all: the first redirect makes one
        let bare = Pool::new(spawner(), vec![endpoint("registry.example")], 2);
        assert!(bare.endpoints_for_a_worker()[0].hint.is_none());
        bare.note_redirect(&crate::sha256(b"aa"), "https://cdn.example/b".into(), 0);
        let hint = bare.endpoints_for_a_worker()[0].hint.clone().unwrap();
        assert_eq!(
            (hint.transport.as_str(), hint.cdn.as_deref()),
            ("https", Some("cdn.example"))
        );
    }

    #[tokio::test]
    async fn test_error_messages_are_truncated_and_cannot_carry_escapes() {
        let pool = pool_with(|mut w| async move {
            let e = ErrorMsg {
                kind: ErrorKind::Failed,
                status: None,
                message: format!("\x1b[2Jboom{}", "x".repeat(5000)),
                notices: Default::default(),
            };
            write_frame(&mut w, Kind::Error, &json(&e).unwrap(), &[])
                .await
                .unwrap();
        })
        .await;
        let text = pool
            .blob(&crate::sha256(b"aa"), 10, &mut |_| Ok(()))
            .await
            .unwrap_err()
            .to_string();
        assert!(!text.contains('\x1b'), "{text:?}");
        assert!(text.len() < 1200, "{}", text.len());
        // An error is an answer: the worker can go on.
        assert_eq!(pool.idle.lock().unwrap().len(), 1);
    }

    /// A registry that refused the credentials is told apart by the kind of
    /// the worker's answer, not by what its text says.
    #[tokio::test]
    async fn test_a_refusal_of_the_credentials_is_typed() {
        for (kind, text) in [
            (ErrorKind::Unauthorized, "boom"),
            (ErrorKind::Failed, "401 Unauthorized DENIED"),
        ] {
            let unauthorized = matches!(kind, ErrorKind::Unauthorized);
            let pool = pool_with(move |mut w| async move {
                let e = ErrorMsg {
                    kind,
                    status: None,
                    message: text.into(),
                    notices: Default::default(),
                };
                write_frame(&mut w, Kind::Error, &json(&e).unwrap(), &[])
                    .await
                    .unwrap();
            })
            .await;
            let e = pool
                .blob(&crate::sha256(b"aa"), 10, &mut |_| Ok(()))
                .await
                .unwrap_err();
            assert_eq!(
                matches!(e, ImageError::Unauthorized(_)),
                unauthorized,
                "{e}"
            );
        }
    }

    #[tokio::test]
    async fn test_rejected_ranges_are_told_apart() {
        let pool = pool_with(|mut w| async move {
            let e = ErrorMsg {
                kind: ErrorKind::Rejected,
                status: Some(416),
                message: String::new(),
                notices: Default::default(),
            };
            write_frame(&mut w, Kind::Error, &json(&e).unwrap(), &[])
                .await
                .unwrap();
        })
        .await;
        let mut sink = |_p: Piece| {
            Box::pin(async { Ok(()) })
                as futures::future::BoxFuture<'static, velarx_types::ImageResult<()>>
        };
        match pool
            .ranges(&crate::sha256(b"aa"), &[0..10], None, &mut sink)
            .await
        {
            Err(RangesError::Rejected(s)) => assert_eq!(s, 416),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn test_data_out_of_the_ranges_asked_is_refused() {
        for (tag, offset, len) in [(5usize, 0u64, 10usize), (0, 95, 10), (0, 0, 11)] {
            let pool = pool_with(move |mut w| async move {
                write_data(&mut w, Kind::Data, &[], tag, offset, &vec![1u8; len])
                    .await
                    .unwrap();
                write_frame(&mut w, Kind::Reply, &reply(), &[])
                    .await
                    .unwrap();
            })
            .await;
            let mut got = 0;
            let mut sink = |p: Piece| {
                got += p.data.len();
                Box::pin(async { Ok(()) })
                    as futures::future::BoxFuture<'static, velarx_types::ImageResult<()>>
            };
            let result = pool
                .ranges(&crate::sha256(b"aa"), &[100..110], None, &mut sink)
                .await;
            assert!(result.is_err(), "{tag} {offset} {len}");
            assert_eq!(got, 0);
        }
    }

    #[tokio::test]
    async fn test_chunks_must_be_asked_for_once_with_their_size() {
        let specs = vec![vec![
            ChunkSpec {
                idx: 3,
                compressed: 10,
                size: 4,
                skip: 0,
            },
            ChunkSpec {
                idx: 4,
                compressed: 10,
                size: 6,
                skip: 0,
            },
        ]];
        // (tag, size) sequences: unknown chunk, wrong size, twice.
        for frames in [vec![(9usize, 4usize)], vec![(3, 5)], vec![(3, 4), (3, 4)]] {
            let pool = pool_with(move |mut w| async move {
                for (tag, len) in frames {
                    write_data(&mut w, Kind::Data, &[], tag, 0, &vec![0u8; len])
                        .await
                        .unwrap();
                }
                write_frame(&mut w, Kind::Reply, &reply(), &[])
                    .await
                    .unwrap();
            })
            .await;
            let mut chunks = pool
                .chunks(&crate::sha256(b"aa"), &[0..20], &specs, 100, None)
                .await
                .unwrap();
            let mut failed = false;
            loop {
                match chunks.next().await {
                    Ok(Some(_)) => {
                        chunks.payload().await.unwrap();
                    }
                    Ok(None) => break,
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
            assert!(failed);
        }
    }

    #[tokio::test]
    async fn test_garbage_is_refused() {
        for junk in [
            vec![0xffu8; 64],
            vec![
                2, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ] {
            let pool = pool_with(move |mut w| async move {
                use tokio::io::AsyncWriteExt;
                w.write_all(&junk).await.unwrap();
                let mut sink = Vec::new();
                let _ = w.read_to_end(&mut sink).await;
            })
            .await;
            assert!(pool.manifest("latest", 100).await.is_err());
            assert!(pool.idle.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn test_a_worker_that_stops_is_an_error() {
        let pool = pool_with(|w| async move { drop(w) }).await;
        let err = pool.manifest("latest", 100).await.unwrap_err();
        assert!(err.to_string().contains("pull worker"), "{err}");
    }

    #[tokio::test]
    async fn a_worker_that_stops_is_told_with_its_status_and_last_words() {
        let mut child = Command::new("sh")
            .args([
                "-c",
                "echo Failed to execute: Permission denied >&2; exit 7",
            ])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let tail = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn(keep_tail(child.stderr.take().unwrap(), tail.clone()));
        let status = tokio::time::timeout(WAIT_TIMEOUT, child.wait()).await;
        task.await.unwrap();
        let err = describe_stop("worker", worker_failed("lost: reset"), status, &tail).to_string();
        assert!(
            err.contains("exited with status 7: Failed to execute: Permission denied"),
            "{err}"
        );
    }

    /// A worker that aborts or is killed is told as that, with its signal:
    /// the memory limit is not blamed for what the kernel did not do.
    #[tokio::test]
    async fn a_worker_that_aborts_is_told_by_its_signal() {
        let mut child = Command::new("sh")
            .args(["-c", "kill -ABRT $$"])
            .spawn()
            .unwrap();
        let tail = Mutex::new(Vec::new());
        let status = tokio::time::timeout(WAIT_TIMEOUT, child.wait()).await;
        let err = describe_stop("job", worker_failed("lost: reset"), status, &tail).to_string();
        assert!(
            err.contains("the job was killed by signal 6 (SIGABRT)"),
            "{err}"
        );
        assert!(!err.contains("memory"), "{err}");
    }
}
