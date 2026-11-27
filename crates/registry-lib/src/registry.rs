// SPDX-License-Identifier: Apache-2.0
//! `velarx-registry`: the registry as a fetcher.
//!
//! It serves the chunks of lazily pulled layers by the ranges of their
//! blobs, to the monitor of a container (or to a pull): the fetcher
//! at the end of the list, the origin.  It asks for the ranges the chunks
//! are in (merged into requests as a pull does), has them decompressed by
//! the confined pull workers, and hands the bytes over in files passed with
//! the replies; it never sees the store, and holds the credentials only for
//! the registries it is asked about.  The one that asks checks every byte.
//!
//! It is started by the engine that needs it, with one connection
//! (`--varlink-fd`), or with a listening socket the engine bound in a
//! directory of this fetcher alone (`--listen-fd 3 --shared PATH`); it
//! writes only beneath the staging the engine hands it (`--staging-fd`).
//! It leaves with its last connection.

use crate::net::pool::Pool;
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::debug;
use velarx_config::{Config, PullConfig, PushConfig};
use velarx_content::activation::{self, IdleExit};
use velarx_content::fetcher::proto::{Downloaded, Hit, RegistryError, Remote};
use velarx_content::list::RegistrySettings;
use velarx_content::pull::Limits;
use velarx_content::serve_fetch::Out;
use velarx_content::serve_registry::{RegistryCalls, RemoteCall};
use velarx_registry::auth::RegistryAccess;
use velarx_registry::client::RegistryClient;
use velarx_registry::helper::HelperRunner;
use velarx_registry::netpolicy::Resolver;
use velarx_sys::spawner::Spawner;
use velarx_types::digest::Digest;
use velarx_types::{ImageError, ImageReference};

/// Registries (repositories with their TLS setting) whose workers are kept
/// for the next request, the least recently used going first.
const POOLS_KEPT: usize = 8;

/// This binary again, for the workers: the file this process runs, whatever
/// became of its name.
const THIS_BINARY: &str = "/proc/self/exe";

pub struct RegistryService {
    pub(crate) pull: PullConfig,
    /// How pushes are made (the size of the pieces of an upload)
    pub(crate) push: PushConfig,
    /// Starts the pull workers (the front executes nothing itself)
    spawner: Arc<Spawner>,
    /// The auth files of the process ([`velarx_registry::auth::default_auth_files`]),
    /// asked once: they depend on its ids and environment, which stay
    auth_files: Vec<std::path::PathBuf>,
    /// The client, and what the auth files were when it read them
    client: Mutex<(velarx_registry::auth::AuthFilesStamp, RegistryClient)>,
    pub(crate) limits: Limits,
    /// KiB of chunks in flight
    pub(crate) memory: Arc<Semaphore>,
    /// KiB of the small files written in memory until they are complete and
    /// handed over, for all the calls of the process: a quarter of the
    /// memory of a pull
    pub(crate) in_memory: Arc<Semaphore>,
    pools: Mutex<Vec<(String, Arc<Pool>)>>,
    /// What the workers have for the person who pulls, sent with the next
    /// piece of a `Get`
    warnings: Arc<Mutex<Vec<String>>>,
    /// What resolves the names its workers ask for, when this process
    /// cannot (the confined front); else the workers' names are resolved
    /// here
    names: std::sync::OnceLock<Arc<dyn Resolver>>,
}

fn failed(e: impl std::fmt::Display) -> RegistryError {
    RegistryError::failed(e.to_string())
}

fn bad(reason: impl Into<String>) -> RegistryError {
    RegistryError::bad(reason)
}

/// What the registry answered: the class of the failure of its client.
fn refused(e: ImageError) -> RegistryError {
    RegistryError::Failed {
        failure: crate::registry_fetch::registry_failure(&e),
    }
}

/// How the requests of a call reach the registry.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reach {
    /// To pull: the mirrors, then the registry; workers without credentials,
    /// which the fetcher answers for
    Pull,
    /// To search: the registry itself
    Search,
    /// To push: the registry itself, workers with the credentials of its
    /// endpoint
    Push,
}

/// The credentials and certificates of a call.
fn access_of(bytes: Option<&[u8]>) -> Result<Option<RegistryAccess>, RegistryError> {
    bytes
        .map(|b| {
            serde_json::from_slice::<RegistryAccess>(b)
                .map_err(|_| bad("the access file is not credentials"))
        })
        .transpose()
        .map(|access| access.filter(|a| !a.is_empty()))
}

/// What an upload tells: the bytes of the blob the registry has taken.
pub(crate) type Tell = Arc<dyn Fn(u64) -> futures::future::BoxFuture<'static, ()> + Send + Sync>;

/// Upload the blob `digest` of `size` bytes that `data` holds, in pieces of
/// `chunk`, to the registry `pool` reaches; `tell` is told the bytes the
/// registry has taken before each piece.  The registry checks the digest
/// once the last piece is in.
pub(crate) async fn upload_file(
    pool: &Arc<Pool>,
    digest: &Digest,
    (size, chunk): (u64, u64),
    data: std::fs::File,
    tell: Tell,
) -> velarx_types::ImageResult<()> {
    let data = Arc::new(data);
    let mut next = move |at: u64| {
        let (data, tell) = (data.clone(), tell.clone());
        Box::pin(async move {
            // the pieces before this one are in the registry
            tell(at).await;
            let read = tokio::task::spawn_blocking(move || {
                read_piece(&data, at, velarx_content::pull::stream::FRAME_SIZE)
            })
            .await
            .map_err(std::io::Error::other)??;
            Ok(read)
        }) as futures::future::BoxFuture<'static, std::io::Result<bytes::Bytes>>
    };
    pool.upload(digest, size, chunk, &mut next).await
}

/// A piece of a blob of an upload, `len` bytes at most from `at` of `file`.
fn read_piece(file: &std::fs::File, at: u64, len: usize) -> std::io::Result<bytes::Bytes> {
    use std::os::unix::fs::FileExt;
    let mut buf = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        let n = file.read_at(&mut buf[filled..], at + filled as u64)?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(buf.into())
}

impl RegistryService {
    /// Where the downloads are made, with the confinement of `pull`.
    fn fetcher(&self, pull: &PullConfig) -> crate::net::url::Fetcher {
        let fetcher = crate::net::url::Fetcher::new(self.spawner(), pull);
        match self.names.get() {
            Some(names) => fetcher.with_names(names.clone()),
            None => fetcher,
        }
    }

    /// Where a URL is read: [`Self::fetcher`] at the speed `[pull]` asks.
    pub(crate) fn url_fetcher(&self) -> crate::net::url::Fetcher {
        self.fetcher(&self.pull)
            .with_min_speed(velarx_content::pull::min_speed(&self.pull))
    }

    /// What starts the confined workers that make the requests.
    pub(crate) fn spawner(&self) -> Arc<Spawner> {
        self.spawner.clone()
    }
}

impl RegistryService {
    /// The service of the confined front: `names` resolves the names its
    /// workers ask for (it opens no socket itself).
    pub fn new(
        (pull, push): (PullConfig, PushConfig),
        helpers: Arc<HelperRunner>,
        spawner: Arc<Spawner>,
        names: Arc<dyn Resolver>,
    ) -> Result<Arc<Self>, velarx_base::ids::IdsError> {
        let service = Self::with_helpers((pull, push), Some(helpers), spawner)?;
        let _ = service.names.set(names);
        Ok(service)
    }

    /// The service of a process that runs the credential helpers itself
    /// (`helpers` none: the process that pulls, which is not confined), or
    /// through the runner it started before it confined itself.
    pub fn with_helpers(
        (pull, push): (PullConfig, PushConfig),
        helpers: Option<Arc<HelperRunner>>,
        spawner: Arc<Spawner>,
    ) -> Result<Arc<Self>, velarx_base::ids::IdsError> {
        let mut client = RegistryClient::new()?;
        if let Some(helpers) = helpers {
            client.set_helper_runner(helpers);
        }
        client.set_min_speed(velarx_content::pull::min_speed(&pull));
        client.set_hints(velarx_registry::hints::HintStore::for_pull(
            pull.registry_hints,
        )?);
        Self::with_client((pull, push), client, spawner)
    }

    /// The service with the registry client `client` (its registries, its
    /// credentials, its certificates): the one of the process that pulls,
    /// when it runs the fetcher itself.
    pub fn with_client(
        (pull, push): (PullConfig, PushConfig),
        client: RegistryClient,
        spawner: Arc<Spawner>,
    ) -> Result<Arc<Self>, velarx_base::ids::IdsError> {
        let limits = Limits::from_config(&pull);
        let auth_files = velarx_registry::auth::default_auth_files()?;
        Ok(Arc::new(Self {
            memory: Arc::new(Semaphore::new((limits.memory_bytes / 1024) as usize)),
            in_memory: Arc::new(Semaphore::new((limits.memory_bytes / 4 / 1024) as usize)),
            limits,
            pull,
            push,
            spawner,
            client: Mutex::new((velarx_registry::auth::auth_files_stamp(&auth_files), client)),
            auth_files,
            pools: Mutex::new(Vec::new()),
            warnings: Arc::default(),
            names: std::sync::OnceLock::new(),
        }))
    }

    /// The client of a call.  The fetcher lives longer than a command: a
    /// `login` or a `logout` since the last call (the auth files changed) is
    /// read now, and the workers that had the old credentials are not used
    /// again.  Files that cannot be read now (a `$REGISTRY_AUTH_FILE` that
    /// was replaced is out of the reach of the confinement, which allows
    /// that file only) leave the credentials as they were.
    fn client(&self) -> RegistryClient {
        let now = velarx_registry::auth::auth_files_stamp(&self.auth_files);
        let mut client = self.client.lock().unwrap_or_else(|e| e.into_inner());
        if client.0 != now {
            client.0 = now;
            match client.1.with_reloaded_credentials(&self.auth_files) {
                Ok(reloaded) => {
                    debug!("the auth files changed: they were read again");
                    client.1 = reloaded;
                    self.pools.lock().unwrap_or_else(|e| e.into_inner()).clear();
                }
                Err(e) => debug!("the auth files changed but cannot be read again: {e}"),
            }
        }
        client.1.clone()
    }

    /// The client for the requests of a call about `repository`.  When the
    /// asker turns TLS verification off for a registry that registries.conf
    /// does not mark insecure (`--tls-verify=false`, as podman allows), the
    /// requests are made on its word, with the credentials of the call
    /// first and then the fetcher's own, as for a verified request; what
    /// that host answers is not kept as a hint for the requests that check
    /// it.
    fn request_client(&self, repository: &str, tls_verify: bool) -> RegistryClient {
        let mut client = self.client();
        if !tls_verify && !client.registries().is_insecure(repository) {
            client.set_hints(None);
        }
        client.with_tls_verify(tls_verify)
    }

    /// The workers for `repository` and how they reach it, and the host.
    /// The workers of a call that brings credentials of its own are the
    /// call's: they are not kept.
    pub(crate) fn pool_for(
        &self,
        repository: &str,
        tls_verify: bool,
        access: Option<&[u8]>,
        reach: Reach,
    ) -> Result<(Arc<Pool>, String), RegistryError> {
        let client = self.request_client(repository, tls_verify);
        let access = access_of(access)?;
        let reference = ImageReference::parse(repository).map_err(failed)?;
        let client = match &access {
            Some(a) => client.with_access(a),
            None => client,
        };
        let target = match reach {
            Reach::Pull => client.target(&reference),
            Reach::Search | Reach::Push => client.push_target(&reference),
        }
        .map_err(failed)?;
        let host = target.endpoint.host.clone();
        let key = format!(
            "{}|{repository}|{tls_verify}",
            match reach {
                Reach::Pull => "pull",
                Reach::Search => "search",
                Reach::Push => "push",
            }
        );
        let mut pools = self.pools.lock().unwrap_or_else(|e| e.into_inner());
        if access.is_none() {
            if let Some(at) = pools.iter().position(|(k, _)| *k == key) {
                let used = pools.remove(at);
                let pool = used.1.clone();
                pools.push(used);
                return Ok((pool, host));
            }
        }
        let exe = self.spawner();
        let pool = match reach {
            Reach::Push => Pool::new(
                exe,
                client.endpoint_specs(&target).map_err(failed)?,
                self.pull.max_workers,
            ),
            // the credentials stay with the fetcher and the worker of
            // each endpoint
            Reach::Pull | Reach::Search => {
                let (specs, auth) = client.brokered_specs(&target).map_err(failed)?;
                Pool::new_brokered(exe, specs, auth, self.pull.max_workers)
            }
        };
        pool.confine(&self.pull);
        if let Some(names) = self.names.get() {
            pool.use_names(names.clone());
        }
        pool.set_hints(client.hint_store().cloned());
        let warnings = self.warnings.clone();
        pool.on_warning(Arc::new(move |line| {
            warnings
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(line)
        }));
        if access.is_none() {
            if pools.len() >= POOLS_KEPT {
                pools.remove(0);
            }
            pools.push((key, pool.clone()));
        }
        Ok((pool, host))
    }

    /// The workers for the repository of a call.
    fn remote_pool(
        &self,
        call: &RemoteCall,
        reach: Reach,
    ) -> Result<(Arc<Pool>, String), RegistryError> {
        let Remote {
            repository,
            tls_verify,
            ..
        } = &call.remote;
        self.pool_for(
            repository,
            tls_verify.unwrap_or(true),
            call.access.as_deref().map(Vec::as_slice),
            reach,
        )
    }

    /// The lines the workers have for the person who asks, for a call that
    /// has no way to tell them: in the log of the fetcher.
    fn log_warnings(&self) {
        let lines = std::mem::take(&mut *self.warnings.lock().unwrap_or_else(|e| e.into_inner()));
        for line in lines {
            tracing::warn!("{line}");
        }
    }
}

/// The repository calls: the registry fetcher is the one that serves them.
#[async_trait]
impl RegistryCalls for RegistryService {
    /// The tags of a repository, every page of them, one a reply.
    async fn tags(
        &self,
        call: RemoteCall,
        max: u64,
        out: &Out<String>,
    ) -> Result<(), RegistryError> {
        let (pool, _) = self.remote_pool(&call, Reach::Pull)?;
        let cancelled = call.cancel.clone();
        let body = tokio::select! {
            body = pool.tags(MAX_TAGS_BYTES) => body.map_err(refused)?,
            _ = cancelled.cancelled() => return Ok(()),
        };
        self.log_warnings();
        let tags = velarx_registry::target::parse_tags(&body).map_err(failed)?;
        for tag in tags
            .into_iter()
            .take(usize::try_from(max).unwrap_or(usize::MAX))
        {
            out.send(tag)
                .await
                .map_err(|_| failed("the asker is gone"))?;
        }
        Ok(())
    }

    /// A search of the registry: Docker's index (v1) for `docker.io`, else
    /// the v1 search where the registry has one, else its catalog; one hit a
    /// reply, at most `limit`.
    async fn search(
        &self,
        call: RemoteCall,
        needle: String,
        limit: u64,
        out: &Out<Hit>,
    ) -> Result<(), RegistryError> {
        let (pool, _) = self.remote_pool(&call, Reach::Search)?;
        let cancelled = call.cancel.clone();
        let host = call.remote.repository.split('/').next().unwrap_or_default();
        let docker = matches!(host, "docker.io" | "index.docker.io");
        // (Docker searches `foo` for `library/foo` too)
        let needle = if docker {
            needle
                .strip_prefix("library/")
                .unwrap_or(&needle)
                .to_string()
        } else {
            needle
        };
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let (v1, body) = tokio::select! {
            found = pool.search(&needle, limit, docker, MAX_SEARCH_BYTES) => found.map_err(refused)?,
            _ = cancelled.cancelled() => return Ok(()),
        };
        self.log_warnings();
        let hits = hits_of(v1, &body, &needle).map_err(failed)?;
        for hit in hits.into_iter().take(limit) {
            out.send(hit)
                .await
                .map_err(|_| failed("the asker is gone"))?;
        }
        Ok(())
    }

    /// The registry takes the credentials of the call, or says why not
    /// (`GET /v2/` and the token service, as `podman login` does).
    async fn login(&self, call: RemoteCall) -> Result<(), RegistryError> {
        let remote = &call.remote;
        let access = access_of(call.access.as_deref().map(Vec::as_slice))?
            .ok_or_else(|| bad("a login is asked with the credentials to check"))?;
        let tls_verify = remote.tls_verify.unwrap_or(true);
        let client = self.request_client(&remote.repository, tls_verify);
        let reference = ImageReference::parse(&remote.repository).map_err(failed)?;
        let client = client.with_access(&access);
        let target = client.push_target(&reference).map_err(failed)?;
        // (a registry that registries.conf marks insecure is asked over http
        // as well)
        let tls_verify = tls_verify && !target.endpoint.insecure;
        // (a confined worker asks the registry, as for every request: this
        // process opens no connection)
        let checker = self.fetcher(&self.pull);
        // (a registry that did not take the credentials, in podman's words)
        tokio::select! {
            checked = checker.login(&target.endpoint.host, &access, tls_verify) => {
                // (a refusal in the registry's own words)
                checked.map_err(|e| RegistryError::Failed {
                    failure: velarx_proto::transfer::Failure {
                        reason: velarx_content::pull::net::origin::failure_text(&e),
                        ..crate::registry_fetch::registry_failure(&e)
                    },
                })
            }
            _ = call.cancel.cancelled() => Ok(()),
        }
    }

    /// The body of `url`, at most `max` bytes, read by a confined worker
    /// into `file` (zeros are holes); a 404 is `not_found`.
    async fn download(
        &self,
        url: &str,
        max: u64,
        file: std::fs::File,
        cancel: velarx_content::fetcher::Cancel,
    ) -> Result<Downloaded, RegistryError> {
        use std::io::Write;
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err(bad("a URL is http or https"));
        }
        let fetcher = self.url_fetcher();
        let mut writer = velarx_storage::SparseWriter::new(file);
        let mut sink = |chunk: &[u8]| writer.write_all(chunk);
        let found = tokio::select! {
            found = fetcher.fetch_opt(url, max, &mut sink) => {
                found.map_err(|e| match e {
                    velarx_content::pull::net::origin::UrlError::TooLarge(n) => {
                        RegistryError::TooLarge { max: n }
                    }
                    e => failed(e),
                })?
            }
            _ = cancel.cancelled() => return Err(failed("cancelled")),
        };
        writer.finish().map_err(failed)?;
        let Some(trailer) = found else {
            return Err(RegistryError::Failed {
                failure: velarx_proto::transfer::Failure {
                    class: velarx_proto::transfer::FailureClass::NotFound,
                    reason: format!("{url}: 404 Not Found"),
                },
            });
        };
        Ok(Downloaded {
            length: trailer.size,
            media_type: None,
            modified: trailer.last_modified,
        })
    }
}

/// The most bytes of the answer of the registry to a request for its tags.
const MAX_TAGS_BYTES: u64 = 16 * 1024 * 1024;

/// The most bytes of the answer of the registry to a search.
const MAX_SEARCH_BYTES: u64 = 16 * 1024 * 1024;

/// The hits of the body of a search: the v1 answer (`results`), else the
/// catalog (`repositories`, those with `needle` in their name).
fn hits_of(v1: bool, body: &[u8], needle: &str) -> Result<Vec<Hit>, serde_json::Error> {
    let v: serde_json::Value = serde_json::from_slice(body)?;
    let mut found = Vec::new();
    if v1 {
        for r in v["results"].as_array().into_iter().flatten() {
            let field = |k: &str| r[k].as_str().unwrap_or_default().to_string();
            found.push(Hit {
                name: field("name"),
                description: field("description"),
                stars: r["star_count"].as_u64().unwrap_or(0),
                official: r["is_official"].as_bool().unwrap_or(false),
                automated: r["is_automated"].as_bool().unwrap_or(false),
            });
        }
    } else {
        for name in v["repositories"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .filter(|r| r.contains(needle))
        {
            found.push(Hit {
                name: name.to_string(),
                ..Hit::default()
            });
        }
    }
    Ok(found)
}

/// The settings the starter gave in a file with no name (`file`), else
/// those of the configuration at `path`.
fn load_settings(
    file: Option<std::os::fd::OwnedFd>,
    path: &Path,
) -> anyhow::Result<RegistrySettings> {
    match file {
        Some(config_file) => Ok(velarx_content::list::registry_settings_from_fd(
            config_file,
        )?),
        None => Ok(RegistrySettings::of(&Config::load_or_default(path)?)),
    }
}

/// The process that starts the workers of `config`'s fetcher, confined (it
/// executes `worker`, and the front, which has no `execve`, asks it).
fn start_spawner(worker: &Path) -> anyhow::Result<Arc<Spawner>> {
    let reach = crate::confine::spawner_reach(worker);
    Spawner::start(
        vec![crate::net::pool::worker_program(worker)
            .map_err(|e| anyhow::anyhow!("the pull worker {}: {e}", worker.display()))?],
        move |_| {
            velarx_sandbox::fetch::enter(&reach, velarx_sandbox::fetch::Role::Spawner).map(|_| ())
        },
    )
    .map(Arc::new)
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// `velarx-registry [--config PATH | --config-fd N] --staging-fd N
/// (--varlink-fd N | --listen-fd N --shared PATH) | --self-test`: the
/// registry fetcher, which serves the fetcher interface and
/// `org.velarx.Registry`.
/// `--varlink-fd`: the one connection this process serves, which it leaves
/// with.  `--listen-fd` with `--shared PATH`: the socket the engine bound at
/// `PATH`, under a directory of this fetcher alone (`list::shared_registry`):
/// this leaves as soon as its last connection is closed, taking `PATH` away,
/// and waits for its first connection no longer than a client may wait
/// before its first call.
/// `--config-fd`: the configuration is the JSON in a file (a sealed
/// file with no name, read-only) the process that started this passed, not a
/// file by its name.  `--staging-fd`: the directory of the staging of the
/// store's layers, the only place of the store this process writes.
/// `--self-test`: confine this process as a fetcher of the configuration
/// with the staging of `--staging-fd`, try what that allows and refuses
/// (and the self-test of one worker it starts) and print the results as
/// JSON `[[what, as it should be], ...]`; nothing is served.
pub fn main(
    args: impl Iterator<Item = std::ffi::OsString>,
    default_config: PathBuf,
    startup: &velarx_sys::fd::Startup,
) -> anyhow::Result<()> {
    let mut config_path = default_config;
    let mut config_fd: Option<i32> = None;
    let mut listen_fd: Option<i32> = None;
    let mut varlink_fd: Option<i32> = None;
    let mut staging_fd: Option<i32> = None;
    let mut shared: Option<PathBuf> = None;
    let mut self_test = false;
    let mut args = args;
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .ok_or_else(|| anyhow::anyhow!("{} needs a value", arg.to_string_lossy()))
        };
        match arg.to_str() {
            Some("--config") => config_path = PathBuf::from(value()?),
            Some("--config-fd") => config_fd = Some(value()?.to_string_lossy().parse()?),
            Some("--listen-fd") => listen_fd = Some(value()?.to_string_lossy().parse()?),
            Some("--varlink-fd") => varlink_fd = Some(value()?.to_string_lossy().parse()?),
            Some("--staging-fd") => staging_fd = Some(value()?.to_string_lossy().parse()?),
            Some("--shared") => shared = Some(PathBuf::from(value()?)),
            Some("--self-test") => self_test = true,
            _ => anyhow::bail!("unknown argument {}", arg.to_string_lossy()),
        }
    }
    // (what this process serves comes from the engine that started it: a
    // connection, or a socket the engine bound in a directory of this
    // fetcher alone, and it writes only beneath the staging the engine
    // opened for it; one that bound a socket of its own, or opened the
    // staging by its path, would have rights the engine never gave it)
    if staging_fd.is_none() {
        anyhow::bail!("--staging-fd is needed: the staging of the layers is handed at the start");
    }
    if shared.is_some() != listen_fd.is_some() {
        anyhow::bail!("--shared is the socket of --listen-fd, and --listen-fd needs --shared");
    }
    if varlink_fd.is_some() && (listen_fd.is_some() || self_test) {
        anyhow::bail!("--varlink-fd is the one connection this process serves");
    }
    if varlink_fd.is_none() && listen_fd.is_none() && !self_test {
        anyhow::bail!("--varlink-fd, or --listen-fd with --shared, is needed");
    }
    // (taken first: the numbers are the ones the starter passed, before this
    // process opens anything)
    let inherited = activation::Inherited::take(startup, listen_fd)?;
    let tunnel = varlink_fd
        .map(|fd| {
            startup
                .adopt(fd)
                .map(std::os::unix::net::UnixStream::from)
                .ok_or_else(|| anyhow::anyhow!("the connection descriptor {fd} is not open"))
        })
        .transpose()?;
    let config_file = config_fd
        .map(|fd| {
            startup
                .adopt(fd)
                .ok_or_else(|| anyhow::anyhow!("the configuration descriptor {fd} is not open"))
        })
        .transpose()?;
    let staging_dir = staging_fd
        .and_then(|fd| startup.adopt(fd))
        .ok_or_else(|| anyhow::anyhow!("the staging descriptor is not open"))?;
    // (what the starter passed that this does not use goes: a descriptor
    // that outlives its purpose is a right nobody granted)
    startup.close_range(3, u32::MAX);
    velarx_base::hardening::harden()?;
    let config = load_settings(config_file, &config_path)?;
    let worker = config
        .pull
        .worker_path
        .clone()
        .unwrap_or_else(|| PathBuf::from(THIS_BINARY));
    if self_test {
        // (before the confinement: the front starts no process)
        let spawner = start_spawner(&worker)?;
        // the confinement of a front of this configuration, and what it
        // allows and refuses, tried from inside
        let staging = Arc::new(staging_dir);
        let mut reach = crate::confine::reach(&config, &worker, None)?;
        reach.staging = Some(staging.clone());
        // (a socket with a name, bound before the confinement as the
        // engine's is: the confined front may not connect to it)
        let socket = velarx_sys::fd::proc_path(&*staging).join(velarx_sandbox::fetch::PROBE_SOCKET);
        let listener = std::os::unix::net::UnixListener::bind(&socket)?;
        velarx_sandbox::fetch::enter(&reach, velarx_sandbox::fetch::Role::Front)
            .map_err(|e| anyhow::anyhow!("the fetcher cannot confine itself: {e}"))?;
        let results = crate::confine::probes(&staging, &spawner, Some(&socket));
        drop(listener);
        let _ = rustix::fs::unlinkat(
            &*staging,
            velarx_sandbox::fetch::PROBE_SOCKET,
            rustix::fs::AtFlags::empty(),
        );
        println!("{}", serde_json::to_string(&results)?);
        return Ok(());
    }
    // (before the confinement: the runner has what this process has now,
    // and runs the credential helpers, which the confined process cannot;
    // before the file size limit, which is this process's, not the helpers')
    let helpers = Arc::new(HelperRunner::start().map_err(|e| {
        anyhow::anyhow!("the fetcher cannot start its credential helper runner: {e}")
    })?);
    // (and the runner that resolves the names of the workers: this process
    // opens no socket once it is confined)
    let names = Arc::new(
        crate::net::runner::Runner::start()
            .map_err(|e| anyhow::anyhow!("the fetcher cannot start its resolver: {e}"))?,
    );
    // (the spawner of the workers, as the runner: forked before the
    // confinement and the limits, which are the front's, not the workers')
    let spawner = start_spawner(&worker)?;
    velarx_base::hardening::limit_file_size(config.pull.max_file_bytes())?;
    // (after the runner: the helpers keep the limits they are used to; a
    // shared fetcher holds a connection for each container that may
    // fetch, and the descriptors of their calls)
    velarx_base::hardening::raise_open_files()?;
    let (listener, idle, services) = match &tunnel {
        // (the one connection of the process that started this: no socket
        // by name, nothing to bind or to take away, gone with the connection)
        Some(_) => (
            None,
            Some(IdleExit {
                after: Duration::from_secs(config.services.first_call_secs),
                socket: None,
                last: true,
                lock: None,
            }),
            None,
        ),
        None => {
            // (the engine bound the socket in the directory of this
            // fetcher alone: the one place it may take a file away from)
            let socket = shared
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--listen-fd needs --shared"))?;
            let (listener, _) = activation::listener_for(&socket, inherited)
                .map_err(|e| anyhow::anyhow!("the fetcher: {e}"))?;
            // (held by its connections: the first one is the starter's,
            // waiting in the queue already)
            let idle = IdleExit {
                after: Duration::from_secs(config.services.first_call_secs),
                socket: Some(socket.clone()),
                last: true,
                lock: Some(
                    std::fs::File::open(activation::lock_path(&socket))
                        .map_err(|e| anyhow::anyhow!("the lock of the socket: {e}"))?,
                ),
            };
            let services = socket.parent().map(std::path::Path::to_path_buf);
            (Some(listener), Some(idle), services)
        }
    };
    if config.pull.registry_hints {
        // (the directory has to be there for the rule that lets the hints be kept)
        velarx_registry::hints::HintStore::at(velarx_registry::hints::HintStore::default_dir()?)
            .prepare();
    }
    // (and the directory of the file `login` writes, for the rule that lets
    // a login made after this start be read)
    if let Some(dir) = velarx_registry::auth::default_auth_file()
        .ok()
        .and_then(|f| f.parent().map(std::path::Path::to_path_buf))
    {
        use std::os::unix::fs::DirBuilderExt;
        let _ = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir);
    }
    let mut reach = crate::confine::reach(&config, &worker, services.as_deref())?;
    // (where the cgroups of the pools go, decided now: the confined front
    // asks no manager)
    reach.cgroups = crate::net::cgroup::place(&config.pull)
        .dir()
        .map(std::path::Path::to_path_buf);
    let staging = Arc::new(staging_dir);
    reach.staging = Some(staging.clone());
    let enforced = velarx_sandbox::fetch::enter(&reach, velarx_sandbox::fetch::Role::Front)
        .map_err(|e| anyhow::anyhow!("the fetcher cannot confine itself: {e}"))?;
    debug!("the fetcher is confined: {enforced:?}");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("registry-fetcher")
        .enable_all()
        .build()?;
    // (a confined front cannot fork another runner, and without one no
    // worker resolves a name: it ends, its calls fail and the engine starts
    // a new fetcher for its next need)
    let resolving = names.clone();
    runtime.spawn(async move {
        resolving.gone().await;
        eprintln!("the fetcher ends: its resolver runner is gone");
        std::process::exit(1);
    });
    let service = RegistryService::new(
        (config.pull.clone(), config.push.clone()),
        helpers,
        spawner,
        names,
    )?;
    let endpoint = {
        let _on = runtime.enter();
        velarx_content::serve_fetch::FetchEndpoint::new(crate::registry_fetch::RegistryFetch::new(
            service, staging,
        ))
    };
    let (_stop, stopped) = tokio::sync::oneshot::channel::<()>();
    // (the calls run on the runtime above; this thread serves the sockets).
    // The connections of the monitors that hold it, besides those of the
    // calls, have their own limit.
    let limits = velarx_content::activation::Limits {
        connections: config.pull.fetcher_connections.max(1),
        ..velarx_content::activation::Limits::of(&config.services)
    };
    match (tunnel, listener, idle) {
        (Some(stream), None, Some(idle)) => {
            velarx_content::serve_fetch::run_one_blocking(stream, endpoint, idle, limits)?
        }
        (None, Some(listener), idle) => {
            velarx_content::serve_fetch::run_blocking(listener, endpoint, idle, limits, stopped)?
        }
        _ => unreachable!("a connection or a listener"),
    }
    Ok(())
}

#[cfg(test)]
mod search_tests {
    use super::*;

    /// A v1 search gives its results with their numbers; a catalog gives the
    /// names that have the term.
    #[test]
    fn a_search_answer_is_the_hits_of_the_v1_search_or_of_the_catalog() {
        let v1 = br#"{"results":[{"name":"library/alpine","description":"a distro","star_count":9,"is_official":true,"is_automated":false}]}"#;
        let hits = hits_of(true, v1, "alpine").unwrap();
        assert_eq!(
            hits,
            [Hit {
                name: "library/alpine".into(),
                description: "a distro".into(),
                stars: 9,
                official: true,
                automated: false,
            }]
        );
        let catalog = br#"{"repositories":["a/alpine","b/busybox"]}"#;
        let hits = hits_of(false, catalog, "alpine").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "a/alpine");
        assert!(hits_of(true, b"not json", "x").is_err());
    }
}

#[cfg(test)]
pub(crate) mod pool_tests {
    use super::*;

    /// A service that starts no worker.
    pub(crate) fn service() -> Arc<RegistryService> {
        service_of(Default::default())
    }

    /// [`service`] with the `[pull]` configuration `pull`.
    pub(crate) fn service_of(pull: PullConfig) -> Arc<RegistryService> {
        let spawner = Arc::new(Spawner::start_beside_idle_threads(Vec::new(), |_| Ok(())).unwrap());
        RegistryService::with_client(
            (pull, Default::default()),
            RegistryClient::with_config(
                velarx_registry::target::TransportConfig {
                    registries: Default::default(),
                    certs_dirs: Vec::new(),
                    tls_verify: true,
                },
                velarx_registry::auth::AuthConfig::from_credentials(std::iter::empty()),
            ),
            spawner,
        )
        .unwrap()
    }

    /// A call that brings nothing (the engine sends an empty `RegistryAccess`
    /// with every call) is served by the workers of the repository: one
    /// pool, so one set of kept-alive connections, not one per call.
    #[test]
    fn calls_with_no_credentials_share_the_pool_of_the_repository() {
        let service = service();
        let empty = br#"{}"#.as_slice();
        let pool = |access| {
            service
                .pool_for("registry.invalid/r/app", true, access, Reach::Pull)
                .unwrap()
                .0
        };
        assert!(Arc::ptr_eq(&pool(None), &pool(Some(empty))));
        assert!(Arc::ptr_eq(&pool(Some(empty)), &pool(Some(empty))));
        let creds = br#"{"creds":{"username":"u","password":"p"}}"#.as_slice();
        assert!(!Arc::ptr_eq(&pool(Some(creds)), &pool(Some(creds))));
    }
}
