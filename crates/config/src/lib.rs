// SPDX-License-Identifier: Apache-2.0
mod containers;
pub use containers::{log_opt_size, parse_size, ContainersConfig, CGROUPS_MODES};

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;
use velarx_base::sync::SyncMode;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    ReadError(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    ParseError(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub userns: UserNamespaceConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub pull: PullConfig,
    #[serde(default)]
    pub push: PushConfig,
    /// Processes that are the origin of a scheme of their own, for both
    /// directions
    #[serde(default)]
    pub transports: Vec<TransportConfig>,
    #[serde(default)]
    pub sources: SourcesConfig,
    #[serde(default)]
    pub sinks: SinksConfig,
    #[serde(default)]
    pub containers: ContainersConfig,
    #[serde(default)]
    pub build: BuildConfig,
    /// The engine service (`org.velarx.Engine`).
    #[serde(default)]
    pub engine: EngineConfig,
    /// The limits of the varlink services (the engine, the store service,
    /// the fetchers, the services of external programs).
    #[serde(default)]
    pub services: ServicesConfig,
    /// `velarx-api` reads this section itself; here it is checked.
    #[serde(default)]
    pub api: ApiConfig,
    /// The OCI runtimes a container can be made with besides the default one:
    /// a name and the path of the runtime, or a list of paths (the first
    /// that is there), or a table with the path and `args` for this runtime
    /// alone (`oci_runtime` of the API, the runtime handlers of the CRI,
    /// `[server] runtime` and `--runtime` by name).  The options of `[server]
    /// runtime_args` go to every runtime.
    #[serde(default)]
    pub runtimes: std::collections::BTreeMap<String, RuntimePaths>,
    /// The file this configuration was read from, when there was one.
    #[serde(skip)]
    pub source: Option<std::path::PathBuf>,
}

/// `[api]`: the keys of `velarx-api` (`crates/api/src/config.rs` reads them).
/// The engine reads `compat_api_enforce_docker_hub` (the routes it serves).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    pub socket: Option<PathBuf>,
    #[serde(default)]
    pub listen: Vec<String>,
    pub idle_exit: Option<u64>,
    pub start_engine: Option<bool>,
    pub token_file: Option<PathBuf>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub tls_client_ca: Option<PathBuf>,
    #[serde(default)]
    pub allow_unauthenticated: bool,
    /// The short names of the Docker API are docker.io names, as Docker's
    /// (false: they are resolved as the libpod API resolves them)
    #[serde(default = "default_true")]
    pub compat_api_enforce_docker_hub: bool,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            socket: None,
            listen: Vec::new(),
            idle_exit: None,
            start_engine: None,
            token_file: None,
            tls_cert: None,
            tls_key: None,
            tls_client_ca: None,
            allow_unauthenticated: false,
            compat_api_enforce_docker_hub: true,
        }
    }
}

/// The engine service: the process that serves `org.velarx.Engine` to the
/// frontends (`velarx varlink`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub struct EngineConfig {
    /// The socket of the interface (default: `engine/engine.sock` next to the
    /// socket of the API)
    pub socket: Option<PathBuf>,
    /// An engine that its socket unit started leaves after this many
    /// seconds with no client connected, whatever containers run (their
    /// monitors go on and the next engine follows them again); the next
    /// connection to its socket starts it again.  0 keeps it.
    pub idle_exit: u64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            socket: None,
            idle_exit: 30,
        }
    }
}

/// The limits of each varlink service of velarx.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub struct ServicesConfig {
    /// The most connections a service serves at once
    pub max_connections: usize,
    /// The most connections of one client process at once (its
    /// `SO_PEERCRED`): one frontend leaves room for the others
    pub max_per_client: usize,
    /// A connection that sends no call within this many seconds of its
    /// connect is closed
    pub first_call_secs: u64,
}

impl Default for ServicesConfig {
    fn default() -> Self {
        Self {
            max_connections: 256,
            max_per_client: 192,
            first_call_secs: 10,
        }
    }
}

/// The limits of builds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub struct BuildConfig {
    /// What one COPY, ADD or context extraction may write, in GiB
    pub max_extract_gib: u64,
    /// Archive entries one ADD or context extraction may have
    pub max_extract_entries: u64,
    /// A copy worker that runs longer is killed
    pub worker_timeout_secs: u64,
    /// Builds that run at the same time; the others wait
    pub max_concurrent: usize,
    /// Builds that run or wait at the same time; above it a build is
    /// refused (429) before its context is read
    pub max_pending: usize,
    /// The scratch space of all the builds together (contexts, the layers
    /// of COPY and ADD, --squash), in GiB
    pub max_scratch_gib: u64,
    /// The entitlements builds may use (`network.host`, `security.insecure`):
    /// a RUN step with `--network=host` or `--security=insecure`, or a build
    /// with `--network=host`, fails unless the entitlement is listed here
    /// and the build request allows it too (`build --allow`); the REST
    /// build routes have no such parameter, so for them this list alone
    /// decides
    pub insecure_entitlements: Vec<velarx_base::entitlement::Entitlement>,
    /// The algorithm of the digests of the images the creating commands make
    /// (`build`, `import`, `manifest create`, `artifact add`) when
    /// `--digest` does not say: `sha256` or `sha512`.  Never applies to
    /// pulls, which use what the image uses, and `commit` follows the image
    /// of its container.
    #[serde(deserialize_with = "creation_algorithm")]
    pub digest: velarx_types::digest::Algorithm,
}

/// `sha256` or `sha512` (the algorithms an image is made with), else the
/// word is refused by name.
fn creation_algorithm<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<velarx_types::digest::Algorithm, D::Error> {
    let word = String::deserialize(d)?;
    velarx_types::digest::Algorithm::from_name(&word).map_err(|_| {
        serde::de::Error::custom(format!("[build] digest = {word:?}: sha256 or sha512"))
    })
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            max_extract_gib: 64,
            max_extract_entries: 4 << 20,
            worker_timeout_secs: 3600,
            max_concurrent: 4,
            max_pending: 16,
            max_scratch_gib: 100,
            insecure_entitlements: Vec::new(),
            digest: velarx_types::digest::Algorithm::Sha256,
        }
    }
}

/// Content sources besides the registry (`org.velarx.Fetcher`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcesConfig {
    /// Processes that provide content over a unix socket, to be named in
    /// `[pull] sources`
    #[serde(default)]
    pub external: Vec<ExternalSourceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalSourceConfig {
    /// The name to use in `[pull] sources`
    pub name: String,
    /// The unix socket of a source that is a separate process, an absolute
    /// path.  The source must run as the user of the process that asks, or as
    /// root.
    #[serde(default)]
    pub socket: Option<PathBuf>,
    /// Or a program started for each use ([`Reach::Command`]): its absolute
    /// path and its arguments, no shell
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    /// Or a directory of files named by the hex of their SHA-256, read by the
    /// process that pulls (no daemon, no socket)
    #[serde(default)]
    pub dir: Option<PathBuf>,
    /// Seconds without a byte after which the source is given up
    #[serde(default = "default_source_idle_secs")]
    pub idle_timeout_secs: u64,
    /// The settings of the program that serves the source, which reads this
    /// file itself: kept as they are, never read or checked here.
    #[serde(default, skip_serializing_if = "toml::Table::is_empty")]
    pub settings: toml::Table,
}

impl ExternalSourceConfig {
    /// How its process is reached, when it is not a `dir`.
    pub fn reach(&self) -> Reach {
        Reach::of(&self.socket, &self.command)
    }
}

/// How the engine reaches a program of the configuration (a source, a
/// sink, a transport): a socket where it runs, or the command that starts it for
/// each use.  A started program gets the connection to it as its descriptor
/// 3, nothing added to its arguments, an empty environment, and it is gone
/// when the connection is closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reach {
    /// The unix socket of a program that runs (or that a service manager
    /// starts)
    Socket(PathBuf),
    /// The program to start: its absolute path, then its arguments
    Command(Vec<String>),
}

impl Reach {
    /// The socket if there is one, else the command (an empty one, of a
    /// configuration that was not checked, fails to start).
    fn of(socket: &Option<PathBuf>, command: &[String]) -> Self {
        match socket {
            Some(socket) => Self::Socket(socket.clone()),
            None => Self::Command(command.to_vec()),
        }
    }
}

/// The `idle_timeout_secs` of a source that does not set it.
pub fn default_source_idle_secs() -> u64 {
    15
}

/// Names that `[pull] sources` knows without a definition, and that an
/// external source may not take.
pub const BUILTIN_SOURCES: [&str; 1] = ["registry"];

/// Whether `name` is a name of a source or a provider: 1 to 32 of `a-z`,
/// `0-9`, `-` and `_`.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Whether `socket` or `command` (exactly one of them) names a program
/// by an absolute path; `what` says whose they are.
fn check_reach(what: &str, socket: Option<&Path>, command: &[String]) -> Result<(), ConfigError> {
    let invalid = |msg: String| Err(ConfigError::Invalid(format!("{what}: {msg}")));
    match (socket, command.first()) {
        (Some(socket), None) if !socket.is_absolute() => {
            invalid(format!("`{}` is not an absolute path", socket.display()))
        }
        (None, Some(program)) if !Path::new(program).is_absolute() => {
            invalid("the first item of command must be an absolute path".into())
        }
        (Some(_), None) | (None, Some(_)) => Ok(()),
        _ => invalid("give a socket or a command, one of them".into()),
    }
}

/// Pushers besides the destination's own (`org.velarx.Pusher`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinksConfig {
    /// Processes that place the objects of an image over a unix socket, to
    /// be named in `[push] sinks`
    #[serde(default)]
    pub external: Vec<ExternalSinkConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalSinkConfig {
    /// The name to use in `[push] sinks`
    pub name: String,
    /// The unix socket of a pusher that is a separate process, an absolute
    /// path.  The pusher must run as the user of the process that asks, or
    /// as root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<PathBuf>,
    /// Or a program started for each use ([`Reach::Command`]): its absolute
    /// path and its arguments, no shell.  Exactly one of `socket` and
    /// `command`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    /// Seconds without a byte after which the process is given up
    #[serde(default = "default_source_idle_secs")]
    pub idle_timeout_secs: u64,
    /// The pusher may be given the credentials of the destination (it
    /// places objects in a registry); by default it is not
    #[serde(default)]
    pub credentials: bool,
}

impl ExternalSinkConfig {
    /// How its process is reached.
    pub fn reach(&self) -> Reach {
        Reach::of(&self.socket, &self.command)
    }
}

/// The names of the destination's own pushers (`registry`, and `dir` for a
/// path): the engine adds them by the destination's scheme, they are not
/// helper sinks, and a helper sink may not take them.
pub const BUILTIN_SINKS: [&str; 2] = ["registry", "dir"];

/// A process that is the origin of a scheme of its own (`[[transports]]`):
/// `velarx pull SCHEME://...` is served by its `org.velarx.Fetcher` and
/// `velarx push IMAGE SCHEME://...` committed by its `org.velarx.Pusher`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    /// The scheme of the destinations it serves (`s3` for `s3://...`):
    /// lowercase, and none of the transports velarx has
    pub scheme: String,
    /// The unix socket of the process, an absolute path: it serves
    /// `org.velarx.Fetcher` and/or `org.velarx.Pusher`.  It must run as the
    /// user of the process that asks, or as root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<PathBuf>,
    /// Or a program started for each use ([`Reach::Command`]): its absolute
    /// path and its arguments, no shell.  Exactly one of `socket` and
    /// `command`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    /// Seconds without a byte after which the process is given up
    #[serde(default = "default_source_idle_secs")]
    pub idle_timeout_secs: u64,
    /// The process may be given the credentials the client brought; by
    /// default it is not
    #[serde(default)]
    pub credentials: bool,
}

impl TransportConfig {
    /// How its process is reached.
    pub fn reach(&self) -> Reach {
        Reach::of(&self.socket, &self.command)
    }
}

/// How images are pushed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushConfig {
    /// Layers regenerated and uploaded at the same time
    #[serde(default = "default_push_parallel_layers")]
    pub parallel_layers: usize,
    /// Size of the pieces of a blob upload (PATCH requests)
    #[serde(default = "default_push_chunk_mib")]
    pub chunk_mib: u64,
    /// The helper sinks of a push, in the order they are asked: names of
    /// `[[sinks.external]]`.  The destination's own pusher (by its scheme:
    /// `registry` for a registry, `dir` for a path, the one of
    /// `[[transports]]`) is always the last, added by the engine and
    /// never named here.  By default none.  What a sink says it placed is
    /// confirmed by the destination's own before the manifest is put; a sink
    /// that fails is skipped and the next one is asked.
    #[serde(default)]
    pub sinks: Option<Vec<String>>,
    /// The compression of the layers that are regenerated (`gzip`, `zstd`,
    /// `zstd:chunked`); by default each layer keeps its own, and one stored
    /// uncompressed is compressed as `zstd:chunked`
    #[serde(default)]
    pub compression: Option<String>,
    /// The level of the layers compressed (gzip 0-9, zstd 1-20); by default
    /// that of the compression
    #[serde(default)]
    pub compression_level: Option<i32>,
    /// Send the repositories known to have a blob, so a pusher can link it
    #[serde(default = "default_true")]
    pub mount: bool,
    /// Ask the pushers what the destination has before regenerating a layer
    #[serde(default = "default_true")]
    pub skip_existing: bool,
}

fn default_push_parallel_layers() -> usize {
    3
}

fn default_push_chunk_mib() -> u64 {
    16
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            parallel_layers: default_push_parallel_layers(),
            chunk_mib: default_push_chunk_mib(),
            sinks: None,
            compression: None,
            compression_level: None,
            mount: true,
            skip_existing: true,
        }
    }
}

/// How images are pulled.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullConfig {
    /// Layers fetched at the same time
    #[serde(default = "default_parallel_layers")]
    pub parallel_layers: usize,
    /// Range requests in flight for one zstd:chunked layer
    #[serde(default = "default_range_concurrency")]
    pub range_concurrency: usize,
    /// Memory for the chunks being decompressed and written, for a pull; a
    /// quarter more for the small files a fetcher holds until they are
    /// complete
    #[serde(default = "default_pull_memory_mib")]
    pub memory_budget_mib: u64,
    /// Threads decompressing and hashing chunks, and copying the files a
    /// fetcher unpacked; 0 uses three per CPU
    #[serde(default)]
    pub workers: usize,
    /// A layer that inflates to more than this is refused
    #[serde(default = "default_max_layer_gib")]
    pub max_layer_gib: u64,
    /// A layer, or an archive, inflates to at most this many times its
    /// compressed size (plus `inflate_floor_mib`)
    #[serde(default = "default_max_inflate_ratio")]
    pub max_inflate_ratio: u64,
    /// What a layer or an archive may always inflate to, in MiB, however
    /// small it is
    #[serde(default = "default_inflate_floor_mib")]
    pub inflate_floor_mib: u64,
    /// A download that has not brought `min_speed_kib` KiB per second on
    /// average over `min_speed_secs` seconds fails (a server that sends a
    /// byte now and then never times out); either 0: no check
    #[serde(default = "default_min_speed_kib")]
    pub min_speed_kib: u64,
    #[serde(default = "default_min_speed_secs")]
    pub min_speed_secs: u64,
    /// How long a built-in fetcher (the registry's, the directory's) may be
    /// silent in a call before the call fails; not 0
    #[serde(default = "default_pull_idle_secs")]
    pub idle_timeout_secs: u64,
    /// Memory the workers of a pull may use before they are slowed down
    /// (cgroup `memory.high`), in MiB; 0: no limit
    #[serde(default = "default_memory_high_mib")]
    pub memory_high_mib: u64,
    /// Memory above which the workers of a pull are killed (cgroup
    /// `memory.max`), in MiB; 0: no limit
    #[serde(default = "default_memory_max_mib")]
    pub memory_max_mib: u64,
    /// Tasks the workers of a pull may have (cgroup `pids.max`); 0: no limit
    #[serde(default = "default_pids_max")]
    pub pids_max: u64,
    /// Fail a pull whose workers cannot be put in a cgroup of their own
    /// instead of starting them with the rlimits of their sandbox only
    #[serde(default)]
    pub require_cgroup: bool,
    /// An archive given to `load` that inflates to more than this is refused
    #[serde(default = "default_max_archive_gib")]
    pub max_archive_gib: u64,
    /// The socket of the Docker daemon a pull from `docker-daemon:` reads
    /// the image of; the engine connects to it, the process that reads the
    /// image is handed the connection
    #[serde(default = "default_docker_socket")]
    pub docker_socket: PathBuf,
    /// Signature policy file; by default ~/.config/velarx/policy.json
    /// (rootless) or /etc/velarx/policy.json; without either, the built-in
    /// policy accepts every image
    #[serde(default)]
    pub policy_path: Option<PathBuf>,
    /// The registries.d directory of the signature storage, instead
    /// of the drop-in directories (the user's for a rootless engine,
    /// /etc/velarx/registries.d...); it must exist
    #[serde(default)]
    pub registries_d: Option<PathBuf>,
    /// The confined workers must have a user namespace of their own: a
    /// kernel without them fails the pulls, instead of confining the
    /// workers without one (Landlock, seccomp, no capability, nobody).
    #[serde(default)]
    pub require_userns: bool,
    /// The worker executable; by default the registry fetcher itself
    #[serde(default)]
    pub worker_path: Option<PathBuf>,
    /// The registry fetcher, `velarx-registry`; by default the one next to
    /// `velarx`
    #[serde(default)]
    pub registry_path: Option<PathBuf>,
    /// The fetcher of a directory, `velarx-dir`; by default the one next to
    /// `velarx`
    #[serde(default)]
    pub dir_path: Option<PathBuf>,
    /// Worker processes of a pull at the same time, each with its
    /// connection to the registry
    #[serde(default = "default_max_workers")]
    pub max_workers: usize,
    /// Remember, for each registry, how it asks for a token and where its
    /// blobs are served from (`$XDG_CACHE_HOME/velarx`, nothing secret):
    /// the next pull asks the token endpoint at once, and the workers
    /// connect to the CDN before the first range is asked; false: neither
    #[serde(default = "default_true")]
    pub registry_hints: bool,
    /// Where the content comes from, in order: the names of
    /// `[[sources.external]]` and `registry`, the origin.  The list is used
    /// as written, in that order: one without `registry` never asks the
    /// registry.  Every digest a source sends is verified;
    /// a source that fails is skipped and the next one is asked.
    #[serde(default = "default_sources")]
    pub sources: Vec<String>,
    /// Where a tag is resolved to the digest of its manifest, in order: the
    /// names of `[[sources.external]]` and `registry`.  A source that is not
    /// the registry is believed for nothing: the tag is the newest signed
    /// record of a key that policy.json accepts for the name.  What follows
    /// `registry` is not asked.
    #[serde(default = "default_sources")]
    pub names: Vec<String>,
    /// Files of lazily pulled images fetched at the same time by one process
    #[serde(default = "default_lazy_fetches")]
    pub lazy_fetches: usize,
    /// Groups of files the background completion of a lazy pull fetches at
    /// the same time (a pull a `run` or a `pull` waits for fetches
    /// `lazy_fetches` at a time)
    #[serde(default = "default_lazy_complete_fetches")]
    pub lazy_complete_fetches: usize,
    /// Lazy pulls the engine service of the store completes in the
    /// background at the same time; the others are queued (a pull a
    /// container is made on, or a command waits for, is not).  0: none is
    /// completed in the background, only when a command asks for it
    #[serde(default = "default_lazy_completers")]
    pub lazy_completers: usize,
    /// Seconds a completion waits at most between two tries of a fetch that
    /// failed for a reason that may pass (the network, a registry that
    /// answers 5xx or 429); it starts at one and doubles
    #[serde(default = "default_lazy_retry_max_secs")]
    pub lazy_retry_max_secs: u64,
    /// The most connections the fetcher an engine starts serves
    /// at once (`[services] max_connections` is that of the other
    /// services): each monitor of a container with lazy layers holds one
    /// for its life, and one or two more while it fetches.
    #[serde(default = "default_fetcher_connections")]
    pub fetcher_connections: usize,
    /// Files of its directory that follow a file a container missed in its
    /// layer, fetched with it in the background (0: only the file that was
    /// asked for)
    #[serde(default = "default_lazy_window_files")]
    pub lazy_window_files: usize,
    /// KiB of the files of that window at most (0: no window); the window of
    /// a layer starts at 256 KiB and doubles with each miss of the layer
    #[serde(default = "default_lazy_window_kib")]
    pub lazy_window_kib: u64,
    /// Seconds a container of a lazily pulled image is watched for the files
    /// it looks up first, to fetch them first the next time (0: no profile)
    #[serde(default = "default_lazy_profile_secs")]
    pub lazy_profile_secs: u64,
    /// Files a startup profile holds at most
    #[serde(default = "default_lazy_profile_files")]
    pub lazy_profile_files: usize,
    /// A pull of an image this node has no profile for asks the content
    /// sources (the peers) for theirs, and fetches in that order
    #[serde(default = "default_true")]
    pub lazy_profile_peers: bool,
}

fn default_lazy_fetches() -> usize {
    8
}

fn default_lazy_complete_fetches() -> usize {
    4
}

fn default_lazy_completers() -> usize {
    2
}

fn default_lazy_retry_max_secs() -> u64 {
    600
}

fn default_fetcher_connections() -> usize {
    1024
}

fn default_lazy_window_files() -> usize {
    64
}

fn default_lazy_window_kib() -> u64 {
    4096
}

fn default_lazy_profile_secs() -> u64 {
    10
}

fn default_lazy_profile_files() -> usize {
    4096
}

fn default_max_workers() -> usize {
    8
}

fn default_parallel_layers() -> usize {
    6
}

fn default_range_concurrency() -> usize {
    4
}

fn default_pull_memory_mib() -> u64 {
    128
}

fn default_max_layer_gib() -> u64 {
    32
}

fn default_max_inflate_ratio() -> u64 {
    128
}

fn default_inflate_floor_mib() -> u64 {
    64
}

fn default_memory_high_mib() -> u64 {
    768
}

fn default_memory_max_mib() -> u64 {
    1024
}

fn default_pids_max() -> u64 {
    128
}

fn default_min_speed_kib() -> u64 {
    1
}

fn default_min_speed_secs() -> u64 {
    120
}

fn default_pull_idle_secs() -> u64 {
    120
}

fn default_max_archive_gib() -> u64 {
    256
}

fn default_docker_socket() -> PathBuf {
    PathBuf::from("/var/run/docker.sock")
}

impl Default for PullConfig {
    fn default() -> Self {
        Self {
            parallel_layers: default_parallel_layers(),
            range_concurrency: default_range_concurrency(),
            memory_budget_mib: default_pull_memory_mib(),
            workers: 0,
            max_layer_gib: default_max_layer_gib(),
            max_inflate_ratio: default_max_inflate_ratio(),
            inflate_floor_mib: default_inflate_floor_mib(),
            min_speed_kib: default_min_speed_kib(),
            min_speed_secs: default_min_speed_secs(),
            idle_timeout_secs: default_pull_idle_secs(),
            memory_high_mib: default_memory_high_mib(),
            memory_max_mib: default_memory_max_mib(),
            pids_max: default_pids_max(),
            require_cgroup: false,
            max_archive_gib: default_max_archive_gib(),
            docker_socket: default_docker_socket(),
            policy_path: None,
            registries_d: None,
            require_userns: false,
            worker_path: None,
            registry_path: None,
            dir_path: None,
            max_workers: default_max_workers(),
            registry_hints: default_true(),
            sources: default_sources(),
            names: default_sources(),
            lazy_fetches: default_lazy_fetches(),
            lazy_complete_fetches: default_lazy_complete_fetches(),
            lazy_completers: default_lazy_completers(),
            lazy_retry_max_secs: default_lazy_retry_max_secs(),
            fetcher_connections: default_fetcher_connections(),
            lazy_window_files: default_lazy_window_files(),
            lazy_window_kib: default_lazy_window_kib(),
            lazy_profile_secs: default_lazy_profile_secs(),
            lazy_profile_files: default_lazy_profile_files(),
            lazy_profile_peers: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// The unix socket of the REST API (`velarx-api` listens on it unless
    /// it is told otherwise); its directory is the runtime directory of
    /// velarx, where the engine's socket and the services' are.
    #[serde(default = "default_socket")]
    pub socket: PathBuf,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default = "default_root_dir")]
    pub root_dir: PathBuf,
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,
    /// Options passed to every call of the OCI runtime, before its command.
    /// By default none, and `--cgroup-manager disabled` in a rootless daemon
    /// that could not get a delegated cgroup (crun would spend a second per
    /// container trying to enable controllers).
    #[serde(default)]
    pub runtime_args: Vec<String>,
    /// The OCI runtime of the containers, like podman's `--runtime`: a name
    /// (`crun`, `runc`, ...) looked up in PATH and where runtimes are
    /// installed, or an absolute path.  The option of the command line takes
    /// the place of this; the default is crun.
    #[serde(default)]
    pub runtime: Option<String>,
    /// What makes the cgroups of the containers of the server: `cgroupfs`
    /// (the default: below the server's own cgroup) or `systemd` (a
    /// transient scope per container, `velarx-<id>.scope` in
    /// `machine.slice`, or in `user.slice` of the user's manager rootless,
    /// made by the runtime through systemd).
    #[serde(default)]
    pub cgroup_manager: CgroupDriver,
    /// Serve the store service (`org.velarx.Store`, the content of the
    /// store by digest, for the services that give it to others, such as a
    /// source of peers) from the daemon, unless another process serves it
    /// already (systemd, or the service that needs it).
    #[serde(default)]
    pub store_service: bool,
    /// Where the events are kept: `journald`, `file` or `none` (empty: the
    /// journal when it is there, else the file); `--events-backend` takes
    /// its place
    #[serde(default)]
    pub events_logger: String,
    /// The file of the `file` events backend (empty:
    /// `<root_dir>/events/events.log`)
    #[serde(default)]
    pub events_logfile_path: String,
    /// The size past which the events file is rotated (`1m`, `4096`...;
    /// empty or 0: 1 MiB)
    #[serde(default)]
    pub events_logfile_max_size: String,
}

impl ServerConfig {
    /// The events backend `events_logger` makes: journald, file or none
    /// (by default the journal when it is there, else the file).
    pub fn effective_events_logger(&self) -> &str {
        match self.events_logger.as_str() {
            l @ ("journald" | "file" | "none") => l,
            _ if Path::new("/run/systemd/journal/socket").exists() => "journald",
            _ => "file",
        }
    }
}

/// What the command line tells its processes of podman's global options.
pub const ENV_ROOT: &str = "VELARX_ROOT";
pub const ENV_RUNROOT: &str = "VELARX_RUNROOT";
pub const ENV_CGROUP_MANAGER: &str = "VELARX_CGROUP_MANAGER";
/// The flags of `--runtime-flag`, separated by U+001F.
pub const ENV_RUNTIME_FLAGS: &str = "VELARX_RUNTIME_FLAGS";
pub const ENV_RUNTIME: &str = "VELARX_RUNTIME";
pub const ENV_HOOKS_DIR: &str = "VELARX_HOOKS_DIR";
/// The signature policy file of `--signature-policy`.
pub const ENV_SIGNATURE_POLICY: &str = "VELARX_SIGNATURE_POLICY";
pub const ENV_CDI_SPEC_DIRS: &str = "VELARX_CDI_SPEC_DIRS";
pub const ENV_EVENTS_LOGGER: &str = "VELARX_EVENTS_LOGGER";
/// The driver of `--storage-driver`.
pub const ENV_STORAGE_DRIVER: &str = "VELARX_STORAGE_DRIVER";

/// podman's `--runtime`: a path, or a name looked up in PATH and where
/// runtimes are installed; podman's words when there is none.
pub fn find_runtime(name: &str) -> Result<PathBuf, String> {
    let wanted = PathBuf::from(name);
    if wanted.is_absolute() {
        return if wanted.is_file() {
            Ok(wanted)
        } else {
            Err(format!(
                "no valid executable found for OCI runtime {name}: invalid argument"
            ))
        };
    }
    let dirs = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&dirs)
        .chain(["/usr/bin", "/usr/local/bin", "/bin"].map(PathBuf::from))
        .map(|d| d.join(&wanted))
        .find(|p| p.is_file())
        .ok_or_else(|| format!("default OCI runtime \"{name}\" not found: invalid argument"))
}

/// A runtime of `[runtimes]`: the path (or a list of paths, as podman's
/// `[engine.runtimes]` has: the first that is there is the runtime), or a
/// table `{ path = ..., args = [...] }` that adds options for this runtime
/// only (gVisor's `runsc` rootless needs `--rootless --ignore-cgroups`, which
/// no other runtime knows).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RuntimePaths {
    One(PathBuf),
    Many(Vec<PathBuf>),
    Table(RuntimeTable),
}

/// The table form of a runtime of `[runtimes]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTable {
    pub path: RuntimePath,
    /// Options for every call of this runtime, after those of `[server]
    /// runtime_args`.
    #[serde(default)]
    pub args: Vec<String>,
}

/// One path or a list of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RuntimePath {
    One(PathBuf),
    Many(Vec<PathBuf>),
}

impl RuntimePath {
    fn paths(&self) -> &[PathBuf] {
        match self {
            RuntimePath::One(p) => std::slice::from_ref(p),
            RuntimePath::Many(v) => v,
        }
    }
}

impl RuntimePaths {
    pub fn paths(&self) -> &[PathBuf] {
        match self {
            RuntimePaths::One(p) => std::slice::from_ref(p),
            RuntimePaths::Many(v) => v,
            RuntimePaths::Table(t) => t.path.paths(),
        }
    }

    /// The options of this runtime alone.
    pub fn args(&self) -> &[String] {
        match self {
            RuntimePaths::Table(t) => &t.args,
            _ => &[],
        }
    }
}

impl Config {
    /// The runtime of `[runtimes]` named `name`: the first of its paths that
    /// is there; `None` when the table has no such name.  The words of the
    /// failure are podman's.
    pub fn configured_runtime(&self, name: &str) -> Option<Result<PathBuf, String>> {
        let paths = self.runtimes.get(name)?.paths();
        Some(paths.iter().find(|p| p.is_file()).cloned().ok_or_else(|| {
            let list: Vec<_> = paths.iter().map(|p| p.display().to_string()).collect();
            format!(
                "no valid executable found for OCI runtime {name}: {}: invalid argument",
                list.join(", ")
            )
        }))
    }

    /// The options of the runtimes of `[runtimes]` that have their own, by
    /// name.
    pub fn runtime_args_by_name(&self) -> std::collections::HashMap<String, Vec<String>> {
        self.runtimes
            .iter()
            .filter(|(_, entry)| !entry.args().is_empty())
            .map(|(name, entry)| (name.clone(), entry.args().to_vec()))
            .collect()
    }

    /// The name of the default runtime: `--runtime`, else `[server]
    /// runtime`; none for crun.
    pub fn default_runtime(&self) -> Option<&str> {
        self.server.runtime.as_deref()
    }

    /// The runtime asked for by `name` as `--runtime` and `[server] runtime`
    /// say it: one of `[runtimes]`, else a path or a name found in PATH.
    pub fn find_runtime(&self, name: &str) -> Result<PathBuf, String> {
        self.configured_runtime(name)
            .unwrap_or_else(|| find_runtime(name))
    }
}

/// The `cgroup_manager` of the server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CgroupDriver {
    #[default]
    Cgroupfs,
    Systemd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    #[serde(default = "default_storage_root")]
    pub root: PathBuf,
    /// The storage driver: unset or `composefs`, the only one.  Any other
    /// value is an error.
    #[serde(default)]
    pub driver: Option<String>,
    #[serde(default = "default_gc_interval")]
    pub gc_interval_secs: u64,
    /// Enable fs-verity for stored files (requires kernel 5.4+ and supported filesystem)
    #[serde(default = "default_fsverity")]
    pub fsverity: bool,
    /// Every file of the store must have fs-verity: a file whose
    /// fs-verity cannot be enabled fails its pull, and a file without it is
    /// not served; the store must be on a file system that has it
    #[serde(default)]
    pub fsverity_require: bool,
    /// The EROFS images of the layers of root containers mounted by the
    /// kernel: "auto" where it can (root, a kernel that mounts them; FUSE
    /// serves them otherwise), or "off"
    #[serde(default = "default_composefs")]
    pub composefs: String,
    /// Read-only stores of other velarx instances (their roots), under
    /// this one: their images are found and run without a pull, and
    /// nothing in them is ever written or collected.
    #[serde(default)]
    pub additional_image_stores: Vec<PathBuf>,
    /// `system check` takes a file of the store that nothing accounts for
    /// (a temporary file, an object no row names, the staging directory of a
    /// container that is gone) for a leftover once it has been unchanged for
    /// this many seconds: a pull that is running may be writing it.
    #[serde(default = "default_check_leftover_age")]
    pub check_leftover_age_secs: u64,
    /// How a pull or a commit makes its files durable: `syncfs` (the
    /// default: the staging file system before the files get their names,
    /// the store before their rows) or `none`, which leaves them to the
    /// kernel.
    #[serde(default)]
    pub sync: SyncMode,
    /// What a manifest must say of the fs-verity digests of the EROFS
    /// images of its layers (`io.containers.composefs.digest`): "check"
    /// (a list with the digest of the image made here is checked; one
    /// with none is another writer's and ignored) or "require" (every layer
    /// states one of ours)
    #[serde(default)]
    pub composefs_digests: ComposefsDigests,
    /// Whether a start holds the files of an image to the chain of trust
    /// (the digest it was made from, or a signature, down to the files) where
    /// the file system supports it: "auto" (the default), "off" (refused
    /// where signatures or digests are required) or "require" (a start that
    /// cannot hold the chain is refused, and `--security-opt verity=off` too).
    #[serde(default)]
    pub verity_chain: VerityChain,
}

/// The `[storage] verity_chain` setting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerityChain {
    /// Held where the file system supports it and the image has a root of
    /// trust
    #[default]
    Auto,
    /// Held only where the node or the container asks for it by name
    Off,
    /// Held for every start, whatever the image: a start whose image cannot
    /// be held (a layer made without fs-verity, a lazy image, a driver that
    /// checks at pull only, no digest and no accepted signature) is refused
    Require,
}

/// The storage driver of this velarx, the only one: the files named by their
/// fs-verity digest and one EROFS image for each layer.  It is the name in
/// `[storage] driver`, `--storage-driver`, the store and `velarx info`.
pub const STORAGE_DRIVER: &str = "composefs";

/// The `[storage] composefs_digests` setting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComposefsDigests {
    /// A list of digests that has the one of the image made here is
    /// checked; a list with none of them, or no list, is fine
    #[default]
    Check,
    /// Every layer of an image that is pulled or loaded states the one of
    /// the image made here
    Require,
}

impl std::fmt::Display for ComposefsDigests {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Check => "check",
            Self::Require => "require",
        })
    }
}

fn default_check_leftover_age() -> u64 {
    86400
}

fn default_composefs() -> String {
    "auto".into()
}

impl PullConfig {
    /// The largest file a process that fetches writes: a layer (`max_layer_gib`).
    pub fn max_file_bytes(&self) -> u64 {
        self.max_layer_gib.max(1).saturating_mul(1 << 30)
    }
}

#[cfg(feature = "engine")]
impl StorageConfig {
    /// What fs-verity the store has.
    pub fn verity_mode(&self) -> velarx_storage::VerityMode {
        velarx_storage::VerityMode::from_config(self.fsverity, self.fsverity_require)
    }

    /// The store: its objects, with those of the read-only stores under
    /// them, and the durability `sync` asks for.
    pub fn file_store(&self) -> velarx_storage::StoreResult<velarx_storage::FileStore> {
        Ok(velarx_storage::FileStore::new(self.objects_dir())?
            .with_additional(self.additional_objects_dirs())
            .with_sync(self.sync)
            .with_verity(self.verity_mode()))
    }
}

fn default_fsverity() -> bool {
    true
}

impl StorageConfig {
    /// The configuration asks for no other driver than composefs
    /// (`[storage] driver`, `--storage-driver`).
    pub fn check_driver(&self) -> Result<(), ConfigError> {
        match self.driver.as_deref() {
            None | Some(STORAGE_DRIVER) => Ok(()),
            Some(other) => Err(ConfigError::Invalid(format!(
                "the storage driver {other:?} is not available: this velarx has only \
                 {STORAGE_DRIVER:?} ([storage] driver, --storage-driver or \
                 {ENV_STORAGE_DRIVER}; remove the setting to use it)"
            ))),
        }
    }

    /// The driver the store was made with (`recorded`) is composefs: a store
    /// of another driver is not opened.
    pub fn check_recorded_driver(&self, recorded: &str) -> Result<(), ConfigError> {
        if recorded == STORAGE_DRIVER {
            return Ok(());
        }
        Err(ConfigError::Invalid(format!(
            "the store {} was made with the storage driver {recorded:?}, and this velarx has \
             only {STORAGE_DRIVER:?}: use the velarx that made it, or remove the store",
            self.root.display()
        )))
    }

    /// The files of the store, each named by its fs-verity digest
    /// (`ab/cdef...`), as the objects of a composefs-rs repository.
    pub fn objects_dir(&self) -> PathBuf {
        self.root.join("objects")
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.root.join("staging")
    }

    pub fn database_path(&self) -> PathBuf {
        self.root.join("db.sqlite")
    }

    /// The objects of the additional image stores, in their order.
    pub fn additional_objects_dirs(&self) -> Vec<PathBuf> {
        self.additional_image_stores
            .iter()
            .map(|r| r.join("objects"))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserNamespaceConfig {
    /// Ranges (`START-END`) that `--userns=auto` and `private` take ids from
    /// when the daemon runs as root.  Empty: the sub ids of `auto_user` in
    /// `/etc/subuid`.  Rootless the ids of the daemon's user namespace are
    /// used.
    #[serde(default)]
    pub uid_ranges: Vec<String>,
    #[serde(default)]
    pub gid_ranges: Vec<String>,
    /// Number of ids of `--userns=private`
    #[serde(default = "default_allocation_size")]
    pub allocation_size: u32,
    /// The user of `/etc/subuid` and `/etc/subgid` that delegates the ids of
    /// `auto` to a daemon running as root (podman's `root-auto-userns-user`)
    #[serde(default = "default_auto_user")]
    pub auto_user: String,
    /// Smallest size of an automatic user namespace
    #[serde(default = "default_auto_min_size")]
    pub auto_min_size: u32,
    /// Largest size of an automatic user namespace, 0 for no limit
    #[serde(default = "default_auto_max_size")]
    pub auto_max_size: u32,
    /// Serve the files of an image whose owner has no id in the user
    /// namespace as owned by the root of the container (podman's
    /// `ignore_chown_errors`); otherwise such an image does not start
    #[serde(default)]
    pub squash_unmapped_owners: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    #[serde(default)]
    pub bridge: BridgeConfig,
    /// Where the subnets of the bridge networks created without one come
    /// from; none: the /24s of 10.90.0.0/16.
    #[serde(default)]
    pub subnet_pools: Vec<SubnetPool>,
    /// Network providers: services that make the network of the containers
    /// that name them (`--network provider:NAME`), over `org.velarx.Network`
    #[serde(default)]
    pub providers: Vec<NetworkProviderConfig>,
    /// CNI networks (`--network cni:NAME`)
    #[serde(default)]
    pub cni: CniConfig,
}

/// Where the CNI plugins, their configurations and the cache of their results
/// are (a daemon running as root executes the plugins).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CniConfig {
    /// The directory of the network configurations (`.conflist`, `.conf`)
    #[serde(default = "default_cni_conf_dir")]
    pub conf_dir: PathBuf,
    /// The directories of the plugins, searched in this order
    #[serde(default = "default_cni_bin_dirs")]
    pub bin_dirs: Vec<PathBuf>,
    /// The directory of the cache of the results (libcni's format, `results/` below;
    /// the daemon releases the attachments of the containers it does not know)
    #[serde(default = "default_cni_cache_dir")]
    pub cache_dir: PathBuf,
    /// Seconds a plugin may take for a command before it is killed
    #[serde(default = "default_cni_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for CniConfig {
    fn default() -> Self {
        Self {
            conf_dir: default_cni_conf_dir(),
            bin_dirs: default_cni_bin_dirs(),
            cache_dir: default_cni_cache_dir(),
            timeout_secs: default_cni_timeout_secs(),
        }
    }
}

fn default_cni_conf_dir() -> PathBuf {
    "/etc/cni/net.d".into()
}

fn default_cni_bin_dirs() -> Vec<PathBuf> {
    vec!["/opt/cni/bin".into(), "/usr/libexec/cni".into()]
}

fn default_cni_cache_dir() -> PathBuf {
    "/var/lib/velarx/cni".into()
}

fn default_cni_timeout_secs() -> u64 {
    60
}

/// A network provider: a separate process that serves `org.velarx.Network`
/// on a unix socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkProviderConfig {
    /// The name that `--network provider:NAME` uses
    pub name: String,
    /// The unix socket of the provider, an absolute path.  The provider
    /// must run as the user of the process that asks, or as root.
    pub socket: PathBuf,
}

/// A pool of subnets: the subnets of SIZE bits of prefix in BASE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubnetPool {
    pub base: String,
    pub size: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeConfig {
    #[serde(default = "default_bridge_name")]
    pub default_bridge: String,
    #[serde(default = "default_bridge_subnet")]
    pub subnet: String,
    #[serde(default = "default_bridge_gateway")]
    pub gateway: String,
}

pub use velarx_base::dirs::DefaultDirs;

fn default_sources() -> Vec<String> {
    vec!["registry".to_string()]
}

fn default_true() -> bool {
    true
}

/// The directories of this process for the defaults of a setting, which
/// cannot fail: the processes that read a configuration have asked for their
/// ids at their start ([`velarx_base::ids::settle`]), so this is where a
/// host without `/proc` is reported if nothing did before.
fn current_dirs() -> DefaultDirs {
    DefaultDirs::current().unwrap_or_else(|e| e.exit())
}

fn default_socket() -> PathBuf {
    current_dirs().run.join("velarx.sock")
}

fn default_state_dir() -> PathBuf {
    current_dirs().run
}

fn default_root_dir() -> PathBuf {
    current_dirs().data
}

fn default_shutdown_timeout() -> u64 {
    30
}

fn default_storage_root() -> PathBuf {
    current_dirs().data
}

fn default_gc_interval() -> u64 {
    3600
}

fn default_auto_user() -> String {
    "containers".to_string()
}

fn default_auto_min_size() -> u32 {
    1024
}

fn default_auto_max_size() -> u32 {
    65536
}

fn default_allocation_size() -> u32 {
    65536
}

fn default_bridge_name() -> String {
    "velarx0".to_string()
}

fn default_bridge_subnet() -> String {
    "10.90.0.0/24".to_string()
}

fn default_bridge_gateway() -> String {
    "10.90.0.1".to_string()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            socket: default_socket(),
            state_dir: default_state_dir(),
            root_dir: default_root_dir(),
            shutdown_timeout_secs: default_shutdown_timeout(),
            runtime_args: Vec::new(),
            runtime: None,
            cgroup_manager: CgroupDriver::default(),
            store_service: false,
            events_logger: String::new(),
            events_logfile_path: String::new(),
            events_logfile_max_size: String::new(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            root: default_storage_root(),
            driver: None,
            gc_interval_secs: default_gc_interval(),
            fsverity: default_fsverity(),
            fsverity_require: false,
            composefs: default_composefs(),
            additional_image_stores: Vec::new(),
            check_leftover_age_secs: default_check_leftover_age(),
            sync: SyncMode::default(),
            composefs_digests: ComposefsDigests::default(),
            verity_chain: VerityChain::default(),
        }
    }
}

impl Default for UserNamespaceConfig {
    fn default() -> Self {
        Self {
            uid_ranges: Vec::new(),
            gid_ranges: Vec::new(),
            allocation_size: default_allocation_size(),
            auto_user: default_auto_user(),
            auto_min_size: default_auto_min_size(),
            auto_max_size: default_auto_max_size(),
            squash_unmapped_owners: false,
        }
    }
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            default_bridge: default_bridge_name(),
            subnet: default_bridge_subnet(),
            gateway: default_bridge_gateway(),
        }
    }
}

impl Config {
    /// The directory of the private sockets between the daemon and its
    /// helpers (mode 0700, next to the daemon socket)
    pub fn services_dir(&self) -> PathBuf {
        self.server
            .socket
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("services")
    }

    /// Socket of the engine service (`org.velarx.Engine`)
    pub fn engine_socket(&self) -> PathBuf {
        self.engine.socket.clone().unwrap_or_else(|| {
            self.server
                .socket
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("engine/engine.sock")
        })
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }

    /// Load config from path, returning default if file doesn't exist.
    /// Returns error if file exists but can't be read or parsed, or if
    /// whether it exists can't be told.
    /// What podman's global options say (`--root`, `--runroot`,
    /// `--cgroup-manager`, `--runtime-flag`, `--hooks-dir`,
    /// `--events-backend`, which the command line gives its processes in
    /// the environment) takes the place of the file's.
    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let mut config = if path.try_exists()? {
            Self::load(path)?
        } else {
            Self::default()
        };
        config.apply_global_options(|name| std::env::var_os(name).filter(|v| !v.is_empty()))?;
        Ok(config)
    }

    /// The settings of podman's global options.
    fn apply_global_options(
        &mut self,
        env: impl Fn(&str) -> Option<std::ffi::OsString>,
    ) -> Result<(), ConfigError> {
        let root = env(ENV_ROOT).map(PathBuf::from);
        let mut runroot = env(ENV_RUNROOT).map(PathBuf::from);
        if let Some(root) = root.filter(|r| *r != self.storage.root) {
            // (a store has a run root of its own: its server, its monitors
            // and networks; another store's are never mixed with them)
            if runroot.is_none() {
                use sha2::Digest;
                let digest = hex::encode(sha2::Sha256::digest(root.as_os_str().as_encoded_bytes()));
                runroot = Some(
                    self.server
                        .state_dir
                        .join(format!("root-{}", &digest[..16])),
                );
            }
            self.storage.root = root.clone();
            self.server.root_dir = root;
        }
        if let Some(run) = runroot {
            // (the server of another run root is another one)
            self.server.socket = run.join("velarx.sock");
            self.engine.socket = Some(run.join("engine.sock"));
            self.server.state_dir = run;
        }
        match env(ENV_CGROUP_MANAGER).as_deref().and_then(|m| m.to_str()) {
            Some("systemd") => self.server.cgroup_manager = CgroupDriver::Systemd,
            Some("cgroupfs") => self.server.cgroup_manager = CgroupDriver::Cgroupfs,
            Some(m) => {
                return Err(ConfigError::Invalid(format!(
                    "{ENV_CGROUP_MANAGER}={m}: the cgroup manager is systemd or cgroupfs"
                )))
            }
            None => {}
        }
        if let Some(r) = env(ENV_RUNTIME) {
            self.server.runtime = Some(r.to_string_lossy().into_owned());
        }
        if let Some(dirs) = env(ENV_HOOKS_DIR) {
            self.containers.hooks_dir = std::env::split_paths(&dirs)
                .map(|d| d.to_string_lossy().into_owned())
                .collect();
        }
        if let Some(dirs) = env(ENV_CDI_SPEC_DIRS) {
            self.containers.cdi_spec_dirs = std::env::split_paths(&dirs)
                .map(|d| d.to_string_lossy().into_owned())
                .collect();
        }
        if let Some(p) = env(ENV_SIGNATURE_POLICY) {
            self.pull.policy_path = Some(PathBuf::from(p));
        }
        if let Some(l) = env(ENV_EVENTS_LOGGER) {
            self.server.events_logger = l.to_string_lossy().into_owned();
        }
        if let Some(d) = env(ENV_STORAGE_DRIVER) {
            self.storage.driver = Some(d.to_string_lossy().into_owned());
        }
        if let Some(flags) = env(ENV_RUNTIME_FLAGS) {
            self.server.runtime_args.extend(
                flags
                    .to_string_lossy()
                    .split('\u{1f}')
                    .filter(|f| !f.is_empty())
                    .map(|f| format!("--{f}")),
            );
        }
        Ok(())
    }

    /// Refuse settings that do not mean what they say.  The processes that
    /// act on them (the daemon, the services) call this after loading; the
    /// client only reads the socket and does not carry the checks.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(runtime) = &self.server.runtime {
            if let Err(e) = self.find_runtime(runtime) {
                return Err(ConfigError::Invalid(format!("[server] runtime: {e}")));
            }
        }
        self.storage.check_driver()?;
        let c = &self.containers.cgroups;
        if !c.is_empty() && !CGROUPS_MODES.contains(&c.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "[containers] cgroups = {c:?}: one of {}",
                CGROUPS_MODES.join(", ")
            )));
        }
        let s = &self.containers.image_signature;
        if !matches!(s.as_str(), "policy" | "require") {
            return Err(ConfigError::Invalid(format!(
                "[containers] image_signature = {s:?}: policy or require"
            )));
        }
        if self.storage.verity_chain == VerityChain::Off {
            let required = match (
                &self.containers.image_signature[..],
                self.storage.composefs_digests,
            ) {
                ("require", _) => "[containers] image_signature = \"require\"",
                (_, ComposefsDigests::Require) => "[storage] composefs_digests = \"require\"",
                _ => "",
            };
            if !required.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "[storage] verity_chain = \"off\": {required} is held by the chain of trust, which cannot be turned off, and every start would be refused"
                )));
            }
        }
        let l = &self.server.events_logger;
        if !matches!(l.as_str(), "" | "journald" | "file" | "none") {
            return Err(ConfigError::Invalid(format!(
                "[server] events_logger = {l:?}: journald, file or none"
            )));
        }
        let m = &self.server.events_logfile_max_size;
        if !m.is_empty() && parse_size(m).is_none() {
            return Err(ConfigError::Invalid(format!(
                "[server] events_logfile_max_size = {m:?}: a size (4096, 1m...)"
            )));
        }
        if let Some(e) = self
            .build
            .insecure_entitlements
            .iter()
            .enumerate()
            .find_map(|(i, e)| {
                self.build.insecure_entitlements[..i]
                    .contains(e)
                    .then_some(e)
            })
        {
            return Err(ConfigError::Invalid(format!(
                "[build] insecure_entitlements: `{e}` is listed twice"
            )));
        }
        if self.pull.idle_timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "[pull] idle_timeout_secs must not be 0".into(),
            ));
        }
        self.validate_network_providers()?;
        self.validate_cni()?;
        self.validate_sources()?;
        self.validate_sinks()
    }

    fn validate_cni(&self) -> Result<(), ConfigError> {
        let invalid = |msg: String| Err(ConfigError::Invalid(msg));
        let cni = &self.network.cni;
        let paths = std::iter::once(("conf_dir", &cni.conf_dir))
            .chain(std::iter::once(("cache_dir", &cni.cache_dir)))
            .chain(cni.bin_dirs.iter().map(|d| ("bin_dirs", d)));
        for (what, path) in paths {
            if !path.is_absolute() {
                return invalid(format!(
                    "[network.cni] {what}: `{}` is not an absolute path",
                    path.display()
                ));
            }
        }
        if cni.timeout_secs == 0 {
            return invalid("[network.cni] timeout_secs is at least 1".to_string());
        }
        Ok(())
    }

    fn validate_network_providers(&self) -> Result<(), ConfigError> {
        let invalid = |msg: String| Err(ConfigError::Invalid(msg));
        let mut seen: Vec<&str> = Vec::new();
        for provider in &self.network.providers {
            let name = provider.name.as_str();
            if !valid_name(name) {
                return invalid(format!(
                    "[[network.providers]] name `{name}`: use 1 to 32 of a-z, 0-9, - and _"
                ));
            }
            if seen.contains(&name) {
                return invalid(format!("[[network.providers]] `{name}` is defined twice"));
            }
            if !provider.socket.is_absolute() {
                return invalid(format!(
                    "[[network.providers]] `{name}`: `{}` is not an absolute path",
                    provider.socket.display()
                ));
            }
            seen.push(name);
        }
        Ok(())
    }

    fn validate_sinks(&self) -> Result<(), ConfigError> {
        let invalid = |msg: String| Err(ConfigError::Invalid(msg));
        let mut defined: Vec<&str> = Vec::new();
        for sink in &self.sinks.external {
            let name = sink.name.as_str();
            if !valid_name(name) {
                return invalid(format!(
                    "[[sinks.external]] name `{name}`: use 1 to 32 of a-z, 0-9, - and _"
                ));
            }
            if BUILTIN_SINKS.contains(&name) {
                return invalid(format!(
                    "[[sinks.external]] name `{name}` is taken by a built-in sink"
                ));
            }
            if defined.contains(&name) {
                return invalid(format!("[[sinks.external]] `{name}` is defined twice"));
            }
            check_reach(
                &format!("[[sinks.external]] `{name}`"),
                sink.socket.as_deref(),
                &sink.command,
            )?;
            if sink.idle_timeout_secs == 0 {
                return invalid(format!(
                    "[[sinks.external]] `{name}`: idle_timeout_secs must not be 0"
                ));
            }
            defined.push(name);
        }
        let push = &self.push;
        if push.parallel_layers == 0 || push.chunk_mib == 0 {
            return invalid("[push] parallel_layers and chunk_mib must not be 0".into());
        }
        if let Some(c) = &push.compression {
            if !matches!(c.as_str(), "gzip" | "zstd" | "zstd:chunked" | "none") {
                return invalid(format!(
                    "[push] compression: `{c}` is not gzip, zstd, zstd:chunked or none"
                ));
            }
        }
        if let Some(list) = &push.sinks {
            let mut seen: Vec<&str> = Vec::new();
            for name in list {
                let name = name.as_str();
                if seen.contains(&name) {
                    return invalid(format!("[push] sinks lists `{name}` twice"));
                }
                seen.push(name);
                if BUILTIN_SINKS.contains(&name) {
                    return invalid(format!(
                        "[push] sinks: `{name}` is the destination's own pusher, the engine adds it: list helper sinks only"
                    ));
                }
                if !defined.contains(&name) {
                    return invalid(format!(
                        "[push] sinks: unknown sink `{name}` (defined in [[sinks.external]]: {})",
                        if defined.is_empty() {
                            "none".to_string()
                        } else {
                            defined.join(", ")
                        }
                    ));
                }
            }
        }
        self.validate_transports()
    }

    fn validate_transports(&self) -> Result<(), ConfigError> {
        let invalid = |msg: String| Err(ConfigError::Invalid(msg));
        let mut seen: Vec<&str> = Vec::new();
        for transport in &self.transports {
            let scheme = transport.scheme.as_str();
            let shaped = scheme.len() <= 32
                && scheme.starts_with(|c: char| c.is_ascii_lowercase())
                && scheme
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+.-".contains(&b));
            if !shaped {
                return invalid(format!(
                    "[[transports]] scheme `{scheme}`: use a lowercase letter, then at most 31 of a-z, 0-9, +, . and -"
                ));
            }
            if velarx_types::transport::ImageLocation::is_transport_name(scheme) {
                return invalid(format!(
                    "[[transports]] scheme `{scheme}` is a transport velarx has"
                ));
            }
            if seen.contains(&scheme) {
                return invalid(format!("[[transports]] `{scheme}` is defined twice"));
            }
            check_reach(
                &format!("[[transports]] `{scheme}`"),
                transport.socket.as_deref(),
                &transport.command,
            )?;
            if transport.idle_timeout_secs == 0 {
                return invalid(format!(
                    "[[transports]] `{scheme}`: idle_timeout_secs must not be 0"
                ));
            }
            seen.push(scheme);
        }
        Ok(())
    }

    fn validate_sources(&self) -> Result<(), ConfigError> {
        let invalid = |msg: String| Err(ConfigError::Invalid(msg));
        let mut defined: Vec<&str> = Vec::new();
        for source in &self.sources.external {
            let name = source.name.as_str();
            if !valid_name(name) {
                return invalid(format!(
                    "[[sources.external]] name `{name}`: use 1 to 32 of a-z, 0-9, - and _"
                ));
            }
            if BUILTIN_SOURCES.contains(&name) {
                return invalid(format!(
                    "[[sources.external]] name `{name}` is taken by a built-in source"
                ));
            }
            if defined.contains(&name) {
                return invalid(format!("[[sources.external]] `{name}` is defined twice"));
            }
            let what = format!("[[sources.external]] `{name}`");
            let given = [
                source.socket.is_some(),
                !source.command.is_empty(),
                source.dir.is_some(),
            ];
            if given.iter().filter(|g| **g).count() != 1 {
                return invalid(format!(
                    "{what}: give a socket, a command or a dir, one of them"
                ));
            }
            match &source.dir {
                Some(dir) if !dir.is_absolute() => {
                    return invalid(format!(
                        "{what}: `{}` is not an absolute path",
                        dir.display()
                    ))
                }
                Some(_) => {}
                None => check_reach(&what, source.socket.as_deref(), &source.command)?,
            }
            if source.idle_timeout_secs == 0 {
                return invalid(format!(
                    "[[sources.external]] `{name}`: idle_timeout_secs must not be 0"
                ));
            }
            defined.push(name);
        }
        let pull = &self.pull;
        if pull.lazy_fetches == 0
            || pull.lazy_complete_fetches == 0
            || pull.lazy_retry_max_secs == 0
        {
            return invalid("[pull] lazy_* settings must not be 0".into());
        }
        for (key, list) in [("sources", &pull.sources), ("names", &pull.names)] {
            for name in list {
                let name = name.as_str();
                if name != "registry" && !defined.contains(&name) {
                    let mut known = vec!["registry"];
                    known.extend(defined.iter().copied());
                    return invalid(format!(
                        "[pull] {key}: unknown source `{name}` (known: {})",
                        known.join(", ")
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use velarx_types::digest::Algorithm;

    #[test]
    fn a_config_that_cannot_be_looked_up_is_an_error_not_the_defaults() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Config::load_or_default(dir.path().join("none.toml")).is_ok());
        let file = dir.path().join("file");
        std::fs::write(&file, "").unwrap();
        // (a regular file is no directory: the lookup fails, root or not)
        let e = Config::load_or_default(file.join("velarx.toml")).unwrap_err();
        assert!(matches!(e, ConfigError::ReadError(_)), "{e}");
    }

    fn dirs(rootful: bool, env: &[(&str, &str)]) -> DefaultDirs {
        let env: HashMap<_, _> = env.iter().copied().collect();
        DefaultDirs::resolve(rootful, |n| env.get(n).map(PathBuf::from))
    }

    const USER: &[(&str, &str)] = &[
        ("HOME", "/home/u"),
        ("XDG_DATA_HOME", "/home/u/.local/share"),
        ("XDG_CONFIG_HOME", "/home/u/.config"),
        ("XDG_RUNTIME_DIR", "/run/user/1000"),
        ("XDG_STATE_HOME", "/home/u/.local/state"),
        ("SUDO_USER", "u"),
    ];

    fn storage_with(driver: Option<&str>) -> StorageConfig {
        StorageConfig {
            root: "/s/store".into(),
            driver: driver.map(String::from),
            ..StorageConfig::default()
        }
    }

    #[test]
    fn composefs_is_the_storage_driver_when_none_is_named_or_it_is() {
        assert_eq!(parse("").unwrap().storage.driver, None);
        storage_with(None).check_driver().unwrap();
        storage_with(Some("composefs")).check_driver().unwrap();
        parse("[storage]\ndriver = \"composefs\"\n")
            .unwrap()
            .validate()
            .unwrap();
        storage_with(None)
            .check_recorded_driver("composefs")
            .unwrap();
    }

    #[test]
    fn another_storage_driver_is_refused_naming_the_one_there_is() {
        for other in ["vfs", "varlink", "overlay", "zfs"] {
            // [storage] driver
            let e = parse(&format!("[storage]\ndriver = \"{other}\"\n"))
                .unwrap_err()
                .to_string();
            assert!(
                e.contains(&format!("{other:?} is not available"))
                    && e.contains("only \"composefs\""),
                "{e}"
            );
            // --storage-driver and its variable say it the same way, and win
            // over the file
            let mut c = parse("[storage]\ndriver = \"composefs\"\n").unwrap();
            c.apply_global_options(|n| (n == ENV_STORAGE_DRIVER).then(|| other.into()))
                .unwrap();
            assert_eq!(c.storage.driver.as_deref(), Some(other));
            let e = c.validate().unwrap_err().to_string();
            assert!(e.contains(&format!("{other:?} is not available")), "{e}");
        }
    }

    #[test]
    fn a_store_of_another_driver_is_not_opened() {
        for recorded in ["vfs", "varlink", "overlay", "zfs"] {
            let e = storage_with(None)
                .check_recorded_driver(recorded)
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("/s/store")
                    && e.contains(&format!("storage driver {recorded:?}"))
                    && e.contains("only \"composefs\""),
                "{e}"
            );
        }
    }

    #[test]
    fn rootful_ignores_the_home_of_the_user_sudo_came_from() {
        for env in [USER, &[][..]] {
            let d = dirs(true, env);
            assert_eq!(d.data, PathBuf::from("/var/lib/velarx"));
            assert_eq!(d.run, PathBuf::from("/run/velarx"));
            assert_eq!(d.config_file, PathBuf::from("/etc/velarx/config.toml"));
        }
    }

    #[test]
    fn rootless_follows_xdg_then_home() {
        let d = dirs(false, USER);
        assert_eq!(d.data, PathBuf::from("/home/u/.local/share/velarx"));
        assert_eq!(d.run, PathBuf::from("/run/user/1000/velarx"));
        assert_eq!(
            d.config_file,
            PathBuf::from("/home/u/.config/velarx/config.toml")
        );
        let d = dirs(false, &[("HOME", "/home/v")]);
        assert_eq!(d.data, PathBuf::from("/home/v/.local/share/velarx"));
        assert_eq!(d.run, PathBuf::from("/run/velarx"));
        assert_eq!(
            d.config_file,
            PathBuf::from("/home/v/.config/velarx/config.toml")
        );
        let d = dirs(false, &[]);
        assert_eq!(d.data, PathBuf::from("/var/lib/velarx"));
        assert_eq!(d.config_file, PathBuf::from("/etc/velarx/config.toml"));
    }

    #[test]
    fn the_config_file_wins_over_the_defaults_in_both_modes() {
        // (the defaults are what serde fills in when the file says nothing)
        let c = parse("[server]\nsocket = \"/x/s.sock\"\nstate_dir = \"/x/run\"\nroot_dir = \"/x/d\"\n[storage]\nroot = \"/x/store\"\n").unwrap();
        assert_eq!(c.server.socket, PathBuf::from("/x/s.sock"));
        assert_eq!(c.server.state_dir, PathBuf::from("/x/run"));
        assert_eq!(c.server.root_dir, PathBuf::from("/x/d"));
        assert_eq!(c.storage.root, PathBuf::from("/x/store"));
    }

    use super::*;

    fn parse(text: &str) -> Result<Config, ConfigError> {
        let config: Config = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn podman_s_global_options_take_the_place_of_the_file() {
        let mut c =
            parse("[server]\nsocket = \"/x/s.sock\"\n[storage]\nroot = \"/x/store\"\n").unwrap();
        let env = |name: &str| match name {
            ENV_ROOT => Some("/g/root".into()),
            ENV_RUNROOT => Some("/o/run".into()),
            ENV_CGROUP_MANAGER => Some("systemd".into()),
            ENV_RUNTIME => Some("/o/crun".into()),
            ENV_RUNTIME_FLAGS => Some("debug\u{1f}log-format=json".into()),
            ENV_HOOKS_DIR => Some("/h1:/h2".into()),
            ENV_CDI_SPEC_DIRS => Some("/c1:/c2".into()),
            ENV_EVENTS_LOGGER => Some("file".into()),
            ENV_SIGNATURE_POLICY => Some("/p/policy.json".into()),
            _ => None,
        };
        c.apply_global_options(env).unwrap();
        assert_eq!(c.storage.root, PathBuf::from("/g/root"));
        assert_eq!(c.server.root_dir, PathBuf::from("/g/root"));
        assert_eq!(c.server.state_dir, PathBuf::from("/o/run"));
        assert_eq!(c.server.socket, PathBuf::from("/o/run/velarx.sock"));
        assert_eq!(c.server.cgroup_manager, CgroupDriver::Systemd);
        assert_eq!(c.server.runtime_args, ["--debug", "--log-format=json"]);
        assert_eq!(c.server.runtime.as_deref(), Some("/o/crun"));
        assert_eq!(c.containers.hooks_dir, ["/h1", "/h2"]);
        assert_eq!(c.containers.cdi_spec_dirs, ["/c1", "/c2"]);
        assert_eq!(c.server.events_logger, "file");
        assert_eq!(c.pull.policy_path, Some(PathBuf::from("/p/policy.json")));
        let e = Config::default()
            .apply_global_options(|n| (n == ENV_CGROUP_MANAGER).then(|| "bogus".into()))
            .unwrap_err();
        assert!(e.to_string().contains("bogus"));
    }

    #[test]
    fn the_container_defaults_and_the_events_settings() {
        let c = parse(
            "[containers]\ncgroups = \"disabled\"\nnetns = \"host\"\nno_hosts = true\n\
             detach_keys = \"ctrl-a\"\ncdi_spec_dirs = [\"/cdi\"]\n\
             [server]\nevents_logger = \"file\"\nevents_logfile_max_size = \"2m\"\n\
             [api]\ncompat_api_enforce_docker_hub = false\n",
        )
        .unwrap();
        assert_eq!(c.containers.cgroups, "disabled");
        assert_eq!(c.containers.netns, "host");
        assert!(c.containers.no_hosts);
        assert_eq!(c.containers.detach_keys.as_deref(), Some("ctrl-a"));
        assert_eq!(c.containers.cdi_spec_dirs, ["/cdi"]);
        assert_eq!(c.server.effective_events_logger(), "file");
        assert!(!c.api.compat_api_enforce_docker_hub);
        assert!(Config::default().api.compat_api_enforce_docker_hub);
        for (text, what) in [
            ("[containers]\ncgroups = \"off\"\n", "[containers] cgroups"),
            ("[server]\nevents_logger = \"x\"\n", "events_logger"),
            (
                "[server]\nevents_logfile_max_size = \"x\"\n",
                "events_logfile_max_size",
            ),
        ] {
            let e = parse(text).unwrap_err().to_string();
            assert!(e.contains(what), "{text}: {e}");
        }
    }

    #[test]
    fn the_oci_runtime_of_the_file_must_be_there() {
        assert_eq!(parse("").unwrap().server.runtime, None);
        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path().join("runc");
        std::fs::File::create(&runtime).unwrap();
        let c = parse(&format!("[server]\nruntime = {:?}\n", runtime)).unwrap();
        assert_eq!(c.server.runtime.as_deref(), runtime.to_str());
        // the option of the command line takes the place of the file's
        let mut c = c;
        c.apply_global_options(|name| (name == ENV_RUNTIME).then(|| "/o/crun".into()))
            .unwrap();
        assert_eq!(c.server.runtime.as_deref(), Some("/o/crun"));
        let e = parse("[server]\nruntime = \"/no/such/runtime\"\n").unwrap_err();
        assert!(
            e.to_string().contains("[server] runtime"),
            "{e} says nothing of [server] runtime"
        );
    }

    #[test]
    fn a_runtime_table_has_the_options_of_its_runtime_alone() {
        let dir = tempfile::tempdir().unwrap();
        let runsc = dir.path().join("runsc");
        let runc = dir.path().join("runc");
        // not executed
        std::fs::write(&runsc, "#!/bin/sh\n").unwrap();
        // not executed
        std::fs::write(&runc, "#!/bin/sh\n").unwrap();
        let c = parse(&format!(
            "[runtimes]\nrunc = {runc:?}\n[runtimes.runsc]\npath = [\"/no/such\", {runsc:?}]\n\
             args = [\"--rootless\", \"--ignore-cgroups\"]\n",
        ))
        .unwrap();
        assert_eq!(c.find_runtime("runsc"), Ok(runsc.clone()));
        assert_eq!(c.find_runtime("runc"), Ok(runc.clone()));
        let by_name = c.runtime_args_by_name();
        assert_eq!(by_name.len(), 1);
        assert_eq!(by_name["runsc"], ["--rootless", "--ignore-cgroups"]);
        // a table takes no other key
        assert!(parse("[runtimes.x]\npath = \"/x\"\nflags = []\n").is_err());
    }

    #[test]
    fn the_runtimes_of_the_configuration_are_found_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let kata = dir.path().join("kata-runtime");
        // not executed
        std::fs::write(&kata, "#!/bin/sh\n").unwrap();
        let c = parse(&format!(
            "[runtimes]\nkata = \"{}\"\ngone = \"{}/gone\"\n",
            kata.display(),
            dir.path().display()
        ))
        .unwrap();
        assert_eq!(c.find_runtime("kata"), Ok(kata.clone()));
        // a name of the table whose file is not there is an error that says so
        let e = c.find_runtime("gone").unwrap_err();
        assert!(e.contains("gone") && e.contains("invalid argument"), "{e}");
        // a path, and a name that is neither
        assert_eq!(c.find_runtime(&kata.to_string_lossy()), Ok(kata.clone()));
        assert!(c.find_runtime("no-such-runtime-xyz").is_err());
        assert!(Config::default().runtimes.is_empty());
        // podman's shape: a list of paths, the first that is there
        let c = parse(&format!(
            "[server]\nruntime = \"kata\"\n[runtimes]\nkata = [\"/no/such\", {:?}]\n",
            kata
        ))
        .unwrap();
        assert_eq!(c.find_runtime("kata"), Ok(kata.clone()));
        // [server] runtime names one of the table, and one of the table
        // that is not there is refused at startup
        assert!(parse("[server]\nruntime = \"k\"\n[runtimes]\nk = [\"/no/such\"]\n").is_err());
    }

    #[test]
    fn another_root_without_a_run_root_has_a_run_root_of_its_own() {
        let mut c =
            parse("[server]\nstate_dir = \"/x/run\"\n[storage]\nroot = \"/x/store\"\n").unwrap();
        c.apply_global_options(|name| (name == ENV_ROOT).then(|| "/o/store".into()))
            .unwrap();
        assert_eq!(c.storage.root, PathBuf::from("/o/store"));
        let run = c.server.state_dir.clone();
        assert_eq!(run.parent(), Some(Path::new("/x/run")));
        assert!(run
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("root-"));
        assert_eq!(c.server.socket, run.join("velarx.sock"));
        // the root of the file is not another one
        let mut c =
            parse("[server]\nstate_dir = \"/x/run\"\n[storage]\nroot = \"/x/store\"\n").unwrap();
        c.apply_global_options(|name| (name == ENV_ROOT).then(|| "/x/store".into()))
            .unwrap();
        assert_eq!(c.server.state_dir, PathBuf::from("/x/run"));
    }

    #[test]
    fn composefs_digests_is_check_unless_the_storage_says_require() {
        assert_eq!(
            parse("").unwrap().storage.composefs_digests,
            ComposefsDigests::Check
        );
        let get = |v: &str| parse(&format!("[storage]\ncomposefs_digests = \"{v}\"\n"));
        assert_eq!(
            get("check").unwrap().storage.composefs_digests,
            ComposefsDigests::Check
        );
        assert_eq!(
            get("require").unwrap().storage.composefs_digests,
            ComposefsDigests::Require
        );
        for bad in ["on", "Require", "enforce"] {
            let err = get(bad).unwrap_err().to_string();
            assert!(
                err.contains("`check`") && err.contains("`require`"),
                "{err}"
            );
        }
        assert_eq!(ComposefsDigests::Require.to_string(), "require");
    }

    #[test]
    fn the_verity_chain_is_held_unless_the_storage_says_off() {
        assert_eq!(parse("").unwrap().storage.verity_chain, VerityChain::Auto);
        let get = |v: &str| parse(&format!("[storage]\nverity_chain = \"{v}\"\n"));
        assert_eq!(get("auto").unwrap().storage.verity_chain, VerityChain::Auto);
        assert_eq!(get("off").unwrap().storage.verity_chain, VerityChain::Off);
        assert_eq!(
            get("require").unwrap().storage.verity_chain,
            VerityChain::Require
        );
        for bad in ["on", "Off", "enforce"] {
            let err = get(bad).unwrap_err().to_string();
            assert!(err.contains("`auto`") && err.contains("`require`"), "{err}");
        }
        // off with what is required of the images: every start would be
        // refused, so the engine does not start
        for (text, key) in [
            (
                "[containers]\nimage_signature = \"require\"\n[storage]\nverity_chain = \"off\"\n",
                "image_signature",
            ),
            (
                "[storage]\ncomposefs_digests = \"require\"\nverity_chain = \"off\"\n",
                "composefs_digests",
            ),
        ] {
            let err = parse(text).unwrap_err().to_string();
            assert!(err.contains("verity_chain") && err.contains(key), "{err}");
            assert!(parse(&text.replace("off", "auto")).is_ok());
        }
    }

    #[test]
    fn sync_is_syncfs_unless_the_storage_says_none() {
        assert_eq!(parse("").unwrap().storage.sync, SyncMode::Syncfs);
        let sync = |v: &str| parse(&format!("[storage]\nsync = \"{v}\"\n"));
        assert_eq!(sync("syncfs").unwrap().storage.sync, SyncMode::Syncfs);
        assert_eq!(sync("none").unwrap().storage.sync, SyncMode::None);
        for bad in ["fsync", "None", "false"] {
            let err = sync(bad).unwrap_err().to_string();
            assert!(err.contains("`syncfs`") && err.contains("`none`"), "{err}");
        }
        assert_eq!(SyncMode::None.to_string(), "none");
        assert_eq!(SyncMode::Syncfs.to_string(), "syncfs");
    }

    #[test]
    fn test_the_sources_default_to_the_registry() {
        assert_eq!(parse("").unwrap().pull.sources, ["registry"]);
        // A list is used as written, the empty one too.
        let config = parse("[pull]\nsources = []\n").unwrap();
        assert!(config.pull.sources.is_empty());
        let config = parse("[pull]\nsources = [\"registry\"]\n").unwrap();
        assert_eq!(config.pull.sources, ["registry"]);
    }

    #[test]
    fn test_the_names_default_to_the_registry_and_are_sources() {
        assert_eq!(parse("").unwrap().pull.names, ["registry"]);
        let config = parse(&format!(
            "{EXTERNAL}[pull]\nnames = [\"cache\", \"registry\"]\n"
        ))
        .unwrap();
        assert_eq!(config.pull.names, ["cache", "registry"]);
        let e = parse("[pull]\nnames = [\"ipfs\"]\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("[pull] names: unknown source `ipfs`"), "{e}");
    }

    const EXTERNAL: &str = "[[sources.external]]\nname = \"cache\"\nsocket = \"/run/cache.sock\"\n";

    const SINK: &str = "[[sinks.external]]\nname = \"backup\"\nsocket = \"/run/backup.sock\"\n";

    /// A transport is a top level table for both directions; the old place
    /// under `[push]` is not read.
    #[test]
    fn test_transports_are_one_table_for_both_directions() {
        let config = parse("[[transports]]\nscheme = \"s3\"\nsocket = \"/run/s3.sock\"\n").unwrap();
        assert_eq!(config.transports[0].scheme, "s3");
        assert_eq!(config.transports[0].idle_timeout_secs, 15);
        assert!(!config.transports[0].credentials);
        let old = "[[push.transports]]\nscheme = \"s3\"\nsocket = \"/run/s3.sock\"\n";
        assert!(parse(old).is_err());
        for (text, why) in [
            (
                "scheme = \"docker\"\nsocket = \"/run/a.sock\"",
                "is a transport velarx has",
            ),
            (
                "scheme = \"S3\"\nsocket = \"/run/a.sock\"",
                "lowercase letter",
            ),
            (
                "scheme = \"s3\"\nsocket = \"a.sock\"",
                "not an absolute path",
            ),
        ] {
            let e = parse(&format!("[[transports]]\n{text}\n"))
                .unwrap_err()
                .to_string();
            assert!(e.contains(why), "{e}");
        }
    }

    #[test]
    fn test_sinks_are_ordered_named_and_checked() {
        let err = |text: &str| parse(text).unwrap_err().to_string();
        let config = parse(&format!("{SINK}[push]\nsinks = [\"backup\"]\n")).unwrap();
        assert_eq!(
            config.push.sinks.as_deref(),
            Some(&["backup".to_string()][..])
        );
        assert!(!config.sinks.external[0].credentials);
        assert_eq!(config.sinks.external[0].idle_timeout_secs, 15);
        let e = err("[push]\nsinks = [\"ipfs\"]\n");
        assert!(e.contains("unknown sink `ipfs`"), "{e}");
        // (the destination's own pushers are the engine's, by the scheme)
        for own in ["registry", "dir"] {
            for list in [format!("[\"{own}\"]"), format!("[\"backup\", \"{own}\"]")] {
                let e = err(&format!("{SINK}[push]\nsinks = {list}\n"));
                assert!(e.contains("destination's own pusher"), "{e}");
            }
        }
        let e = err("[[sinks.external]]\nname = \"dir\"\nsocket = \"/s\"\n");
        assert!(e.contains("built-in"), "{e}");
        let e = err(&format!("{SINK}[push]\nsinks = [\"backup\", \"backup\"]\n"));
        assert!(e.contains("twice"), "{e}");
        let e = err("[[sinks.external]]\nname = \"registry\"\nsocket = \"/s\"\n");
        assert!(e.contains("built-in"), "{e}");
        let e = err("[[sinks.external]]\nname = \"a\"\nsocket = \"rel/s.sock\"\n");
        assert!(e.contains("not an absolute path"), "{e}");
        let e = err("[[sinks.external]]\nname = \"a\"\nsocket = \"/s\"\nidle_timeout_secs = 0\n");
        assert!(e.contains("idle_timeout_secs"), "{e}");
        let e = err(&format!("{SINK}{SINK}"));
        assert!(e.contains("twice"), "{e}");
        assert_eq!(parse("").unwrap().pull.idle_timeout_secs, 120);
        assert_eq!(
            parse("[pull]\nidle_timeout_secs = 9\n")
                .unwrap()
                .pull
                .idle_timeout_secs,
            9
        );
        let e = err("[pull]\nidle_timeout_secs = 0\n");
        assert!(e.contains("idle_timeout_secs"), "{e}");
        let e = err("[push]\ncompression = \"lz4\"\n");
        assert!(e.contains("compression"), "{e}");
        assert!(parse("[push]\ncompression = \"zstd:chunked\"\ncompression_level = 5\n").is_ok());
    }

    #[test]
    fn test_sources_are_ordered_and_named() {
        let config = parse(&format!(
            "{EXTERNAL}[pull]\nsources = [\"cache\", \"registry\"]\n"
        ))
        .unwrap();
        assert_eq!(config.pull.sources, ["cache", "registry"]);
        assert_eq!(config.sources.external[0].idle_timeout_secs, 15);
        // The registry is not added to a list.
        let config = parse(&format!("{EXTERNAL}[pull]\nsources = [\"cache\"]\n")).unwrap();
        assert_eq!(config.pull.sources, ["cache"]);
    }

    #[test]
    fn test_unknown_sources_are_errors() {
        let err = |text: &str| parse(text).unwrap_err().to_string();
        let e = err("[pull]\nsources = [\"ipfs\", \"registry\"]\n");
        assert!(
            e.contains("unknown source `ipfs`") && e.contains("registry"),
            "{e}"
        );
        // (the order is the one given: the registry is a name like another)
        let config = parse(&format!(
            "{EXTERNAL}[pull]\nsources = [\"registry\", \"cache\"]\n"
        ))
        .unwrap();
        assert_eq!(config.pull.sources, ["registry", "cache"]);
        // (an archive is no source of a pull: it is its origin, by scheme)
        for name in ["stores", "archive"] {
            let e = err(&format!("[pull]\nsources = [\"{name}\"]\n"));
            assert!(e.contains(&format!("unknown source `{name}`")), "{e}");
        }
    }

    /// A source or a transport is reached by a socket or by a command that
    /// starts it for each use, exactly one of them; a command is a list
    /// whose first item is an absolute path.
    #[test]
    fn test_a_program_is_reached_by_a_socket_or_a_command() {
        let source = |text: &str| parse(&format!("[[sources.external]]\nname = \"a\"\n{text}\n"));
        let sink = |text: &str| parse(&format!("[[sinks.external]]\nname = \"a\"\n{text}\n"));
        let transport = |text: &str| parse(&format!("[[transports]]\nscheme = \"s3\"\n{text}\n"));
        let command = "command = [\"/usr/libexec/velarx/dircache\", \"/var/cache/layers\"]";
        let started = Reach::Command(vec![
            "/usr/libexec/velarx/dircache".into(),
            "/var/cache/layers".into(),
        ]);
        assert_eq!(
            source(command).unwrap().sources.external[0].reach(),
            started
        );
        assert_eq!(sink(command).unwrap().sinks.external[0].reach(), started);
        assert_eq!(transport(command).unwrap().transports[0].reach(), started);
        assert_eq!(
            transport("socket = \"/s\"").unwrap().transports[0].reach(),
            Reach::Socket("/s".into())
        );
        for (text, why) in [
            (format!("socket = \"/s\"\n{command}"), "one of them"),
            (String::new(), "one of them"),
            ("command = []".into(), "one of them"),
            ("command = [\"dircache\"]".into(), "absolute path"),
        ] {
            for e in [source(&text), sink(&text), transport(&text)] {
                let e = e.unwrap_err().to_string();
                assert!(e.contains(why), "{text}: {e}");
            }
        }
        let e = source(&format!("dir = \"/d\"\n{command}"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("one of them"), "{e}");
    }

    #[test]
    fn test_external_sources_are_checked() {
        let err = |text: &str| parse(text).unwrap_err().to_string();
        for name in ["", "Cache", "a b", "registry", &"x".repeat(33)] {
            let e = err(&format!(
                "[[sources.external]]\nname = \"{name}\"\nsocket = \"/s\"\n"
            ));
            assert!(e.contains("name"), "{name}: {e}");
        }
        let e = err("[[sources.external]]\nname = \"a\"\nsocket = \"rel/s.sock\"\n");
        assert!(e.contains("absolute"), "{e}");
        let e = err(&format!("{EXTERNAL}{EXTERNAL}"));
        assert!(e.contains("twice"), "{e}");
        let e = err("[[sources.external]]\nname = \"a\"\nsocket = \"/s\"\nidle_timeout_secs = 0\n");
        assert!(e.contains("idle_timeout"), "{e}");
        assert!(parse("[pull]\nlazy_fetches = 0\n").is_err());
        // a key of the engine is still refused when it is not one
        let e = err("[[sources.external]]\nname = \"a\"\nsocket = \"/s\"\nidle_timeout = 5\n");
        assert!(e.contains("idle_timeout"), "{e}");
    }

    /// The settings of an external source reach its program as they are
    /// written: any key, any value, sub-tables, none of them checked.
    #[test]
    fn test_the_settings_of_a_source_are_kept_as_they_are() {
        let text = "[[sources.external]]\nname = \"cache\"\nsocket = \"/run/cache.sock\"\n\
                    [sources.external.settings]\nanything = [\"a\", 1]\nport = 0\n\
                    [sources.external.settings.deeper]\nx = { y = true }\n";
        let config = parse(text).unwrap();
        let written: toml::Table = toml::from_str(text).unwrap();
        assert_eq!(
            toml::Value::Table(config.sources.external[0].settings.clone()),
            written["sources"]["external"][0]["settings"]
        );
        // (and none for a source that has no settings)
        let config = parse(EXTERNAL).unwrap();
        assert!(config.sources.external[0].settings.is_empty());
    }

    #[test]
    fn test_the_private_sockets_are_in_one_directory() {
        let config = parse("[server]\nsocket = \"/run/x/velarx.sock\"\n").unwrap();
        assert_eq!(config.services_dir(), Path::new("/run/x/services"));
    }

    #[test]
    fn test_network_providers_are_checked() {
        let err = |text: &str| parse(text).unwrap_err().to_string();
        let ok = "[[network.providers]]\nname = \"overlay\"\nsocket = \"/run/o.sock\"\n";
        let config = parse(ok).unwrap();
        assert_eq!(config.network.providers[0].name, "overlay");
        for name in ["", "Over", "a:b", "a b", &"x".repeat(33)] {
            let e = err(&format!(
                "[[network.providers]]\nname = \"{name}\"\nsocket = \"/s\"\n"
            ));
            assert!(e.contains("name"), "{name}: {e}");
        }
        let e = err("[[network.providers]]\nname = \"a\"\nsocket = \"rel.sock\"\n");
        assert!(e.contains("absolute"), "{e}");
        let e = err(&format!("{ok}{ok}"));
        assert!(e.contains("twice"), "{e}");
    }

    #[test]
    fn a_key_that_is_not_a_setting_is_an_error() {
        for (text, key) in [
            ("[server]\nsocke = \"/x\"\n", "socke"),
            ("[storage]\nroott = \"/x\"\n", "roott"),
            ("[pull]\nparalel_layers = 2\n", "paralel_layers"),
            ("[network.bridge]\nnme = \"x\"\n", "nme"),
            ("[api]\nlisten_on = []\n", "listen_on"),
            ("[cgroup]\ndefault_shm_size = \"1\"\n", "cgroup"),
            ("[logging]\nlevel = \"debug\"\n", "logging"),
            ("[containers]\nlog_drivr = \"x\"\n", "log_drivr"),
            ("[build]\nx = 1\n", "x"),
            ("[userns]\nx = 1\n", "x"),
            ("[sources]\nx = 1\n", "x"),
            ("[push]\nx = 1\n", "x"),
            ("[engine]\nx = 1\n", "x"),
            ("[services]\nx = 1\n", "x"),
            ("[network]\nx = 1\n", "x"),
        ] {
            let e = parse(text).unwrap_err().to_string();
            assert!(e.contains(key) && e.contains("unknown"), "{text}: {e}");
        }
    }

    #[test]
    fn the_cgroup_mode_of_the_engine() {
        for ok in ["enabled", "scope", "split", "disabled"] {
            assert!(parse(&format!("[containers]\ncgroups = \"{ok}\"\n")).is_ok());
        }
        assert!(parse("[containers]\ncgroups = \"slice\"\n").is_err());
        assert!(parse("[containers]\nimage_signature = \"require\"\n").is_ok());
        assert!(parse("[containers]\nimage_signature = \"policy\"\n").is_ok());
        assert!(parse("[containers]\nimage_signature = \"check\"\n").is_err());
        // the separate key of the engine section is gone
        assert!(parse("[engine]\ncgroup_mode = \"unit\"\n").is_err());
    }

    /// Every setting of the defaults is in the example file, as a line
    /// (commented or not) with its name.
    #[test]
    fn the_example_names_every_setting() {
        fn names(v: &toml::Value, out: &mut Vec<String>) {
            if let Some(t) = v.as_table() {
                for (k, v) in t {
                    out.push(k.clone());
                    names(v, out);
                }
            }
        }
        let example = include_str!("../../../config.toml.example");
        let v = toml::Value::try_from(Config::default()).unwrap();
        let mut keys = Vec::new();
        names(&v, &mut keys);
        let mut missing = Vec::new();
        for k in keys {
            let found = example.lines().any(|l| {
                l.trim_start_matches([' ', '#'])
                    .split(['.', '[', ']', '='])
                    .any(|p| p.trim() == k)
            });
            if !found {
                missing.push(k);
            }
        }
        assert!(missing.is_empty(), "config.toml.example has no {missing:?}");
    }

    #[test]
    fn the_build_entitlements_are_checked() {
        use velarx_base::entitlement::Entitlement;
        assert!(Config::default().build.insecure_entitlements.is_empty());
        let ok =
            parse("[build]\ninsecure_entitlements = [\"security.insecure\", \"network.host\"]\n")
                .unwrap();
        assert_eq!(
            ok.build.insecure_entitlements,
            [Entitlement::SecurityInsecure, Entitlement::NetworkHost]
        );
        for (text, what) in [
            ("[build]\ninsecure_entitlements = [\"host\"]\n", "host"),
            (
                "[build]\ninsecure_entitlements = [\"network.hosts\"]\n",
                "network.hosts",
            ),
            (
                "[build]\ninsecure_entitlements = \"network.host\"\n",
                "invalid type",
            ),
            (
                "[build]\ninsecure_entitlements = [\"network.host\", \"network.host\"]\n",
                "listed twice",
            ),
        ] {
            let e = parse(text).unwrap_err().to_string();
            assert!(e.contains(what), "{text}: {e}");
        }
    }

    #[test]
    fn the_digest_of_the_images_that_are_made_is_sha256_or_sha512() {
        assert_eq!(parse("").unwrap().build.digest, Algorithm::Sha256);
        assert_eq!(
            parse("[build]\ndigest = \"sha512\"\n")
                .unwrap()
                .build
                .digest,
            Algorithm::Sha512
        );
        for bad in ["sha384", "SHA512", "", "md5"] {
            let e = parse(&format!("[build]\ndigest = {bad:?}\n"))
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("[build] digest")
                    && e.contains(&format!("{bad:?}"))
                    && e.contains("sha256 or sha512"),
                "{bad}: {e}"
            );
        }
        let e = parse("[build]\ndigest = 512\n").unwrap_err().to_string();
        assert!(e.contains("invalid type"), "{e}");
    }

    #[test]
    fn the_cni_settings_are_checked() {
        let ok = parse("[network.cni]\nconf_dir = \"/c\"\nbin_dirs = [\"/b\"]\ncache_dir = \"/r\"\ntimeout_secs = 5\n").unwrap();
        assert_eq!(ok.network.cni.bin_dirs, [PathBuf::from("/b")]);
        assert_eq!(
            Config::default().network.cni.conf_dir,
            PathBuf::from("/etc/cni/net.d")
        );
        for bad in [
            "[network.cni]\nconf_dir = \"c\"\n",
            "[network.cni]\nbin_dirs = [\"/b\", \"b\"]\n",
            "[network.cni]\ncache_dir = \"r\"\n",
            "[network.cni]\ntimeout_secs = 0\n",
            "[network.cni]\nunknown = 1\n",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    /// The settings of config.toml.example, commented out or not, by
    /// table: the header (`[pull]`, `[[network.subnet_pools]]`) and its
    /// lines `key = value`.
    fn example_settings() -> Vec<(String, Vec<&'static str>)> {
        let table = |h: &str| {
            h.starts_with('[')
                && h.ends_with(']')
                && h.chars()
                    .all(|c| matches!(c, '[' | ']' | '.' | '_') || c.is_ascii_lowercase())
        };
        fn setting(l: &str) -> Option<&str> {
            let (key, value) = l.split_once(" = ")?;
            let plain = key.starts_with(|c: char| c.is_ascii_lowercase())
                && key
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
            let toml = value.starts_with(['"', '[', '{', 't', 'f'])
                || value.starts_with(|c: char| c.is_ascii_digit());
            (plain && toml).then_some(l)
        }
        let mut blocks: Vec<(String, Vec<&str>)> = Vec::new();
        for l in include_str!("../../../config.toml.example").lines() {
            let l = l.strip_prefix("# ").unwrap_or(l);
            if table(l) {
                blocks.push((l.to_string(), Vec::new()));
            } else if let (Some(s), Some(block)) = (setting(l), blocks.last_mut()) {
                block.1.push(s);
            }
        }
        blocks
    }

    /// Every setting the example shows commented out is accepted by the
    /// loader (the structures refuse unknown keys, so a stale name fails):
    /// the lines `# key = value` of each table, with the table.
    #[test]
    fn the_settings_of_the_example_are_accepted() {
        let mut checked = 0;
        for (header, settings) in &example_settings() {
            // the settings of a source are its program's to check
            if header.starts_with("[sources.external.settings") {
                continue;
            }
            let text = format!("{header}\n{}\n", settings.join("\n"));
            // the names and types: some values are valid only with other
            // settings of the file (the sources of [pull])
            if let Err(e) = toml::from_str::<Config>(&text) {
                panic!("config.toml.example: {text}{e}");
            }
            checked += settings.len();
        }
        assert!(checked > 80, "only {checked} settings found in the example");
    }

    /// The values the example gives the settings of its plain tables are
    /// their defaults: the ones it sets and the ones it shows commented out,
    /// except where the default is made at run time (an empty value, a
    /// directory of the user) and the comment says what it is.
    #[test]
    fn the_example_shows_the_defaults() {
        let defaults = toml::Value::try_from(Config::default()).unwrap();
        let example = include_str!("../../../config.toml.example");
        let made = |v: &toml::Value| match v {
            toml::Value::String(s) => s.is_empty() || s.contains("/velarx"),
            toml::Value::Array(a) => a.is_empty(),
            _ => false,
        };
        let mut wrong = Vec::new();
        for (header, settings) in &example_settings() {
            if header.starts_with("[[") {
                continue;
            }
            let path: Vec<&str> = header.trim_matches(['[', ']']).split('.').collect();
            let Some(table) = path.iter().try_fold(&defaults, |v, k| v.get(k)) else {
                continue;
            };
            for s in settings {
                let commented = !example.lines().any(|l| l == *s);
                let shown: toml::Table = toml::from_str(s).unwrap();
                for (key, value) in shown {
                    match table.get(&key) {
                        Some(d) if *d != value && !(commented && made(d)) => {
                            wrong.push(format!("{header} {s}: the default is {d:?}"))
                        }
                        None if !commented => wrong.push(format!("{header} {s}: no default")),
                        _ => {}
                    }
                }
            }
        }
        assert!(
            wrong.is_empty(),
            "config.toml.example:\n{}",
            wrong.join("\n")
        );
    }

    #[test]
    fn test_the_example_configuration_is_valid() {
        let config = parse(include_str!("../../../config.toml.example")).unwrap();
        assert_eq!(config.pull.sources, ["registry"]);
    }
}
