// SPDX-License-Identifier: Apache-2.0
//! The registry fetcher of the engine: the process `velarx-registry`, a
//! binary of its own, which the engine finds or starts
//! ([`shared_registry`]), and what it passes to it.

use crate::fetcher::fetch_client::FetchConn;
use crate::shared::SharedRegistry;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use velarx_config::Config;

/// The environment the fetcher and its workers keep: how to find certificates and proxies.
pub const ENVIRONMENT: &[&str] = &[
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "all_proxy",
];

/// The variables the fetcher a process starts gets: the proxy and
/// certificate settings, where the registries configuration is, and where
/// the credentials are (`HOME`, which has the auth file, and the
/// variables that name one).
pub fn passed_environment() -> impl Iterator<Item = &'static str> {
    const WHERE: &[&str] = &[
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
        "XDG_DATA_HOME",
        velarx_registry::config::REGISTRIES_CONF_ENV,
        velarx_base::trace::ENV,
    ];
    const CREDENTIALS: &[&str] = &["HOME", "REGISTRY_AUTH_FILE", "DOCKER_CONFIG"];
    ENVIRONMENT.iter().chain(WHERE).chain(CREDENTIALS).copied()
}

/// What `velarx-dir` takes of the configuration: the limits of its
/// services, of the files it writes and of what it inflates.  The engine's
/// whole configuration is not given to a helper that needs none of the rest.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperSettings {
    pub services: velarx_config::ServicesConfig,
    /// The largest file it writes (`[pull] max_layer_gib`), in bytes
    pub max_file_bytes: u64,
    /// `[pull] max_inflate_ratio`
    pub max_inflate_ratio: u64,
    /// `[pull] inflate_floor_mib`
    pub inflate_floor_mib: u64,
    /// `[pull] max_archive_gib`
    pub max_archive_gib: u64,
}

impl HelperSettings {
    pub fn of(config: &Config) -> Self {
        Self {
            services: config.services.clone(),
            max_file_bytes: config.pull.max_file_bytes(),
            max_inflate_ratio: config.pull.max_inflate_ratio,
            inflate_floor_mib: config.pull.inflate_floor_mib,
            max_archive_gib: config.pull.max_archive_gib,
        }
    }
}

/// What the registry fetcher takes of the configuration: the sections it
/// reads, `[pull]`, `[push]` and `[services]`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySettings {
    pub pull: velarx_config::PullConfig,
    pub push: velarx_config::PushConfig,
    pub services: velarx_config::ServicesConfig,
}

impl RegistrySettings {
    pub fn of(config: &Config) -> Self {
        Self {
            pull: config.pull.clone(),
            push: config.push.clone(),
            services: config.services.clone(),
        }
    }
}

/// The text of the file with no name that a starter gave a process: a
/// regular file that nobody can write to, read from its start.
fn text_from_fd(file: OwnedFd) -> io::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let mut file = std::fs::File::from(file);
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 0 || meta.mode() & 0o222 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the configuration is not a file with no name that is read-only",
        ));
    }
    // (the same file for every fetcher that is started: from the start)
    std::io::Seek::rewind(&mut file)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(text)
}

fn json_error(e: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// The settings a starter gave the registry fetcher in a file with no name
/// (the one [`Private`] and the shared fetcher are started with).
pub fn registry_settings_from_fd(file: OwnedFd) -> io::Result<RegistrySettings> {
    serde_json::from_str(&text_from_fd(file)?).map_err(json_error)
}

/// The settings a starter gave `velarx-dir` in a file with no name.
pub fn settings_from_fd(file: OwnedFd) -> io::Result<HelperSettings> {
    serde_json::from_str(&text_from_fd(file)?).map_err(json_error)
}

/// The binary of the registry fetcher: `[pull] registry_path`, else
/// `velarx-registry` next to the running executable.
pub fn registry_binary(config: &Config) -> PathBuf {
    config
        .pull
        .registry_path
        .clone()
        .unwrap_or_else(|| velarx_base::spawn::sibling("velarx-registry"))
}

/// The binary of the fetcher of a directory: `[pull] dir_path`, else
/// `velarx-dir` next to the running executable.
pub fn dir_binary(config: &Config) -> PathBuf {
    config
        .pull
        .dir_path
        .clone()
        .unwrap_or_else(|| velarx_base::spawn::sibling("velarx-dir"))
}

/// What starts a registry fetcher for `config`, shared or private.
struct Inputs {
    rootful: bool,
    exe: PathBuf,
    /// The staging of the store, the only place it writes: made, and given
    /// to the fetcher open as it starts
    staging: PathBuf,
    /// The configuration it serves
    json: Vec<u8>,
    /// The services directory (absolute: the fetcher runs in `/`)
    services: PathBuf,
    environment: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl Inputs {
    fn of(config: &Config) -> io::Result<Self> {
        let rootful = velarx_base::ids::rootful().map_err(io::Error::other)?;
        let exe = registry_binary(config);
        // (the workers of the fetcher are its own binary unless the
        // configuration names another: said so, a configuration that names
        // it is the same one)
        let mut config = config.clone();
        config.pull.worker_path.get_or_insert_with(|| exe.clone());
        let staging = config
            .storage
            .staging_dir()
            .join(crate::pull::staged::LAYERS);
        velarx_base::ipc::ensure_private_dir(&staging)
            .map_err(|e| no_fetcher(&staging.display().to_string(), e))?;
        let json = serde_json::to_vec(&RegistrySettings::of(&config))
            .map_err(|e| no_fetcher("the configuration", e))?;
        let services = std::path::absolute(config.services_dir())
            .map_err(|e| no_fetcher("the services directory", e))?;
        Ok(Self {
            rootful,
            exe,
            staging,
            json,
            services,
            environment: registry_environment(rootful),
        })
    }

    /// The command that starts it, and what it is given as its descriptors:
    /// the connection or the listener (3), the configuration (4) and, for a
    /// fetcher that writes the staging, the staging (5).
    fn command(
        &self,
        listening: &[&str],
        staging: bool,
    ) -> io::Result<(std::process::Command, Vec<OwnedFd>)> {
        velarx_base::ipc::ensure_private_dir(&self.services)
            .map_err(|e| no_fetcher(&self.services.display().to_string(), e))?;
        let config_file = crate::pull::unnamed::read_only_unnamed(&self.services, &self.json)
            .map_err(|e| no_fetcher("the configuration file", e))?;
        let mut cmd = std::process::Command::new(&self.exe);
        cmd.args(listening).args(["--config-fd", "4"]);
        let mut fds = vec![config_file];
        if staging {
            fds.push(
                rustix::fs::open(
                    &self.staging,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|e| no_fetcher(&self.staging.display().to_string(), e))?,
            );
            cmd.args(["--staging-fd", "5"]);
        }
        cmd.env_clear();
        for (name, value) in &self.environment {
            if let Some(v) = value {
                cmd.env(name, v);
            }
        }
        Ok((cmd, fds))
    }
}

/// A fetcher that is this process's alone: started with the one
/// connection to it as its descriptor 3, no socket in the file system, and
/// gone when the connection (and every one it handed out) is closed.
pub struct Private {
    /// This end of the connection
    pub stream: std::os::unix::net::UnixStream,
    /// The process
    pub child: std::process::Child,
}

impl Private {
    /// The connection as a client, the process left to a thread that waits
    /// for it (a fetcher that ended is not a zombie of this process).  This
    /// connection, or one it hands out, dropped while a call is in flight
    /// (given up, as for silence) kills the process; connections that end
    /// between calls do not: the process leaves by itself at end of file.
    pub fn connect(self) -> io::Result<FetchConn> {
        let Self { stream, mut child } = self;
        // (before the thread that reaps it: the number is not reused until then)
        let pid = rustix::process::Pid::from_child(&child);
        let process = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())?;
        std::thread::Builder::new()
            .name("fetcher-reaper".into())
            .spawn(move || {
                let _ = child.wait();
            })?;
        Ok(FetchConn::new(stream)?.killing(process))
    }
}

/// Start `cmd` with the connection to it as its descriptor 3 and `extra`
/// as 4, 5, ...: standard input and output are `/dev/null`, the directory
/// is `/`, and no other descriptor is passed.
fn spawn_private(mut cmd: std::process::Command, extra: Vec<OwnedFd>) -> io::Result<Private> {
    use std::os::fd::AsRawFd;
    let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
    cmd.current_dir("/")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null());
    velarx_base::spawn::pass_fds(
        &mut cmd,
        theirs.as_raw_fd(),
        extra.iter().map(|f| f.as_raw_fd()).collect(),
    );
    let child = cmd.spawn()?;
    Ok(Private {
        stream: ours,
        child,
    })
}

/// Start one of our programs (`inputs.exe`) with `args` and the
/// connection to it as `--varlink-fd 3` (the configuration is 4 and the
/// staging 5).
fn spawn_ours(inputs: &Inputs, args: &[&str], staging: bool) -> io::Result<Private> {
    let (mut cmd, extra) = inputs.command(&[], staging)?;
    cmd.args(args).args(["--varlink-fd", "3"]);
    spawn_private(cmd, extra)
}

/// Start the program `command` (its path, absolute, and its arguments; no
/// shell) for one use: the connection to it is its descriptor 3, nothing is
/// added to its arguments, and its environment is empty.  Its standard
/// error is ours.
pub fn private_command(command: &[String]) -> io::Result<Private> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "an empty command"))?;
    let mut cmd = std::process::Command::new(program);
    cmd.args(args).env_clear();
    spawn_private(cmd, Vec::new())
}

/// A connection to the program `reach` names: on its socket, or to
/// the one started for it ([`private_command`]).
pub async fn connect_reach(reach: &velarx_config::Reach) -> io::Result<FetchConn> {
    match reach {
        velarx_config::Reach::Socket(socket) => FetchConn::connect_checked(socket).await,
        velarx_config::Reach::Command(command) => connect_command(command).await,
    }
}

/// A connection to `command` started for it ([`private_command`]).
async fn connect_command(command: &[String]) -> io::Result<FetchConn> {
    let command = command.to_vec();
    tokio::task::spawn_blocking(move || private_command(&command)?.connect())
        .await
        .map_err(io::Error::other)?
}

/// Start a registry fetcher for `config` with a connection of its own (see
/// [`Private`]; [`shared_registry`] is the one several processes find by
/// its socket).
pub fn private_registry(config: &Config) -> io::Result<Private> {
    spawn_ours(&Inputs::of(config)?, &[], true)
}

/// Start the fetcher of the directory `dir` (items named by their
/// digests, `[[sources.external]]` with a `dir`) as `name`, with a
/// connection of its own: `velarx-dir`, which reads `dir` and
/// writes the staging of the store, and does nothing else.
pub fn private_dir(config: &Config, name: &str, dir: &Path) -> io::Result<Private> {
    let dir = std::path::absolute(dir).map_err(|e| no_fetcher(&dir.display().to_string(), e))?;
    let dir = dir.to_string_lossy();
    let mut inputs = Inputs::of(config)?;
    inputs.exe = dir_binary(config);
    // (it reads a directory: no home, no credentials, no proxy, no helper)
    inputs.environment.clear();
    inputs.json = settings_json(config)?;
    spawn_ours(&inputs, &["--name", name, "--dir", &dir], true)
}

/// What `velarx-dir` does for one path it is told by `Open`: it writes the
/// destination of a push, or serves the origin of a pull; in either case it
/// confines itself to the target and has no staging until it needs one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Push,
    /// The origin of a pull: it writes the staging of the layers it unpacks
    Pull,
}

impl Direction {
    fn flag(self) -> &'static str {
        match self {
            Direction::Push => "--push",
            Direction::Pull => "--origin",
        }
    }
}

/// Start `velarx-dir` for a path (see [`Direction`]) with a connection of
/// its own.  It learns the path from `Open(target)` and confines itself
/// there.
pub fn private_dir_origin(config: &Config, direction: Direction) -> io::Result<Private> {
    let mut inputs = Inputs::of(config)?;
    inputs.exe = dir_binary(config);
    inputs.environment.clear();
    inputs.json = settings_json(config)?;
    spawn_ours(&inputs, &[direction.flag()], direction == Direction::Pull)
}

fn settings_json(config: &Config) -> io::Result<Vec<u8>> {
    serde_json::to_vec(&HelperSettings::of(config)).map_err(|e| no_fetcher("the settings", e))
}

/// The fetcher of `config` when no service manager holds its
/// socket: the one that serves the configuration, the environment and the
/// binary of this process, found in the services directory or started
/// there ([`crate::shared`]).  It gets the configuration (in a read-only
/// file with no name), not a path to it, and the variables of this
/// process that name the registries configuration, the credentials and the
/// credential helpers; it outlives this process while connections to it
/// are open.  One per configuration in a process.
///
/// It is the confinement of the pulls: an error says why there is none,
/// and the caller fails rather than fetch without it.
pub fn shared_registry(config: &Config) -> io::Result<Arc<SharedRegistry>> {
    static SHARED: Mutex<Vec<Arc<SharedRegistry>>> = Mutex::new(Vec::new());
    let Inputs {
        rootful,
        exe,
        staging,
        json,
        services,
        environment,
    } = Inputs::of(config)?;
    let key = registry_key(&json, rootful, &exe, &environment);
    // (a directory of its own: the fetcher may take its socket away there,
    // which is no right on the sockets of the other services)
    let socket = services
        .join(format!("registry-{key}"))
        .join("registry.sock");
    let mut shared = SHARED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(found) = shared.iter().find(|s| s.socket() == socket) {
        return Ok(found.clone());
    }
    let (_, extra) = Inputs {
        rootful,
        exe: exe.clone(),
        staging,
        json,
        services: services.clone(),
        environment: environment.clone(),
    }
    .command(&[], true)?;
    let log = services.join(format!("registry-{key}.log"));
    let path = socket.clone();
    let registry = Arc::new(SharedRegistry::new(socket, log, extra, move || {
        let mut cmd = std::process::Command::new(&exe);
        cmd.args(["--listen-fd", "3"])
            .args(["--config-fd", "4"])
            .args(["--staging-fd", "5"])
            .arg("--shared")
            .arg(&path)
            .env_clear();
        for (name, value) in &environment {
            if let Some(v) = value {
                cmd.env(name, v);
            }
        }
        cmd
    }));
    shared.push(registry.clone());
    Ok(registry)
}

/// The variables the fetcher of this process gets (where the
/// registries configuration and the credentials are, the credential
/// helpers, the proxies and the certificates), with their values here.
fn registry_environment(rootful: bool) -> Vec<(&'static str, Option<std::ffi::OsString>)> {
    passed_environment()
        .chain(HELPER_ENVIRONMENT.iter().copied())
        .map(|name| {
            let value = if rootful && name == "PATH" {
                // (root looks for its helpers where the system's programs
                // are, not in a search path `sudo` may have kept from the
                // user)
                Some(velarx_registry::auth::ROOT_PATH.into())
            } else {
                std::env::var_os(name)
            };
            (name, value)
        })
        .collect()
}

/// The name of the fetcher of a process: a digest of what it
/// does with its calls.  The binary that runs it, the user, the
/// configuration (`json`), the variables it is given (`environment`), and
/// what it reads once as it starts: the registries configuration and the
/// certificates of the registries (`certs.d`, by the times of their
/// files).  An engine with anything else in one of them never reaches it.
fn registry_key(
    json: &[u8],
    rootful: bool,
    exe: &Path,
    environment: &[(&str, Option<std::ffi::OsString>)],
) -> String {
    use sha2::{Digest, Sha256};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let mut hash = Sha256::new();
    let mut part = |name: &[u8], value: Option<&[u8]>| {
        for bytes in [name, value.unwrap_or_default()] {
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
        hash.update([u8::from(value.is_some())]);
    };
    part(b"version", Some(env!("CARGO_PKG_VERSION").as_bytes()));
    part(
        b"user",
        Some(&rustix::process::geteuid().as_raw().to_le_bytes()),
    );
    part(b"rootful", Some(&[u8::from(rootful)]));
    let binary = std::fs::metadata(exe).ok().map(|m| {
        format!(
            "{} {} {} {} {}.{}",
            exe.display(),
            m.dev(),
            m.ino(),
            m.size(),
            m.mtime(),
            m.mtime_nsec()
        )
    });
    part(b"binary", binary.as_deref().map(str::as_bytes));
    part(b"configuration", Some(json));
    for (name, value) in environment {
        part(name.as_bytes(), value.as_deref().map(|v| v.as_bytes()));
    }
    for file in velarx_registry::config::RegistriesConfig::files() {
        let content = std::fs::read(&file).ok();
        part(file.as_os_str().as_bytes(), content.as_deref());
    }
    let certs = velarx_registry::target::default_certs_dirs().unwrap_or_default();
    for (file, stamp) in certs_files(&certs) {
        part(
            file.as_os_str().as_bytes(),
            stamp.as_deref().map(str::as_bytes),
        );
    }
    hex::encode(&hash.finalize()[..16])
}

/// The files of the `certs.d` directories `dirs` (in a directory of each
/// host), in order, with their inode, size and time of change: what a
/// fetcher that read them as it started depends on.
fn certs_files(dirs: &[PathBuf]) -> Vec<(PathBuf, Option<String>)> {
    use std::os::unix::fs::MetadataExt;
    let sorted = |dir: &Path| -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .collect();
        paths.sort();
        paths
    };
    let mut files = Vec::new();
    for dir in dirs {
        for host in sorted(dir) {
            for file in sorted(&host) {
                let stamp = std::fs::metadata(&file).ok().map(|m| {
                    format!(
                        "{} {} {} {}.{}",
                        m.dev(),
                        m.ino(),
                        m.size(),
                        m.ctime(),
                        m.ctime_nsec()
                    )
                });
                files.push((file, stamp));
            }
        }
    }
    files
}

/// Why the fetcher of a confined pull cannot be started: the
/// pull does not go without it.
fn no_fetcher(what: &str, e: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!(
        "cannot start the fetcher that confines the pulls: {what}: {e}"
    ))
}

/// What the credential helpers of a fetcher the pulling process starts find
/// in the environment (the fetcher's runner runs them): where the programs
/// are, the session bus, and where `pass`, the AWS and the Google tools
/// keep their files.
const HELPER_ENVIRONMENT: &[&str] = &[
    "PATH",
    "DBUS_SESSION_BUS_ADDRESS",
    "GNUPGHOME",
    "PASSWORD_STORE_DIR",
    "AWS_PROFILE",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "CLOUDSDK_CONFIG",
    "GOOGLE_APPLICATION_CREDENTIALS",
];

/// The registry fetcher of a process that pulls: the process this one
/// shares with the others of its configuration ([`shared_registry`]),
/// found or started on first use (a command that pulls nothing, as `velarx
/// ps`, starts nothing).
pub struct RegistryOrigin {
    config: Config,
    shared: std::sync::OnceLock<Arc<SharedRegistry>>,
    /// Each connection is a fetcher of its own ([`private_registry`])
    private: bool,
}

impl RegistryOrigin {
    /// The fetcher the processes of `config` share ([`shared_registry`]):
    /// for a service that outlives the commands and has connections of
    /// others to serve.
    pub fn new(config: &Config) -> Arc<Self> {
        Arc::new(Self {
            config: config.clone(),
            shared: std::sync::OnceLock::new(),
            private: false,
        })
    }

    /// A fetcher of its own for each connection, started when the
    /// connection is asked for and gone when it is closed: for a process
    /// that is the only one to use it (a command's engine), which leaves no
    /// socket and shares nothing.
    pub fn private(config: &Config) -> Arc<Self> {
        Arc::new(Self {
            config: config.clone(),
            shared: std::sync::OnceLock::new(),
            private: true,
        })
    }

    /// The fetcher `shared` finds or starts (tests); `config` is the one the
    /// other fetchers it needs (a `dir`) are started for.
    pub fn with_shared(shared: Arc<SharedRegistry>, config: &Config) -> Arc<Self> {
        let made = Self {
            config: config.clone(),
            shared: std::sync::OnceLock::new(),
            private: false,
        };
        let _ = made.shared.set(shared);
        Arc::new(made)
    }

    /// How long the built-in fetchers may be silent in a call
    /// (`[pull] idle_timeout_secs`).
    pub fn idle(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.config.pull.idle_timeout_secs)
    }

    /// A connection to a fetcher of the directory `dir` (`[[sources.external]]`
    /// with a `dir`), a confined process of its own for this connection
    /// ([`private_dir`]).
    pub async fn connect_dir(&self, name: &str, dir: &Path) -> io::Result<FetchConn> {
        let (config, name, dir) = (self.config.clone(), name.to_string(), dir.to_path_buf());
        tokio::task::spawn_blocking(move || private_dir(&config, &name, &dir)?.connect())
            .await
            .map_err(io::Error::other)?
    }

    /// A connection to `velarx-dir` for a path ([`private_dir_origin`]).
    pub async fn connect_dir_origin(&self, direction: Direction) -> io::Result<FetchConn> {
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || private_dir_origin(&config, direction)?.connect())
            .await
            .map_err(io::Error::other)?
    }

    /// A new connection to the fetcher, with no scope yet; an error when it
    /// cannot be started, and the call that needs it fails.
    pub async fn connect(&self) -> io::Result<FetchConn> {
        if self.private {
            let config = self.config.clone();
            return tokio::task::spawn_blocking(move || private_registry(&config)?.connect())
                .await
                .map_err(io::Error::other)?;
        }
        let shared = match self.shared.get() {
            Some(s) => s.clone(),
            None => {
                let made = shared_registry(&self.config)?;
                // (a second one made at the same time is dropped)
                self.shared.get_or_init(|| made).clone()
            }
        };
        // (under the lock of the socket, and maybe a start: not on a thread
        // of the runtime)
        let stream = tokio::task::spawn_blocking(move || shared.attach())
            .await
            .map_err(io::Error::other)??;
        FetchConn::new(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How long the built-in fetchers may be silent is `[pull]
    /// idle_timeout_secs`.
    #[test]
    fn the_built_in_fetchers_may_be_silent_as_long_as_the_configuration_says() {
        let mut config = Config::default();
        assert_eq!(RegistryOrigin::new(&config).idle().as_secs(), 120);
        config.pull.idle_timeout_secs = 7;
        assert_eq!(RegistryOrigin::private(&config).idle().as_secs(), 7);
    }

    /// The registry fetcher is given the sections it reads and no other.
    #[test]
    fn the_registry_fetcher_is_given_three_sections_of_the_configuration() {
        let mut config = Config::default();
        config.pull.max_workers += 1;
        let json = serde_json::to_value(RegistrySettings::of(&config)).unwrap();
        let mut sections: Vec<_> = json.as_object().unwrap().keys().collect();
        sections.sort();
        assert_eq!(sections, ["pull", "push", "services"]);
        assert_eq!(json["pull"]["max_workers"], config.pull.max_workers);
        // (a whole configuration is not settings)
        let whole = serde_json::to_string(&config).unwrap();
        assert!(serde_json::from_str::<RegistrySettings>(&whole).is_err());
    }

    /// The fetcher's socket is named by everything that makes what it does,
    /// and is short enough to bind wherever the configuration is.
    #[test]
    fn the_shared_fetcher_is_named_by_its_configuration() {
        let tmp = tempfile::tempdir().unwrap();
        let mut dir = tmp.path().to_path_buf();
        while dir.as_os_str().len() <= 120 {
            dir.push("a-directory-with-a-long-name");
        }
        let mut config = Config::default();
        config.server.socket = dir.join("velarx.sock");
        // (the fetcher makes the staging of its store)
        config.storage.root = tmp.path().join("store");
        let one = shared_registry(&config).unwrap();
        assert!(one.socket().as_os_str().len() > 107);
        assert!(one.socket().starts_with(config.services_dir()));
        assert!(Arc::ptr_eq(&one, &shared_registry(&config).unwrap()));
        // (nothing is started before a pull or a monitor needs it)
        assert!(!one.socket().exists());
        assert!(one.started().is_none());
        config.pull.max_workers += 1;
        let other = shared_registry(&config).unwrap();
        assert_ne!(one.socket(), other.socket());

        // a services directory others can enter is refused
        let shared = tmp.path().join("shared");
        std::fs::create_dir_all(shared.join("services")).unwrap();
        std::fs::set_permissions(
            shared.join("services"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        config.server.socket = shared.join("velarx.sock");
        let Err(e) = shared_registry(&config) else {
            panic!("a fetcher in a directory others can enter");
        };
        assert!(
            e.to_string()
                .contains("cannot start the fetcher that confines the pulls"),
            "{e}"
        );
        assert!(e.to_string().contains("chmod 700"), "{e}");
        // fixed, the next pull has it
        std::fs::set_permissions(
            shared.join("services"),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        shared_registry(&config).unwrap();
    }

    fn sh(script: &str, arg: &str) -> Vec<String> {
        ["/bin/sh", "-c", script, arg].map(String::from).to_vec()
    }

    const GONE: std::time::Duration = std::time::Duration::from_secs(60);

    /// The program gets the connection as its descriptor 3, the directory
    /// `/` and no environment, and what it writes there is what the
    /// engine reads until the program ends.
    #[test]
    fn a_command_is_started_with_the_connection_as_descriptor_3() {
        use std::io::Read;
        let script = "echo \"$PWD\" >&3; /usr/bin/env >&3";
        let mut private = private_command(&sh(script, "")).unwrap();
        let mut said = String::new();
        private.stream.read_to_string(&mut said).unwrap();
        assert!(said.starts_with("/\n"), "{said}");
        assert!(!said.contains("HOME=") && !said.contains("PATH="), "{said}");
        assert!(private.child.wait().unwrap().success());
    }

    /// A command that cannot be started is an error at once, and one that
    /// exits before it answers is a connection that fails.
    #[tokio::test]
    async fn a_command_that_does_not_run_is_an_error() {
        assert!(private_command(&["/nonexistent/program".into()]).is_err());
        assert!(private_command(&[]).is_err());
        let private = private_command(&["/bin/true".into()]).unwrap();
        let pid = private.child.id() as i32;
        let mut conn = private.connect().unwrap();
        assert!(conn.get_info().await.is_err());
        assert!(velarx_base::testing::wait_exit(pid, GONE));
    }

    /// The end of the connection ends the program, and does not kill it:
    /// it was let to finish what it does at end of file.
    #[tokio::test]
    async fn the_end_of_the_connection_ends_the_program() {
        let tmp = tempfile::tempdir().unwrap();
        let done = tmp.path().join("done");
        let script = "cat <&3; touch \"$0\"";
        let private = private_command(&sh(script, &done.to_string_lossy())).unwrap();
        let pid = private.child.id() as i32;
        drop(private.connect().unwrap());
        assert!(velarx_base::testing::wait_exit(pid, GONE));
        assert!(done.exists(), "the program was killed");
    }

    /// A program that is silent for its idle time is given up: the call
    /// ends with the silence, and the process is killed with the connection.
    #[tokio::test(start_paused = true)]
    async fn a_program_that_is_silent_is_killed() {
        let private = private_command(&sh("exec sleep 100000", "")).unwrap();
        let pid = private.child.id() as i32;
        let mut conn = private.connect().unwrap();
        let idle = std::time::Duration::from_secs(5);
        let e = crate::idle::within(idle, conn.get_info())
            .await
            .unwrap_err();
        assert!(crate::idle::is_silent(&e));
        drop(conn);
        assert!(velarx_base::testing::wait_exit(pid, GONE));
    }

    /// A fetcher whose manifests never come.
    struct Silent;

    #[async_trait::async_trait]
    impl crate::serve_fetch::StagingFetcher for Silent {
        fn described(&self) -> crate::serve_fetch::Described {
            crate::serve_fetch::Described {
                name: "silent".into(),
                capabilities: vec!["metadata".into()],
                max_objects: 1,
            }
        }

        async fn get_file(
            &self,
            _scope: &crate::serve_fetch::Scope,
            _kind: crate::fetcher::fetch::FileKind,
            _reference: &str,
            _max: u64,
        ) -> Result<(std::fs::File, Option<String>), crate::fetcher::fetch::FetcherError> {
            std::future::pending().await
        }
    }

    /// A call given up on a connection that the program handed out kills
    /// the program too.
    #[tokio::test(start_paused = true)]
    async fn a_program_silent_on_a_connection_it_handed_out_is_killed() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("silent.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let api = Arc::new(Silent);
        let _served =
            crate::serve_fetch::serve_in_thread(listener, api, Default::default()).unwrap();
        // (the process is started for the connection, whose calls are
        // served here)
        let started = private_command(&sh("exec sleep 100000", "")).unwrap();
        let pid = started.child.id() as i32;
        let private = Private {
            stream: std::os::unix::net::UnixStream::connect(&socket).unwrap(),
            child: started.child,
        };
        let mut conn = private.connect().unwrap();
        let idle = std::time::Duration::from_secs(5);
        let scope = crate::fetcher::fetch_client::Scoping::bare(idle);
        conn.open(scope).await.unwrap();
        let mut handed = conn.connect().await.unwrap();
        let e = crate::idle::within(
            idle,
            handed.get_file(crate::fetcher::fetch::FileKind::Manifest, "a", 1),
        )
        .await
        .unwrap_err();
        assert!(crate::idle::is_silent(&e));
        drop(handed);
        assert!(velarx_base::testing::wait_exit(pid, GONE));
    }
}
