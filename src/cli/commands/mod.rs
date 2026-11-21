// SPDX-License-Identifier: Apache-2.0
//! The commands of the `velarx` command line, as the client runs them.

use crate::cli::progress::{self, format_bytes, Renderer, Transfer};
use crate::cli::run::{
    attach_session, parse_memory_size, parse_port_mapping, run_container, AttachRequest,
    RunContainerArgs,
};
use crate::cli::{
    self, Commands, ContainerCommands, HealthcheckCommands, ImageCommands, NetworkCommands,
    PodCommands, RegistryCommands, SystemCommands, VolumeCommands,
};
use crate::client;
use velarx_config::Config;
use velarx_registry as registry;
use velarx_types::transport::ImageLocation;
use velarx_wire::logging;

mod container;
mod image;
mod login;
mod logs;
mod network;
mod pod;
mod system;
mod volume;
use container::*;
pub use image::*;
pub(crate) use login::*;
use logs::*;
use network::*;
use pod::*;
use system::*;
use volume::*;

/// Which binary runs the commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binary {
    /// `velarx-client`: talks to the engine service; what needs the engine
    /// it leaves to `velarx`.
    Client,
    /// `velarx`: the engine too, in this process.
    Engine,
}

/// What the code that runs a command knows of the way it was invoked,
/// besides the command: the global options, and how the command reaches an
/// engine, worked out from the command before it is handed to that code.
struct Invocation<'a> {
    global: &'a cli::GlobalArgs,
    /// What the command does when no engine service answers.
    daemonless: cli::Daemonless,
    /// The container the command makes, for the cgroups of its engine.
    #[cfg(feature = "engine")]
    cgroups: Option<crate::engine::AskedCgroups>,
}

impl<'a> Invocation<'a> {
    fn of(global: &'a cli::GlobalArgs, command: &Commands) -> Self {
        Self {
            global,
            daemonless: cli::daemonless(command),
            #[cfg(feature = "engine")]
            cgroups: match command {
                Commands::Container(cmd) => crate::engine::AskedCgroups::of(cmd),
                _ => None,
            },
        }
    }
}

static BINARY: std::sync::OnceLock<Binary> = std::sync::OnceLock::new();

/// `velarx-client`.
pub fn main(startup: &velarx_sys::fd::Startup) -> anyhow::Result<()> {
    exit_on_error(main_as(Binary::Client, startup))
}

/// `velarx`.
pub fn main_engine(startup: &velarx_sys::fd::Startup) -> anyhow::Result<()> {
    exit_on_error(main_as(Binary::Engine, startup))
}

/// `result`, or the error said as main would say it and the process left
/// with the status podman gives it: 125, the error of the command
/// itself, unless the error is a `run::Failed` with its own (a container's
/// own status is given with `exit_with`).
fn exit_on_error(result: anyhow::Result<()>) -> anyhow::Result<()> {
    if let Err(e) = result {
        // a signal ended it: the status of a process the signal killed
        if let Some(client::ClientError::Interrupted(sig)) = e.downcast_ref() {
            std::process::exit(128 + sig);
        }
        // (an error that only repeats its cause says it once)
        let mut texts: Vec<String> = e.chain().map(|c| c.to_string()).collect();
        texts.dedup();
        if texts.len() == 1 {
            eprintln!("Error: {}", texts[0]);
        } else {
            eprintln!("Error: {e:?}");
        }
        std::process::exit(error_status(&e));
    }
    Ok(())
}

fn error_status(e: &anyhow::Error) -> i32 {
    e.downcast_ref::<cli::run::Failed>()
        .map_or(125, |f| f.status)
}

fn main_as(binary: Binary, startup: &velarx_sys::fd::Startup) -> anyhow::Result<()> {
    velarx_base::trace::point("client start");
    let _ = BINARY.set(binary);
    let cli = cli::parse();
    // What the engine does in this process tree (the engine service, the
    // containers of a unit...): before any
    // thread is started.
    if let Some(command) = engine_command(&cli)? {
        return match binary {
            #[cfg(feature = "engine")]
            Binary::Engine => {
                let cli::GlobalArgs {
                    config,
                    socket,
                    log_level,
                    log_format,
                    ..
                } = cli.global;
                crate::daemon::run(
                    crate::cli::engine::DaemonCli {
                        config,
                        socket,
                        log_level,
                        log_format,
                        command,
                    },
                    startup,
                )
            }
            #[cfg(not(feature = "engine"))]
            Binary::Engine => {
                let _ = command;
                unreachable!("velarx is built with the engine")
            }
            Binary::Client => exec_engine(),
        };
    }
    if let Commands::Kube { ref args } = cli.command {
        return cli::kube::run(&cli.global, args);
    }
    if let Commands::Unshare {
        rootless_netns,
        ref command,
    } = cli.command
    {
        if binary == Binary::Client {
            return exec_engine();
        }
        // before any thread: it joins the namespaces
        #[cfg(feature = "engine")]
        return run_unshare(&cli.global, rootless_netns, command).map(|never| match never {});
        #[cfg(not(feature = "engine"))]
        {
            let _ = (rootless_netns, command);
            unreachable!("velarx is built with the engine");
        }
    }
    // (GPG signing is the full binary's)
    if (matches!(
        &cli.command,
        Commands::Image(
            cli::ImageCommands::Trust(_)
                | cli::ImageCommands::GenerateSigstoreKey { .. }
                | cli::ImageCommands::Sign { .. }
        )
    ) || matches!(
        &cli.command,
        Commands::Image(cli::ImageCommands::Push { signing, .. }) if signing.sign_by.is_some()
    )) && binary == Binary::Client
    {
        return exec_engine();
    }
    // With no engine service, the command runs in the engine of this process:
    // in the rootless namespaces, joined before any thread.
    let in_process = daemonless_engine(&cli)?;
    if in_process {
        match binary {
            Binary::Client => {
                // a client of the engine service: no engine in it
                anyhow::bail!(no_server(&get_socket_path(&cli.global)?))
            }
            #[cfg(feature = "engine")]
            Binary::Engine => {
                // (the engine of this process makes cgroups; a command that
                // goes to an engine service has no engine here, and
                // `--help`, `version` and the like never get this far)
                velarx_base::cgroup::require_v2().map_err(anyhow::Error::msg)?;
                if cli::joins_namespaces(&cli.command) {
                    velarx_runtime::userns::rootless::join(
                        &cli.global.config,
                        "engine",
                        cli::starts_processes(&cli.command),
                    )?;
                }
            }
            #[cfg(not(feature = "engine"))]
            Binary::Engine => unreachable!("velarx is built with the engine"),
        }
    }
    // (the services of an engine in this process say only what is wrong,
    // as the engine's commands do)
    let level = if in_process { "warn" } else { "info" };
    logging::init(
        cli.global.log_level.as_deref().unwrap_or(level),
        &cli.global.log_format,
    );
    let result = run(cli, startup);
    finish_engine();
    result
}

/// The command of the engine `cli` asks for, if it is one.
fn engine_command(cli: &cli::Cli) -> anyhow::Result<Option<crate::cli::engine::DaemonCommand>> {
    use crate::cli::engine::DaemonCommand;
    Ok(match &cli.command {
        Commands::Varlink {
            time,
            listen_fd,
            lifeline_fd,
            cors,
            tls_cert,
            tls_key,
            tls_client_ca,
        } => {
            for (given, name) in [
                (cors.is_some(), "--cors"),
                (tls_cert.is_some(), "--tls-cert"),
                (tls_key.is_some(), "--tls-key"),
                (tls_client_ca.is_some(), "--tls-client-ca"),
            ] {
                if given {
                    anyhow::bail!(
                        "{name} is not supported by velarx varlink: the engine serves \
                         varlink, the REST API is velarx-api's (unix:// or tcp://, \
                         without TLS or CORS headers)"
                    );
                }
            }
            Some(DaemonCommand::Daemon {
                time: *time,
                listen_fd: *listen_fd,
                lifeline_fd: *lifeline_fd,
            })
        }
        Commands::Container(cmd) => {
            let socket = get_socket_path(&cli.global)?;
            let server_up = server_answers(&cli.global, &socket);
            let route = cli::run::route(
                cmd,
                cli::run::in_unit(),
                cli::run::from_manager(),
                cli.global.socket.is_some(),
                server_up,
            )
            .map_err(anyhow::Error::msg)?;
            if route != cli::run::Route::Engine {
                return Ok(None);
            }
            if !server_up && BINARY.get() == Some(&Binary::Client) {
                anyhow::bail!(no_server(&socket));
            }
            Some(DaemonCommand::Container(cmd.clone()))
        }
        _ => None,
    })
}

/// Whether the command runs in the engine of this process: one that can,
/// with no engine service.
fn daemonless_engine(cli: &cli::Cli) -> anyhow::Result<bool> {
    if cli.global.socket.is_some() || cli::daemonless(&cli.command) != cli::Daemonless::InProcess {
        return Ok(false);
    }
    let socket = get_socket_path(&cli.global)?;
    Ok(!server_answers(&cli.global, &socket))
}

/// Whether the command goes to the engine service on `socket` (the socket of
/// the command: asked once, so that every part of the command sees the same
/// answer).  `velarx` runs every command in the engine of its own process, as
/// podman does: it calls a service only when the user names one (`--socket`,
/// `--url`, `--remote`, `VELARX_HOST`, which the callers look at first), never
/// because one happens to answer.  `velarx-client` has no engine: the service
/// is all it has.
fn server_answers(global: &cli::GlobalArgs, socket: &std::path::Path) -> bool {
    if global.own_engine.is_some()
        || (BINARY.get() == Some(&Binary::Engine) && global.socket.is_none())
    {
        return false;
    }
    static ANSWERS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ANSWERS.get_or_init(|| std::os::unix::net::UnixStream::connect(socket).is_ok())
}

/// What `velarx-client` says when no engine service answers on `socket`.
fn no_server(socket: &std::path::Path) -> String {
    format!(
        "cannot connect to the engine service at {}: it does not run \
         (start it with `velarx varlink`, or use `velarx` \
         to run the command without a service)",
        socket.display()
    )
}

/// `velarx`, installed next to this binary: it runs the engine, for the
/// commands that are the engine's own.  The same arguments.
fn exec_engine() -> anyhow::Result<()> {
    use std::os::unix::process::CommandExt;
    let sibling = std::env::current_exe()?
        .parent()
        .map(|dir| dir.join("velarx"))
        .filter(|path| path.exists());
    let err = std::process::Command::new(sibling.unwrap_or_else(|| "velarx".into()))
        .args(std::env::args_os().skip(1))
        .exec();
    anyhow::bail!("cannot run velarx: {err}")
}

/// Leave with `code`, after the engine of the command is done.
fn exit_with(code: i32) -> ! {
    finish_engine();
    std::process::exit(code)
}

#[cfg(feature = "engine")]
/// `velarx unshare`: the command in the namespaces of the rootless engine,
/// with the paths of the store in the environment as podman sets them.
fn run_unshare(
    global: &cli::GlobalArgs,
    rootless_netns: bool,
    command: &[std::ffi::OsString],
) -> anyhow::Result<std::convert::Infallible> {
    let config = Config::load_or_default(&global.config)?;
    let argv = if command.is_empty() {
        vec![std::env::var_os("SHELL").unwrap_or_else(|| "/bin/sh".into())]
    } else {
        command.to_vec()
    };
    let env = [
        (
            "CONTAINERS_GRAPHROOT".to_string(),
            config.storage.root.clone().into_os_string(),
        ),
        (
            "CONTAINERS_RUNROOT".to_string(),
            config.server.state_dir.clone().into_os_string(),
        ),
    ];
    let netns_run = rootless_netns.then(|| config.server.state_dir.join("networks"));
    Err(velarx_runtime::userns::rootless::unshare(
        &config.storage.database_path(),
        &argv,
        &env,
        netns_run.as_deref(),
    )
    .into())
}

fn run(cli: cli::Cli, startup: &velarx_sys::fd::Startup) -> anyhow::Result<()> {
    let cli::Cli { global, command } = cli;
    let inv = Invocation::of(&global, &command);
    match command {
        Commands::Varlink { .. } | Commands::Unshare { .. } => {
            unreachable!()
        }
        #[cfg(feature = "engine")]
        Commands::Image(cli::ImageCommands::Trust(cmd)) => cli::trust::run(cmd)?,
        #[cfg(feature = "engine")]
        Commands::Image(cli::ImageCommands::GenerateSigstoreKey {
            output_prefix,
            passphrase_file,
        }) => cli::sigstore_key::run(&output_prefix, passphrase_file.as_deref())?,
        Commands::Image(cmd) => run_image_command(cmd, &inv)?,
        Commands::Container(cmd) => run_container_command(cmd, &inv, startup)?,
        Commands::Volume(cmd) => run_volume_command(cmd, &inv)?,
        Commands::Pod(cmd) => run_pod_command(cmd, &inv)?,
        Commands::Network(cmd) => run_network_command(cmd, &inv)?,
        Commands::AutoUpdate(args) => {
            cli::autoupdate::run(args, &get_client(&inv)?, &registry_access)?
        }
        Commands::Secret(cmd) => cli::secret::run(cmd, &get_client(&inv)?)?,
        Commands::Artifact(cmd) => cli::artifact::run(cmd, &get_client(&inv)?)?,
        Commands::Manifest(cmd) => cli::manifest::run(cmd, &get_client(&inv)?, &registry_access)?,
        Commands::Kube { .. } => unreachable!("run before the engine is chosen"),
        Commands::Quadlet(cmd) => cli::quadlet::run(cmd)?,
        Commands::Version { format } => {
            // the server's too, if one answers
            let socket = get_socket_path(&global)?;
            let client = server_answers(&global, &socket)
                .then(|| client::EngineClient::new(&socket).ok())
                .flatten();
            let v = cli::report::version(client.as_ref());
            match format {
                Some(f) => cli::report::one(&v, &f)?,
                None => print!("{}", cli::report::version_text(&v)?),
            }
        }
        Commands::Info { format } => run_info(&inv, format.as_deref())?,
        Commands::Health => run_health(&inv)?,
        Commands::System(cmd) => run_system_command(cmd, &inv)?,
        Commands::Healthcheck(cmd) => run_healthcheck_command(cmd, &inv)?,
        Commands::Events {
            since,
            until,
            filter,
            format,
            no_trunc,
            stream,
        } => run_events_command(
            &inv,
            since,
            until,
            filter,
            cli::events::Format::new(format.as_deref(), no_trunc),
            stream,
        )?,
        Commands::Stats {
            all,
            no_stream,
            format,
            latest,
            view,
            containers,
        } => {
            let containers = if latest {
                cli::run::named_or_latest(&get_client(&inv)?, true, containers)?
            } else {
                containers
            };
            run_stats_command(&inv, all, no_stream, format, containers, &view)?
        }
        Commands::Completion { shell } => {
            cli::generate_completions(shell);
        }
        Commands::Registry(cmd) => match cmd {
            RegistryCommands::Login {
                username,
                password,
                password_stdin,
                authfile,
                compat_auth_file,
                secret,
                tls_verify,
                cert_dir,
                get_login,
                verbose,
                server,
            } => {
                let authfile = one_authfile(authfile, compat_auth_file)?;
                let (username, password) = match secret {
                    None => (username, password),
                    Some(name) => {
                        if password.is_some() {
                            anyhow::bail!("--secret can not be used with --password options");
                        }
                        let found = get_client(&inv)?.secret_inspect(&name, true).map_err(|e| {
                            if e.is_not_found() {
                                anyhow::anyhow!(
                                    "no secret with name or id {name:?}: no such secret"
                                )
                            } else {
                                anyhow::anyhow!("{e}")
                            }
                        })?;
                        let data =
                            String::from_utf8_lossy(&found.data.unwrap_or_default()).into_owned();
                        (username.or(Some(name)), Some(data))
                    }
                };
                run_login_command(
                    &global.config,
                    LoginArgs {
                        username,
                        password,
                        password_stdin,
                        authfile,
                        tls_verify,
                        cert_dir,
                        get_login,
                        verbose,
                    },
                    server,
                )?;
            }
            RegistryCommands::Logout {
                all,
                authfile,
                compat_auth_file,
                server,
            } => {
                let authfile = one_authfile(authfile, compat_auth_file)?;
                run_logout_command(all, authfile, server)?;
            }
        },
    }

    Ok(())
}

/// Format a byte size into human-readable form (e.g., "1.5 GB", "256 MB")
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn get_socket_path(global: &cli::GlobalArgs) -> anyhow::Result<std::path::PathBuf> {
    if let Some(ref socket) = global.socket {
        Ok(socket.clone())
    } else {
        let config = Config::load_or_default(&global.config)?;
        Ok(config.engine_socket())
    }
}

/// What runs the operations of a command: the engine service, or (with none
/// running) the service of the engine of the command in this process.
fn get_client(inv: &Invocation<'_>) -> anyhow::Result<client::EngineClient> {
    let global = inv.global;
    let socket_path = get_socket_path(global)?;
    // With no engine service, the engine of this process runs the command.
    if global.socket.is_none() && !server_answers(global, &socket_path) {
        match inv.daemonless {
            cli::Daemonless::InProcess => return engine(inv),
            cli::Daemonless::NeedsServer(_) => return server(inv),
            cli::Daemonless::Standalone(_) => {}
        }
    }
    if global.signature_policy.is_some() {
        anyhow::bail!(
            "--signature-policy is not supported with an engine service: its policy is the \
             one of its configuration ([pull] policy_path)"
        );
    }
    Ok(client::EngineClient::new(&socket_path)?)
}

/// What a command that needs the engine service says when none runs.
fn needs_server(what: &str) -> String {
    format!(
        "{what} needs the engine service, which does not run: start it with \
         `velarx varlink` (or `systemctl --user start velarx-engine.socket`)"
    )
}

/// The engine service, for what only a service does (`NeedsServer`: the
/// command is about the service, so its socket is the one named).
fn server(inv: &Invocation<'_>) -> anyhow::Result<client::EngineClient> {
    let global = inv.global;
    let socket = get_socket_path(global)?;
    if global.socket.is_none()
        && (global.own_engine.is_some()
            || std::os::unix::net::UnixStream::connect(&socket).is_err())
    {
        if let cli::Daemonless::NeedsServer(what) = inv.daemonless {
            if let Some(option) = global.own_engine {
                anyhow::bail!("{what} needs the engine service, which does not take {option}");
            }
            anyhow::bail!(needs_server(what));
        }
    }
    Ok(client::EngineClient::new(&socket)?)
}

#[cfg(feature = "engine")]
fn engine(inv: &Invocation<'_>) -> anyhow::Result<client::EngineClient> {
    if BINARY.get() != Some(&Binary::Engine) {
        // (`main_as` gave the command to `velarx`)
        anyhow::bail!("no engine service answers, and velarx-client runs no engine");
    }
    if let Some(e) = crate::engine::process::started() {
        return crate::engine::process::service(e);
    }
    let config = crate::engine::load_config(&inv.global.config)?;
    // (`create --cgroups=disabled`: an image it pulls gets its workers no
    // cgroup, as `run` does)
    let config = match &inv.cgroups {
        Some(asked) if crate::engine::cgroups_disabled(&config, asked) => {
            crate::engine::without_pull_cgroups(config)
        }
        _ => config,
    };
    let role = crate::daemon::Role::Engine {
        notify_socket: None,
        listen_fds: Vec::new(),
        preserve_holes: Vec::new(),
        split_cgroup: None,
        in_process: None,
        // (asked when a container needs it: `start`, `restart` and `exec`
        // of one with `--cgroups=disabled` do not connect to the manager)
        systemd_cgroups: velarx_core::services::SystemdCgroups::probe(
            crate::engine::systemd_cgroups_probe,
        ),
    };
    // (the engine service it serves from this process)
    crate::engine::process::service(crate::engine::process::start(
        config,
        &inv.global.config,
        &role,
    )?)
}

#[cfg(feature = "engine")]
fn finish_engine() {
    crate::engine::process::finish();
}

#[cfg(not(feature = "engine"))]
fn engine(_inv: &Invocation<'_>) -> anyhow::Result<client::EngineClient> {
    // (`main_as` gave the command to `velarx`)
    anyhow::bail!("no engine service answers, and velarx-client runs no engine")
}

#[cfg(not(feature = "engine"))]
fn finish_engine() {}

/// Format duration in human-readable form
fn format_duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.2}s", ms as f64 / 1000.0)
    } else {
        let minutes = ms / 60_000;
        let seconds = (ms % 60_000) as f64 / 1000.0;
        format!("{}m {:.1}s", minutes, seconds)
    }
}

/// A registry that could not be reached: the words of the failure say which
/// one it was and what was asked.
#[derive(Debug)]
struct RegistryUnreachable(String);

impl std::fmt::Display for RegistryUnreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RegistryUnreachable {}

/// The failure of a login, as an error that tells a registry that could not
/// be reached from one that refused.
#[cfg(feature = "engine")]
fn login_failure(e: &velarx_types::ImageError) -> anyhow::Error {
    let text = velarx_content::pull::net::origin::failure_text(e);
    match e {
        velarx_types::ImageError::Unreachable(_) => anyhow::Error::new(RegistryUnreachable(text)),
        _ => anyhow::anyhow!("{text}"),
    }
}

/// The registry takes these credentials (an engine build asks it).
#[cfg(feature = "engine")]
fn check_login(
    config: &std::path::Path,
    server: &str,
    username: &str,
    password: &str,
    tls_verify: bool,
    cert_dir: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let access = registry::auth::RegistryAccess {
        creds: Some(registry::Credentials::basic(username, password)),
        certs: cert_dir
            .map(registry::certs::RawCerts::read_dir)
            .transpose()
            .map_err(|e| anyhow::anyhow!("--cert-dir: {e}"))?,
        ..Default::default()
    };
    // The fetcher asks the registry: the password goes to it in
    // a file with no name, and this process opens no connection.
    let config = crate::engine::load_config(config)?;
    let origin = velarx_content::list::RegistryOrigin::private(&config);
    let remote = velarx_content::pull::net::origin::OriginRemote::new(
        origin,
        &format!("{server}/library/login"),
        tls_verify,
        &access,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(remote.login())
        .map_err(|e| login_failure(&e))
}

/// (the thin client has no HTTP client: the server of a login is not asked)
#[cfg(not(feature = "engine"))]
fn check_login(
    _config: &std::path::Path,
    _server: &str,
    _username: &str,
    _password: &str,
    _tls_verify: bool,
    _cert_dir: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_password_on_stdin_is_read_as_podman_reads_it() {
        assert_eq!(password_of_stdin("pw\n"), "pw");
        assert_eq!(password_of_stdin("pw\r\n"), "pw");
        assert_eq!(password_of_stdin("pw\n\n"), "pw");
        assert_eq!(password_of_stdin("a\nb\n"), "ab");
        assert_eq!(password_of_stdin("pw  \n"), "pw  ");
        assert_eq!(password_of_stdin(" pw"), " pw");
    }

    use super::*;

    /// A configuration that cannot be read stops a login: it is not taken
    /// for none, which would ask the registry from this process instead of
    /// the confined fetcher.
    #[cfg(feature = "engine")]
    #[test]
    fn a_login_with_a_configuration_that_cannot_be_read_fails() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "[pull\nmax_workers = ").unwrap();
        let e = check_login(&config, "localhost:1", "u", "p", true, None).unwrap_err();
        assert!(!e.is::<RegistryUnreachable>(), "{e}");
        assert!(e.to_string().contains("failed to parse config"), "{e}");
    }

    #[test]
    fn check_prints_what_podman_prints() {
        use velarx_proto::system::*;
        assert_eq!(check_text(&CheckReport::default()), "");
        let p = |image: Option<&str>, action| CheckProblem {
            image: image.map(str::to_string),
            kind: "k".into(),
            message: "m".into(),
            path: None,
            action,
            ..Default::default()
        };
        let report = CheckReport {
            problems: vec![
                p(Some("img"), CheckAction::ImageRemoved),
                p(Some("img"), CheckAction::ImageRemoved),
                p(None, CheckAction::None),
            ],
            removed_containers: vec![CheckRemovedContainer {
                id: "ctr".into(),
                name: "n".into(),
            }],
            ..Default::default()
        };
        assert_eq!(
            check_text(&report),
            "Damaged layer k:\n1 error occurred:\n\t* k: m\n\n\
             Damaged image img:\n2 errors occurred:\n\t* k: m\n\t* k: m\n\n\
             Deleted damaged image: img\n\
             Deleted damaged container: ctr\n"
        );
    }

    #[test]
    fn check_flags_are_podmans() {
        let cli = cli::parse_for_test([
            "velarx",
            "system",
            "check",
            "-q",
            "-r",
            "-f",
            "-m",
            "1h",
            "--timeout",
            "5s",
        ])
        .unwrap();
        let Commands::System(SystemCommands::Check {
            quick,
            repair,
            force,
            max,
            timeout,
            ..
        }) = cli.command
        else {
            panic!()
        };
        assert!(quick && repair && force);
        assert_eq!(
            (max.as_deref(), timeout.as_deref()),
            (Some("1h"), Some("5s"))
        );
        let cli = cli::parse_for_test(["velarx", "system", "check", "--repair-lossy"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::System(SystemCommands::Check { force: true, .. })
        ));
    }

    use crate::cli::run::each_named;

    fn api(status: u16) -> client::ClientError {
        client::ClientError::api(status, "x".into())
    }

    #[test]
    fn test_errors_exit_as_podman_s() {
        let names = ["a".to_string(), "b".to_string()];
        // only missing names: podman's rm and stop exit 1
        let e = each_named(&names, false, |_| Err(api(404))).unwrap_err();
        assert_eq!(error_status(&e), 1);
        // a missing name and another error: the missing decides, 1
        let e = each_named(&names, false, |n| {
            Err(api(if n == "a" { 404 } else { 500 }))
        })
        .unwrap_err();
        assert_eq!(error_status(&e), 1);
        // the last failure is the error, said as podman says it
        assert_eq!(e.to_string(), "x");
        // stop: 125 even for the missing, podman's message
        let e = cli::run::each_named_as(&names[..1], false, &cli::run::Statuses::CONTAINER, |_| {
            Err(api(404))
        })
        .unwrap_err();
        assert_eq!(error_status(&e), 125);
        assert_eq!(
            e.to_string(),
            "no container with name or ID \"a\" found: no such container"
        );
        // rm of a running container: 2; another error: 125
        let e = each_named(&names[..1], false, |_| Err(api(409))).unwrap_err();
        assert_eq!(error_status(&e), 2);
        let e = each_named(&names[..1], false, |_| Err(api(400))).unwrap_err();
        assert_eq!(error_status(&e), 125);
        // volume rm of a volume in use: 2
        let e = cli::run::each_named_as(&names[1..], false, &cli::run::Statuses::VOLUME_RM, |_| {
            Err(api(409))
        })
        .unwrap_err();
        assert_eq!(error_status(&e), 2);
        // ... and a missing one: podman looked it up first, 2 and the
        // in-use error is the last
        for list in [["a", "b"], ["b", "a"]] {
            let list = list.map(String::from);
            let e = cli::run::each_named_as(&list, false, &cli::run::Statuses::VOLUME_RM, |n| {
                Err(api(if n == "a" { 404 } else { 409 }))
            })
            .unwrap_err();
            assert_eq!(error_status(&e), 2, "{list:?}");
        }
        // a missing name ignored, the other found
        each_named(
            &names,
            true,
            |n| if n == "a" { Err(api(404)) } else { Ok(()) },
        )
        .unwrap();
        // any other error: 125
        assert_eq!(error_status(&anyhow::anyhow!("no such pod")), 125);
        let e = anyhow::Error::from(cli::run::Failed {
            status: 2,
            message: "x".into(),
        });
        assert_eq!(error_status(&e.context("in context")), 2);
    }

    #[test]
    fn test_context_tar_leaves_out_what_is_ignored() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path();
        std::fs::create_dir_all(p.join(".git/objects")).unwrap();
        std::fs::create_dir_all(p.join("sub/keep")).unwrap();
        std::fs::write(p.join(".git/objects/o"), "o").unwrap();
        std::fs::write(p.join("secret.env"), "s").unwrap();
        std::fs::write(p.join("sub/keep/k"), "k").unwrap();
        std::fs::write(p.join("sub/other"), "o").unwrap();
        std::fs::write(p.join("app"), "a").unwrap();
        std::fs::write(p.join("Containerfile"), "FROM x").unwrap();
        std::fs::write(
            p.join(".containerignore"),
            ".git\n*.env\nsub\n!sub/keep\nContainerfile\n",
        )
        .unwrap();
        std::os::unix::fs::symlink("/etc/passwd", p.join("link")).unwrap();
        let mut out = Vec::new();
        context_tar(
            p,
            None,
            vec![("added".into(), b"FROM y".to_vec())],
            &["Containerfile".into()],
            &[],
            &mut out,
        )
        .unwrap();
        let mut names: Vec<(String, tar::EntryType)> = tar::Archive::new(&out[..])
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.path()
                        .unwrap()
                        .to_string_lossy()
                        .trim_end_matches('/')
                        .to_string(),
                    e.header().entry_type(),
                )
            })
            .collect();
        names.sort_by(|a, b| a.0.cmp(&b.0));
        let shown: Vec<&str> = names.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            shown,
            [
                ".containerignore",
                "Containerfile",
                "added",
                "app",
                "link",
                "sub/keep",
                "sub/keep/k"
            ]
        );
        let link = names.iter().find(|(n, _)| n == "link").unwrap();
        assert_eq!(link.1, tar::EntryType::Symlink);

        // --ignorefile replaces the context's
        let other = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(other.path(), "app\n").unwrap();
        let mut out = Vec::new();
        context_tar(p, Some(other.path()), Vec::new(), &[], &[], &mut out).unwrap();
        let names: Vec<String> = tar::Archive::new(&out[..])
            .entries()
            .unwrap()
            .map(|e| {
                e.unwrap()
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .trim_end_matches('/')
                    .to_string()
            })
            .collect();
        assert!(!names.contains(&"app".to_string()), "{names:?}");
        assert!(names.contains(&"secret.env".to_string()), "{names:?}");
        let missing = d.path().join("nonexistent-ignore");
        assert!(context_tar(p, Some(&missing), Vec::new(), &[], &[], &mut Vec::new()).is_err());
    }
}
