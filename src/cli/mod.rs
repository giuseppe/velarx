// SPDX-License-Identifier: Apache-2.0
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

pub mod attach;
pub mod autoupdate;
pub mod checkpoint;
pub mod commands;
pub mod cp;
pub mod engine;
pub mod events;
pub mod gpg;
pub mod kube;
pub mod manifest;
pub mod progress;
pub mod quadlet;
pub mod run;
pub mod sigstore_key;
pub mod transport;
pub mod trust;
pub use trust::TrustCommands;
pub mod artifact;
pub mod podlogs;
pub mod report;
pub mod secret;
pub mod template;
pub use secret::SecretCommands;

mod container_args;
mod daemonless;
mod image_args;
mod layout;
mod system_args;
pub use container_args::*;
pub use daemonless::*;
pub use image_args::*;
pub use layout::*;
pub use system_args::*;

pub fn default_config() -> PathBuf {
    // (a default of the command line, asked for by the parser: an unreadable
    // map is reported and ends the command)
    velarx_config::DefaultDirs::current()
        .unwrap_or_else(|e| e.exit())
        .config_file
}

/// The configuration file of the command (`--config`).
static CONFIG_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// The configuration of the command, for the settings the command line
/// itself takes (the detach keys).
pub fn config() -> anyhow::Result<velarx_config::Config> {
    let path = CONFIG_PATH.get().cloned().unwrap_or_else(default_config);
    Ok(velarx_config::Config::load_or_default(path)?)
}

#[derive(Parser)]
#[command(name = "velarx")]
#[command(author = "Velarx Authors")]
// `-V` and `--version` (the field `version`, for the help) are answered by
// print_version_if_asked, before the parse
#[command(disable_version_flag = true)]
#[command(about = "A container engine for Linux that runs OCI images")]
// as podman (pflag): an option given twice takes its last value
#[command(args_override_self = true)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Commands,
}

/// The options that come before the command and are the same for all of
/// them.
#[derive(clap::Args)]
pub struct GlobalArgs {
    /// Path to config file
    #[arg(long, default_value_os_t = default_config())]
    pub config: PathBuf,

    /// Path to the socket of the engine service (overrides the config file;
    /// also VELARX_SOCKET).  With it the command always goes to that engine,
    /// never to one of its own.
    #[arg(long)]
    pub socket: Option<PathBuf>,

    /// The level of the messages (default: info; warn for the commands the
    /// engine runs itself); debug also says, for a container that enforces
    /// the fs-verity digests, each link of the chain of trust from the
    /// digest to the mount (`verity chain:`)
    #[arg(long)]
    pub log_level: Option<String>,

    #[arg(long, default_value = "text")]
    pub log_format: String,

    /// podman's containers.conf module: refused, the settings are those of
    /// --config
    #[arg(long, value_name = "MODULE", hide = true)]
    pub module: Vec<String>,

    /// The events backend: journald, file or none (default: `[server]
    /// events_logger` of the configuration)
    #[arg(long, value_name = "BACKEND")]
    pub events_backend: Option<String>,

    /// The root of the store (the configuration file's storage root); with
    /// no --runroot, another store has a run root (and a server) of its own
    #[arg(long, value_name = "PATH")]
    pub root: Option<PathBuf>,

    /// The directory of the sockets and the state of the running containers
    /// (the configuration file's state_dir); the server of the commands is
    /// the one of that directory
    #[arg(long, value_name = "PATH")]
    pub runroot: Option<PathBuf>,

    /// The directory of the temporary files of the command and its
    /// processes (their TMPDIR)
    #[arg(long, value_name = "PATH")]
    pub tmpdir: Option<PathBuf>,

    /// The storage driver of the store (`composefs`; the one the store was
    /// made with when none is given); `overlay`, the name reported for
    /// it, is accepted and chooses nothing
    #[arg(long, value_name = "DRIVER")]
    pub storage_driver: Option<String>,

    /// The OCI runtime: a path, or a name looked up in PATH (default:
    /// [server] runtime of the configuration, else crun)
    #[arg(long, value_name = "NAME|PATH")]
    pub runtime: Option<String>,

    /// Add a global flag of the OCI runtime (`debug` for `--debug`)
    #[arg(long, value_name = "FLAG")]
    pub runtime_flag: Vec<String>,

    /// How the cgroups of the containers are made: cgroupfs or systemd
    #[arg(long, value_name = "MANAGER")]
    pub cgroup_manager: Option<String>,

    /// A directory of OCI hooks (repeatable; default: `[containers]
    /// hooks_dir` of the configuration)
    #[arg(long, value_name = "DIR")]
    pub hooks_dir: Vec<PathBuf>,

    /// A directory of CDI spec files (repeatable; default: `[containers]
    /// cdi_spec_dirs` of the configuration)
    #[arg(long, value_name = "DIR")]
    pub cdi_spec_dir: Vec<PathBuf>,

    /// Always ask the engine service, never an engine of the command's own
    #[arg(long, short = 'r')]
    pub remote: bool,

    /// The address of the engine service: unix:///PATH (as VELARX_HOST)
    #[arg(long, value_name = "URL")]
    pub url: Option<String>,

    /// The global option of the engine's settings given (`--runtime`...):
    /// the command runs in an engine of its own, never in the engine service
    /// that has settings of its own
    #[arg(skip)]
    pub own_engine: Option<&'static str>,

    /// The signature policy file of this command, instead of the
    /// configured one (pull, push, load, build, create, run,
    /// artifact pull and push; the engine of the command only)
    #[arg(long, global = true, hide = true, value_name = "PATH")]
    pub signature_policy: Option<PathBuf>,

    /// Send the standard output to /dev/null
    #[arg(long)]
    pub noout: bool,

    /// Send the standard output to this file
    #[arg(long, value_name = "FILE", conflicts_with = "noout")]
    pub out: Option<PathBuf>,

    /// Print version
    #[arg(short = 'V', long)]
    pub version: bool,
}

#[derive(Subcommand)]
#[allow(
    clippy::large_enum_variant,
    reason = "parsed once into one value; boxing a clap variant means a struct of its own for each"
)]
pub enum Commands {
    #[command(subcommand, about = "Manage images")]
    Image(ImageCommands),

    #[command(subcommand, about = "Manage containers")]
    Container(ContainerCommands),

    /// Run a command in the user and mount namespaces of the rootless
    /// engine (the files of sub ids are the root's there)
    #[command(trailing_var_arg = true)]
    Unshare {
        /// Join the rootless network namespace of the bridge networks too
        #[arg(long)]
        rootless_netns: bool,
        /// The command (default: $SHELL)
        #[arg(allow_hyphen_values = true)]
        command: Vec<std::ffi::OsString>,
    },

    #[command(subcommand, about = "Manage volumes")]
    Volume(VolumeCommands),

    #[command(subcommand, about = "Manage networks")]
    Network(NetworkCommands),

    #[command(subcommand, about = "Manage pods")]
    Pod(PodCommands),

    #[command(subcommand, about = "Manage secrets")]
    Secret(SecretCommands),

    #[command(subcommand, about = "Manage manifest lists")]
    Manifest(manifest::ManifestCommands),

    #[command(
        name = "auto-update",
        about = "Update the containers of systemd units whose image changed"
    )]
    AutoUpdate(autoupdate::AutoUpdateArgs),

    #[command(subcommand, about = "Manage registry authentication")]
    Registry(RegistryCommands),

    #[command(
        subcommand,
        about = "Choose the generator of the Quadlet units (velarx's or podman's)"
    )]
    Quadlet(quadlet::QuadletCommands),

    #[command(subcommand, about = "Manage OCI artifacts")]
    Artifact(artifact::ArtifactCommands),

    #[command(about = "Show the version of velarx, and of the engine service")]
    Version {
        /// Go template of the versions, or `json`
        #[arg(long, short)]
        format: Option<String>,
    },

    #[command(about = "Show runtime information")]
    Info {
        /// Go template of the information, or `json`
        #[arg(long, short)]
        format: Option<String>,
    },

    #[command(about = "Check runtime health")]
    Health,

    /// Serve the engine: the varlink interface org.velarx.Engine on the
    /// engine socket (`[engine] socket`), which the command line, the thin
    /// client and the frontends (velarx-api, velarx-cri) call
    #[command(about = "Serve the engine")]
    Varlink {
        /// Exit after SECONDS without a client connected (running containers
        /// go on under their monitors, and the next engine follows them
        /// again); the default is `[engine] idle_exit`, 0 never.  For an
        /// engine started by its socket.
        #[arg(long, short = 't', value_name = "SECONDS")]
        time: Option<u64>,
        /// Refused: the engine serves varlink; the REST API is velarx-api's,
        /// which has no CORS headers
        #[arg(long, value_name = "ORIGIN")]
        cors: Option<String>,
        /// Refused: velarx-api serves the REST API on a unix socket or
        /// plain TCP, with no TLS
        #[arg(long, value_name = "FILE")]
        tls_cert: Option<String>,
        /// Refused (as --tls-cert)
        #[arg(long, value_name = "FILE")]
        tls_key: Option<String>,
        /// Refused (as --tls-cert)
        #[arg(long, value_name = "FILE")]
        tls_client_ca: Option<String>,
        /// The listening socket is this descriptor (a frontend that started
        /// the engine passes it)
        #[arg(long, value_name = "FD", hide = true)]
        listen_fd: Option<i32>,
        /// The engine stops when the other end of this socket is closed (the
        /// frontend that started it passes it, and keeps its end as long as
        /// it lives)
        #[arg(long, value_name = "FD", hide = true)]
        lifeline_fd: Option<i32>,
    },

    #[command(subcommand, about = "Manage system resources")]
    System(SystemCommands),

    #[command(subcommand, about = "Manage container healthchecks")]
    Healthcheck(HealthcheckCommands),

    #[command(about = "Get real-time events from the server")]
    Events {
        /// Show events since timestamp (e.g., 2024-01-01T00:00:00 or unix timestamp)
        #[arg(long)]
        since: Option<String>,
        /// Show events until timestamp
        #[arg(long)]
        until: Option<String>,
        /// Filter events by type (container, image, network, volume)
        #[arg(long, short)]
        filter: Vec<String>,
        /// Output format: json, or a template of the fields
        /// ({{.Type}}, {{.Status}}, {{.ID}}, {{.Name}}, {{.Image}},
        /// {{.ContainerExitCode}}, {{.Time}}, {{.Attributes}}...)
        #[arg(long)]
        format: Option<String>,
        /// Do not truncate the output (default true)
        #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value = "true", action = clap::ArgAction::Set)]
        no_trunc: bool,
        /// Follow the events as they happen (false: list those kept)
        #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value = "true", action = clap::ArgAction::Set)]
        stream: bool,
    },

    #[command(about = "Display a live stream of resource usage statistics")]
    Stats {
        /// Show all containers (default shows just running)
        #[arg(long, short)]
        all: bool,
        /// Disable streaming stats and only pull the first result
        #[arg(long)]
        no_stream: bool,
        /// Pretty-print output
        #[arg(long)]
        format: Option<String>,
        /// The container made last
        #[arg(long, short = 'l')]
        latest: bool,
        #[command(flatten)]
        view: StatsView,
        /// Container names or IDs
        containers: Vec<String>,
    },

    #[command(about = "Generate shell completions")]
    Completion {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: CompletionShell,
    },

    /// Play, tear down, generate and apply Kubernetes YAML (runs `velarx-kube`)
    ///
    /// The program is found next to this executable or in PATH, and gets the
    /// global options `--config`, `--log-level` and `--log-format` in front
    /// of the arguments.
    #[command(disable_help_flag = true)]
    Kube {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
}

/// When `container run` and `container create` pull the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullPolicy {
    Always,
    Missing,
    Never,
    /// Pull when the registry has another version
    Newer,
}

/// A stream of `--attach`, in lower case.
pub fn parse_attach_stream(s: &str) -> Result<String, String> {
    match s.to_lowercase().as_str() {
        l @ ("stdin" | "stdout" | "stderr") => Ok(l.to_string()),
        _ => Err(format!(
            "invalid stream {s:?} for --attach - must be one of stdin, stdout, or stderr"
        )),
    }
}

pub fn parse_pull_policy(s: &str) -> Result<PullPolicy, String> {
    // (podman's words, in any case; `true` and `false` are Docker's)
    match s.to_lowercase().as_str() {
        "always" | "true" => Ok(PullPolicy::Always),
        "missing" | "ifmissing" | "ifnotpresent" | "" => Ok(PullPolicy::Missing),
        "never" | "false" => Ok(PullPolicy::Never),
        "newer" | "ifnewer" => Ok(PullPolicy::Newer),
        _ => Err(format!("unsupported pull policy \"{s}\"")),
    }
}

/// Shell types for completion generation
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Elvish,
    PowerShell,
}

impl From<CompletionShell> for Shell {
    fn from(shell: CompletionShell) -> Self {
        match shell {
            CompletionShell::Bash => Shell::Bash,
            CompletionShell::Zsh => Shell::Zsh,
            CompletionShell::Fish => Shell::Fish,
            CompletionShell::Elvish => Shell::Elvish,
            CompletionShell::PowerShell => Shell::PowerShell,
        }
    }
}

/// Generate shell completions and write them to stdout
pub fn generate_completions(shell: CompletionShell) {
    let mut cmd = Cli::command();
    let shell: Shell = shell.into();
    generate(shell, &mut cmd, "velarx", &mut io::stdout());
}

/// `-v` and `--version` among the global options print podman's line.
fn print_version_if_asked(args: &[std::ffi::OsString]) {
    let mut i = 1;
    while let Some(a) = args.get(i).and_then(|a| a.to_str()) {
        if !a.starts_with('-') || a == "--" {
            return;
        }
        if a == "-v" || a == "-V" || a == "--version" {
            println!(
                "velarx version {} ({})",
                env!("CARGO_PKG_VERSION"),
                velarx_base::buildinfo::commit()
            );
            std::process::exit(0);
        }
        let name = a.split_once('=').map_or(a, |(n, _)| n);
        if VALUE_OPTIONS.contains(&name) && !a.contains('=') {
            i += 1;
        }
        i += 1;
    }
}

/// The command of velarx, with podman's (pflag) rule for an option's value:
/// a negative number after the option is its value (`--pids-limit -1`,
/// `--memory-swap -1`, `--oom-score-adj -500`, `--cpu-quota -1`).  clap
/// takes `-1` for a short option unless each option says otherwise.
pub(crate) fn command_line() -> clap::Command {
    fn negative(cmd: clap::Command) -> clap::Command {
        cmd.mut_args(|a| {
            if a.get_action().takes_values() && !a.is_positional() {
                a.allow_negative_numbers(true)
            } else {
                a
            }
        })
        .mut_subcommands(negative)
    }
    negative(Cli::command())
}

/// `Cli::try_parse_from` with the command `cmd` ([`command_line`]).
fn try_parse_with(
    cmd: clap::Command,
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<Cli, clap::Error> {
    use clap::FromArgMatches;
    let mut matches = cmd.try_get_matches_from(args)?;
    Cli::from_arg_matches_mut(&mut matches)
}

pub fn parse() -> Cli {
    print_version_if_asked(&std::env::args_os().collect::<Vec<_>>());
    let args = match podman_layout(std::env::args_os().collect()) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(125);
        }
    };
    // podman's status for a command line it does not take is 125 (clap's
    // is 2); the help and the version stay a success
    // (built once: the retries below build their own)
    let cmd = command_line();
    let mut args = end_options_after_operand(&cmd, args);
    let mut cmd = Some(cmd);
    let mut cli = loop {
        match try_parse_with(
            cmd.take().unwrap_or_else(command_line),
            args.iter().cloned(),
        ) {
            Ok(cli) => break cli,
            Err(e) => {
                // (`--all=true`: a flag that takes no value in clap does in
                // Go's)
                if let (clap::error::ErrorKind::TooManyValues, Some(invalid)) =
                    (e.kind(), e.get(clap::error::ContextKind::InvalidArg))
                {
                    if layout::plain_bool_flag(&mut args, &invalid.to_string()) {
                        continue;
                    }
                }
                if let (clap::error::ErrorKind::UnknownArgument, Some(invalid)) =
                    (e.kind(), e.get(clap::error::ContextKind::InvalidArg))
                {
                    match layout::hoist_global_option(&mut args, &invalid.to_string()) {
                        Ok(true) => continue,
                        Ok(false) => {}
                        Err(why) => {
                            eprintln!("Error: {why}");
                            std::process::exit(125);
                        }
                    }
                }
                if let Some(words) = layout::go_operand_error(&e, &args) {
                    eprintln!("Error: {words}");
                    std::process::exit(125);
                }
                let typed: Vec<_> = std::env::args_os().collect();
                if let Some(words) = layout::go_flag_error(&e, &args, &typed) {
                    eprintln!("Error: {words}");
                    std::process::exit(125);
                }
                let _ = e.print();
                std::process::exit(if e.use_stderr() { 125 } else { 0 });
            }
        }
    };
    // `build --runtime-flag`, `--hooks-dir`: those of the RUN containers,
    // which are all the containers the command makes
    if let Commands::Image(ImageCommands::Build { extra, .. }) = &mut cli.command {
        cli.global.runtime_flag.append(&mut extra.runtime_flag);
        cli.global.hooks_dir.append(&mut extra.hooks_dir);
    }
    if cli.global.signature_policy.is_some() && !takes_signature_policy(&cli.command) {
        eprintln!("Error: unknown flag: --signature-policy");
        std::process::exit(125);
    }
    // (before they are exported: the settings of the files)
    let own_engine = engine_setting(&cli.global);
    export_global_options(&cli.global);
    // --noout, --out: the standard output of the command goes there
    let out = match (&cli.global.out, cli.global.noout) {
        (Some(path), _) => {
            Some(std::fs::File::create(path).map_err(|e| format!("{}: {e}", path.display())))
        }
        (None, true) => Some(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/null")
                .map_err(|e| e.to_string()),
        ),
        (None, false) => None,
    };
    match out {
        Some(Ok(f)) => {
            if let Err(e) = rustix::stdio::dup2_stdout(&f) {
                eprintln!("Error: redirecting the output: {e}");
                std::process::exit(125);
            }
        }
        Some(Err(e)) => {
            eprintln!("Error: {e}");
            std::process::exit(125);
        }
        None => {}
    }
    // podman --remote (or --url) has no flags of the engine
    if cli.global.remote || cli.global.url.is_some() {
        if let Some(flag) = engine_only_flag(&cli.global) {
            eprintln!("Error: unknown flag: {flag}");
            std::process::exit(125);
        }
    }
    if !cli.global.module.is_empty() {
        eprintln!(
            "Error: --module: velarx reads no containers.conf: its settings are in {}",
            cli.global.config.display()
        );
        std::process::exit(125);
    }
    let _ = CONFIG_PATH.set(cli.global.config.clone());
    if cli.global.socket.is_none() {
        if let Some(url) = cli.global.url.clone() {
            match socket_of_host(&url) {
                Ok(p) => cli.global.socket = Some(p),
                Err(e) => {
                    eprintln!("Error: --url: {e}");
                    std::process::exit(125);
                }
            }
        }
    }
    if cli.global.socket.is_none() {
        cli.global.socket = socket_from_env(std::env::var_os("VELARX_SOCKET"));
    }
    // (podman's named connection of the environment: velarx has none)
    if cli.global.socket.is_none()
        && std::env::var_os("CONTAINER_CONNECTION").is_some_and(|c| !c.is_empty())
    {
        eprintln!(
            "Error: CONTAINER_CONNECTION: velarx has no named connections: use --socket or VELARX_HOST=unix://"
        );
        std::process::exit(125);
    }
    if cli.global.socket.is_none() {
        // the address of the engine (the REST API of podman and docker is
        // another socket, velarx-api's: CONTAINER_HOST and DOCKER_HOST name it)
        if let Some(v) = std::env::var_os("VELARX_HOST").filter(|v| !v.is_empty()) {
            match socket_of_host(&v.to_string_lossy()) {
                Ok(p) => cli.global.socket = Some(p),
                Err(e) => {
                    eprintln!("Error: VELARX_HOST: {e}");
                    std::process::exit(125);
                }
            }
        }
    }
    if let Some(name) = own_engine {
        if cli.global.socket.is_some() || cli.global.remote {
            eprintln!(
                "Error: {name}: the engine has the settings of its own configuration \
                 (without --remote, --url, --socket or VELARX_HOST the command runs in \
                 an engine of its own)"
            );
            std::process::exit(125);
        }
        cli.global.own_engine = Some(name);
    }
    // --remote: the engine of the configuration, never one of this process
    if cli.global.remote && cli.global.socket.is_none() {
        match velarx_config::Config::load_or_default(&cli.global.config) {
            Ok(config) => cli.global.socket = Some(config.engine_socket()),
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(125);
            }
        }
    }
    cli
}

/// Whether `command` is one that has podman's `--signature-policy`.
fn takes_signature_policy(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Image(
            ImageCommands::Pull { .. }
                | ImageCommands::Push { .. }
                | ImageCommands::Load { .. }
                | ImageCommands::Build { .. }
        ) | Commands::Container(ContainerCommands::Create { .. } | ContainerCommands::Run { .. })
            | Commands::Artifact(
                artifact::ArtifactCommands::Pull { .. } | artifact::ArtifactCommands::Push { .. }
            )
    )
}

/// The first of the global options of podman's engine that is given
/// (a remote client does not have them).
fn engine_only_flag(global: &GlobalArgs) -> Option<&'static str> {
    if global.root.is_some() {
        Some("--root")
    } else if global.runroot.is_some() {
        Some("--runroot")
    } else if global.tmpdir.is_some() {
        Some("--tmpdir")
    } else if global.storage_driver.is_some() {
        Some("--storage-driver")
    } else if global.runtime.is_some() {
        Some("--runtime")
    } else if !global.runtime_flag.is_empty() {
        Some("--runtime-flag")
    } else if global.cgroup_manager.is_some() {
        Some("--cgroup-manager")
    } else if !global.hooks_dir.is_empty() {
        Some("--hooks-dir")
    } else if !global.cdi_spec_dir.is_empty() {
        Some("--cdi-spec-dir")
    } else if global.events_backend.is_some() {
        Some("--events-backend")
    } else {
        None
    }
}

/// The first of podman's global options that changes the settings of the
/// engine (a server started without it has other ones).
fn engine_setting(global: &GlobalArgs) -> Option<&'static str> {
    // (the storage driver of a store is the one it was made with: a server
    // has its store's, and a driver asked for is not a thing to say to it;
    // "overlay" is podman's name for the default and chooses nothing)
    if global
        .storage_driver
        .as_deref()
        .is_some_and(|d| !matches!(d, "" | "overlay"))
    {
        Some("--storage-driver")
    } else if global.runtime.is_some() {
        Some("--runtime")
    } else if !global.runtime_flag.is_empty() {
        Some("--runtime-flag")
    } else if global.cgroup_manager.is_some() {
        Some("--cgroup-manager")
    } else if !global.hooks_dir.is_empty() {
        Some("--hooks-dir")
    } else if !global.cdi_spec_dir.is_empty() {
        Some("--cdi-spec-dir")
    } else if global.events_backend.as_deref().is_some_and(|b| {
        // (the configuration's own is the server's too)
        velarx_config::Config::load_or_default(&global.config)
            .map_or(true, |c| b != c.server.effective_events_logger())
    }) {
        Some("--events-backend")
    } else {
        None
    }
}

/// podman's global options for the processes of the command (the engine of
/// this one, the server it starts, the monitors): in their environment,
/// where the configuration reads them.
fn export_global_options(global: &GlobalArgs) {
    use velarx_config as c;
    let refuse = |what: String| -> ! {
        eprintln!("Error: {what}");
        std::process::exit(125);
    };
    if let Some(b) = &global.events_backend {
        if !matches!(b.as_str(), "journald" | "file" | "none") {
            refuse(format!(
                "configuring runtime: {b:?} is not a valid events backend: invalid argument"
            ));
        }
        std::env::set_var(c::ENV_EVENTS_LOGGER, b);
    }
    if let Some(d) = &global.storage_driver {
        match d.as_str() {
            // (podman's default, and the graph driver velarx reports: it
            // chooses nothing here; `vfs` is a driver of its own, chosen only
            // when asked for)
            "" | "overlay" => {}
            name => match c::StorageDriverKind::parse(name) {
                Ok(kind) => std::env::set_var(c::ENV_STORAGE_DRIVER, kind.name()),
                Err(e) => refuse(format!(
                    "--storage-driver {e}; overlay is accepted as podman's name and chooses nothing"
                )),
            },
        }
    }
    if let Some(dir) = &global.tmpdir {
        let dir = std::path::absolute(dir).unwrap_or_else(|_| dir.clone());
        if let Err(e) = std::fs::create_dir_all(&dir) {
            refuse(format!("--tmpdir {}: {e}", dir.display()));
        }
        std::env::set_var("TMPDIR", dir);
    }
    if let Some(m) = &global.cgroup_manager {
        if !matches!(m.as_str(), "systemd" | "cgroupfs") {
            refuse(
                "configuring runtime: cgroup manager must be one of cgroupfs and systemd: invalid argument"
                    .into(),
            );
        }
        std::env::set_var(c::ENV_CGROUP_MANAGER, m);
    }
    for (var, path) in [
        (c::ENV_ROOT, &global.root),
        (c::ENV_RUNROOT, &global.runroot),
    ] {
        if let Some(p) = path {
            let p = std::path::absolute(p).unwrap_or_else(|_| p.clone());
            std::env::set_var(var, p);
        }
    }
    if let Some(r) = &global.runtime {
        if let Err(e) = c::find_runtime(r) {
            refuse(e);
        }
        std::env::set_var(c::ENV_RUNTIME, r);
    }
    if !global.runtime_flag.is_empty() {
        std::env::set_var(c::ENV_RUNTIME_FLAGS, global.runtime_flag.join("\u{1f}"));
    }
    if let Some(p) = &global.signature_policy {
        let p = std::path::absolute(p).unwrap_or_else(|_| p.clone());
        std::env::set_var(c::ENV_SIGNATURE_POLICY, p);
    }
    if !global.hooks_dir.is_empty() {
        match std::env::join_paths(&global.hooks_dir) {
            Ok(joined) => std::env::set_var(c::ENV_HOOKS_DIR, joined),
            Err(e) => refuse(format!("--hooks-dir: {e}")),
        }
    }
    if !global.cdi_spec_dir.is_empty() {
        match std::env::join_paths(&global.cdi_spec_dir) {
            Ok(joined) => std::env::set_var(c::ENV_CDI_SPEC_DIRS, joined),
            Err(e) => refuse(format!("--cdi-spec-dir: {e}")),
        }
    }
}

/// The socket of an engine address (`unix:///run/velarx/engine/engine.sock`,
/// or a path): the client reaches the engine by its unix socket only.
fn socket_of_host(host: &str) -> Result<PathBuf, String> {
    let path = match host.split_once("://") {
        Some(("unix", path)) => path,
        Some((scheme, _)) => {
            return Err(format!(
                "`{host}`: only unix:// addresses are supported, not {scheme}://"
            ))
        }
        None => host,
    };
    if !path.starts_with('/') {
        return Err(format!("`{host}`: the socket must be an absolute path"));
    }
    Ok(PathBuf::from(path))
}

/// `VELARX_SOCKET`, as `--socket` (empty: not set).
fn socket_from_env(value: Option<std::ffi::OsString>) -> Option<PathBuf> {
    value.filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// `Cli::try_parse_from` for the tests, on a thread with the stack of a
/// main thread (8 MiB): building the command line of every command takes
/// more than the 2 MiB of a test's thread in a debug build.
#[cfg(test)]
pub fn parse_for_test<I, T>(argv: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let argv: Vec<std::ffi::OsString> = argv.into_iter().map(Into::into).collect();
    std::thread::Builder::new()
        .stack_size(8 << 20)
        .spawn(move || {
            let cmd = command_line();
            let argv = end_options_after_operand(&cmd, argv);
            try_parse_with(cmd, argv)
        })
        .expect("a thread for the parse")
        .join()
        .expect("the parse")
}
