// SPDX-License-Identifier: Apache-2.0
//! What the engine runs in a process of its own: the engine service, the
//! engine commands of a unit.

use crate::cli;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// The global options of `velarx` and the engine command it runs.
#[derive(Parser)]
#[command(
    name = "velarx",
    version,
    about = "The velarx daemon and container shim"
)]
pub struct DaemonCli {
    /// Path to config file
    #[arg(long, default_value_os_t = cli::default_config())]
    pub config: PathBuf,

    /// Accepted as `velarx` takes it: the engine listens on the socket of
    /// the config file
    #[arg(long)]
    pub socket: Option<PathBuf>,

    /// The default is `info` for the daemon, `warn` for the other commands
    #[arg(long)]
    pub log_level: Option<String>,

    #[arg(long, default_value = "text")]
    pub log_format: String,

    #[command(subcommand)]
    pub command: DaemonCommand,
}

#[derive(Subcommand)]
#[allow(
    clippy::large_enum_variant,
    reason = "parsed once into one value; boxing a clap variant means a struct of its own for each"
)]
pub enum DaemonCommand {
    #[command(about = "Start the engine service")]
    Daemon {
        /// Exit after SECONDS without a client connected (running containers
        /// go on under their monitors, and the next engine follows them
        /// again); the default is `[engine] idle_exit`, 0 never.  For an
        /// engine started by its socket.
        #[arg(long, short = 't', value_name = "SECONDS")]
        time: Option<u64>,
        /// The listening socket is this descriptor
        #[arg(long, value_name = "FD")]
        listen_fd: Option<i32>,
        /// Stop when the other end of this socket is closed
        #[arg(long, value_name = "FD")]
        lifeline_fd: Option<i32>,
    },

    /// The commands of `velarx container` that run a container in this
    /// process, without the engine service: what a systemd unit runs.
    #[command(
        subcommand,
        about = "Run and manage containers without the engine service"
    )]
    Container(cli::ContainerCommands),
}
