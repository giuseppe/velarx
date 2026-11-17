// SPDX-License-Identifier: Apache-2.0
//! The man pages of `velarx-p2p`, written from its clap definition
//! (`make man` runs this; the pages are never in git), one per subcommand:
//! velarx-p2p.8, velarx-p2p-generate-key.8, velarx-p2p-status.8, ...
//!
//!     cargo run -p velarx-p2p --example generate-man-p2p -- [DIR]
//!
//! A daemon's page is in section 8; the commands are in it too, for the
//! service is the binary that answers them.

use std::path::{Path, PathBuf};

use clap::CommandFactory;
use velarx_p2p::cli::Args;

fn main() -> std::io::Result<()> {
    let dir = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new("share/man").to_path_buf());
    std::fs::create_dir_all(&dir)?;
    let mut cmd = Args::command()
        .disable_help_subcommand(true)
        // the default of --config is computed for the user who runs this
        // (a packager's home): the page tells the rule instead
        .mut_arg("config", |a| {
            a.hide_default_value(true).help(
                "Path to the config file of the engine (default: \
                 /etc/velarx/config.toml as root, \
                 $XDG_CONFIG_HOME/velarx/config.toml otherwise)",
            )
        });
    cmd.build();
    write(&dir, &cmd)?;
    Ok(())
}

/// The pages of `cmd`, one per subcommand too, in section 8.
fn write(dir: &Path, cmd: &clap::Command) -> std::io::Result<()> {
    for sub in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
        write(dir, sub)?;
    }
    clap_mangen::Man::new(cmd.clone())
        .section("8")
        .generate_to(dir)?;
    Ok(())
}
