// SPDX-License-Identifier: Apache-2.0
//! The man pages of the command line, written from the clap definitions of
//! `velarx` (`make man` runs this; the pages are never in git).
//!
//!     cargo run -p velarx --example generate-man -- [DIR]
//!
//! DIR (default share/man of the source tree) gets velarx.1 and one page per
//! subcommand (velarx-image.1, velarx-container.1, ...), and the same tree
//! for the thin client (velarx-client.1, velarx-client-image.1, ...), which
//! takes the same command line and leaves the engine's part of it to
//! `velarx`.  `velarx NAME` runs the program `velarx-NAME`, so the pages of
//! the subcommands of a binary of its own are written by an example of that
//! binary's package (the peers service's, in section 8).

use std::path::{Path, PathBuf};

use clap::CommandFactory;
use velarx::cli::Cli;

fn main() -> std::io::Result<()> {
    let dir = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new("share/man").to_path_buf());
    std::fs::create_dir_all(&dir)?;
    let mut cmd = Cli::command()
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
    write(&dir, &cmd, None)?;
    // The thin client: the same pages under its own name; its page says
    // what it does not do (the engine's commands are `velarx`'s).
    write(&dir, &cmd, Some("velarx-client"))?;
    Ok(())
}

/// The pages of `cmd`, one per subcommand too, in `dir`: `velarx`'s for the
/// engine's command line, the binary's for the thin client's copy of it.
fn write(dir: &Path, cmd: &clap::Command, binary: Option<&'static str>) -> std::io::Result<()> {
    let name = cmd.get_name().to_owned();
    for sub in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
        write(dir, sub, binary)?;
    }
    let mut cmd = cmd.clone();
    if let Some(binary) = binary {
        // `velarx-client` itself is `binary`; its subcommands are
        // `binary-name` (velarx-client-image.1, ...) and keep their own
        // description: only the top page says what the thin client is.
        if name == "velarx" {
            cmd = cmd
                .name(binary)
                .display_name(binary)
                .bin_name(binary)
                .about("The command line of velarx-client, as a client of the engine service");
        } else {
            // the full name of the subcommand (velarx-container-run, set by
            // `build`), not its last word: `container run` and `run` must
            // not write the same page.  (A one-shot program: the name lives
            // until it exits.)
            let display = cmd.get_display_name().unwrap_or(&name);
            let rest = display.strip_prefix("velarx").unwrap_or(display);
            let full: &'static str = format!("{binary}{rest}").leak();
            // the synopsis: `velarx-client container run`, not `velarx ...`
            let bin = cmd.get_bin_name().unwrap_or(&name);
            let bin = format!("{binary}{}", bin.strip_prefix("velarx").unwrap_or(bin));
            cmd = cmd.name(full).display_name(full).bin_name(bin);
        }
    }
    clap_mangen::Man::new(cmd).generate_to(dir)?;
    Ok(())
}
