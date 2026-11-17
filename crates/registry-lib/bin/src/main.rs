// SPDX-License-Identifier: Apache-2.0
//! `velarx-registry`: the registry fetcher, started by the engine that
//! needs it (`velarx_content::list::shared_registry`), and its confined pull
//! workers (`velarx-registry pull-worker`).

fn main() -> anyhow::Result<()> {
    let startup = velarx_sys::fd::Startup::take().expect("main is the first to take it");
    velarx_base::buildinfo::set(env!("VELARX_GIT_COMMIT"), env!("VELARX_BUILD_TIME"));
    if let Some(line) =
        velarx_base::buildinfo::version_line("velarx-registry", env!("CARGO_PKG_VERSION"))
    {
        println!("{line}");
        return Ok(());
    }
    let mut args = std::env::args_os().skip(1).peekable();
    // The pull worker is this binary again.
    if args.peek().is_some_and(|a| a == "pull-worker") {
        velarx_wire::proctitle::set("velarx-pull");
        return velarx_registry_lib::net::worker::main(&startup);
    }
    velarx_wire::proctitle::set("velarx-registry");
    velarx_wire::logging::init("warn", "text");
    let config = velarx_config::DefaultDirs::current()
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .config_file;
    velarx_registry_lib::registry::main(args, config, &startup)
}
