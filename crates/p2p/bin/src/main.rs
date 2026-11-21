// SPDX-License-Identifier: Apache-2.0
//! The P2P service: libp2p, the DHT, and the overlay network, in one process
//! per server, apart from the daemon and the containers.  Its command line
//! is `velarx_p2p::cli` (shared with the man pages, `make man`).

use clap::Parser;
use velarx_config::Config;
use velarx_p2p::cli::{Args, CaCommand, Command};
use velarx_p2p::settings::{self, Settings};
use velarx_p2p::{control, overlay_helper, overlay_service, sandbox, service, Role};
use velarx_wire::logging;

/// Ask the running service on its control socket and print the answer.
fn ask(config: &Config, settings: &Settings, command: Command) -> anyhow::Result<()> {
    let client = control::P2pClient::new(&settings.control_socket(config));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let json = match command {
        Command::Status => serde_json::to_string_pretty(&runtime.block_on(client.status())?)?,
        Command::Peers => serde_json::to_string_pretty(&runtime.block_on(client.peers())?)?,
        Command::Stats => serde_json::to_string_pretty(&runtime.block_on(client.stats())?)?,
        Command::Images => {
            serde_json::to_string_pretty(&runtime.block_on(client.remote_images(true))?)?
        }
        Command::Advertised => {
            serde_json::to_string_pretty(&runtime.block_on(client.advertised())?)?
        }
        Command::Serving => serde_json::to_string_pretty(&runtime.block_on(client.serving())?)?,
        Command::Knowledge { layer } => {
            serde_json::to_string_pretty(&runtime.block_on(client.beliefs(layer.as_deref()))?)?
        }
        Command::Explain { target, json } => {
            let decisions = runtime.block_on(client.explain(target.as_deref().unwrap_or("")))?;
            if json {
                serde_json::to_string_pretty(&decisions)?
            } else {
                control::render_decisions(&decisions)
            }
        }
        Command::GenerateKey { .. }
        | Command::Ca { .. }
        | Command::Serve { .. }
        | Command::Overlay => {
            unreachable!("handled before")
        }
    };
    println!("{json}");
    Ok(())
}

/// `ca`: the operator's tool of the authority, on files.
fn run_ca(command: &CaCommand, args: &Args) -> anyhow::Result<()> {
    use velarx_p2p::ca;
    match command {
        CaCommand::Init { dir, days } => {
            ca::init(dir, *days)?;
            println!("Made the authority in {}", dir.display());
        }
        CaCommand::Request { identity } => {
            let file = match identity {
                Some(file) => file.clone(),
                None => {
                    let config = Config::load_or_default(&args.config)?;
                    let path = args
                        .p2p_config
                        .clone()
                        .unwrap_or_else(|| settings::default_path(&args.config));
                    Settings::load_or_default(&path)?.identity_file(&config)
                }
            };
            let key = velarx_p2p::identity::load_or_create(&file)
                .map_err(|e| anyhow::anyhow!("the identity of the node: {e}"))?;
            print!("{}", ca::request(&key));
        }
        CaCommand::Sign {
            ca: dir,
            request,
            name,
            zone,
            role,
            days,
            output,
        } => {
            let text = std::fs::read_to_string(request)
                .map_err(|e| anyhow::anyhow!("{}: {e}", request.display()))?;
            let role = role.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            let (pem, who) = ca::sign(dir, &text, name, zone.as_deref(), role, *days)?;
            match output {
                Some(file) => {
                    std::fs::write(file, &pem)
                        .map_err(|e| anyhow::anyhow!("{}: {e}", file.display()))?;
                    eprintln!(
                        "Signed {} ({}) for {days} days: {}",
                        who.name,
                        who.peer_id,
                        file.display()
                    );
                }
                None => {
                    print!("{pem}");
                    eprintln!("Signed {} ({}) for {days} days", who.name, who.peer_id);
                }
            }
        }
        CaCommand::Revoke { ca: dir, peers } => {
            let peers = peers
                .iter()
                .map(|p| {
                    p.parse()
                        .map_err(|e| anyhow::anyhow!("{p}: not a peer id: {e}"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let list = ca::revoke(dir, &peers)?;
            println!(
                "{}/revoked is the list {}: {} peer(s) revoked.  Give it to the nodes (revocation_path)",
                dir.display(),
                list.number,
                list.peers.len()
            );
        }
        CaCommand::Show { file } => print!("{}", ca::show(file)?),
    }
    Ok(())
}

/// `overlay`: the overlay node.  The helper first (no process is started once
/// confined), then the confinement, before the runtime starts its threads.
fn run_overlay(
    config: Config,
    settings: Settings,
    config_path: &std::path::Path,
    settings_path: &std::path::Path,
) -> anyhow::Result<()> {
    let settings = settings.of_overlay(&config)?;
    let helper = overlay_service::start_overlay_helper(&settings)?;
    let (listener, socket) = overlay_service::bind_socket(&config, &settings)?;
    // (made or read before: the confined node makes no file)
    let identity = velarx_p2p::identity::load_or_create(&settings.identity_file(&config))
        .map_err(|e| anyhow::anyhow!("the identity of the overlay node: {e}"))?;
    let authority = settings.authority(&identity)?;
    // (removed when this process is gone: once confined it may not)
    let _remover = velarx_base::ipc::remove_when_gone(&[socket])
        .map_err(|e| anyhow::anyhow!("cannot start the remover of the socket: {e}"))?;
    sandbox::enter(
        Role::Overlay,
        &config,
        &settings,
        &[config_path, settings_path],
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(overlay_service::run_overlay(
        config, settings, helper, listener, identity, authority,
    ));
    runtime.shutdown_background();
    result
}

fn main() -> anyhow::Result<()> {
    // (the version line of the command line reads it: crates/p2p/src/cli.rs)
    velarx_base::buildinfo::set(env!("VELARX_GIT_COMMIT"), env!("VELARX_BUILD_TIME"));
    // The privileged overlay helper the service starts (no thread yet).
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some(overlay_service::OVERLAY_HELPER) {
        overlay_helper::main(&argv[2..])?;
        return Ok(());
    }
    let args = Args::parse();
    if let Some(Command::GenerateKey { path }) = &args.command {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        control::generate_swarm_key(path)
            .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", path.display()))?;
        println!("Wrote the swarm key to {}", path.display());
        println!("Copy it to the other nodes (keep it private) and set in p2p.toml:");
        println!("  private_key_path = \"{}\"", path.display());
        return Ok(());
    }
    // (libp2p walks the DHT when a node starts listening with no peer, and
    // warns that it has none on the first node of a swarm: no fault)
    logging::init_quieter(
        &args.log_level,
        &args.log_format,
        "libp2p_kad::behaviour=error",
    );
    if let Some(Command::Ca { command }) = &args.command {
        return run_ca(command, &args);
    }
    let config = Config::load_or_default(&args.config)?;
    config.validate()?;
    let settings_path = args
        .p2p_config
        .clone()
        .unwrap_or_else(|| settings::default_path(&args.config));
    let settings = Settings::load_or_default(&settings_path)?;
    if let Some(Command::Serve { dir }) = &args.command {
        let identity = velarx_p2p::identity::load_or_create(&settings.identity_file(&config))
            .map_err(|e| anyhow::anyhow!("the identity of the node: {e}"))?;
        let authority = settings.authority(&identity)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        return runtime.block_on(service::serve_dir(settings, dir, identity, authority));
    }
    if let Some(Command::Overlay) = &args.command {
        return run_overlay(config, settings, &args.config, &settings_path);
    }
    if let Some(command) = args.command {
        return ask(&config, &settings, command);
    }

    // The store service first (no process is started once confined), then
    // the confinement, before the runtime starts its threads.
    let store = service::start_store_service(&config, &args.config)?;
    let sockets = service::bind_sockets(&config, &settings)?;
    // (made or read before: the confined service makes no file)
    let identity_file = settings.identity_file(&config);
    let identity = velarx_p2p::identity::load_or_create(&identity_file)
        .map_err(|e| anyhow::anyhow!("the identity of the node: {e}"))?;
    let authority = settings.authority(&identity)?;
    service::reach_store_by_connector(&config)?;
    // (removed when this process is gone: once confined it may not)
    let _remover = velarx_base::ipc::remove_when_gone(&sockets.paths)
        .map_err(|e| anyhow::anyhow!("cannot start the remover of the sockets: {e}"))?;
    sandbox::enter(
        Role::Content,
        &config,
        &settings,
        &[&args.config, &settings_path],
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async move {
        // (reaped by a thread of the runtime, confined like the others)
        if let Some(mut store) = store {
            tokio::task::spawn_blocking(move || store.wait());
        }
        service::run_with(config, settings, sockets, identity, authority).await
    });
    // (not waiting for the store service: it leaves with this process)
    runtime.shutdown_background();
    result
}
