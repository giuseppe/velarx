// SPDX-License-Identifier: Apache-2.0
//! `velarx`: the engine (its service is `velarx varlink`)
//! and the command line; the workers of the engine are modes of it.

fn main() -> anyhow::Result<()> {
    let startup = velarx_sys::fd::Startup::take().expect("main is the first to take it");
    velarx_base::buildinfo::set(env!("VELARX_GIT_COMMIT"), env!("VELARX_BUILD_TIME"));
    let mut args = std::env::args_os().skip(1);
    match args.next() {
        // The confined copies of COPY and ADD.
        Some(a) if a == "build-worker" => {
            velarx_wire::proctitle::set("velarx-build");
            velarx_core::services::build::worker::main(&startup)
        }
        // The confined clones of ADD of a git repository.
        Some(a) if a == "git-clone" => {
            velarx_wire::proctitle::set("velarx-git");
            velarx_core::services::build::git::main(&startup)
        }
        // The store service (`store_service`): the content of the store, by
        // digest, for the services that give it to others; started by systemd or on demand.
        Some(a) if a == "store-service" => {
            velarx_wire::proctitle::set("velarx-store");
            velarx_core::store_service::main(args, &startup)
        }
        // The DNS server of the bridge networks, before any thread starts.
        Some(a) if a == "dns-server" => {
            velarx_wire::proctitle::set("velarx-dns");
            let state = args
                .next()
                .ok_or_else(|| anyhow::anyhow!("dns-server needs the state directory"))?;
            // (the network lock it exits holding is kept until main returns:
            // the process ends then)
            let _held = velarx_runtime::network::dnsd::server_main(std::path::Path::new(&state))?;
            Ok(())
        }
        // The process that holds the rootless network namespace.
        Some(a) if a == "netns-holder" => {
            velarx_wire::proctitle::set("velarx-netns");
            let run = args
                .next()
                .ok_or_else(|| anyhow::anyhow!("netns-holder needs the networks directory"))?;
            let join = args.next().is_some();
            velarx_runtime::network::rootless_netns::holder_main(
                std::path::Path::new(&run),
                join,
                &startup,
            )
        }
        // The published ports of a rootless bridge network.
        Some(a) if a == "port-forward" => {
            velarx_wire::proctitle::set("velarx-ports");
            let rest: Vec<String> = args.map(|a| a.to_string_lossy().into_owned()).collect();
            Ok(velarx_runtime::network::portfwd::main(&rest)?)
        }
        _ => velarx::cli::commands::main_engine(&startup),
    }
}
