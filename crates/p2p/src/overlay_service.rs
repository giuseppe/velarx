// SPDX-License-Identifier: Apache-2.0
//! The overlay node (`velarx-p2p overlay`): a process of its own with its own
//! membership of a swarm of its own, apart from the content service
//! ([`crate::service`]), so that the containers' packets and the
//! content's requests do not compete, and each is
//! confined for what it does.  It starts the privileged overlay helper,
//! carries the packets of the containers and the gossip of the subnets and
//! names, and is the network provider (`org.velarx.Network`,
//! `velarx_runtime::network::provider`) the engine names, on its own socket.

use crate::service::serve_control;
use crate::settings::Settings;
use crate::tun_overlay::TunOverlayManager;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use tracing::{debug, info};
use velarx_config::Config;
use velarx_proto::info::Info;
use velarx_runtime::network::provider as netprov;

/// The subcommand of `velarx-p2p` that is the privileged overlay helper
/// (`network::overlay_helper::main`).
pub const OVERLAY_HELPER: &str = "overlay-helper";

/// Start the overlay helper: before the process confines itself (it starts
/// no process afterwards).  The helper is the one process of the node that
/// keeps capabilities: this one gives them up at once, before it forks the
/// remover of its socket.
pub fn start_overlay_helper(
    settings: &Settings,
) -> anyhow::Result<(crate::overlay_helper::Client, std::process::Child)> {
    let overlay: ipnet::Ipv4Net = settings
        .overlay
        .cidr
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid overlay CIDR: {}", e))?;
    let exe = std::env::current_exe()?;
    let helper = crate::overlay_helper::spawn(&exe, &[OVERLAY_HELPER], &overlay)?;
    velarx_sandbox::drop_privileges().map_err(|e| anyhow::anyhow!(e))?;
    Ok(helper)
}

/// The socket of the network provider, bound before the process confines
/// itself (it makes no socket by name and removes none: they are removed
/// when it is gone, `velarx_base::ipc::remove_when_gone`).
pub fn bind_socket(
    config: &Config,
    settings: &Settings,
) -> anyhow::Result<(std::os::unix::net::UnixListener, std::path::PathBuf)> {
    let socket = settings.network_socket(config);
    let listener = velarx_base::ipc::bind_private(&socket)
        .map_err(|e| anyhow::anyhow!("cannot create the socket {}: {e}", socket.display()))?;
    Ok((listener, socket))
}

/// Run the overlay node until it is told to stop: `settings` are the
/// overlay's ([`Settings::of_overlay`]), `helper` the one started before
/// the process confined itself.
pub async fn run_overlay(
    config: Config,
    settings: Settings,
    helper: (crate::overlay_helper::Client, std::process::Child),
    listener: std::os::unix::net::UnixListener,
    identity: libp2p::identity::Keypair,
    authority: Option<Arc<crate::authority::Authority>>,
) -> anyhow::Result<()> {
    let p2p = &settings;
    // (the helper goes with its socket, when the process ends)
    let (helper, _helper_process) = (Arc::new(helper.0), helper.1);
    let limits = velarx_content::activation::Limits::of(&config.services);
    let node = crate::service::start_node(p2p, super::Role::Overlay, identity, authority).await?;
    info!("P2P overlay node {} started", node.peer_id());

    // The subnet of the node is a /24 of the overlay range that a hash of
    // its peer id gives (`overlay_router::subnet_for`)
    let base_cidr: ipnet::Ipv4Net = p2p
        .overlay
        .cidr
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid overlay CIDR: {}", e))?;
    if base_cidr != base_cidr.trunc()
        || !(crate::overlay_router::MIN_OVERLAY_PREFIX..=crate::overlay_router::MAX_OVERLAY_PREFIX)
            .contains(&base_cidr.prefix_len())
    {
        anyhow::bail!(
            "settings.overlay.cidr = \"{base_cidr}\": a network of /{} to /{} is needed",
            crate::overlay_router::MIN_OVERLAY_PREFIX,
            crate::overlay_router::MAX_OVERLAY_PREFIX
        );
    }
    if p2p.overlay.subnet_attempt >= crate::overlay_router::MAX_SUBNET_ATTEMPTS {
        anyhow::bail!(
            "settings.overlay.subnet_attempt = {}: at most {}",
            p2p.overlay.subnet_attempt,
            crate::overlay_router::MAX_SUBNET_ATTEMPTS - 1
        );
    }
    let node_subnet =
        crate::overlay_router::subnet_for(base_cidr, &node.peer_id(), p2p.overlay.subnet_attempt);
    info!(
        "Initializing TUN overlay network: node_subnet={}",
        node_subnet
    );

    let init = crate::overlay_helper::Request::Init {
        node_subnet: node_subnet.to_string(),
        dns_table: p2p.overlay.dns_table,
        dns_rule_priority: p2p.overlay.dns_rule_priority,
    };
    let asked = Arc::clone(&helper);
    tokio::task::spawn_blocking(move || asked.call(&init))
        .await
        .map_err(|e| anyhow::anyhow!("overlay helper: {e}"))??;
    let dns_upstreams = if p2p.overlay.dns_upstreams.is_empty() {
        crate::dns_server::host_resolvers()
            .map_err(|e| anyhow::anyhow!("the name servers of the host: {e}"))?
    } else {
        p2p.overlay
            .dns_upstreams
            .iter()
            .map(|s| {
                velarx_netkernel::dnsrec::parse_upstream(s).ok_or_else(|| {
                    anyhow::anyhow!("settings.overlay.dns_upstreams: `{s}` is not an address")
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?
    };
    let mut manager = TunOverlayManager::new(
        node.peer_id(),
        base_cidr,
        node_subnet,
        Arc::clone(&node),
        helper,
        dns_upstreams,
    );
    manager
        .start()
        .await
        .map_err(|e| anyhow::anyhow!("cannot start the overlay: {e}"))?;
    info!(
        "TUN overlay network initialized: node_ip={}, subnet={}",
        manager.node_ip(),
        manager.node_subnet()
    );
    manager
        .announce()
        .await
        .map_err(|e| anyhow::anyhow!("cannot announce the overlay: {e}"))?;
    let manager = Arc::new(manager);
    // The overlay network is a network provider on a socket of its own
    let _network = serve_control(listener, "p2p-network", limits, network::Network(manager))?;

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
    info!("P2P overlay node shutting down");
    let _ = node.shutdown().await;
    Ok(())
}

/// The description of the interface of this service as zlink sends it: its
/// checked-in definition without the comment that opens the file.
fn description(interface: &str) -> String {
    let file = match interface {
        "org.velarx.Network" => include_str!("../../../interfaces/org.velarx.Network.varlink"),
        other => unreachable!("{other} is not served here"),
    };
    let (_, text) = file.split_once("\n\n").expect("a comment, an empty line");
    text.strip_suffix('\n').unwrap_or(text).to_string()
}

/// The error of the overlay as the interface names it.
fn provider_failed(e: std::io::Error) -> netprov::ProviderError {
    let reason = e.to_string();
    match e.kind() {
        std::io::ErrorKind::InvalidInput => netprov::ProviderError::InvalidArgument { reason },
        std::io::ErrorKind::NotFound => netprov::ProviderError::NotFound { reason },
        _ => netprov::ProviderError::Failed { reason },
    }
}

mod network {
    use super::*;

    /// The calls of `org.velarx.Network`: the overlay network of the
    /// containers.
    #[derive(Clone)]
    pub(super) struct Network(pub(super) Arc<TunOverlayManager>);

    #[zlink::service(
        interface = "org.velarx.Network",
        description = super::description,
        vendor = "org.velarx",
        product = "velarx",
        version = env!("CARGO_PKG_VERSION"),
        url = env!("CARGO_PKG_REPOSITORY"),
        types = [netprov::Device]
    )]
    impl Network {
        /// Who serves this interface and what it can do.  The first call of a
        /// connection; a client refuses a `proto` other than its own.
        async fn get_info(&self) -> Info {
            Info {
                name: "overlay".into(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                proto: velarx_netdetach::provider::PROTO,
                ..Info::default()
            }
        }

        /// The interfaces of the host to move into the container, and the
        /// name server it uses (the overlay's is this node's address: it
        /// resolves the names of the containers of all nodes).
        async fn prepare(&self, id: String) -> Result<netprov::Prepared, netprov::ProviderError> {
            let (_, net) = self
                .0
                .prepare_container(&id)
                .await
                .map_err(provider_failed)?;
            Ok(netprov::Prepared {
                devices: vec![netprov::Device {
                    host: net.host_if_name,
                    container: net.container_if_name,
                }],
                dns: Some(self.0.node_ip()),
            })
        }

        /// Route the container in its network namespace, the one
        /// descriptor the call carries, and give it the name `name` (the
        /// overlay tells the other nodes about it).  `default_route`: this
        /// network is its way out (no other network is).
        async fn start(
            &self,
            id: String,
            name: String,
            default_route: bool,
            #[zlink(fds)] netns: Vec<OwnedFd>,
        ) -> Result<netprov::Ack, netprov::ProviderError> {
            let Ok([netns]) = <[OwnedFd; 1]>::try_from(netns) else {
                return Err(netprov::ProviderError::InvalidArgument {
                    reason: "a start carries one descriptor, the network namespace".into(),
                });
            };
            self.0
                .container_started(&id, netns, default_route)
                .await
                .map_err(provider_failed)?;
            if let Some(c) = self.0.get_container(&id).await {
                info!(
                    "overlay network finalized for container {id}: ip={}, veth={}",
                    c.overlay_ip, c.veth_host
                );
            }
            let failed = |e: crate::P2PError| netprov::ProviderError::Failed {
                reason: e.to_string(),
            };
            self.0.announce().await.map_err(failed)?;
            self.0.register_dns(&id, &name).await.map_err(failed)?;
            Ok(netprov::Ack {})
        }

        /// Undo the network of a container that does not run any more.
        /// Idempotent: a `Stop` of a container that is not started, or was
        /// stopped, is a success (the engine's reconcile and a monitor's
        /// teardown may both call it).
        async fn stop(&self, id: String) -> Result<netprov::Ack, netprov::ProviderError> {
            if let Err(e) = self.0.unregister_dns(&id).await {
                debug!("Failed to unregister DNS for container {id}: {e}");
            }
            self.0
                .cleanup_container(&id)
                .await
                .map_err(provider_failed)?;
            Ok(netprov::Ack {})
        }
    }

    /// The interface as the macro described it (the binary serves the file).
    #[cfg(test)]
    pub(super) fn description() -> String {
        format!("{}", __Network_INTERFACE_0)
    }
}

/// The text of the interface definition `interfaces/org.velarx.Network.varlink`,
/// as velarx-p2p serves it: the interface of every network provider.
#[cfg(test)]
pub(crate) fn network_definition() -> String {
    format!(
        "# SPDX-License-Identifier: Apache-2.0\n\
         #\n\
         # The interface org.velarx.Network: a network provider, a process on a unix\n\
         # socket that makes the network of the containers that name it\n\
         # (`--network provider:NAME`, `[[network.providers]]` of config.toml).  The\n\
         # engine calls Prepare before the spec of a container is made (the\n\
         # interfaces of the host to move into it, its name server), Start once it\n\
         # runs (with its network namespace as the one descriptor of the call: never\n\
         # a pid, which could be reused) and Stop when it does not run any more.  A\n\
         # client calls GetInfo on each connection and refuses a `proto` other than\n\
         # its own ({}).  Generated from the overlay provider of velarx-p2p\n\
         # (crates/runtime/src/network/provider.rs, crates/p2p/src/overlay_service.rs) by the\n\
         # test `service::tests::the_interface_files_are_current`:\n\
         # VELARX_WRITE_INTERFACES=1 cargo test -p velarx-p2p --lib service writes it.\n\
         # Who may call: a peer of the same user or root (SO_PEERCRED); any\n\
         # accepted peer may make every call.\n\
         \n{}\n",
        velarx_netdetach::provider::PROTO,
        network::description()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The text a service sends for `GetInterfaceDescription` (the file,
    /// embedded) is what the descriptors of the types and methods say.
    #[test]
    fn the_description_served_is_what_the_types_say() {
        assert_eq!(description("org.velarx.Network"), network::description());
    }
}
