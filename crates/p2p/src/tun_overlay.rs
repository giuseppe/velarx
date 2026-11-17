// SPDX-License-Identifier: Apache-2.0
//! P2P Overlay Network Manager
//!
//! This module manages the P2P overlay network for container communication.
//! It creates veth pairs and handles routing between containers and P2P peers.
//!
//! Architecture:
//! - veth pairs connect containers to the overlay network
//! - Container gets one end of veth with overlay IP (eth0)
//! - Host keeps the other end for routing
//! - The veth is moved to container namespace via OCI netDevices
//! - Local packets are forwarded by kernel routing
//! - Remote packets are sent over libp2p to peer nodes
//!
//! What needs privileges (the veth pairs, addresses, routes, sysctls, the
//! packet sockets, the containers' namespaces) is the overlay helper's
//! (overlay_helper.rs), a process of its own: this side asks it and works
//! on the packet sockets it hands over.

use ipnet::Ipv4Net;
use libp2p::PeerId;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::{debug, error, info, warn};

use crate::dns_server::DnsHandler;
use crate::overlay_helper::{Client as Helper, Reply, Request};
use crate::overlay_router::{OverlayRouter, Routed};
use crate::{OverlayEvent, P2PNode};

/// Container overlay network information
#[derive(Debug, Clone)]
pub struct ContainerOverlay {
    /// Container ID
    pub container_id: String,
    /// Container's overlay IP address
    pub overlay_ip: Ipv4Addr,
    /// veth interface name on host side
    pub veth_host: String,
    /// The MAC address of the container's `eth0`, as the overlay helper read
    /// it in the container's namespace when the container started (`None`
    /// before)
    pub container_mac: Option<[u8; 6]>,
    /// The address of the host side.
    pub host_mac: [u8; 6],
    /// The packet socket bound to the host side (from the helper).
    pub packets: Arc<OwnedFd>,
}

/// The DNS sockets of a container (from the helper): UDP, and TCP
/// listening.
struct DnsSockets {
    udp: OwnedFd,
    tcp: OwnedFd,
}

/// Information needed to configure OCI netDevices
#[derive(Debug, Clone)]
pub struct NetDeviceConfig {
    /// Host interface name that will be moved to container
    pub host_if_name: String,
    /// Name the interface should have inside the container
    pub container_if_name: String,
}

/// `sll_pkttype` of a frame the host itself sent on the interface
/// (`PACKET_OUTGOING`): the packet socket sees what this side writes too.
const PACKET_OUTGOING: u8 = libc::PACKET_OUTGOING;

/// A container of the overlay, and the stop of the reader of its veth: the
/// reader ends when the entry is dropped (the sender with it).
struct Entry {
    overlay: ContainerOverlay,
    _stop: oneshot::Sender<()>,
}

/// What the reader of the packets of the veth of a container runs on.
struct VethReader {
    packets: Arc<OwnedFd>,
    if_mac: [u8; 6],
    veth_name: String,
    container_id: String,
    /// The only address this container sends from
    overlay_ip: Ipv4Addr,
    /// The node's address, the gateway of the container
    node_ip: Ipv4Addr,
    router: Arc<OverlayRouter>,
    p2p_node: Arc<P2PNode>,
}

impl VethReader {
    /// Run the veth packet reader loop
    /// Uses AF_PACKET socket to read raw packets from the veth
    /// Handles ARP requests (for node IP) and sends the packets for other nodes
    /// through the tunnel
    /// (the DNS is the sockets' of `dns_sockets`, served by DNS: it ends the
    /// reader when it fails)
    async fn run(
        self,
        mut stopped: oneshot::Receiver<()>,
        dns: impl std::future::Future<Output = std::io::Result<()>>,
    ) -> std::io::Result<()> {
        tokio::pin!(dns);
        // The helper's packet socket, bound to the veth: a duplicate of
        // its own for the runtime, non-blocking.
        let sock = self.packets.try_clone()?;
        rustix::fs::fcntl_setfl(
            &sock,
            rustix::fs::fcntl_getfl(&sock)? | rustix::fs::OFlags::NONBLOCK,
        )?;
        let async_fd = velarx_sys::fd::register(
            sock,
            tokio::io::Interest::READABLE | tokio::io::Interest::WRITABLE,
        )?;

        let node_ip = self.node_ip;
        let if_mac = self.if_mac;

        info!(
            "Veth packet reader started for container {} on {} (mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, node_ip={})",
            self.container_id, self.veth_name,
            if_mac[0], if_mac[1], if_mac[2], if_mac[3], if_mac[4], if_mac[5],
            node_ip
        );

        let mut buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                _ = &mut stopped => {
                    info!("Veth packet reader for container {} received shutdown signal", self.container_id);
                    break;
                }

                result = &mut dns => {
                    return result.and(Err(std::io::Error::other("the DNS sockets ended")));
                }

                result = async_fd.readable() => {
                    let mut guard = result?;
                    loop {
                        // Read a packet with sender address to determine direction
                        let (n, packet_type) = match velarx_sys::packet::recv_frame(
                            async_fd.get_ref().as_fd(),
                            &mut buf,
                        ) {
                            Ok(f) => (f.len, f.packet_type),
                            Err(err) => {
                                match err.kind() {
                                    std::io::ErrorKind::WouldBlock => {
                                        guard.clear_ready();
                                        break;
                                    }
                                    std::io::ErrorKind::Interrupted => continue,
                                    // (a socket that fails again and again is
                                    // still readable: the reader ends)
                                    _ => return Err(err),
                                }
                            }
                        };
                        if n == 0 {
                            break;
                        }
                        // Only the frames of the container: not the ones
                        // this side wrote itself
                        if packet_type == PACKET_OUTGOING {
                            continue;
                        }
                        self.frame(&buf[..n], packet_type, node_ip).await;
                    }
                }
            }
        }

        Ok(())
    }

    /// One frame from the container, by its ethertype.
    async fn frame(&self, packet: &[u8], packet_type: u8, node_ip: Ipv4Addr) {
        // Minimum ethernet frame size
        if packet.len() < 14 {
            return;
        }
        let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
        debug!(
            "Received packet on {}: len={}, ethertype=0x{:04x}, pkttype={}",
            self.veth_name,
            packet.len(),
            ethertype,
            packet_type
        );
        match ethertype {
            0x0806 => self.arp(packet, node_ip),
            0x0800 => self.ipv4(packet).await,
            _ => {}
        }
    }

    /// An ARP packet: answered for the node's IP.  (The MAC of the container
    /// is not learnt from what it sends: it is the one the helper read.)
    fn arp(&self, packet: &[u8], node_ip: Ipv4Addr) {
        let veth_name = self.veth_name.as_str();
        if let Some(response) = TunOverlayManager::handle_arp_packet(
            packet,
            node_ip,
            &self.if_mac,
            veth_name,
            &self.container_id,
        ) {
            match send_frame(&self.packets, &response) {
                Ok(sent) => debug!(
                    "Sent ARP response ({} bytes) on {} for container {}",
                    sent, veth_name, self.container_id
                ),
                Err(err) => error!("Failed to send ARP response on {}: {}", veth_name, err),
            }
        }
    }

    /// An IPv4 packet: one for the node itself is the kernel's (the DNS
    /// sockets, ping), any other is forwarded to its container.
    async fn ipv4(&self, packet: &[u8]) {
        let veth_name = self.veth_name.as_str();
        let ip_packet = &packet[14..];

        if ip_packet.len() >= 20 {
            let protocol = ip_packet[9];
            let src_ip = Ipv4Addr::new(ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]);
            let dest_ip = Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);
            debug!(
                "IPv4 packet on {}: proto={}, src={}, dst={}, len={}",
                veth_name,
                protocol,
                src_ip,
                dest_ip,
                ip_packet.len()
            );
        }

        if ip_packet.len() < 20 {
            return;
        }
        // This veth is the container's alone, and the address is the one it
        // was given: a packet from another address is not its own (it would
        // pass for another container's)
        let src_ip = Ipv4Addr::new(ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]);
        if src_ip != self.overlay_ip {
            debug!(
                "Packet from {} on {}: the address of container {} is {}, dropped",
                src_ip, self.veth_name, self.container_id, self.overlay_ip
            );
            return;
        }
        let dest_ip = Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);
        if dest_ip != self.node_ip {
            self.route(packet).await;
        }
    }

    /// A packet for a container of another node goes there through the
    /// tunnel.  One for a container of this node is the kernel's (the
    /// helper routes the address to its veth): the service does not
    /// deliver it a second time.
    async fn route(&self, packet: &[u8]) {
        let ip_packet = &packet[14..];
        let dest_ip = Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);

        if self.router.is_local_container_ip(&dest_ip).await {
            return;
        }
        if let Ok(peer) = self.router.lookup_route(dest_ip).await {
            let packet = crate::tun_tunnel::TunPacket::new(ip_packet.to_vec());
            if let Err(e) = self.p2p_node.send_tun_packet(peer, packet).await {
                debug!("Failed to send a packet for {} to {}: {}", dest_ip, peer, e);
            }
        }
    }
}

/// P2P Overlay Network Manager
///
/// Manages the overlay network for P2P container communication.
/// Each node gets a /24 subnet from the overlay CIDR, and containers
/// on that node get IPs within that subnet.
pub struct TunOverlayManager {
    /// Overlay router for packet routing
    router: Arc<OverlayRouter>,
    /// P2P node for sending packets
    p2p_node: Arc<P2PNode>,
    /// Active container overlays
    containers: Arc<RwLock<HashMap<String, Entry>>>,
    /// DNS handler for container name resolution
    dns_handler: Arc<DnsHandler>,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
    /// The privileged helper.
    helper: Arc<Helper>,
    /// One prepare, start or cleanup of a container at a time: the helper
    /// has one veth per id, and the runtime's entry and the helper's must
    /// change in the same order.
    operations: Arc<IdLocks>,
}

/// The packets of other nodes that wait to be delivered to a container.
const INBOUND_PACKETS: usize = 1024;

/// An async lock for each name: the holders of one name go one at a time, the
/// holders of different names do not wait for each other.
#[derive(Default)]
struct IdLocks {
    locks: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl IdLocks {
    /// The lock of `id`, waited for.
    async fn lock(&self, id: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
            // (a name nobody holds or waits for is forgotten: the map
            // does not grow with the containers that came and went)
            locks.retain(|_, l| Arc::strong_count(l) > 1);
            locks.entry(id.to_string()).or_default().clone()
        };
        lock.lock_owned().await
    }
}

/// Cleanup of the overlay of a container: its entry (the reader ends with
/// it), its address and its veth.  With `reader`, only the entry that reader
/// belongs to (a container prepared again since has another).
async fn release(
    containers: &RwLock<HashMap<String, Entry>>,
    router: &OverlayRouter,
    helper: &Arc<Helper>,
    operations: &IdLocks,
    container_id: &str,
    reader: Option<&Arc<OwnedFd>>,
) -> std::io::Result<()> {
    info!("Cleaning up overlay for container {}", container_id);
    let _one_at_a_time = operations.lock(container_id).await;
    // (the map is not held while the helper works)
    let entry = {
        let mut containers = containers.write().await;
        match (containers.get(container_id), reader) {
            (Some(e), Some(r)) if !Arc::ptr_eq(&e.overlay.packets, r) => None,
            _ => containers.remove(container_id),
        }
    };
    if let Some(entry) = entry {
        router.remove_container_ip(&entry.overlay.overlay_ip).await;
        // The host side goes (and the container's with it).
        let request = Request::Cleanup {
            id: container_id.to_string(),
        };
        ask(helper, request).await?;
    }
    info!("Cleaned up overlay for container {}", container_id);
    Ok(())
}

/// Ask the helper (a blocking exchange) from the runtime.
async fn ask(helper: &Arc<Helper>, req: Request) -> std::io::Result<(Reply, Option<OwnedFd>)> {
    ask_with(helper, req, None).await
}

/// [`ask`], the request carrying the descriptor FD.
async fn ask_with(
    helper: &Arc<Helper>,
    req: Request,
    fd: Option<OwnedFd>,
) -> std::io::Result<(Reply, Option<OwnedFd>)> {
    use std::os::fd::AsFd;
    let helper = helper.clone();
    tokio::task::spawn_blocking(move || helper.call_with(&req, fd.as_ref().map(|f| f.as_fd())))
        .await
        .map_err(std::io::Error::other)?
}

/// Send FRAME on the packet socket FD (bound to its veth).
fn send_frame(fd: &OwnedFd, frame: &[u8]) -> std::io::Result<usize> {
    Ok(rustix::net::send(
        fd,
        frame,
        rustix::net::SendFlags::empty(),
    )?)
}

impl TunOverlayManager {
    /// Enable IP forwarding on the host (the helper's job): routing
    /// between the containers of the host.
    async fn enable_ip_forwarding(&self) -> std::io::Result<()> {
        ask(&self.helper, Request::Forwarding).await?;
        info!("Enabled IPv4 forwarding for overlay network");
        Ok(())
    }

    /// Create a new overlay manager
    /// HELPER: the client of the privileged overlay helper.
    pub fn new(
        peer_id: PeerId,
        base: Ipv4Net,
        node_subnet: Ipv4Net,
        p2p_node: Arc<P2PNode>,
        helper: Arc<Helper>,
        dns_upstreams: Vec<std::net::SocketAddr>,
    ) -> Self {
        let router = Arc::new(OverlayRouter::new(peer_id, base, node_subnet));

        let dns_handler = Arc::new(DnsHandler::new(
            p2p_node.overlay().clone(),
            router.node_ip(),
            dns_upstreams,
        ));

        Self {
            router,
            p2p_node,
            containers: Arc::new(RwLock::new(HashMap::new())),
            dns_handler,
            shutdown_tx: None,
            helper,
            operations: Arc::default(),
        }
    }

    /// Get this node's overlay IP (gateway for containers)
    pub fn node_ip(&self) -> Ipv4Addr {
        self.router.node_ip()
    }

    /// Get this node's overlay subnet
    pub fn node_subnet(&self) -> Ipv4Net {
        self.router.node_subnet()
    }

    /// Start the overlay manager
    pub async fn start(&mut self) -> std::io::Result<()> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Enable IP forwarding on the host for container-to-container communication
        // This is required for routing between containers on the same host
        self.enable_ip_forwarding().await?;

        // The routes to the containers of the other nodes, from their
        // announcements.
        // (one task takes them in the order they came: two announcements
        // of one peer apply in that order, the later wins)
        let router = self.router.clone();
        let gossip = self.p2p_node.overlay().clone();
        let mut announced_rx = gossip
            .overlay_events()
            .ok_or_else(|| std::io::Error::other("the overlay events are taken already"))?;
        tokio::spawn(async move {
            while let Some(event) = announced_rx.recv().await {
                let routed = match event {
                    OverlayEvent::Peer(peer, info) => {
                        Self::handle_peer_announcement(&router, peer, info.node_subnet).await
                    }
                    OverlayEvent::Gone(peer) => router.remove_peer(&peer).await,
                };
                // (a peer without a route has no name for the DNS either)
                for peer in routed.withdrawn {
                    gossip.set_tun_overlay_routed(&peer, false).await;
                }
                for peer in routed.restored {
                    gossip.set_tun_overlay_routed(&peer, true).await;
                }
            }
        });

        // The packets of the other nodes for the containers of this one.
        // (a network drops what it cannot carry: the packets wait for the
        // delivery in a queue of a size, and past it they are dropped)
        let (inbound_tx, mut inbound_rx) =
            mpsc::channel::<(PeerId, crate::tun_tunnel::TunPacket)>(INBOUND_PACKETS);
        self.p2p_node
            .set_tun_packet_handler(move |peer, packet| {
                let _ = inbound_tx.try_send((peer, packet));
            })
            .await
            .map_err(std::io::Error::other)?;
        let containers = self.containers.clone();
        let router = self.router.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some((peer, packet)) = inbound_rx.recv() => {
                        Self::deliver_inbound(&router, &containers, peer, &packet.data).await;
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Overlay manager shutting down");
                        break;
                    }
                }
            }
        });

        info!(
            "P2P Overlay manager started: node_ip={}, subnet={}",
            self.router.node_ip(),
            self.router.node_subnet()
        );

        Ok(())
    }

    /// Prepare overlay network for a container (before crun create): the
    /// helper makes its veth pair, the container's side with its address,
    /// the host's with its route and a packet socket; the runtime moves the
    /// container's side (the NetDeviceConfig of the OCI spec).
    pub async fn prepare_container(
        &self,
        container_id: &str,
    ) -> std::io::Result<(ContainerOverlay, NetDeviceConfig)> {
        info!("Preparing overlay network for container {}", container_id);
        let _one_at_a_time = self.operations.lock(container_id).await;
        // An entry of the id is a leftover (a stop that never came): its
        // reader and its address go, the helper replaces its veth.
        if self.containers.read().await.contains_key(container_id) {
            warn!("Container {container_id} was prepared already: its overlay is replaced");
            let old = self.containers.write().await.remove(container_id);
            if let Some(old) = old {
                self.router
                    .remove_container_ip(&old.overlay.overlay_ip)
                    .await;
            }
        }
        let overlay_ip = self.router.allocate_container_ip().await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "no overlay IPs available",
            )
        })?;
        let prepared = self.prepare_with_ip(container_id, overlay_ip).await;
        if prepared.is_err() {
            self.router.remove_container_ip(&overlay_ip).await;
        }
        prepared
    }

    /// `prepare_container` once OVERLAY_IP is reserved.
    async fn prepare_with_ip(
        &self,
        container_id: &str,
        overlay_ip: Ipv4Addr,
    ) -> std::io::Result<(ContainerOverlay, NetDeviceConfig)> {
        let request = Request::Prepare {
            id: container_id.to_string(),
            ip: overlay_ip,
        };
        let (veth_host, veth_container, host_mac, packets) =
            match ask(&self.helper, request).await? {
                (
                    Reply::Prepared {
                        veth_host,
                        veth_container,
                        host_mac,
                    },
                    Some(fd),
                ) => (veth_host, veth_container, host_mac, fd),
                _ => {
                    return Err(std::io::Error::other(
                        "the overlay helper did not prepare the veth",
                    ))
                }
            };
        // (the DNS sockets are the helper's to make: port 53, on the veth)
        let dns = match self.dns_sockets(container_id).await {
            Ok(dns) => dns,
            Err(e) => {
                let cleanup = Request::Cleanup {
                    id: container_id.to_string(),
                };
                if let Err(c) = ask(&self.helper, cleanup).await {
                    warn!("Cleaning up the veth of container {container_id}: {c}");
                }
                return Err(e);
            }
        };
        let container_if_name = "eth0".to_string();
        // (the MAC of the container's eth0 is the helper's to tell, once
        // the runtime moved the interface and the container started)
        let overlay_info = ContainerOverlay {
            container_id: container_id.to_string(),
            overlay_ip,
            veth_host: veth_host.clone(),
            container_mac: None,
            host_mac,
            packets: Arc::new(packets),
        };
        let (stop, stopped) = oneshot::channel();
        self.containers.write().await.insert(
            container_id.to_string(),
            Entry {
                overlay: overlay_info.clone(),
                _stop: stop,
            },
        );
        // Ready for the ARP and DNS queries before the container starts.
        self.start_veth_packet_reader(&overlay_info, dns, stopped);
        info!(
            "Overlay network prepared for container {}: ip={}, veth={}",
            container_id, overlay_ip, veth_host
        );
        Ok((
            overlay_info,
            NetDeviceConfig {
                host_if_name: veth_container,
                container_if_name,
            },
        ))
    }

    /// The UDP and the TCP socket for the DNS of CONTAINER_ID, from the
    /// helper.
    async fn dns_sockets(&self, container_id: &str) -> std::io::Result<DnsSockets> {
        let socket = |tcp| async move {
            let request = Request::Dns {
                id: container_id.to_string(),
                tcp,
            };
            match ask(&self.helper, request).await? {
                (Reply::Ok, Some(fd)) => Ok(fd),
                _ => Err(std::io::Error::other(
                    "the overlay helper did not make the DNS socket",
                )),
            }
        };
        Ok(DnsSockets {
            udp: socket(false).await?,
            tcp: socket(true).await?,
        })
    }

    /// Called after container starts, with its network namespace `netns`:
    /// the helper routes in it (a default route through the node's
    /// address, or only the overlay's when another network has the
    /// default), then the container is asked its MAC.
    pub async fn container_started(
        &self,
        container_id: &str,
        netns: OwnedFd,
        add_default_route: bool,
    ) -> std::io::Result<()> {
        info!(
            "Container {} started, finalizing network (default_route={})",
            container_id, add_default_route
        );
        let _one_at_a_time = self.operations.lock(container_id).await;
        if !self.containers.read().await.contains_key(container_id) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no overlay network was prepared for container {container_id}"),
            ));
        }
        let request = Request::Started {
            id: container_id.to_string(),
            default_route: add_default_route,
        };
        let mac = match ask_with(&self.helper, request, Some(netns)).await? {
            (Reply::Started { mac }, _) => mac,
            _ => {
                return Err(std::io::Error::other(
                    "the overlay helper did not tell the address of eth0",
                ))
            }
        };
        // (the container may have gone while the helper worked)
        match self.containers.write().await.get_mut(container_id) {
            Some(entry) => entry.overlay.container_mac = Some(mac),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("container {container_id} left the overlay while it started"),
                ))
            }
        }
        info!(
            "Overlay network setup complete for container {}",
            container_id
        );
        Ok(())
    }

    /// Cleanup overlay networking for a container
    pub async fn cleanup_container(&self, container_id: &str) -> std::io::Result<()> {
        release(
            &self.containers,
            &self.router,
            &self.helper,
            &self.operations,
            container_id,
            None,
        )
        .await
    }

    /// Get container overlay information
    pub async fn get_container(&self, container_id: &str) -> Option<ContainerOverlay> {
        self.containers
            .read()
            .await
            .get(container_id)
            .map(|e| e.overlay.clone())
    }

    /// Announce our overlay presence to peers
    pub async fn announce(&self) -> Result<(), crate::P2PError> {
        self.p2p_node
            .announce_tun_overlay(self.router.node_subnet())
            .await
    }

    /// Register a DNS record for a container
    /// This allows other containers in the P2P cluster to resolve this container by name
    pub async fn register_dns(
        &self,
        container_id: &str,
        container_name: &str,
    ) -> Result<(), crate::P2PError> {
        let overlay_ip = {
            let containers = self.containers.read().await;
            containers.get(container_id).map(|c| c.overlay.overlay_ip)
        };
        let overlay_ip =
            overlay_ip.ok_or_else(|| crate::P2PError::UnknownContainer(container_id.into()))?;

        let record = crate::DnsRecord {
            name: container_name.to_string(),
            ipv4: overlay_ip,
            container_id: container_id.to_string(),
        };

        info!(
            "Registering DNS record: {} -> {} (container: {})",
            record.name, record.ipv4, record.container_id
        );

        self.p2p_node.add_dns_record(record).await
    }

    /// Unregister a DNS record for a container
    pub async fn unregister_dns(&self, container_id: &str) -> Result<(), crate::P2PError> {
        info!("Unregistering DNS record for container {}", container_id);
        self.p2p_node
            .remove_dns_record_by_container_id(container_id)
            .await
    }

    /// Start a packet reader for a container's host-side veth
    /// It answers the ARP requests for the node's address and forwards packets
    /// between containers; the DNS sockets DNS (UDP and TCP, the helper's) are
    /// served with it, and a failure of them ends it.
    fn start_veth_packet_reader(
        &self,
        overlay: &ContainerOverlay,
        dns: DnsSockets,
        stopped: oneshot::Receiver<()>,
    ) {
        let (container_id, veth_host) = (overlay.container_id.as_str(), overlay.veth_host.as_str());
        let (packets, if_mac) = (overlay.packets.clone(), overlay.host_mac);
        let overlay_ip = overlay.overlay_ip;

        let dns_handler = self.dns_handler.clone();
        let node_ip = dns_handler.node_ip();
        let veth_name = veth_host.to_string();
        let container_id_owned = container_id.to_string();
        let router = self.router.clone();
        let p2p_node = self.p2p_node.clone();
        let (containers, helper, operations) = (
            self.containers.clone(),
            self.helper.clone(),
            self.operations.clone(),
        );
        let reader_packets = packets.clone();

        info!(
            "Starting veth packet reader for container {} on {}",
            container_id, veth_host
        );

        tokio::spawn(async move {
            let reader = VethReader {
                packets,
                if_mac,
                veth_name,
                container_id: container_id_owned.clone(),
                overlay_ip,
                node_ip,
                router,
                p2p_node,
            };
            let dns = crate::dns_sockets::serve(dns.udp, dns.tcp, dns_handler, overlay_ip);
            let router = reader.router.clone();
            if let Err(e) = reader.run(stopped, dns).await {
                // (a container with no reader has no ARP for its gateway, no
                // DNS and no way out: it is taken out of the overlay, which
                // its owner sees, and not left without a network)
                error!(
                    "Veth packet reader for container {} exited with error: {}: its overlay is removed",
                    container_id_owned, e
                );
                let released = release(
                    &containers,
                    &router,
                    &helper,
                    &operations,
                    &container_id_owned,
                    Some(&reader_packets),
                )
                .await;
                if let Err(e) = released {
                    error!("Cleanup of {container_id_owned}: {e}");
                }
            } else {
                debug!(
                    "Veth packet reader for container {} stopped",
                    container_id_owned
                );
            }
        });
    }

    /// The route to the containers a peer announced, if its subnet is one it
    /// may have and no other peer claims it.  The peer is told apart from the
    /// others in the result: `withdrawn` has the peers that have no route
    /// now, `restored` those that have one.
    async fn handle_peer_announcement(
        router: &OverlayRouter,
        peer_id: PeerId,
        subnet: Ipv4Net,
    ) -> Routed {
        // (a peer whose newest claim is refused has no subnet: the one it
        // claimed before goes, and a subnet it contested may be routed
        // again)
        let refused = |routed: Routed| {
            let mut routed = routed;
            if !routed.withdrawn.contains(&peer_id) {
                routed.withdrawn.push(peer_id);
            }
            routed
        };
        match router.add_route(peer_id, subnet).await {
            Ok(mut routed) => {
                // (a peer that claims a contested subnet is not in the
                // difference: it had no route before and has none now)
                if !router.has_route(&peer_id).await && !routed.withdrawn.contains(&peer_id) {
                    routed.withdrawn.push(peer_id);
                }
                routed
            }
            Err(e) => {
                debug!("Overlay announcement of peer {} ignored: {}", peer_id, e);
                refused(router.remove_peer(&peer_id).await)
            }
        }
    }

    /// An IP packet of another node to the container that has its destination.
    async fn deliver_inbound(
        router: &OverlayRouter,
        containers: &RwLock<HashMap<String, Entry>>,
        peer: PeerId,
        ip_packet: &[u8],
    ) {
        if ip_packet.len() < 20 || ip_packet[0] >> 4 != 4 {
            return;
        }
        // a peer sends from the containers of its own subnet only
        let src = Ipv4Addr::new(ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]);
        if router.lookup_route(src).await.ok() != Some(peer) {
            debug!(
                "Packet of {} from {}: not an address of that peer",
                peer, src
            );
            return;
        }
        let dest = Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);
        let target = containers
            .read()
            .await
            .values()
            .map(|e| &e.overlay)
            .find(|c| c.overlay_ip == dest)
            .map(|c| (c.packets.clone(), c.host_mac, c.container_mac));
        let Some((packets, host_mac, mac)) = target else {
            debug!("Packet of {} for {}: no such container here", peer, dest);
            return;
        };
        let Some(mac) = mac else {
            debug!(
                "Packet of {} for {}: the container has not started, dropped",
                peer, dest
            );
            return;
        };
        // (the MACs are made by the forward: its frame starts with 12 bytes
        // of them)
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(ip_packet);
        if let Err(e) = Self::forward_packet_to_veth(&packets, &host_mac, mac, &frame) {
            debug!("Failed to deliver a packet of {} to {}: {}", peer, dest, e);
        }
    }

    /// Handle an ARP packet and generate a response if it's for our node IP
    fn handle_arp_packet(
        packet: &[u8],
        node_ip: Ipv4Addr,
        our_mac: &[u8; 6],
        veth_name: &str,
        container_id: &str,
    ) -> Option<Vec<u8>> {
        // ARP packet structure (after ethernet header):
        // 0-1: Hardware type (0x0001 for Ethernet)
        // 2-3: Protocol type (0x0800 for IPv4)
        // 4: Hardware address length (6 for Ethernet)
        // 5: Protocol address length (4 for IPv4)
        // 6-7: Operation (1 = request, 2 = reply)
        // 8-13: Sender hardware address
        // 14-17: Sender protocol address
        // 18-23: Target hardware address
        // 24-27: Target protocol address

        if packet.len() < 14 + 28 {
            return None;
        }

        let arp = &packet[14..];

        // Check it's an ARP request for IPv4 over Ethernet
        let hw_type = u16::from_be_bytes([arp[0], arp[1]]);
        let proto_type = u16::from_be_bytes([arp[2], arp[3]]);
        let hw_len = arp[4];
        let proto_len = arp[5];
        let operation = u16::from_be_bytes([arp[6], arp[7]]);

        if hw_type != 1 || proto_type != 0x0800 || hw_len != 6 || proto_len != 4 {
            return None;
        }

        // Only respond to ARP requests
        if operation != 1 {
            return None;
        }

        // Get target IP (what they're looking for)
        let target_ip = Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]);

        if target_ip != node_ip {
            return None;
        }

        let sender_mac = &arp[8..14];
        let sender_ip = &arp[14..18];

        info!(
            "ARP request for {} (our node IP) on {} from container {}",
            node_ip, veth_name, container_id
        );

        let mut reply = Vec::with_capacity(14 + 28);

        reply.extend_from_slice(sender_mac); // Destination MAC (original sender)
        reply.extend_from_slice(our_mac); // Source MAC (us)
        reply.push(0x08); // Ethertype: ARP
        reply.push(0x06);

        // ARP payload
        reply.push(0x00);
        reply.push(0x01); // Hardware type: Ethernet
        reply.push(0x08);
        reply.push(0x00); // Protocol type: IPv4
        reply.push(0x06); // Hardware address length
        reply.push(0x04); // Protocol address length
        reply.push(0x00);
        reply.push(0x02); // Operation: Reply

        // Sender (us)
        reply.extend_from_slice(our_mac);
        reply.extend_from_slice(&node_ip.octets());

        // Target (original sender)
        reply.extend_from_slice(sender_mac);
        reply.extend_from_slice(sender_ip);

        Some(reply)
    }

    /// Forward a packet to a container's veth interface, on its packet
    /// socket, as from the gateway (HOST_MAC, the host side's address)
    /// to DEST_MAC (the address of the container's `eth0`).
    fn forward_packet_to_veth(
        packets: &OwnedFd,
        host_mac: &[u8; 6],
        dest_container_mac: [u8; 6],
        packet: &[u8],
    ) -> std::io::Result<()> {
        if packet.len() < 14 {
            return Ok(());
        }
        let mut frame = Vec::with_capacity(packet.len());
        frame.extend_from_slice(&dest_container_mac);
        frame.extend_from_slice(host_mac);
        frame.extend_from_slice(&packet[12..]);
        let sent = send_frame(packets, &frame)?;
        debug!("forward_packet_to_veth: sent {} bytes", sent);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frame of IPv4 from `src` to `dst`.
    fn frame(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x08, 0x00]);
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 1;
        ip[12..16].copy_from_slice(&src.octets());
        ip[16..20].copy_from_slice(&dst.octets());
        f.extend_from_slice(&ip);
        f
    }

    fn datagrams() -> (Arc<OwnedFd>, OwnedFd) {
        use rustix::net::{AddressFamily, SocketFlags, SocketType};
        let (a, b) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .unwrap();
        (Arc::new(a), b)
    }

    fn received(fd: &OwnedFd) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 2048];
        let n = rustix::net::recv(fd, &mut buf, rustix::net::RecvFlags::empty())
            .ok()?
            .0;
        buf.truncate(n);
        Some(buf)
    }

    /// What a container's veth carries to another container of the node is
    /// the kernel's, which routes the container's address to its veth: the
    /// reader delivers nothing itself, so the packet comes once.
    #[tokio::test]
    async fn a_packet_for_a_container_of_the_node_is_not_delivered_twice() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("swarm.key");
        crate::control::generate_swarm_key(&key).unwrap();
        let node = Arc::new(
            P2PNode::with_config(crate::P2PConfig {
                role: crate::Role::Overlay,
                dial: crate::dial_filter::Rules::on_one_host(),
                listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
                enable_mdns: false,
                private_key_path: Some(key),
                ..Default::default()
            })
            .await
            .unwrap(),
        );
        let base: Ipv4Net = "10.200.0.0/16".parse().unwrap();
        let subnet: Ipv4Net = "10.200.1.0/24".parse().unwrap();
        let router = Arc::new(OverlayRouter::new(node.peer_id(), base, subnet));
        let (ip_a, ip_b) = (Ipv4Addr::new(10, 200, 1, 2), Ipv4Addr::new(10, 200, 1, 3));
        assert_eq!(router.allocate_container_ip().await, Some(ip_a));
        assert_eq!(router.allocate_container_ip().await, Some(ip_b));
        let (a_packets, a_peer) = datagrams();
        let (b_packets, b_peer) = datagrams();
        let overlay = |id: &str, ip, packets: &Arc<OwnedFd>, mac| Entry {
            overlay: ContainerOverlay {
                container_id: id.to_string(),
                overlay_ip: ip,
                veth_host: format!("veth{id}"),
                container_mac: mac,
                host_mac: [2, 0, 0, 0, 0, 0xee],
                packets: packets.clone(),
            },
            _stop: oneshot::channel().0,
        };
        let b_mac = [2, 0, 0, 0, 0, 0xbb];
        let containers = Arc::new(RwLock::new(HashMap::from([
            (
                "a".to_string(),
                overlay("a", ip_a, &a_packets, Some([2, 0, 0, 0, 0, 0xaa])),
            ),
            ("b".to_string(), overlay("b", ip_b, &b_packets, Some(b_mac))),
        ])));
        let reader = VethReader {
            packets: a_packets.clone(),
            if_mac: [2, 0, 0, 0, 0, 0xee],
            veth_name: "vetha".into(),
            container_id: "a".into(),
            overlay_ip: ip_a,
            node_ip: router.node_ip(),
            router,
            p2p_node: node,
        };
        // a packet for a container of this node is the kernel's: the
        // reader does not deliver it a second time
        reader.ipv4(&frame(ip_a, ip_b)).await;
        assert!(received(&b_peer).is_none());
        assert!(received(&a_peer).is_none());
        // the reader of a ends when its entry goes (the cleanup), not before
        let (stop, stopped) = oneshot::channel();
        containers.write().await.get_mut("a").unwrap()._stop = stop;
        let mut running = tokio::spawn(reader.run(stopped, std::future::pending()));
        let early = tokio::time::timeout(std::time::Duration::from_millis(200), &mut running);
        assert!(
            early.await.is_err(),
            "the reader runs while its entry is there"
        );
        containers.write().await.remove("a");
        let ended = tokio::time::timeout(std::time::Duration::from_secs(5), running).await;
        assert!(matches!(ended, Ok(Ok(Ok(())))), "{ended:?}");
    }

    /// The holders of one id go one at a time, in the order they asked; those
    /// of other ids do not wait; a name nobody uses is forgotten.
    #[tokio::test]
    async fn operations_on_one_container_do_not_overlap() {
        use futures::FutureExt;
        let locks = IdLocks::default();
        let first = locks.lock("a").await;
        // (a second operation on "a" waits; one on "b" does not)
        let mut second = Box::pin(locks.lock("a"));
        assert!(second.as_mut().now_or_never().is_none());
        let other = locks.lock("b").now_or_never().expect("another id is free");
        drop(first);
        let second = second.as_mut().now_or_never().expect("free after the drop");
        drop((second, other));
        // (the next call forgets the two names)
        drop(locks.lock("c").await);
        assert_eq!(locks.locks.lock().unwrap().len(), 1);
    }

    /// A stop of a container while its prepare waits for the helper
    /// went past it (no entry yet: nothing to clean up) and the prepare then
    /// left the container prepared after the stop.  The stop now waits for
    /// the prepare and cleans up what it made.  The helper here is a fake
    /// one that holds its answer to Prepare until the stop was asked.
    #[tokio::test]
    async fn a_stop_during_a_prepare_cleans_up_what_the_prepare_made() {
        use crate::overlay_helper::{recv, send};
        use std::os::fd::AsFd;
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("swarm.key");
        crate::control::generate_swarm_key(&key).unwrap();
        let node = Arc::new(
            P2PNode::with_config(crate::P2PConfig {
                role: crate::Role::Overlay,
                dial: crate::dial_filter::Rules::on_one_host(),
                listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
                enable_mdns: false,
                private_key_path: Some(key),
                ..Default::default()
            })
            .await
            .unwrap(),
        );
        let (mine, theirs) = crate::overlay_helper::socketpair().unwrap();
        let (asked_tx, asked_rx) = std::sync::mpsc::channel::<()>();
        let (answer_tx, answer_rx) = std::sync::mpsc::channel::<()>();
        let fake = std::thread::spawn(move || {
            let (mut seen, mut peers) = (Vec::new(), Vec::new());
            while let Some((req, _)) = recv::<Request>(theirs.as_fd()).unwrap() {
                let (reply, fd): (Reply, OwnedFd) = match &req {
                    Request::Prepare { .. } => {
                        asked_tx.send(()).unwrap();
                        answer_rx.recv().unwrap();
                        let (packets, peer) = datagrams();
                        let packets = Arc::try_unwrap(packets).unwrap();
                        peers.push(peer);
                        let reply = Reply::Prepared {
                            veth_host: "veth0123abcd".into(),
                            veth_container: "veth0123abcdc".into(),
                            host_mac: [2, 0, 0, 0, 0, 0xee],
                        };
                        (reply, packets)
                    }
                    Request::Dns { tcp: false, .. } => (
                        Reply::Ok,
                        std::net::UdpSocket::bind("127.0.0.1:0").unwrap().into(),
                    ),
                    Request::Dns { tcp: true, .. } => (
                        Reply::Ok,
                        std::net::TcpListener::bind("127.0.0.1:0").unwrap().into(),
                    ),
                    _ => (Reply::Ok, std::fs::File::open("/dev/null").unwrap().into()),
                };
                seen.push(
                    format!("{req:?}")
                        .split([' ', '{'])
                        .next()
                        .unwrap()
                        .to_string(),
                );
                send(theirs.as_fd(), &reply, Some(fd.as_fd())).unwrap();
            }
            seen
        });
        let manager = Arc::new(TunOverlayManager::new(
            node.peer_id(),
            "10.200.0.0/16".parse().unwrap(),
            "10.200.1.0/24".parse().unwrap(),
            node,
            Arc::new(Helper::new(mine)),
            Vec::new(),
        ));
        const ID: &str = "0123abcdef";
        let prepare = tokio::spawn({
            let m = manager.clone();
            async move { m.prepare_container(ID).await.map(|_| ()) }
        });
        tokio::task::spawn_blocking(move || asked_rx.recv().unwrap())
            .await
            .unwrap();
        let stop = tokio::spawn({
            let m = manager.clone();
            async move { m.cleanup_container(ID).await }
        });
        // (the stop runs as far as it can before the helper answers)
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        answer_tx.send(()).unwrap();
        prepare.await.unwrap().unwrap();
        stop.await.unwrap().unwrap();
        assert!(
            manager.get_container(ID).await.is_none(),
            "the container is prepared after its stop"
        );
        drop(manager);
        let seen = fake.join().unwrap();
        assert_eq!(seen, ["Prepare", "Dns", "Dns", "Cleanup"]);
    }

    /// A reader that fails (here: a packet "socket" that cannot be read)
    /// takes its container out of the overlay and has the veth removed: the
    /// container is not left with no ARP, no DNS and no way out.
    #[tokio::test]
    async fn a_reader_that_fails_takes_its_container_out_of_the_overlay() {
        use crate::overlay_helper::{recv, send};
        use std::os::fd::AsFd;
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("swarm.key");
        crate::control::generate_swarm_key(&key).unwrap();
        let node = Arc::new(
            P2PNode::with_config(crate::P2PConfig {
                role: crate::Role::Overlay,
                dial: crate::dial_filter::Rules::on_one_host(),
                listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
                enable_mdns: false,
                private_key_path: Some(key),
                ..Default::default()
            })
            .await
            .unwrap(),
        );
        let (mine, theirs) = crate::overlay_helper::socketpair().unwrap();
        let (cleaned_tx, cleaned_rx) = std::sync::mpsc::channel::<()>();
        let fake = std::thread::spawn(move || {
            while let Some((req, _)) = recv::<Request>(theirs.as_fd()).unwrap() {
                let (reply, fd): (Reply, OwnedFd) = match &req {
                    Request::Prepare { .. } => (
                        Reply::Prepared {
                            veth_host: "veth0123abcd".into(),
                            veth_container: "veth0123abcdc".into(),
                            host_mac: [2, 0, 0, 0, 0, 0xee],
                        },
                        std::fs::File::open("/dev/null").unwrap().into(),
                    ),
                    Request::Dns { tcp: false, .. } => (
                        Reply::Ok,
                        std::net::UdpSocket::bind("127.0.0.1:0").unwrap().into(),
                    ),
                    Request::Dns { tcp: true, .. } => (
                        Reply::Ok,
                        std::net::TcpListener::bind("127.0.0.1:0").unwrap().into(),
                    ),
                    _ => (Reply::Ok, std::fs::File::open("/dev/null").unwrap().into()),
                };
                if matches!(req, Request::Cleanup { .. }) {
                    cleaned_tx.send(()).unwrap();
                }
                send(theirs.as_fd(), &reply, Some(fd.as_fd())).unwrap();
            }
        });
        let manager = TunOverlayManager::new(
            node.peer_id(),
            "10.200.0.0/16".parse().unwrap(),
            "10.200.1.0/24".parse().unwrap(),
            node,
            Arc::new(Helper::new(mine)),
            Vec::new(),
        );
        manager.prepare_container("0123abcdef").await.unwrap();
        tokio::task::spawn_blocking(move || {
            cleaned_rx.recv_timeout(std::time::Duration::from_secs(10))
        })
        .await
        .unwrap()
        .expect("the veth of a container with no reader is removed");
        assert!(manager.get_container("0123abcdef").await.is_none());
        drop(manager);
        // (the task of the reader lets go of the helper when it ends)
        tokio::task::spawn_blocking(move || fake.join().unwrap())
            .await
            .unwrap();
    }

    /// An overlay that cannot be started is an error of the service, not a
    /// warning of a service that then runs without it: the helper refuses to
    /// turn forwarding on, and `start` says so.
    #[tokio::test]
    async fn an_overlay_whose_helper_refuses_does_not_start() {
        use crate::overlay_helper::{recv, send};
        use std::os::fd::AsFd;
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("swarm.key");
        crate::control::generate_swarm_key(&key).unwrap();
        let node = Arc::new(
            P2PNode::with_config(crate::P2PConfig {
                role: crate::Role::Overlay,
                dial: crate::dial_filter::Rules::on_one_host(),
                listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
                enable_mdns: false,
                private_key_path: Some(key),
                ..Default::default()
            })
            .await
            .unwrap(),
        );
        let (mine, theirs) = crate::overlay_helper::socketpair().unwrap();
        let fake = std::thread::spawn(move || {
            while let Some((req, _)) = recv::<Request>(theirs.as_fd()).unwrap() {
                assert!(matches!(req, Request::Forwarding), "{req:?}");
                let refused = Reply::Error {
                    message: "no".into(),
                };
                send(theirs.as_fd(), &refused, None).unwrap();
            }
        });
        let mut manager = TunOverlayManager::new(
            node.peer_id(),
            "10.200.0.0/16".parse().unwrap(),
            "10.200.1.0/24".parse().unwrap(),
            node,
            Arc::new(Helper::new(mine)),
            Vec::new(),
        );
        let err = manager.start().await.expect_err("the helper refused");
        assert!(err.to_string().contains("no"), "{err}");
        drop(manager);
        fake.join().unwrap();
    }

    #[tokio::test]
    async fn a_packet_goes_to_the_peer_that_announced_the_subnet() {
        let base: Ipv4Net = "10.200.0.0/16".parse().unwrap();
        let local = PeerId::random();
        let router = OverlayRouter::new(
            local,
            base,
            crate::overlay_router::subnet_for(base, &local, 0),
        );
        let peer = loop {
            let p = PeerId::random();
            if crate::overlay_router::subnet_for(base, &p, 0) != router.node_subnet() {
                break p;
            }
        };
        let subnet = crate::overlay_router::subnet_for(base, &peer, 0);
        let dest = subnet.hosts().nth(6).unwrap();
        assert!(router.lookup_route(dest).await.is_err());
        let routed = TunOverlayManager::handle_peer_announcement(&router, peer, subnet).await;
        assert_eq!(routed.restored, vec![peer]);
        assert!(routed.withdrawn.is_empty());
        assert_eq!(router.lookup_route(dest).await.ok(), Some(peer));
        // a subnet that is not one of a peer is ignored, and the peer is
        // not one that has a subnet
        let other = PeerId::random();
        let routed = TunOverlayManager::handle_peer_announcement(
            &router,
            other,
            "10.0.0.0/8".parse().unwrap(),
        )
        .await;
        assert_eq!(routed.withdrawn, vec![other]);
        assert!(router
            .lookup_route(Ipv4Addr::new(10, 1, 1, 1))
            .await
            .is_err());
        // a peer whose newest claim is refused loses the subnet it had
        let routed = TunOverlayManager::handle_peer_announcement(
            &router,
            peer,
            "10.0.0.0/8".parse().unwrap(),
        )
        .await;
        assert_eq!(routed.withdrawn, vec![peer]);
        assert!(router.lookup_route(dest).await.is_err());
    }
}
