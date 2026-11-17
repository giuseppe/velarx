// SPDX-License-Identifier: Apache-2.0
//! P2P-Integrated DNS Resolver for Container Name Resolution
//!
//! This module implements a DNS resolver that handles DNS queries from containers
//! using DNS records gossiped over the P2P network. It allows containers
//! to reach each other by name across the cluster.
//!
//! The queries come from the sockets of `dns_sockets` (UDP and TCP, one
//! pair for each container); this module answers one query at a time.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout_at, Duration, Instant};
use tracing::{debug, warn};

use crate::{DnsRecord, OverlayGossip};

/// The record types the resolver reads of a query (the others are the
/// name servers').
use velarx_netkernel::dns::{self, CLASS_IN, TYPE_A, TYPE_AAAA, TYPE_PTR};

/// The largest answer that goes to a container in one frame of its veth
/// (an MTU of 1500 bytes, less the IPv4 and UDP headers); a client that
/// offers no larger buffer (EDNS) takes 512 bytes.
const MAX_UDP_ANSWER: u16 = 1472;
const MIN_UDP_ANSWER: u16 = 512;

/// The name servers glibc reads of a `resolv.conf`, at most.
const MAX_NAME_SERVERS: usize = 3;

const DNS_TYPE_OPT: u16 = 41;
const DNS_TC_TRUNCATED: u8 = 0x02;

/// How long an upstream server has to answer a forwarded query over UDP.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);

/// ... and over TCP (the connection included).
const UPSTREAM_TCP_TIMEOUT: Duration = Duration::from_secs(5);

/// How a client asks.  A client over TCP takes an answer of any size, and
/// its query goes to the name servers over TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

/// The name servers of a `resolv.conf` as glibc reads them: its first
/// three `nameserver` lines, in order, at port 53; none (or no file): the
/// host's own, 127.0.0.1.
pub fn parse_resolv_conf(text: &str, index: impl Fn(&str) -> Option<u32>) -> Vec<SocketAddr> {
    let mut servers = velarx_netkernel::dnsrec::resolv_conf_servers(text, index);
    servers.truncate(MAX_NAME_SERVERS);
    if servers.is_empty() {
        servers.push(SocketAddr::from((Ipv4Addr::LOCALHOST, 53)));
    }
    servers
}

/// The name servers of the host, from its `/etc/resolv.conf`: where the
/// names that are not containers go, as for a process of the host (the
/// service is in the host's network namespace: a local resolver, such as
/// the stub of systemd-resolved at 127.0.0.53, is reached as by any
/// process of the host).
pub fn host_resolvers() -> std::io::Result<Vec<SocketAddr>> {
    let text = match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    Ok(parse_resolv_conf(&text, |name| {
        velarx_netkernel::netlink::Netlink::open()
            .and_then(|mut nl| nl.link(name))
            .ok()
            .flatten()
            .map(|link| link.index)
    }))
}

/// The resolver of the overlay: answers the queries of the containers.
pub struct DnsHandler {
    /// Gossip discovery for DNS records
    gossip: Arc<OverlayGossip>,
    /// Node's overlay IP (the DNS server address from container's perspective)
    node_ip: Ipv4Addr,
    /// DNS domain suffix for container names
    domain_suffix: String,
    /// Upstream DNS servers for external queries
    upstream_dns: Vec<SocketAddr>,
}

impl DnsHandler {
    /// Create a new DNS handler; `upstream_dns` are the name servers the
    /// names that are not containers are asked of, in order.
    pub fn new(
        gossip: Arc<OverlayGossip>,
        node_ip: Ipv4Addr,
        upstream_dns: Vec<SocketAddr>,
    ) -> Self {
        Self {
            gossip,
            node_ip,
            domain_suffix: ".velarx".to_string(),
            upstream_dns,
        }
    }

    /// Get the node IP (for ARP responses)
    pub fn node_ip(&self) -> Ipv4Addr {
        self.node_ip
    }

    /// The answer to the query QUERY of a client that asked over TRANSPORT:
    /// the address of a container (A; no IPv6 address, AAAA), the name of a
    /// container's address (PTR), and anything else as the name servers
    /// answer it.  None for a message that is not a query.
    pub async fn answer(&self, query: &[u8], transport: Transport) -> Option<Vec<u8>> {
        let q = dns::question(query)?;
        debug!(
            "DNS query: name='{}', type={}, class={}",
            q.name, q.qtype, q.qclass
        );
        if q.qclass == CLASS_IN {
            // (the one record of a zone the shared code answers from)
            let record = match q.qtype {
                TYPE_A | TYPE_AAAA => self.container(&q.name).await.map(|r| dns::Record {
                    names: vec![q.name.clone()],
                    ips: vec![r.ipv4],
                    ips6: Vec::new(),
                }),
                TYPE_PTR => self.ptr_record(&q.name).await,
                _ => None,
            };
            if let Some(record) = record {
                let size = match transport {
                    Transport::Udp => dns::UDP_SIZE,
                    Transport::Tcp => usize::from(u16::MAX),
                };
                if let dns::Answer::Reply(answer) = dns::answer(&[record], query, size) {
                    return Some(answer);
                }
            }
        }
        debug!("'{}' is not a container's: asked upstream", q.name);
        Some(match self.forward_to_upstream(query, &q, transport).await {
            Some(answer) => answer,
            None => dns::head(query, &q, dns::RCODE_SERVFAIL),
        })
    }

    /// The record of the container named `name`, with the domain suffix or
    /// without: `NAME` is the answer of [`OverlayGossip::resolve_dns`] (the
    /// peer that held the name first, whoever announces it later) and
    /// `NAME.<peer id>` the container of that peer.  Any other name, a host
    /// of the Internet among them, is not a container's: a member of the
    /// swarm cannot answer it for the containers of every node.
    async fn container(&self, name: &str) -> Option<DnsRecord> {
        let name = self.extract_container_name(name);
        let mut labels = name.split('.');
        match (labels.next()?, labels.next(), labels.next()) {
            (container, None, _) => self.gossip.resolve_dns(container).await,
            (container, Some(peer), None) => self.gossip.resolve_dns_of(peer, container).await,
            _ => None,
        }
    }

    /// Forward a DNS query to the upstream DNS servers, one after the other
    /// until one answers.  The query offers the name servers no larger
    /// buffer than one frame of the veth; an answer larger than the client
    /// takes is cut to its header and question, truncated (the client asks
    /// again over TCP).  A client over TCP is answered from the name
    /// servers over TCP, whatever the size.
    async fn forward_to_upstream(
        &self,
        query: &[u8],
        q: &dns::Question,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        if self.upstream_dns.is_empty() {
            warn!("No upstream DNS servers: the name is not resolved");
            return None;
        }
        if transport == Transport::Tcp {
            for upstream in &self.upstream_dns {
                debug!("Forwarding DNS query to {} over TCP", upstream);
                match ask_upstream_tcp(*upstream, query).await {
                    Ok(response) => return Some(response),
                    Err(e) => debug!("DNS upstream {} over TCP: {}", upstream, e),
                }
            }
            warn!("All upstream DNS servers failed");
            return None;
        }
        let mut forwarded = query.to_vec();
        let takes = clamp_edns(&mut forwarded, q.end, MAX_UDP_ANSWER);
        for upstream in &self.upstream_dns {
            debug!("Forwarding DNS query to {}", upstream);
            match ask_upstream(*upstream, &forwarded).await {
                Ok(response) if response.len() > takes as usize => {
                    debug!(
                        "DNS response from {} ({} bytes): truncated to the {} the client takes",
                        upstream,
                        response.len(),
                        takes
                    );
                    // (the flags and the code of the answer, cut)
                    let mut cut = dns::head(query, q, 0);
                    cut[2..4].copy_from_slice(&response[2..4]);
                    cut[2] |= DNS_TC_TRUNCATED;
                    return Some(cut);
                }
                Ok(response) => {
                    debug!(
                        "Received DNS response from {} ({} bytes)",
                        upstream,
                        response.len()
                    );
                    return Some(response);
                }
                Err(e) => debug!("DNS upstream {}: {}", upstream, e),
            }
        }
        warn!("All upstream DNS servers failed");
        None
    }

    /// Extract container name from DNS query name
    fn extract_container_name(&self, name: &str) -> String {
        let name = name.trim_end_matches('.');

        if name.ends_with(&self.domain_suffix) {
            name[..name.len() - self.domain_suffix.len()].to_string()
        } else {
            name.to_string()
        }
    }

    /// The container whose address a PTR query names
    /// ("2.3.200.10.in-addr.arpa" for 10.200.3.2), if there is one: one
    /// record per address, whatever order the peers announced in
    /// ([`OverlayGossip::get_all_dns_records`] keeps one record per
    /// name, chosen the same on every node).
    async fn ptr_record(&self, name: &str) -> Option<dns::Record> {
        let ip = dns::parse_reverse(name)?;
        let record = self
            .gossip
            .get_all_dns_records()
            .await
            .into_iter()
            .find(|r| r.ipv4 == ip)?;
        debug!("PTR resolved {} -> {}", ip, record.name);
        Some(dns::Record {
            names: vec![record.name],
            ips: vec![ip],
            ips6: Vec::new(),
        })
    }
}

/// Offer the name servers at most `max` bytes of answer in the EDNS record
/// of `query` (whose question ends at `question_end`), if it has one; the
/// size of the answer the client takes: what it offered (at least 512
/// bytes), at most `max`.
fn clamp_edns(query: &mut [u8], question_end: usize, max: u16) -> u16 {
    let count = |at: usize| u16::from_be_bytes([query[at], query[at + 1]]);
    let mut takes = MIN_UDP_ANSWER;
    // (a query has nothing but its question and its additional records)
    if count(6) != 0 || count(8) != 0 {
        return takes;
    }
    let mut pos = question_end;
    for _ in 0..count(10) {
        // the name: labels, or a pointer
        loop {
            let Some(&len) = query.get(pos) else {
                return takes;
            };
            if len & 0xC0 == 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + len as usize;
            if len == 0 {
                break;
            }
        }
        let Some(fixed) = query.get_mut(pos..pos + 10) else {
            return takes;
        };
        let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        if u16::from_be_bytes([fixed[0], fixed[1]]) == DNS_TYPE_OPT {
            let offered = u16::from_be_bytes([fixed[2], fixed[3]]);
            takes = offered.clamp(MIN_UDP_ANSWER, max);
            fixed[2..4].copy_from_slice(&offered.min(max).to_be_bytes());
        }
        pos += 10 + rdlen;
    }
    takes
}

/// Ask the name server `upstream` for `query` on a socket of its own,
/// connected to it: the kernel hands over datagrams from that address only.
/// What comes is taken for the answer when it carries the transaction ID and
/// the question of the query; anything else is ignored till the time is up.
async fn ask_upstream(upstream: SocketAddr, query: &[u8]) -> std::io::Result<Vec<u8>> {
    let local = if upstream.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let socket = UdpSocket::bind(local).await?;
    socket.connect(upstream).await?;
    socket.send(query).await?;
    let deadline = Instant::now() + UPSTREAM_TIMEOUT;
    // (as large as a datagram: an answer is never cut by the read)
    let mut buf = vec![0u8; 65535];
    loop {
        let n = timeout_at(deadline, socket.recv(&mut buf))
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
        if answers(&buf[..n], query) {
            buf.truncate(n);
            return Ok(buf);
        }
        debug!(
            "DNS upstream {}: a datagram that is not the answer",
            upstream
        );
    }
}

/// Ask the name server `upstream` for `query` over TCP (a message with its
/// length in two bytes before it, in both directions), all within
/// `UPSTREAM_TCP_TIMEOUT`.  The answer must carry the transaction ID and the
/// question of the query.
async fn ask_upstream_tcp(upstream: SocketAddr, query: &[u8]) -> std::io::Result<Vec<u8>> {
    let length = u16::try_from(query.len())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let exchange = async {
        let mut stream = TcpStream::connect(upstream).await?;
        let mut message = length.to_be_bytes().to_vec();
        message.extend_from_slice(query);
        stream.write_all(&message).await?;
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await?;
        let mut response = vec![0u8; usize::from(u16::from_be_bytes(head))];
        stream.read_exact(&mut response).await?;
        Ok::<_, std::io::Error>(response)
    };
    let response = tokio::time::timeout(UPSTREAM_TCP_TIMEOUT, exchange)
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    if !answers(&response, query) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not the answer to the query",
        ));
    }
    Ok(response)
}

/// Whether `response` is the answer to `query`: a response with the
/// transaction ID of the query and its question.
fn answers(response: &[u8], query: &[u8]) -> bool {
    let question_end = |m: &[u8]| -> Option<usize> {
        let qdcount = u16::from_be_bytes([*m.get(4)?, *m.get(5)?]);
        if qdcount != 1 {
            return None;
        }
        let mut pos = 12;
        loop {
            let len = *m.get(pos)? as usize;
            pos += 1;
            if len == 0 {
                break;
            }
            if len & 0xC0 != 0 {
                return None;
            }
            pos += len;
        }
        (m.len() >= pos + 4).then_some(pos + 4)
    };
    let (Some(end), Some(asked)) = (question_end(response), question_end(query)) else {
        return false;
    };
    response[..2] == query[..2] && response[2] & 0x80 != 0 && response[12..end] == query[12..asked]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::GossipMessage;

    /// A query for `example.org` A with the transaction ID `id`.
    fn query(id: u16) -> Vec<u8> {
        let mut q = id.to_be_bytes().to_vec();
        q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        q.extend_from_slice(b"\x07example\x03org\x00");
        q.extend_from_slice(&[0, 1, 0, 1]);
        q
    }

    /// The answer to `query` that says `tag` in its one record.
    fn answer(query: &[u8], id: u16, tag: u8) -> Vec<u8> {
        let mut a = query.to_vec();
        a[..2].copy_from_slice(&id.to_be_bytes());
        a[2] |= 0x80;
        a[7] = 1;
        a.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, tag]);
        a
    }

    fn handler(upstream: Vec<SocketAddr>) -> DnsHandler {
        let gossip = Arc::new(OverlayGossip::default());
        DnsHandler::new(gossip, Ipv4Addr::new(10, 200, 1, 1), upstream)
    }

    /// The answer that is taken is the one of the name server asked, with the
    /// transaction ID and the question of the query: a datagram from
    /// another address, or with another ID or question, is not.
    #[tokio::test]
    async fn only_the_answer_of_the_server_asked_is_taken() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let handler = handler(vec![server.local_addr().unwrap()]);
        let q = query(0x1234);
        let asking = tokio::spawn({
            let q = q.clone();
            async move {
                let parsed = dns::question(&q).unwrap();
                handler
                    .forward_to_upstream(&q, &parsed, Transport::Udp)
                    .await
            }
        });
        let mut buf = [0u8; 512];
        let (n, client) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &q[..]);
        // a stranger with the right ID and question, to the port of the query
        stranger
            .send_to(&answer(&q, 0x1234, 66), client)
            .await
            .unwrap();
        // the server itself: another ID, another question, then the answer
        server
            .send_to(&answer(&q, 0x4321, 67), client)
            .await
            .unwrap();
        let mut other = answer(&q, 0x1234, 68);
        other[13] ^= 0x20;
        server.send_to(&other, client).await.unwrap();
        server.send_to(&q, client).await.unwrap();
        server
            .send_to(&answer(&q, 0x1234, 1), client)
            .await
            .unwrap();
        let got = asking.await.unwrap().expect("the answer");
        assert_eq!(got, answer(&q, 0x1234, 1));
    }

    /// A server that does not answer is given up, and the next one asked.
    #[tokio::test]
    async fn the_next_server_is_asked_when_one_is_silent() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let handler = handler(vec![
            silent.local_addr().unwrap(),
            second.local_addr().unwrap(),
        ]);
        let q = query(7);
        let asking = tokio::spawn({
            let q = q.clone();
            async move {
                let parsed = dns::question(&q).unwrap();
                handler
                    .forward_to_upstream(&q, &parsed, Transport::Udp)
                    .await
            }
        });
        let mut buf = [0u8; 512];
        let (_, _) = silent.recv_from(&mut buf).await.unwrap();
        let (_, client) = second.recv_from(&mut buf).await.unwrap();
        second.send_to(&answer(&q, 7, 9), client).await.unwrap();
        assert_eq!(asking.await.unwrap(), Some(answer(&q, 7, 9)));
    }

    #[test]
    fn the_upstreams_come_from_the_resolver_file_or_the_settings() {
        let conf = "# generated\nsearch lan\n; nameserver 192.0.2.99\nnameserver 192.0.2.1\n\
                    nameserver\nnameserver 192.0.2.1%eth0\nnameserver fe80::1%nowhere\n\
                    nameserver 2001:db8::53 # a comment\noptions edns0\n\
                    nameserver fe80::1%eth0\nnameserver fe80::2%7\nnameserver 192.0.2.4\n";
        let eth0 = |name: &str| (name == "eth0").then_some(2);
        let scoped = |ip: &str, scope| {
            SocketAddr::V6(std::net::SocketAddrV6::new(
                ip.parse().unwrap(),
                53,
                0,
                scope,
            ))
        };
        // (glibc reads three)
        assert_eq!(
            parse_resolv_conf(conf, eth0),
            vec![
                "192.0.2.1:53".parse::<SocketAddr>().unwrap(),
                "[2001:db8::53]:53".parse().unwrap(),
                scoped("fe80::1", 2),
            ]
        );
        assert_eq!(
            parse_resolv_conf("nameserver fe80::2%7\n", eth0),
            vec![scoped("fe80::2", 7)]
        );
        // none: the host's own, as glibc
        let local = vec!["127.0.0.1:53".parse::<SocketAddr>().unwrap()];
        assert_eq!(parse_resolv_conf("", eth0), local);
        assert_eq!(parse_resolv_conf("search lan\n", eth0), local);
    }

    /// A name that is not a container's is asked upstream whatever its
    /// type (an AAAA, an MX); a container's has its address and no IPv6
    /// one; no answer upstream is a failure the client is told at once.
    #[tokio::test]
    async fn what_is_not_a_container_is_asked_upstream_and_a_failure_is_said() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gossip = Arc::new(OverlayGossip::default());
        gossip
            .add_dns_record(DnsRecord {
                name: "web".into(),
                ipv4: "10.200.1.2".parse().unwrap(),
                container_id: "c1".into(),
            })
            .await;
        let handler = Arc::new(DnsHandler::new(
            gossip,
            Ipv4Addr::new(10, 200, 1, 1),
            vec![server.local_addr().unwrap()],
        ));
        let typed = |id: u16, name: &[u8], qtype: u16| {
            let mut q = id.to_be_bytes().to_vec();
            q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
            q.extend_from_slice(name);
            q.extend_from_slice(&qtype.to_be_bytes());
            q.extend_from_slice(&[0, 1]);
            q
        };
        // the container: its address, and an empty answer for IPv6
        let a = handler
            .answer(&typed(1, b"\x03web\x06velarx\x00", TYPE_A), Transport::Udp)
            .await
            .unwrap();
        assert_eq!(a[6..8], [0, 1]);
        assert_eq!(a[a.len() - 4..], [10, 200, 1, 2]);
        let aaaa = handler
            .answer(&typed(2, b"\x03web\x00", TYPE_AAAA), Transport::Udp)
            .await
            .unwrap();
        assert_eq!((aaaa[3] & 0x0f, &aaaa[6..8]), (0, &[0u8, 0][..]));
        // the others go upstream, whatever their type
        for (id, qtype) in [(3u16, TYPE_AAAA), (4, 15), (5, TYPE_PTR)] {
            let q = typed(id, b"\x07example\x03org\x00", qtype);
            let asking = tokio::spawn({
                let (handler, q) = (handler.clone(), q.clone());
                async move { handler.answer(&q, Transport::Udp).await }
            });
            let mut buf = [0u8; 512];
            let (n, client) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &q[..], "type {qtype}");
            let mut answer = q.clone();
            answer[2] |= 0x80;
            server.send_to(&answer, client).await.unwrap();
            assert_eq!(asking.await.unwrap(), Some(answer));
        }
        // nobody upstream: a failure (SERVFAIL), with the ID and the question
        let alone = DnsHandler::new(
            Arc::new(OverlayGossip::default()),
            Ipv4Addr::new(10, 200, 1, 1),
            Vec::new(),
        );
        let q = typed(6, b"\x07example\x03org\x00", TYPE_A);
        let failed = alone.answer(&q, Transport::Udp).await.unwrap();
        assert_eq!(failed[..2], q[..2]);
        assert_eq!(failed[3] & 0x0f, 2);
        assert_eq!(failed[12..], q[12..]);
    }

    /// A member that announces a dotted name (a host of the Internet) does
    /// not answer it for the containers of the swarm: only `NAME` and
    /// `NAME.<peer id>` are the table's, the rest is asked upstream.
    #[tokio::test]
    async fn a_dotted_record_does_not_shadow_the_upstream() {
        let gossip = Arc::new(OverlayGossip::default());
        let _events = gossip.overlay_events();
        let peer = libp2p::PeerId::random();
        gossip
            .handle_gossip_message(
                peer,
                GossipMessage::TunOverlayAnnounce {
                    node_subnet: "10.200.3.0/24".parse().unwrap(),
                },
            )
            .await;
        gossip
            .handle_gossip_message(
                peer,
                GossipMessage::DnsRecordAnnounce {
                    records: ["registry.example.com", "web"]
                        .map(|name| DnsRecord {
                            name: name.into(),
                            ipv4: "10.200.3.5".parse().unwrap(),
                            container_id: format!("c-{name}"),
                        })
                        .to_vec(),
                },
            )
            .await;
        let handler = DnsHandler::new(gossip, Ipv4Addr::new(10, 200, 1, 1), Vec::new());
        for name in [
            "registry.example.com",
            "registry.example.com.velarx",
            "registry.example",
        ] {
            assert_eq!(handler.container(name).await, None, "{name}");
        }
        assert!(handler.container("web").await.is_some());
        assert!(handler.container(&format!("web.{peer}")).await.is_some());
        // (asked as a client does: nothing upstream, a failure, not the
        // container's address)
        let mut q = vec![0, 7, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x08registry\x07example\x03com\x00\x00\x01\x00\x01");
        let answer = handler.answer(&q, Transport::Udp).await.unwrap();
        assert_eq!(answer[3] & 0x0f, 2, "SERVFAIL");
    }

    /// The PTR answer of an address is the name of the container whose
    /// address the A answer gives: a name two peers claim belongs to the
    /// first one on both paths, and the address of the record that lost is
    /// nobody's; the other's container is reached as `web.<peer id>`.
    #[tokio::test]
    async fn a_ptr_answer_names_the_container_the_a_answer_names() {
        let gossip = Arc::new(OverlayGossip::default());
        let _events = gossip.overlay_events();
        let (a, b) = (libp2p::PeerId::random(), libp2p::PeerId::random());
        let record = |id: &str, ip: &str| DnsRecord {
            name: "web".into(),
            ipv4: ip.parse().unwrap(),
            container_id: id.into(),
        };
        for (peer, subnet, id, ip) in [
            (a, "10.200.2.0/24", "zz", "10.200.2.5"),
            (b, "10.200.3.0/24", "aa", "10.200.3.5"),
        ] {
            gossip
                .handle_gossip_message(
                    peer,
                    GossipMessage::TunOverlayAnnounce {
                        node_subnet: subnet.parse().unwrap(),
                    },
                )
                .await;
            gossip
                .handle_gossip_message(
                    peer,
                    GossipMessage::DnsRecordAnnounce {
                        records: vec![record(id, ip)],
                    },
                )
                .await;
        }
        let handler = DnsHandler::new(gossip, Ipv4Addr::new(10, 200, 1, 1), Vec::new());
        assert_eq!(
            handler.container("web.velarx").await.map(|r| r.ipv4),
            Some(Ipv4Addr::new(10, 200, 2, 5))
        );
        assert_eq!(
            handler
                .container(&format!(
                    "web.{}.velarx",
                    b.to_string().to_ascii_lowercase()
                ))
                .await
                .map(|r| r.ipv4),
            Some(Ipv4Addr::new(10, 200, 3, 5)),
            "the container of a peer by its own name (a question is in lower case)"
        );
        assert_eq!(
            handler
                .container(&format!("web.{}", libp2p::PeerId::random()))
                .await,
            None
        );
        assert_eq!(
            handler
                .ptr_record("5.2.200.10.in-addr.arpa")
                .await
                .map(|r| r.names),
            Some(vec!["web".to_string()])
        );
        assert_eq!(
            handler.ptr_record("5.3.200.10.in-addr.arpa").await,
            None,
            "the address of the record that lost"
        );
    }

    /// An answer made here holds its question and its records only: the
    /// EDNS record of the query is not copied, nor counted.
    #[tokio::test]
    async fn an_answer_made_here_counts_only_what_it_holds() {
        let gossip = Arc::new(OverlayGossip::default());
        gossip
            .add_dns_record(DnsRecord {
                name: "web".into(),
                ipv4: "10.200.1.2".parse().unwrap(),
                container_id: "c1".into(),
            })
            .await;
        let handler = DnsHandler::new(gossip, Ipv4Addr::new(10, 200, 1, 1), Vec::new());
        let mut q = 9u16.to_be_bytes().to_vec();
        // (no recursion desired, one EDNS record)
        q.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 1]);
        q.extend_from_slice(b"\x03web\x00\x00\x01\x00\x01");
        q.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        let end = 12 + 5 + 4;
        for (qtype, records) in [(TYPE_A, 1u8), (TYPE_AAAA, 0)] {
            q[end - 4..end - 2].copy_from_slice(&qtype.to_be_bytes());
            let answer = handler.answer(&q, Transport::Udp).await.unwrap();
            assert_eq!(answer[..2], q[..2]);
            assert_eq!(answer[2] & 0x81, 0x80, "a response, RD as asked");
            assert_eq!(answer[4..12], [0, 1, 0, records, 0, 0, 0, 0]);
            assert_eq!(answer[12..end], q[12..end]);
        }
    }

    /// The name servers are offered no larger buffer than a frame of the
    /// veth, and an answer larger than the client takes is cut, truncated.
    #[tokio::test]
    async fn an_answer_is_never_larger_than_the_client_takes() {
        // the EDNS record of a client that takes 4096 bytes
        let mut q = query(5);
        q[11] = 1;
        q.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        let end = 12 + b"\x07example\x03org\x00".len() + 4;
        let mut clamped = q.clone();
        assert_eq!(
            clamp_edns(&mut clamped, end, MAX_UDP_ANSWER),
            MAX_UDP_ANSWER
        );
        assert_eq!(
            clamped[end + 3..end + 5],
            MAX_UDP_ANSWER.to_be_bytes(),
            "offered at most a frame"
        );
        // no EDNS: 512 bytes
        assert_eq!(clamp_edns(&mut query(5), end, MAX_UDP_ANSWER), 512);
        // a small offer is passed on as it is, and taken as 512
        let mut small = q.clone();
        small[end + 3..end + 5].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(clamp_edns(&mut small, end, MAX_UDP_ANSWER), 512);
        assert_eq!(small[end + 3..end + 5], 100u16.to_be_bytes());

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let handler = handler(vec![server.local_addr().unwrap()]);
        let asking = tokio::spawn({
            let q = q.clone();
            async move {
                let parsed = dns::question(&q).unwrap();
                handler
                    .forward_to_upstream(&q, &parsed, Transport::Udp)
                    .await
            }
        });
        let mut buf = [0u8; 512];
        let (n, client) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &clamped[..], "the query with its buffer clamped");
        // an answer of 2000 bytes, larger than a frame
        let mut big = answer(&q, 5, 1);
        big.resize(2000, 0);
        server.send_to(&big, client).await.unwrap();
        let cut = asking.await.unwrap().unwrap();
        assert_eq!(cut.len(), end);
        assert_eq!(cut[..2], q[..2]);
        assert_ne!(cut[2] & DNS_TC_TRUNCATED, 0, "truncated");
        assert_eq!(cut[4..12], [0, 1, 0, 0, 0, 0, 0, 0]);
    }

    /// An answer too large for UDP is cut and marked truncated, and the
    /// client's retry over TCP is answered whole, from the name server over
    /// TCP (here the one server at one port, UDP and TCP).
    #[tokio::test]
    async fn a_truncated_answer_is_given_whole_over_tcp() {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(addr).await.unwrap();
        let handler = Arc::new(handler(vec![addr]));
        let q = query(11);
        let mut big = answer(&q, 11, 1);
        big.resize(3000, 0);
        let server = tokio::spawn({
            let (q, big) = (q.clone(), big.clone());
            async move {
                // UDP: the answer is larger than the client takes
                let mut buf = [0u8; 512];
                let (n, client) = udp.recv_from(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], &q[..]);
                udp.send_to(&big, client).await.unwrap();
                // TCP: the query with its length, the answer with its
                let (mut stream, _) = tcp.accept().await.unwrap();
                let mut length = [0u8; 2];
                stream.read_exact(&mut length).await.unwrap();
                assert_eq!(usize::from(u16::from_be_bytes(length)), q.len());
                let mut got = vec![0u8; q.len()];
                stream.read_exact(&mut got).await.unwrap();
                assert_eq!(got, q);
                stream
                    .write_all(&(big.len() as u16).to_be_bytes())
                    .await
                    .unwrap();
                stream.write_all(&big).await.unwrap();
            }
        });
        let cut = handler.answer(&q, Transport::Udp).await.unwrap();
        assert_ne!(cut[2] & DNS_TC_TRUNCATED, 0);
        assert!(cut.len() < 100);
        let whole = handler.answer(&q, Transport::Tcp).await.unwrap();
        assert_eq!(whole, big);
        server.await.unwrap();
    }

    /// A name server over TCP that answers another question, or that
    /// is not there, is not believed: the next one is asked, and when none
    /// answers, SERVFAIL.
    #[tokio::test]
    async fn a_wrong_or_missing_tcp_answer_is_not_taken() {
        let liar = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gone = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gone_addr = gone.local_addr().unwrap();
        drop(gone);
        let handler = handler(vec![gone_addr, liar.local_addr().unwrap()]);
        let q = query(12);
        let server = tokio::spawn({
            let q = q.clone();
            async move {
                let (mut stream, _) = liar.accept().await.unwrap();
                let mut length = [0u8; 2];
                stream.read_exact(&mut length).await.unwrap();
                let mut got = vec![0u8; q.len()];
                stream.read_exact(&mut got).await.unwrap();
                let wrong = answer(&q, 13, 1);
                stream
                    .write_all(&(wrong.len() as u16).to_be_bytes())
                    .await
                    .unwrap();
                stream.write_all(&wrong).await.unwrap();
            }
        });
        let failed = handler.answer(&q, Transport::Tcp).await.unwrap();
        assert_eq!(failed[..2], q[..2]);
        assert_eq!(failed[3] & 0x0f, 2, "SERVFAIL");
        server.await.unwrap();
    }

    #[test]
    fn test_extract_container_name() {
        let gossip = Arc::new(OverlayGossip::default());
        let handler = DnsHandler::new(gossip, Ipv4Addr::new(10, 200, 1, 1), Vec::new());

        assert_eq!(handler.extract_container_name("web.velarx"), "web");
        assert_eq!(handler.extract_container_name("web.velarx."), "web");
        assert_eq!(handler.extract_container_name("web"), "web");
    }
}
