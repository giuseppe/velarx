// SPDX-License-Identifier: Apache-2.0
//! The nftables table of the bridge networks.
//!
//! The base chains dispatch through maps, so that a network or a published
//! port is an element added or deleted, never a rule looked up by handle:
//! `net_post`, `net_fwd_in`, `net_fwd_out` map a subnet to the chains of its
//! bridge, `dnat_*` map host ports to container addresses, `published`
//! holds the addresses with published ports (hairpin from 127.0.0.1).  Every
//! setup redeclares the table and refills the base chains: it is one
//! idempotent nf_tables transaction, sent over netlink.

use crate::bridge::{BridgeContainer, NetDef};
use crate::nftnl::{
    concat, ifname, reg, Batch, Elem, ElemData, Expr, Hook, Nft, SetData, SetDef, Tab, Ty,
    CT_STATE, CT_STATUS, FORWARD, INPUT, IP, IP6, META_IIFNAME, META_L4PROTO, META_OIFNAME,
    NETWORK_HEADER, OUTPUT, POSTROUTING, PREROUTING, REG_1, TRANSPORT_HEADER,
};
use std::collections::BTreeMap;
use std::io;
use velarx_wire::addr::Proto;

/// Which table is ours.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Firewall {
    /// The name of the `ip` and `ip6` tables.
    pub table: String,
}

/// The tables of the firewall: `ip` for IPv4, `ip6` for the IPv6 subnets
/// of the dual-stack networks.  Same layout, but what IPv6 does not have:
/// no hairpin from the loopback (no `route_localnet`), no DNS rules (the
/// server answers on the IPv4 gateway).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fam {
    V4,
    V6,
}

impl Fam {
    fn nf(self) -> u8 {
        match self {
            Fam::V4 => IP,
            Fam::V6 => IP6,
        }
    }

    fn ty(self) -> Ty {
        match self {
            Fam::V4 => Ty::Ipv4,
            Fam::V6 => Ty::Ipv6,
        }
    }

    /// The length of an address, and in 32 bit words.
    fn len(self) -> u32 {
        match self {
            Fam::V4 => 4,
            Fam::V6 => 16,
        }
    }

    fn words(self) -> u32 {
        self.len() / 4
    }

    /// The offset of the address in the network header.
    fn offset(self, dst: bool) -> u32 {
        match (self, dst) {
            (Fam::V4, false) => 12,
            (Fam::V4, true) => 16,
            (Fam::V6, false) => 8,
            (Fam::V6, true) => 24,
        }
    }
}

/// The subnet of N in FAM: the address and the length of the prefix.
fn subnet_of(n: &NetDef, f: Fam) -> Option<(Vec<u8>, u8)> {
    match f {
        Fam::V4 => Some((n.subnet.addr.octets().to_vec(), n.subnet.prefix)),
        Fam::V6 => n.subnet6.map(|s| (s.addr.octets().to_vec(), s.prefix)),
    }
}

const TCP: u8 = 6;
const UDP: u8 = 17;
/// `RTN_LOCAL`
const ADDR_LOCAL: u32 = 2;
/// `IPS_DST_NAT`
const STATUS_DNAT: u32 = 0x20;
/// The conntrack states `established` and `related`.
const STATE_EST_REL: u32 = 0x6;

fn l4proto(proto: u8) -> Vec<Expr<'static>> {
    vec![
        Expr::Meta {
            key: META_L4PROTO,
            dreg: REG_1,
        },
        Expr::Cmp {
            reg: REG_1,
            ne: false,
            data: vec![proto],
        },
    ]
}

fn network_load(offset: u32, len: u32, dreg: u32) -> Expr<'static> {
    Expr::Payload {
        base: NETWORK_HEADER,
        offset,
        len,
        dreg,
    }
}

/// The destination port, in the register DREG.
fn dport(dreg: u32) -> Expr<'static> {
    Expr::Payload {
        base: TRANSPORT_HEADER,
        offset: 2,
        len: 2,
        dreg,
    }
}

fn cmp(data: Vec<u8>, ne: bool) -> Expr<'static> {
    Expr::Cmp {
        reg: REG_1,
        ne,
        data,
    }
}

/// `ip daddr NET/LEN` (`!=` when NE), the way nft compares: the bytes that
/// the prefix covers, masked when it ends inside one.
fn in_subnet(f: Fam, dst: bool, net: &[u8], len: u8, ne: bool) -> Vec<Expr<'static>> {
    let offset = f.offset(dst);
    if len.is_multiple_of(8) {
        let n = usize::from(len / 8);
        return vec![
            network_load(offset, n as u32, REG_1),
            cmp(net[..n].to_vec(), ne),
        ];
    }
    let mut mask = vec![0u8; net.len()];
    for (i, m) in mask.iter_mut().enumerate() {
        let bits = usize::from(len).saturating_sub(i * 8).min(8);
        *m = (0xffu16 << (8 - bits)) as u8;
    }
    let masked = net.iter().zip(&mask).map(|(a, m)| a & m).collect();
    vec![
        network_load(offset, f.len(), REG_1),
        Expr::Bitwise { reg: REG_1, mask },
        cmp(masked, ne),
    ]
}

/// `ct status dnat` (`!` when NOT, which is `== 0`).
fn ct_dnat(not: bool) -> Vec<Expr<'static>> {
    ct_flag(CT_STATUS, STATUS_DNAT, not)
}

fn ct_flag(key: u32, mask: u32, zero: bool) -> Vec<Expr<'static>> {
    vec![
        Expr::Ct { key, dreg: REG_1 },
        Expr::Bitwise {
            reg: REG_1,
            mask: mask.to_ne_bytes().to_vec(),
        },
        cmp(vec![0; 4], !zero),
    ]
}

fn iifname(name: &str, ne: bool) -> Vec<Expr<'static>> {
    vec![
        Expr::Meta {
            key: META_IIFNAME,
            dreg: REG_1,
        },
        cmp(ifname(name), ne),
    ]
}

fn rule<'a>(parts: Vec<Vec<Expr<'a>>>) -> Vec<Expr<'a>> {
    parts.into_iter().flatten().collect()
}

impl Firewall {
    fn tab(&self, f: Fam) -> Tab<'_> {
        Tab {
            family: f.nf(),
            name: &self.table,
        }
    }

    /// Whether C has an address in FAM (the IPv6 table is used only then).
    fn uses(c: &BridgeContainer, f: Fam) -> bool {
        f == Fam::V4 || c.attachments.iter().any(|a| a.net.subnet6.is_some())
    }

    /// The table, the sets and the chains, as far as missing.
    fn declare(&self, b: &mut Batch, f: Fam) {
        let t = self.tab(f);
        let a: &[Ty] = &[f.ty()];
        let service: &[Ty] = &[Ty::Service];
        let pair: &[Ty] = &[f.ty(), Ty::Service];
        b.new_table(&t);
        for name in ["net_post", "net_fwd_in", "net_fwd_out"] {
            let def = SetDef {
                key: a,
                data: SetData::Verdict,
                interval: true,
            };
            b.new_set(&t, name, &def);
        }
        let map = |key, data| SetDef {
            key,
            data: SetData::Value(data),
            interval: false,
        };
        b.new_set(&t, "dnat_tcp", &map(service, pair));
        b.new_set(&t, "dnat_udp", &map(service, pair));
        b.new_set(&t, "dnat_ip_tcp", &map(pair, pair));
        b.new_set(&t, "dnat_ip_udp", &map(pair, pair));
        let set = |key| SetDef {
            key,
            data: SetData::None,
            interval: false,
        };
        b.new_set(&t, "published", &set(a));
        b.new_set(&t, "dns_gw", &set(a));
        b.new_set(&t, "dns_ok", &set(&[f.ty(), Ty::Ifname]));
        b.new_chain(&t, "portfw", None);
        let base = |kind, num, priority| Hook {
            kind,
            num,
            priority,
        };
        b.new_chain(&t, "prerouting", Some(&base("nat", PREROUTING, -100)));
        b.new_chain(&t, "output", Some(&base("nat", OUTPUT, -100)));
        b.new_chain(&t, "postrouting", Some(&base("nat", POSTROUTING, 100)));
        b.new_chain(&t, "forward", Some(&base("filter", FORWARD, 0)));
        b.new_chain(&t, "martians", Some(&base("filter", PREROUTING, -90)));
        b.new_chain(&t, "input", Some(&base("filter", INPUT, 0)));
    }

    /// The rules of the base chains.
    fn base_rules(&self, b: &mut Batch, f: Fam) {
        let t = self.tab(f);
        let v4 = f == Fam::V4;
        for chain in [
            "portfw",
            "prerouting",
            "output",
            "postrouting",
            "forward",
            "martians",
            "input",
        ] {
            b.flush_chain(&t, chain);
        }
        let port_reg = reg(f.words());
        for (proto, p) in [(TCP, "tcp"), (UDP, "udp")] {
            b.rule(
                &t,
                "portfw",
                &rule(vec![
                    l4proto(proto),
                    vec![
                        network_load(f.offset(true), f.len(), REG_1),
                        dport(port_reg),
                        Expr::Lookup {
                            set: &format!("dnat_ip_{p}"),
                            sreg: REG_1,
                            dreg: Some(REG_1),
                        },
                        Expr::Dnat {
                            family: f.nf(),
                            addr: REG_1,
                            proto: port_reg,
                        },
                    ],
                ]),
            );
        }
        for (proto, p) in [(TCP, "tcp"), (UDP, "udp")] {
            b.rule(
                &t,
                "portfw",
                &rule(vec![
                    l4proto(proto),
                    vec![
                        dport(REG_1),
                        Expr::Lookup {
                            set: &format!("dnat_{p}"),
                            sreg: REG_1,
                            dreg: Some(REG_1),
                        },
                        Expr::Dnat {
                            family: f.nf(),
                            addr: REG_1,
                            proto: port_reg,
                        },
                    ],
                ]),
            );
        }
        // (::1 cannot be routed to a bridge: the forwarder has it)
        let not_lo: Vec<Expr> = if v4 {
            Vec::new()
        } else {
            vec![
                network_load(f.offset(true), 16, REG_1),
                cmp(std::net::Ipv6Addr::LOCALHOST.octets().to_vec(), true),
            ]
        };
        for chain in ["prerouting", "output"] {
            b.rule(
                &t,
                chain,
                &rule(vec![
                    vec![
                        Expr::FibDaddrType { dreg: REG_1 },
                        cmp(ADDR_LOCAL.to_ne_bytes().to_vec(), false),
                    ],
                    not_lo.clone(),
                    vec![Expr::Jump("portfw")],
                ]),
            );
        }
        let vmap = |set, dst| {
            vec![
                network_load(f.offset(dst), f.len(), REG_1),
                Expr::Lookup {
                    set,
                    sreg: REG_1,
                    dreg: Some(0),
                },
            ]
        };
        if v4 {
            b.rule(
                &t,
                "postrouting",
                &rule(vec![
                    in_subnet(f, false, &[127, 0, 0, 0], 8, false),
                    vec![
                        network_load(f.offset(true), 4, REG_1),
                        Expr::Lookup {
                            set: "published",
                            sreg: REG_1,
                            dreg: None,
                        },
                        Expr::Masquerade,
                    ],
                ]),
            );
        }
        b.rule(&t, "postrouting", &vmap("net_post", false));
        b.rule(&t, "forward", &vmap("net_fwd_in", true));
        b.rule(&t, "forward", &vmap("net_fwd_out", false));
        if !v4 {
            return;
        }
        b.rule(
            &t,
            "martians",
            &rule(vec![
                iifname("lo", true),
                in_subnet(f, true, &[127, 0, 0, 0], 8, false),
                ct_dnat(true),
                vec![Expr::Drop],
            ]),
        );
        // DNS: the server on a gateway answers its own bridge only.
        for proto in [TCP, UDP] {
            let dns = |dst_is: Vec<Expr<'static>>, verdict: Expr<'static>| {
                rule(vec![
                    l4proto(proto),
                    vec![dport(REG_1), cmp(vec![0, 53], false)],
                    dst_is,
                    vec![verdict],
                ])
            };
            b.rule(&t, "input", &dns(iifname("lo", false), Expr::Accept));
            b.rule(
                &t,
                "input",
                &dns(
                    vec![
                        network_load(f.offset(true), 4, REG_1),
                        Expr::Meta {
                            key: META_IIFNAME,
                            dreg: reg(1),
                        },
                        Expr::Lookup {
                            set: "dns_ok",
                            sreg: REG_1,
                            dreg: None,
                        },
                    ],
                    Expr::Accept,
                ),
            );
            b.rule(
                &t,
                "input",
                &dns(
                    vec![
                        network_load(f.offset(true), 4, REG_1),
                        Expr::Lookup {
                            set: "dns_gw",
                            sreg: REG_1,
                            dreg: None,
                        },
                    ],
                    Expr::Drop,
                ),
            );
        }
    }

    /// The names of the chains of a bridge.
    fn chain_names(br: &str) -> [(String, &'static str); 3] {
        [
            (format!("{br}-post"), "net_post"),
            (format!("{br}-in"), "net_fwd_in"),
            (format!("{br}-out"), "net_fwd_out"),
        ]
    }

    /// The chains of the network N and their rules.
    fn network_chains(&self, b: &mut Batch, n: &NetDef, f: Fam) {
        let t = self.tab(f);
        let br = &n.bridge;
        let Some((net, len)) = subnet_of(n, f).filter(|_| n.macvlan.is_none()) else {
            return;
        };
        for (chain, _) in Self::chain_names(br) {
            b.new_chain(&t, &chain, None);
            b.flush_chain(&t, &chain);
        }
        let (post, inn, out) = (
            format!("{br}-post"),
            format!("{br}-in"),
            format!("{br}-out"),
        );
        // A container that reaches a published port of its network through
        // the host gets the reply through the host as well.
        b.rule(
            &t,
            &post,
            &rule(vec![
                ct_dnat(false),
                in_subnet(f, true, &net, len, false),
                vec![Expr::Masquerade],
            ]),
        );
        if !n.internal {
            b.rule(
                &t,
                &post,
                &rule(vec![
                    in_subnet(f, true, &net, len, true),
                    vec![Expr::Masquerade],
                ]),
            );
        }
        b.rule(
            &t,
            &inn,
            &rule(vec![
                ct_flag(CT_STATE, STATE_EST_REL, false),
                vec![Expr::Accept],
            ]),
        );
        if n.internal {
            b.rule(&t, &inn, &rule(vec![iifname(br, true), vec![Expr::Drop]]));
            b.rule(
                &t,
                &out,
                &rule(vec![
                    vec![
                        Expr::Meta {
                            key: META_OIFNAME,
                            dreg: REG_1,
                        },
                        cmp(ifname(br), true),
                    ],
                    vec![Expr::Drop],
                ]),
            );
        } else {
            // Published ports and the containers of the bridge; nothing else
            // reaches the containers (a host of the LAN that routes the
            // subnet to us, another network).
            b.rule(&t, &inn, &rule(vec![ct_dnat(false), vec![Expr::Accept]]));
            b.rule(
                &t,
                &inn,
                &rule(vec![iifname(br, false), vec![Expr::Accept]]),
            );
            b.rule(&t, &inn, &[Expr::Drop]);
            b.rule(&t, &out, &[Expr::Accept]);
        }
        b.add_elements(&t, "dns_gw", &self.dns_elems(n, f).0);
        b.add_elements(&t, "dns_ok", &self.dns_elems(n, f).1);
        for (chain, map) in Self::chain_names(br) {
            b.add_elements(&t, map, &Self::net_elems(n, f, &chain));
        }
    }

    /// The elements of the DNS server on the gateway of N: IPv4 only.
    fn dns_elems(&self, n: &NetDef, f: Fam) -> (Vec<Elem>, Vec<Elem>) {
        if f != Fam::V4 || n.macvlan.is_some() {
            return (Vec::new(), Vec::new());
        }
        let gw = n.gateway.octets();
        (
            vec![Elem::new(gw.to_vec(), ElemData::None)],
            vec![Elem::new(
                concat(&[&gw, &ifname(&n.bridge)]),
                ElemData::None,
            )],
        )
    }

    /// The elements of the interval of the subnet of N, to the chain CHAIN.
    fn net_elems(n: &NetDef, f: Fam, chain: &str) -> Vec<Elem> {
        match subnet_of(n, f).filter(|_| n.macvlan.is_none()) {
            Some((net, len)) => Elem::prefix(&net, len, ElemData::Jump(chain.to_string())),
            None => Vec::new(),
        }
    }

    /// The elements of the published ports of C: to the address of its first
    /// network.  A port published on an address of the other family is not
    /// in this one.  By set.
    fn port_elements(&self, c: &BridgeContainer, f: Fam) -> BTreeMap<String, Vec<Elem>> {
        let mut out: BTreeMap<String, Vec<Elem>> = BTreeMap::new();
        let Some(first) = c.attachments.first().filter(|a| a.net.macvlan.is_none()) else {
            return out;
        };
        if c.ports.is_empty() {
            return out;
        }
        let ip: Vec<u8> = match f {
            Fam::V4 => first.ip.octets().to_vec(),
            Fam::V6 => match first.ip6 {
                Some(ip6) => ip6.octets().to_vec(),
                None => return out,
            },
        };
        for p in &c.ports {
            let host: Option<Vec<u8>> = match (p.host_ip, f) {
                (None, _) => None,
                (Some(std::net::IpAddr::V4(h)), Fam::V4) => Some(h.octets().to_vec()),
                (Some(std::net::IpAddr::V6(h)), Fam::V6) => Some(h.octets().to_vec()),
                _ => continue,
            };
            let proto = match p.proto {
                Proto::Tcp => "tcp",
                Proto::Udp => "udp",
                Proto::Sctp => "sctp",
            };
            for k in 0..u32::from(p.range.max(1)) {
                let hp = (u32::from(p.host_port) + k) as u16;
                let cp = (u32::from(p.container_port) + k) as u16;
                let data = ElemData::Value(concat(&[&ip, &cp.to_be_bytes()]));
                let (set, key) = match &host {
                    None => (format!("dnat_{proto}"), hp.to_be_bytes().to_vec()),
                    Some(h) => (format!("dnat_ip_{proto}"), concat(&[h, &hp.to_be_bytes()])),
                };
                out.entry(set).or_default().push(Elem::new(key, data));
            }
        }
        if f == Fam::V4 {
            out.entry("published".into())
                .or_default()
                .push(Elem::new(ip, ElemData::None));
        }
        out
    }

    /// Set up C: the table, the chains and elements of its networks and its
    /// ports.
    pub fn setup(&self, c: &BridgeContainer) -> io::Result<()> {
        let mut b = Batch::new();
        for f in [Fam::V4, Fam::V6] {
            if !Self::uses(c, f) {
                continue;
            }
            self.declare(&mut b, f);
            self.base_rules(&mut b, f);
            for a in &c.attachments {
                self.network_chains(&mut b, &a.net, f);
            }
            let t = self.tab(f);
            for (set, elems) in self.port_elements(c, f) {
                b.add_elements(&t, &set, &elems);
            }
        }
        Nft::open()?.apply(b)
    }

    /// Delete the ports of C and the chains of its networks whose REMOVE
    /// entry is true.  Of the ports, the elements that are C's go: a host
    /// port that another container published is left (the element there has
    /// that container's address).  A deletion names the key alone, so each
    /// port element is added with C's value before it is deleted, in the
    /// same transaction: one that another container took between the read
    /// and the transaction fails it instead of being deleted.  The
    /// elements of the networks and their chains are destroyed (no error for
    /// what is not there).
    pub fn teardown(&self, c: &BridgeContainer, remove: &[bool]) -> io::Result<()> {
        let mut nft = Nft::open()?;
        let mut b = Batch::new();
        for f in [Fam::V4, Fam::V6] {
            if !Self::uses(c, f) {
                continue;
            }
            let t = self.tab(f);
            self.declare(&mut b, f);
            for (set, elems) in self.port_elements(c, f) {
                let there = nft.elements(&t, &set)?;
                let ours: Vec<Elem> = elems
                    .into_iter()
                    .filter(|e| there.iter().any(|p| p.key == e.key && p.data == e.data))
                    .collect();
                b.add_elements(&t, &set, &ours);
                b.del_elements(&t, &set, &keys(&ours));
            }
            for (a, _) in c.attachments.iter().zip(remove).filter(|(_, r)| **r) {
                let n = &a.net;
                if subnet_of(n, f).is_none() || n.macvlan.is_some() {
                    continue;
                }
                let br = &n.bridge;
                let (gw, ok) = self.dns_elems(n, f);
                for (set, elems) in [("dns_gw", gw), ("dns_ok", ok)] {
                    b.destroy_elements(&t, set, &keys(&elems));
                }
                for (chain, map) in Self::chain_names(br) {
                    let elems = Self::net_elems(n, f, &chain);
                    b.destroy_elements(&t, map, &keys(&elems));
                }
                // (after the elements that jump to them)
                for (chain, _) in Self::chain_names(br) {
                    b.destroy_chain(&t, &chain);
                }
            }
        }
        nft.apply(b)
    }

    /// Delete the tables, if there are any: when no bridge of ours is left,
    /// nothing of ours stays in the ruleset.
    pub fn delete_tables(&self) -> io::Result<()> {
        let mut b = Batch::new();
        for f in [Fam::V4, Fam::V6] {
            b.destroy_table(&self.tab(f));
        }
        Nft::open()?.apply(b)
    }

    /// Remove what bridges that are gone left in the table (a process
    /// killed before its teardown): the subnet elements that jump to their
    /// chains, and the chains.  LIVE tells whether a bridge is in use.
    ///
    /// Engines of the host share the table, and not all of them take the
    /// lock of the root engines (`/run/velarx-networks.lock`: an engine with
    /// a `/run` of its own, in a container), so another one can add or
    /// delete the same elements and chains between the read and the delete
    /// (EBUSY: a chain a new element still jumps to; not found: already
    /// gone, or the table taken down): the pass is read again and retried,
    /// up to PURGE_TRIES times; then its error is returned (a table that is
    /// gone is no error: the pass finds nothing to purge).
    pub fn purge(&self, live: &mut dyn FnMut(&str) -> bool) -> io::Result<()> {
        let mut tries = 0;
        loop {
            // (`Nft::apply` keeps the kind of the error, not its errno)
            let busy = |e: &io::Error| {
                matches!(
                    e.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::ResourceBusy
                        | io::ErrorKind::WouldBlock
                )
            };
            match self.purge_once(live) {
                Err(e) if busy(&e) && tries < PURGE_TRIES => {
                    tries += 1;
                    // The first passes read again at once: the read and
                    // the delete of a pass are microseconds apart, so a
                    // conflict is not likely twice in a row; an engine
                    // that keeps on changing the table is given time.
                    if tries > PURGE_IMMEDIATE {
                        std::thread::sleep(std::time::Duration::from_millis(
                            (tries - PURGE_IMMEDIATE).min(10),
                        ));
                    }
                }
                r => return r,
            }
        }
    }

    /// One pass of `purge`.  LIVE is asked once per bridge: its answer can
    /// change meanwhile (the last port of a bridge goes when the kernel
    /// takes down a namespace, on its own time), and an element kept for a
    /// bridge whose chain is deleted would make the batch fail with EBUSY.
    fn purge_once(&self, live: &mut dyn FnMut(&str) -> bool) -> io::Result<()> {
        let mut seen: std::collections::HashMap<String, bool> = Default::default();
        let mut live = |br: &str| -> bool {
            if let Some(l) = seen.get(br) {
                return *l;
            }
            let l = live(br);
            seen.insert(br.to_string(), l);
            l
        };
        let mut nft = Nft::open()?;
        for f in [Fam::V4, Fam::V6] {
            let t = self.tab(f);
            let chains = nft.chains(&t)?;
            // No table: nothing to purge.
            if chains.is_empty() {
                continue;
            }
            let mut b = Batch::new();
            // The ports of containers that are gone are read before the
            // subnets: a container set up meanwhile has its subnet there.
            let mut ports = Vec::new();
            for set in [
                "dnat_tcp",
                "dnat_udp",
                "dnat_ip_tcp",
                "dnat_ip_udp",
                "published",
            ] {
                ports.push((set, nft.elements(&t, set)?));
            }
            let (dns_gw, dns_ok) = (nft.elements(&t, "dns_gw")?, nft.elements(&t, "dns_ok")?);
            // The elements first: a chain that is referenced cannot be deleted.
            let mut live_nets = Vec::new();
            for (_, map) in Self::chain_names("") {
                let elems = nft.elements(&t, map)?;
                let mut dead = |chain: &str| chain_bridge(chain).is_some_and(|br| !live(br));
                let stale = stale_elements(&elems, &mut dead);
                live_nets.extend(live_ranges(&elems, &mut |c| !dead(c)));
                b.del_elements(&t, map, &stale);
            }
            for (set, elems) in &ports {
                let stale: Vec<Elem> = elems
                    .iter()
                    .filter(|e| {
                        let ip = match &e.data {
                            ElemData::Value(v) => &v[..v.len() - 4],
                            _ => &e.key,
                        };
                        !live_nets
                            .iter()
                            .any(|(a, z)| a.as_slice() <= ip && ip < z.as_slice())
                    })
                    .cloned()
                    .collect();
                b.del_elements(&t, set, &keys(&stale));
            }
            let dead_ok: Vec<Elem> = dns_ok
                .iter()
                .filter(|e| !live(&cstr_name(&e.key[e.key.len() - 16..])))
                .cloned()
                .collect();
            let dead_gw: Vec<Elem> = dns_gw
                .iter()
                .filter(|g| {
                    !dns_ok
                        .iter()
                        .any(|o| o.key[..o.key.len() - 16] == g.key && !dead_ok.contains(o))
                })
                .cloned()
                .collect();
            b.del_elements(&t, "dns_ok", &keys(&dead_ok));
            b.del_elements(&t, "dns_gw", &keys(&dead_gw));
            for (name, base) in &chains {
                match chain_bridge(name) {
                    Some(br) if !base && velarx_wire::addr::valid_ifname(br) && !live(br) => {
                        b.flush_chain(&t, name);
                        b.del_chain(&t, name);
                    }
                    _ => {}
                }
            }
            nft.apply(b)?;
        }
        Ok(())
    }
}

/// How many times `Firewall::purge` reads again a table that another
/// engine changed under it; the first PURGE_IMMEDIATE passes do not wait,
/// the next ones 1 ms more each, 10 ms at most (about 200 ms in all).
const PURGE_TRIES: u64 = 40;
const PURGE_IMMEDIATE: u64 = 16;

/// ELEMS without their data: what a deletion names.
fn keys(elems: &[Elem]) -> Vec<Elem> {
    elems
        .iter()
        .map(|e| Elem {
            key: e.key.clone(),
            data: ElemData::None,
            end: e.end,
        })
        .collect()
}

/// The intervals of ELEMS (as a set of intervals lists them) that jump to a
/// chain for which STALE answers true: their start and end elements.
fn stale_elements(elems: &[Elem], stale: &mut dyn FnMut(&str) -> bool) -> Vec<Elem> {
    let mut out = Vec::new();
    for e in elems.iter().filter(|e| !e.end) {
        let ElemData::Jump(chain) = &e.data else {
            continue;
        };
        if !stale(chain) {
            continue;
        }
        out.push(e.clone());
        // The end of the interval: the first end element after the start.
        let end = elems
            .iter()
            .filter(|o| o.end && o.key > e.key)
            .min_by(|a, b| a.key.cmp(&b.key));
        if let Some(end) = end {
            out.push(end.clone());
        }
    }
    keys(&out)
}

/// The intervals of ELEMS that jump to a chain for which LIVE answers true:
/// start and end (exclusive) of each.
fn live_ranges(elems: &[Elem], live: &mut dyn FnMut(&str) -> bool) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for e in elems.iter().filter(|e| !e.end) {
        let ElemData::Jump(chain) = &e.data else {
            continue;
        };
        if !live(chain) {
            continue;
        }
        let end = elems
            .iter()
            .filter(|o| o.end && o.key > e.key)
            .map(|o| o.key.clone())
            .min()
            .unwrap_or_else(|| vec![0xff; e.key.len()]);
        out.push((e.key.clone(), end));
    }
    out
}

/// The name in an interface name register (padded with zeros).
fn cstr_name(b: &[u8]) -> String {
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// The bridge of the chain `BRIDGE-post`, `BRIDGE-in` or `BRIDGE-out`.
fn chain_bridge(name: &str) -> Option<&str> {
    ["-post", "-in", "-out"]
        .iter()
        .find_map(|s| name.strip_suffix(s))
        .filter(|b| !b.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::Attachment;
    use velarx_wire::addr::{PortSpec, Subnet};

    fn fw() -> Firewall {
        Firewall {
            table: "shtest".into(),
        }
    }

    fn container(internal: bool) -> BridgeContainer {
        BridgeContainer {
            id: "c0ffee".into(),
            name: "web".into(),
            attachments: vec![Attachment {
                net: NetDef {
                    id: "n1".into(),
                    name: "n".into(),
                    bridge: "shbr7".into(),
                    subnet: Subnet::parse("10.88.7.0/24").unwrap(),
                    gateway: "10.88.7.1".parse().unwrap(),
                    internal,
                    dns: true,
                    mtu: 0,
                    dns_servers: vec![],
                    subnet6: None,
                    gateway6: None,
                    macvlan: None,
                    routes: vec![],
                },
                ifname: "eth0".into(),
                ip: "10.88.7.5".parse().unwrap(),
                mac: None,
                aliases: vec!["www".into()],
                ip6: None,
            }],
            ports: vec![
                PortSpec::parse("8080-8081:80-81").unwrap(),
                PortSpec::parse("127.0.0.1:53:53/udp").unwrap(),
            ],
        }
    }

    fn dual_stack(internal: bool) -> BridgeContainer {
        let mut c = container(internal);
        let a = &mut c.attachments[0];
        a.net.subnet6 = velarx_wire::addr::Subnet6::parse("fd00:7::/64");
        a.net.gateway6 = Some("fd00:7::1".parse().unwrap());
        a.ip6 = Some("fd00:7::5".parse().unwrap());
        c.ports.push(PortSpec::parse("[::1]:9090:90").unwrap());
        c
    }

    /// Run the test NAME in a user and network namespace of its own, where
    /// the process is root of the ruleset it changes; true when the caller
    /// is that run and goes on.  Skipped where there is no such namespace
    /// or no nf_tables.
    fn in_netns(name: &str) -> bool {
        if std::env::var_os("VELARX_NFT_TEST_NS").is_some() {
            if Nft::open()
                .and_then(|mut n| {
                    let mut b = Batch::new();
                    b.new_table(&Tab {
                        family: IP,
                        name: "probe",
                    });
                    n.apply(b)
                })
                .is_err()
            {
                eprintln!("skipped: no nf_tables here");
                return false;
            }
            return true;
        }
        let unshare = |args: &[&str]| std::process::Command::new("unshare").args(args).output();
        if !unshare(&["-rn", "true"]).is_ok_and(|o| o.status.success()) {
            eprintln!("skipped: no user and network namespaces");
            return false;
        }
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new("unshare")
            .args(["-rn"])
            .arg(exe)
            .args(["--exact", &format!("firewall::tests::{name}")])
            .env("VELARX_NFT_TEST_NS", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        false
    }

    fn tab(f: Fam) -> Tab<'static> {
        Tab {
            family: f.nf(),
            name: "shtest",
        }
    }

    fn chain_names(f: Fam) -> Vec<String> {
        let mut v: Vec<String> = Nft::open()
            .unwrap()
            .chains(&tab(f))
            .unwrap()
            .into_iter()
            .map(|c| c.0)
            .collect();
        v.sort();
        v
    }

    fn elements(f: Fam, set: &str) -> Vec<Elem> {
        Nft::open().unwrap().elements(&tab(f), set).unwrap()
    }

    #[test]
    fn a_container_comes_and_goes() {
        if !in_netns("a_container_comes_and_goes") {
            return;
        }
        let c = container(false);
        fw().setup(&c).unwrap();
        // Again: the same state, no error.
        fw().setup(&c).unwrap();
        let names = chain_names(Fam::V4);
        for n in [
            "portfw",
            "prerouting",
            "input",
            "shbr7-post",
            "shbr7-in",
            "shbr7-out",
        ] {
            assert!(names.contains(&n.to_string()), "{n} in {names:?}");
        }
        assert!(chain_names(Fam::V6).is_empty());
        let jump = |c: &str| ElemData::Jump(c.into());
        assert_eq!(elements(Fam::V4, "net_in_not_there"), Vec::<Elem>::new());
        let post = elements(Fam::V4, "net_post");
        assert_eq!(post.len(), 2);
        assert!(post.contains(&Elem::new(vec![10, 88, 7, 0], jump("shbr7-post"))));
        assert!(post.iter().any(|e| e.end && e.key == [10, 88, 8, 0]));
        assert_eq!(elements(Fam::V4, "dnat_tcp").len(), 2);
        assert_eq!(elements(Fam::V4, "dnat_udp").len(), 0);
        let ip_udp = elements(Fam::V4, "dnat_ip_udp");
        assert_eq!(
            ip_udp,
            vec![Elem::new(
                vec![127, 0, 0, 1, 0, 53, 0, 0],
                ElemData::Value(vec![10, 88, 7, 5, 0, 53, 0, 0])
            )]
        );
        assert_eq!(elements(Fam::V4, "published").len(), 1);
        let ok = elements(Fam::V4, "dns_ok");
        assert_eq!(ok[0].key[..4], [10, 88, 7, 1]);
        assert_eq!(&ok[0].key[4..9], b"shbr7");
        // The ports go, the network stays.
        fw().teardown(&c, &[false]).unwrap();
        assert_eq!(elements(Fam::V4, "dnat_tcp").len(), 0);
        assert_eq!(elements(Fam::V4, "published").len(), 0);
        assert_eq!(elements(Fam::V4, "net_post").len(), 2);
        // The network goes, and going twice is no error.
        for _ in 0..2 {
            fw().teardown(&c, &[true]).unwrap();
        }
        assert_eq!(elements(Fam::V4, "net_post").len(), 0);
        assert_eq!(elements(Fam::V4, "dns_gw").len(), 0);
        assert!(!chain_names(Fam::V4).contains(&"shbr7-in".to_string()));
        assert!(chain_names(Fam::V4).contains(&"portfw".to_string()));
        fw().delete_tables().unwrap();
        fw().delete_tables().unwrap();
        assert!(chain_names(Fam::V4).is_empty());
    }

    #[test]
    fn dual_stack_and_internal_networks() {
        if !in_netns("dual_stack_and_internal_networks") {
            return;
        }
        for internal in [false, true] {
            let c = dual_stack(internal);
            fw().setup(&c).unwrap();
            let post = elements(Fam::V6, "net_post");
            let mut start = vec![0xfd, 0, 0, 7];
            start.resize(16, 0);
            let mut end = vec![0xfd, 0, 0, 7, 0, 0, 0, 1];
            end.resize(16, 0);
            assert!(post.iter().any(|e| !e.end && e.key == start));
            assert!(post.iter().any(|e| e.end && e.key == end));
            // The loopback port is IPv6 only here, the others IPv4 only.
            assert_eq!(elements(Fam::V6, "dnat_ip_tcp").len(), 1);
            assert_eq!(elements(Fam::V4, "dnat_ip_tcp").len(), 0);
            assert_eq!(elements(Fam::V6, "dnat_tcp").len(), 2);
            assert_eq!(elements(Fam::V6, "published").len(), 0);
            fw().teardown(&c, &[true]).unwrap();
            assert_eq!(elements(Fam::V6, "net_post").len(), 0);
            fw().delete_tables().unwrap();
        }
    }

    #[test]
    fn a_port_of_another_container_is_kept() {
        if !in_netns("a_port_of_another_container_is_kept") {
            return;
        }
        let a = container(false);
        fw().setup(&a).unwrap();
        let mut b = container(false);
        b.attachments[0].ip = "10.88.7.6".parse().unwrap();
        // The same host ports, other address: the transaction fails whole.
        assert!(fw().setup(&b).is_err());
        assert_eq!(elements(Fam::V4, "dnat_tcp").len(), 2);
        // The teardown of b removes what is b's (nothing), and a keeps its
        // ports.
        fw().teardown(&b, &[false]).unwrap();
        assert_eq!(elements(Fam::V4, "dnat_tcp").len(), 2);
    }

    /// A host port that a container lost (its rule was flushed) and another
    /// took must not stop the teardown from removing the other ports of the
    /// first: only the elements that are its own go.
    #[test]
    fn a_teardown_removes_its_ports_when_another_container_took_one() {
        if !in_netns("a_teardown_removes_its_ports_when_another_container_took_one") {
            return;
        }
        let a = container(false);
        fw().setup(&a).unwrap();
        let t = tab(Fam::V4);
        let first = elements(Fam::V4, "dnat_tcp")
            .into_iter()
            .find(|e| e.key == 8080u16.to_be_bytes())
            .unwrap();
        let mut b = Batch::new();
        b.del_elements(&t, "dnat_tcp", &keys(&[first]));
        Nft::open().unwrap().apply(b).unwrap();
        let mut other = container(false);
        other.attachments[0].ip = "10.88.7.6".parse().unwrap();
        other.ports = vec![PortSpec::parse("8080:80").unwrap()];
        fw().setup(&other).unwrap();
        fw().teardown(&a, &[false]).unwrap();
        let left = elements(Fam::V4, "dnat_tcp");
        assert_eq!(left.len(), 1, "{left:?}");
        assert_eq!(left[0].key, 8080u16.to_be_bytes());
        assert_eq!(
            left[0].data,
            ElemData::Value(concat(&[&[10, 88, 7, 6], &80u16.to_be_bytes()]))
        );
        assert_eq!(elements(Fam::V4, "dnat_ip_udp").len(), 0);
        assert_eq!(elements(Fam::V4, "published").len(), 1);
    }

    /// The elements of containers whose bridge is gone are purged, those of
    /// the bridges that are in use are not.
    #[test]
    fn the_ports_of_a_gone_container_are_purged() {
        if !in_netns("the_ports_of_a_gone_container_are_purged") {
            return;
        }
        let mut other = container(false);
        other.id = "other".into();
        let a = &mut other.attachments[0];
        a.net.bridge = "shbr8".into();
        a.net.subnet = Subnet::parse("10.88.8.0/24").unwrap();
        a.net.gateway = "10.88.8.1".parse().unwrap();
        a.ip = "10.88.8.5".parse().unwrap();
        other.ports = vec![PortSpec::parse("9000:90").unwrap()];
        fw().setup(&container(false)).unwrap();
        fw().setup(&other).unwrap();
        assert_eq!(elements(Fam::V4, "published").len(), 2);
        fw().purge(&mut |b| b == "shbr8").unwrap();
        // only what is on the bridge in use stays
        let left = elements(Fam::V4, "dnat_tcp");
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].key, 9000u16.to_be_bytes());
        assert_eq!(elements(Fam::V4, "dnat_ip_udp").len(), 0);
        let published = elements(Fam::V4, "published");
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].key, [10, 88, 8, 5]);
        let ok = elements(Fam::V4, "dns_ok");
        assert_eq!(ok.len(), 1);
        assert_eq!(elements(Fam::V4, "dns_gw").len(), 1);
    }

    /// A range of ports bigger than one netlink message is set up and taken
    /// down, in more than one transaction.
    #[test]
    fn a_long_range_of_ports_is_set_up_and_taken_down() {
        if !in_netns("a_long_range_of_ports_is_set_up_and_taken_down") {
            return;
        }
        let mut c = container(false);
        c.ports = vec![PortSpec::parse("20000-25000:20000-25000/udp").unwrap()];
        fw().setup(&c).unwrap();
        assert_eq!(elements(Fam::V4, "dnat_udp").len(), 5001);
        fw().teardown(&c, &[true]).unwrap();
        assert_eq!(elements(Fam::V4, "dnat_udp").len(), 0);
    }

    /// The kernel that refuses the batch itself (no privilege over the
    /// ruleset) answers once: it is an error, not a wait.
    #[test]
    fn a_batch_the_kernel_refuses_is_an_error() {
        if rustix::process::geteuid().is_root() || std::env::var_os("VELARX_NFT_TEST_NS").is_some()
        {
            return;
        }
        let r = velarx_base::testing::returns_within(std::time::Duration::from_secs(10), || {
            let mut b = Batch::new();
            b.new_table(&tab(Fam::V4));
            Nft::open().and_then(|mut n| n.apply(b)).is_err()
        });
        assert!(r);
    }

    #[test]
    fn stale_rules_are_purged() {
        if !in_netns("stale_rules_are_purged") {
            return;
        }
        let c = container(false);
        fw().setup(&c).unwrap();
        // The bridge is in use: nothing goes.
        fw().purge(&mut |b| b == "shbr7").unwrap();
        assert_eq!(elements(Fam::V4, "net_post").len(), 2);
        assert!(chain_names(Fam::V4).contains(&"shbr7-in".to_string()));
        // The bridge is gone: its elements and chains go, not the others.
        fw().purge(&mut |_| false).unwrap();
        // (and the ports and the DNS of its containers)
        for set in ["dnat_tcp", "dnat_ip_udp", "published", "dns_gw", "dns_ok"] {
            assert_eq!(elements(Fam::V4, set).len(), 0, "{set}");
        }
        for map in ["net_post", "net_fwd_in", "net_fwd_out"] {
            assert_eq!(elements(Fam::V4, map).len(), 0, "{map}");
        }
        let names = chain_names(Fam::V4);
        assert!(!names.iter().any(|n| n.starts_with("shbr7")), "{names:?}");
        assert!(names.contains(&"forward".to_string()));
        // No table: nothing to do.
        fw().delete_tables().unwrap();
        fw().delete_tables().unwrap();
        fw().purge(&mut |_| false).unwrap();
    }

    /// Engines of the host purge the same table: a pass that meets another
    /// engine's changes is tried again, it does not fail.
    #[test]
    fn engines_that_purge_the_same_table_do_not_fail() {
        if !in_netns("engines_that_purge_the_same_table_do_not_fail") {
            return;
        }
        let c = container(false);
        fw().setup(&c).unwrap();
        let stop = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|s| {
            // an engine that sets rules up and takes them down
            s.spawn(|| {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = fw().setup(&c);
                    let _ = fw().teardown(&c, &[true]);
                }
            });
            let purgers: Vec<_> = (0..3)
                .map(|_| {
                    s.spawn(|| {
                        for _ in 0..60 {
                            fw().purge(&mut |_| false)?;
                        }
                        io::Result::Ok(())
                    })
                })
                .collect();
            // (the engine stops before a failure is reported: the scope
            // waits for it)
            let results: Vec<_> = purgers.into_iter().map(|p| p.join()).collect();
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            for r in results {
                r.unwrap().unwrap();
            }
        });
    }

    /// A bridge whose answer changes during a pass (its last port goes)
    /// is asked once: its elements and its chains go together or stay
    /// together, never a kept element that jumps to a deleted chain (EBUSY).
    #[test]
    fn a_pass_asks_once_per_bridge() {
        if !in_netns("a_pass_asks_once_per_bridge") {
            return;
        }
        let c = container(false);
        fw().setup(&c).unwrap();
        let mut answer = false;
        fw().purge_once(&mut |_| {
            answer = !answer;
            answer
        })
        .unwrap();
        assert!(chain_names(Fam::V4).contains(&"shbr7-post".to_string()));
        assert!(!elements(Fam::V4, "net_post").is_empty());
    }

    /// What nft makes of the rules we send.
    #[test]
    fn nft_reads_the_rules() {
        let Some(nft) = velarx_base::testing::find_nft() else {
            return;
        };
        if std::env::var_os("VELARX_NFT_TEST_NS").is_none() && !in_netns("nft_reads_the_rules") {
            return;
        }
        fw().setup(&container(false)).unwrap();
        let out = std::process::Command::new(nft)
            .args(["list", "table", "ip", "shtest"])
            .output()
            .unwrap();
        let s = String::from_utf8_lossy(&out.stdout);
        for line in [
            "elements = { 10.88.7.0/24 : jump shbr7-post }",
            "type ipv4_addr . ifname",
            "elements = { 10.88.7.1 . \"shbr7\" }",
            "dnat ip to ip daddr . tcp dport map @dnat_ip_tcp",
            "dnat ip to tcp dport map @dnat_tcp",
            "type nat hook postrouting priority srcnat; policy accept;",
            "fib daddr type local jump portfw",
            "ip saddr 127.0.0.0/8 ip daddr @published masquerade",
            "ip saddr vmap @net_post",
            "iifname != \"lo\" ip daddr 127.0.0.0/8 ct status ! dnat drop",
            "tcp dport 53 ip daddr . iifname @dns_ok accept",
            "ct status dnat ip daddr 10.88.7.0/24 masquerade",
            "ip daddr != 10.88.7.0/24 masquerade",
            "ct state established,related accept",
            "iifname \"shbr7\" accept",
        ] {
            assert!(s.contains(line), "{line}\n{s}");
        }
        assert!(s.contains("8080 : 10.88.7.5 . 80"), "{s}");
    }

    #[test]
    fn subnet_matches() {
        let load = |e: &Expr| match e {
            Expr::Payload { offset, len, .. } => (*offset, *len),
            e => panic!("{e:?}"),
        };
        // Whole bytes: only those are compared.
        let v = in_subnet(Fam::V4, true, &[10, 88, 7, 0], 24, false);
        assert_eq!(v.len(), 2);
        assert_eq!(load(&v[0]), (16, 3));
        assert!(matches!(&v[1], Expr::Cmp { ne: false, data, .. } if data == &[10, 88, 7]));
        // A prefix that ends inside a byte is masked.
        let v = in_subnet(Fam::V4, false, &[10, 88, 16, 0], 20, true);
        assert_eq!(load(&v[0]), (12, 4));
        assert!(matches!(&v[1], Expr::Bitwise { mask, .. } if mask == &[255, 255, 240, 0]));
        assert!(matches!(&v[2], Expr::Cmp { ne: true, data, .. } if data == &[10, 88, 16, 0]));
        let v6 = in_subnet(
            Fam::V6,
            true,
            &[0xfd, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            64,
            false,
        );
        assert_eq!(load(&v6[0]), (24, 8));
    }

    #[test]
    fn stale_elements_of_intervals() {
        let j = |c: &str| ElemData::Jump(c.into());
        let end = |k: u8| Elem {
            key: vec![10, k, 0, 0],
            data: ElemData::None,
            end: true,
        };
        let elems = vec![
            Elem::new(vec![10, 1, 0, 0], j("stale1-post")),
            end(2),
            Elem::new(vec![10, 5, 0, 0], j("live0-post")),
            end(6),
            Elem::new(vec![10, 7, 0, 0], j("not-a-bridge-chain")),
            end(8),
            Elem::new(vec![10, 9, 0, 0], j("stale1-in")),
            end(10),
        ];
        let stale = stale_elements(&elems, &mut |c| {
            chain_bridge(c).is_some_and(|b| b != "live0")
        });
        let keys: Vec<(u8, bool)> = stale.iter().map(|e| (e.key[1], e.end)).collect();
        assert_eq!(keys, vec![(1, false), (2, true), (9, false), (10, true)]);
        assert!(stale.iter().all(|e| e.data == ElemData::None));
    }
}
