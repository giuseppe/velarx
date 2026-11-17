// SPDX-License-Identifier: Apache-2.0
pub mod dial;
pub mod dnsd;
pub mod engine;
pub mod pasta;
mod pool;
pub mod portfwd;
pub mod provider;
pub mod rootless_netns;
pub mod spec_netns;

pub use engine::ConnectRequest;
use engine::ContainerNetworks;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tracing::{info, warn};
use velarx_config::NetworkConfig;
use velarx_db::{Database, NetworkRecord};
use velarx_netdetach::def::NetworkDef;
use velarx_netkernel::error::{NetworkError, NetworkResult};
use velarx_wire::addr::{self, Subnet, Subnet6};

/// The driver of a stored network: records are written from
/// `NetworkDriver::as_str`, so another name is a corrupt record.
fn stored_driver(name: &str) -> NetworkResult<NetworkDriver> {
    name.parse().map_err(|_| {
        NetworkError::InvalidConfig(format!(
            "the stored network has the unknown driver `{name}`"
        ))
    })
}

/// Whether the engine attaches the containers of a network of `driver`
/// (`connect` and `disconnect` go to it); the others attach nothing.
fn attached_by_engine(driver: NetworkDriver) -> bool {
    match driver {
        NetworkDriver::Bridge | NetworkDriver::Macvlan => true,
        NetworkDriver::Overlay | NetworkDriver::Host | NetworkDriver::None => false,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum NetworkDriver {
    Bridge,
    Host,
    None,
    /// An overlay network, made by a network provider.
    Overlay,
    /// The containers on the LAN of a parent interface (rootful).
    Macvlan,
}

impl std::str::FromStr for NetworkDriver {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, NetworkError> {
        match s {
            "bridge" => Ok(NetworkDriver::Bridge),
            "host" => Ok(NetworkDriver::Host),
            "none" => Ok(NetworkDriver::None),
            "overlay" => Ok(NetworkDriver::Overlay),
            "macvlan" => Ok(NetworkDriver::Macvlan),
            other => Err(NetworkError::InvalidConfig(format!(
                "unknown network driver `{other}`"
            ))),
        }
    }
}

impl NetworkDriver {
    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkDriver::Bridge => "bridge",
            NetworkDriver::Host => "host",
            NetworkDriver::None => "none",
            NetworkDriver::Overlay => "overlay",
            NetworkDriver::Macvlan => "macvlan",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreateNetworkRequest {
    pub name: String,
    pub driver: NetworkDriver,
    pub subnet: Option<String>,
    pub gateway: Option<String>,
    /// The IPv6 subnet of a dual-stack network (also with the `ipv6`
    /// option alone: one is picked).
    pub subnet6: Option<String>,
    pub gateway6: Option<String>,
    pub options: HashMap<String, String>,
    /// Static routes of the containers (bridge and macvlan networks).
    pub routes: Vec<addr::Route>,
}

pub use velarx_wire::addr::split_subnets;

/// Names the networks cannot have.
const RESERVED_NAMES: &[&str] = &[
    "none",
    "host",
    "pasta",
    "slirp4netns",
    "bridge",
    "default",
    "podman",
];

/// The options of `network create`: what the CLI and the API store.
const KNOWN_OPTIONS: &[&str] = &[
    "interface_name",
    "internal",
    "disable_dns",
    "dns",
    "ip_range",
    "mtu",
    "ipam_driver",
    "ipv6",
    "isolate",
];

/// At most this many DNS servers per network.
const MAX_DNS_SERVERS: usize = 3;

fn valid_network_name(name: &str) -> bool {
    name.len() <= 64
        && name
            .bytes()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

/// The gateway of a new network on `subnet` (`gateway` or its first host),
/// which no network of `defs` overlaps.
fn free_subnet_gateway(
    defs: &[NetworkDef],
    subnet: &Subnet,
    gateway: Option<&str>,
) -> NetworkResult<Ipv4Addr> {
    if let Some(o) = defs.iter().find(|d| d.subnet.overlaps(subnet)) {
        return Err(NetworkError::AlreadyExists(format!(
            "the subnet `{subnet}` overlaps with the network `{}`",
            o.name
        )));
    }
    match gateway.filter(|g| !g.is_empty()) {
        Some(g) => g
            .parse::<Ipv4Addr>()
            .ok()
            .filter(|g| subnet.is_host(*g))
            .ok_or_else(|| bad(format!("invalid gateway `{g}` for the subnet `{subnet}`"))),
        None => Ok(subnet.first_host()),
    }
}

/// The bridge and macvlan networks among ROWS and BUILTIN; a record that
/// cannot be read is an error, not a network that is not there.
fn network_defs(rows: &[NetworkRecord], builtin: NetworkDef) -> NetworkResult<Vec<NetworkDef>> {
    let mut defs = Vec::new();
    for r in rows {
        defs.extend(NetworkDef::from_record(r)?);
    }
    defs.push(builtin);
    Ok(defs)
}

/// Why the network `new` cannot be inserted among `rows`, the networks
/// there are (and the default one): its subnet overlaps another, or its
/// interface is another's.  Checked where the record is inserted.
fn no_network_in_the_way(
    new: &NetworkRecord,
    rows: &[NetworkRecord],
    builtin: NetworkDef,
) -> Result<(), String> {
    let Some(def) = NetworkDef::from_record(new).map_err(|e| e.to_string())? else {
        return Ok(());
    };
    let mut others = Vec::new();
    for r in rows {
        others.extend(NetworkDef::from_record(r).map_err(|e| e.to_string())?);
    }
    others.push(builtin);
    for o in others {
        if o.subnet.overlaps(&def.subnet) {
            return Err(format!(
                "the subnet `{}` overlaps with the network `{}`",
                def.subnet, o.name
            ));
        }
        if def.macvlan.is_none() && o.bridge == def.bridge {
            return Err(format!(
                "the interface `{}` is used by the network `{}`",
                def.bridge, o.name
            ));
        }
        if let (Some(a), Some(b)) = (o.subnet6, def.subnet6) {
            if a.overlaps(&b) {
                return Err(format!(
                    "the subnet `{b}` overlaps with the network `{}`",
                    o.name
                ));
            }
        }
    }
    Ok(())
}

fn bad(msg: impl Into<String>) -> NetworkError {
    NetworkError::InvalidConfig(msg.into())
}

/// Check and normalize the options of a bridge network: the DNS servers
/// and the range are rewritten in their canonical form.
fn check_bridge_options(
    options: &mut HashMap<String, String>,
    subnet: &Subnet,
) -> NetworkResult<()> {
    for (k, v) in options.iter() {
        if k.starts_with("label.") {
            continue;
        }
        if !KNOWN_OPTIONS.contains(&k.as_str()) {
            return Err(bad(format!("unsupported network option `{k}`")));
        }
        match k.as_str() {
            "ipv6" if v != "true" && v != "false" => {
                return Err(bad(format!("invalid value `{v}` of the option `ipv6`")))
            }
            "isolate" if !matches!(v.as_str(), "true" | "false" | "strict") => {
                return Err(bad(format!(
                    "invalid value `{v}` of the option `isolate`: true, false or strict"
                )))
            }
            // (the bridges never forward to each other: what `true` and
            // `strict` ask for is the rule; `false` cannot be had)
            "isolate" if v == "false" => {
                return Err(bad(
                    "the option `isolate=false` is not supported: the bridge networks of velarx \
                     never forward traffic to each other"
                        .to_string(),
                ))
            }
            "ipam_driver" if v != "host-local" => {
                return Err(bad(format!("the IPAM driver `{v}` is not supported")))
            }
            "mtu" if !v.parse::<u32>().is_ok_and(|m| (68..=65535).contains(&m)) => {
                return Err(bad(format!("invalid MTU `{v}`")))
            }
            "interface_name" if !addr::valid_ifname(v) => {
                return Err(bad(format!("invalid interface name `{v}`")))
            }
            _ => {}
        }
    }
    if let Some(v) = options.get("dns") {
        let servers = check_dns_servers(v)?;
        options.insert("dns".to_string(), servers);
    }
    normalize_range(options, subnet)
}

/// The DNS servers of the option `dns` (at most MAX_DNS_SERVERS addresses),
/// in their canonical form.
fn check_dns_servers(v: &str) -> NetworkResult<String> {
    let servers: Vec<&str> = v
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if servers.len() > MAX_DNS_SERVERS {
        return Err(bad(format!(
            "at most {MAX_DNS_SERVERS} DNS servers per network"
        )));
    }
    if let Some(s) = servers
        .iter()
        .find(|s| s.parse::<std::net::IpAddr>().is_err())
    {
        return Err(bad(format!("invalid DNS server `{s}`")));
    }
    Ok(servers.join(","))
}

/// The lease range (`ip_range`) of the subnet, as `FIRST-LAST`.
fn normalize_range(options: &mut HashMap<String, String>, subnet: &Subnet) -> NetworkResult<()> {
    if let Some(v) = options.get("ip_range") {
        let (first, last) = addr::parse_ip_range(v)
            .filter(|(a, b)| subnet.contains(*a) && subnet.contains(*b))
            .ok_or_else(|| bad(format!("invalid IP range `{v}` for the subnet `{subnet}`")))?;
        options.insert("ip_range".to_string(), format!("{first}-{last}"));
    }
    Ok(())
}

/// Check and normalize the options of a macvlan network: its parent and
/// mode, the MTU, the range, labels.
fn check_macvlan_options(
    options: &mut HashMap<String, String>,
    subnet: &Subnet,
) -> NetworkResult<()> {
    for (k, v) in options.iter() {
        if k.starts_with("label.") {
            continue;
        }
        match k.as_str() {
            "parent" if !addr::valid_ifname(v) => {
                return Err(bad(format!("invalid parent interface `{v}`")))
            }
            "mode" if velarx_netkernel::bridge::macvlan_mode(v).is_err() => {
                return Err(bad(format!("invalid macvlan mode `{v}`")))
            }
            "mtu" if !v.parse::<u32>().is_ok_and(|m| (68..=65535).contains(&m)) => {
                return Err(bad(format!("invalid MTU `{v}`")))
            }
            "ipam_driver" if v != "host-local" => {
                return Err(bad(format!("the IPAM driver `{v}` is not supported")))
            }
            "parent" | "mode" | "mtu" | "ipam_driver" | "ip_range" => {}
            k => return Err(bad(format!("unsupported macvlan network option `{k}`"))),
        }
    }
    normalize_range(options, subnet)
}

/// Keep the static routes of REQ in the options of the network.
fn store_routes(req: &mut CreateNetworkRequest) {
    if !req.routes.is_empty() {
        let routes: Vec<String> = req.routes.iter().map(ToString::to_string).collect();
        req.options.insert("routes".into(), routes.join(";"));
    }
}

/// The options that only mean something for a bridge network.
const BRIDGE_ONLY_OPTIONS: &[&str] = &[
    "internal",
    "disable_dns",
    "dns",
    "ip_range",
    "ipv6",
    "mtu",
    "interface_name",
];

/// The options of a host or none network: the bridge ones are refused,
/// rather than kept and ignored.
fn check_other_options(options: &HashMap<String, String>) -> NetworkResult<()> {
    for k in options.keys() {
        if BRIDGE_ONLY_OPTIONS.contains(&k.as_str()) {
            return Err(bad(format!(
                "the network option `{}` needs the bridge driver",
                k.replace('_', "-")
            )));
        }
    }
    match options.get("ipam_driver").map(String::as_str) {
        None | Some("host-local") => Ok(()),
        Some(d) => Err(bad(format!("the IPAM driver `{d}` is not supported"))),
    }
}

/// A subnet of POOLS that overlaps no subnet of USED, in order; without
/// pools a /24 of 10.90.0.0/16 (podman takes 10.88.0.0/16 and
/// 10.89.0.0/16).
fn free_subnet(used: &[Subnet], pools: &[velarx_config::SubnetPool]) -> Option<Subnet> {
    let default = [velarx_config::SubnetPool {
        base: "10.90.0.0/16".into(),
        size: 24,
    }];
    let pools = if pools.is_empty() {
        &default[..]
    } else {
        pools
    };
    pools.iter().find_map(|p| {
        let base = Subnet::parse_with(&p.base, 1)?;
        if p.size < base.prefix || p.size > 30 {
            return None;
        }
        let step = 1u64 << (32 - u32::from(p.size));
        let count = 1u64 << (u32::from(p.size) - u32::from(base.prefix));
        (0..count.min(1 << 16)).find_map(|i| {
            let addr = u64::from(base.network()) + i * step;
            let s = Subnet::parse(&format!("{}/{}", Ipv4Addr::from(addr as u32), p.size))?;
            used.iter().all(|u| !u.overlaps(&s)).then_some(s)
        })
    })
}

pub struct NetworkService {
    db: Database,
    config: NetworkConfig,
    engine: Arc<ContainerNetworks>,
}

impl NetworkService {
    pub fn new(db: Database, config: NetworkConfig, engine: Arc<ContainerNetworks>) -> Self {
        Self { db, config, engine }
    }

    pub fn engine(&self) -> &Arc<ContainerNetworks> {
        &self.engine
    }

    pub async fn create(&self, req: CreateNetworkRequest) -> NetworkResult<String> {
        if !valid_network_name(&req.name) {
            return Err(bad(format!("invalid network name `{}`", req.name)));
        }
        let builtin = NetworkDef::builtin(&self.config.bridge)?;
        if RESERVED_NAMES.contains(&req.name.as_str()) || req.name == builtin.name {
            return Err(bad(format!("the network name `{}` is reserved", req.name)));
        }
        let id = {
            let mut b = [0u8; 32];
            rustix::rand::getrandom(&mut b, rustix::rand::GetRandomFlags::empty())
                .map_err(|e| NetworkError::Io(e.into()))?;
            hex::encode(b)
        };
        // The networks are read, a subnet picked from them and the record
        // inserted after another look at them, in one transaction: a network
        // created meanwhile by another process makes the pick again.
        let mut attempts = 0;
        loop {
            let existing = self.db.list_networks().await?;
            if existing.iter().any(|n| n.name == req.name) {
                return Err(NetworkError::AlreadyExists(format!(
                    "network name {} already used: network already exists",
                    req.name
                )));
            }
            let record = self
                .plan(req.clone(), &id, &existing, builtin.clone())
                .await?;
            let checked = record.clone();
            let builtin = builtin.clone();
            match self
                .db
                .insert_network_checked(&record, move |rows| {
                    no_network_in_the_way(&checked, rows, builtin)
                })
                .await
            {
                Ok(()) => {
                    info!("Created network {} ({})", record.name, id);
                    return Ok(id);
                }
                // (each refusal is a network another create inserted: the
                // bound is only against a refusal that would come back)
                Err(velarx_types::DbError::AlreadyExists(_)) if attempts < 256 => attempts += 1,
                Err(velarx_types::DbError::AlreadyExists(m)) => {
                    return Err(NetworkError::AlreadyExists(m))
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// The record of the network `req` asks for, given the networks there
    /// are (`existing`), with the subnet and the gateway chosen.
    async fn plan(
        &self,
        mut req: CreateNetworkRequest,
        id: &str,
        existing: &[NetworkRecord],
        builtin: NetworkDef,
    ) -> NetworkResult<NetworkRecord> {
        // An IPv6 subnet given as the only subnet.
        if req.subnet.as_deref().is_some_and(|s| s.contains(':')) && req.subnet6.is_none() {
            req.subnet6 = req.subnet.take();
            req.gateway6 = req.gateway.take();
        }
        if req.driver != NetworkDriver::Bridge && (req.subnet6.is_some() || req.gateway6.is_some())
        {
            return Err(bad("an IPv6 subnet needs the bridge driver"));
        }
        match req.driver {
            NetworkDriver::Bridge => {
                let defs = network_defs(existing, builtin)?;
                let subnet = match req.subnet.as_deref().filter(|s| !s.is_empty()) {
                    Some(s) => {
                        Subnet::parse(s).ok_or_else(|| bad(format!("invalid IPv4 subnet `{s}`")))?
                    }
                    None => {
                        // The first /24 that neither a network nor the
                        // host uses.
                        let mut used: Vec<Subnet> = defs.iter().map(|d| d.subnet).collect();
                        loop {
                            let s = free_subnet(&used, &self.config.subnet_pools)
                                .ok_or_else(|| bad("cannot find a free subnet"))?;
                            match self.engine.check_host(None, &s).await {
                                Ok(()) => break s,
                                Err(NetworkError::InvalidConfig(_)) => used.push(s),
                                Err(e) => return Err(e),
                            }
                        }
                    }
                };
                let gateway = free_subnet_gateway(&defs, &subnet, req.gateway.as_deref())?;
                check_bridge_options(&mut req.options, &subnet)?;
                store_routes(&mut req);
                let bridge = req
                    .options
                    .get("interface_name")
                    .cloned()
                    .unwrap_or_else(|| velarx_netdetach::def::default_bridge_name(id));
                if let Some(o) = defs.iter().find(|d| d.bridge == bridge) {
                    return Err(NetworkError::AlreadyExists(format!(
                        "the interface `{bridge}` is used by the network `{}`",
                        o.name
                    )));
                }
                // Never an interface of the host, never its addresses.
                self.engine.check_host(Some(&bridge), &subnet).await?;
                let v6 = self.ipv6_subnet(&req, &defs).await?;
                req.options.remove("ipv6");
                req.subnet = Some(subnet.to_string());
                req.gateway = Some(gateway.to_string());
                req.subnet6 = v6.map(|(s, _)| s.to_string());
                req.gateway6 = v6.map(|(_, g)| g.to_string());
            }
            NetworkDriver::Macvlan => {
                let defs = network_defs(existing, builtin)?;
                // The subnet of the LAN: no DHCP here.
                let s = req
                    .subnet
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        bad("a macvlan network needs a subnet (DHCP is not supported)")
                    })?;
                let subnet =
                    Subnet::parse(s).ok_or_else(|| bad(format!("invalid IPv4 subnet `{s}`")))?;
                let gateway = free_subnet_gateway(&defs, &subnet, req.gateway.as_deref())?;
                check_macvlan_options(&mut req.options, &subnet)?;
                store_routes(&mut req);
                let parent = match req.options.get("parent") {
                    Some(p) => p.clone(),
                    // The interface of the default route, as podman.
                    None => self.engine.default_route_interface().await?,
                };
                // (netlink: /sys shows the namespace it was mounted in)
                if !self.engine.interface_exists(&parent).await? {
                    return Err(NetworkError::InterfaceNotFound(parent));
                }
                req.options.insert("parent".into(), parent);
                req.subnet = Some(subnet.to_string());
                req.gateway = Some(gateway.to_string());
            }
            NetworkDriver::Overlay => {
                info!(
                    "Creating overlay network {} - a network provider makes it",
                    req.name
                );
            }
            NetworkDriver::Host | NetworkDriver::None => {
                if !req.routes.is_empty() {
                    return Err(bad("the network option `route` needs the bridge driver"));
                }
                check_other_options(&req.options)?
            }
        }

        Ok(NetworkRecord {
            id: id.to_string(),
            name: req.name.clone(),
            driver: req.driver.as_str().to_string(),
            subnet: req.subnet,
            gateway: req.gateway,
            options: Some(serde_json::to_string(&req.options).unwrap_or_default()),
            created_at: chrono::Utc::now().to_rfc3339(),
            subnet6: req.subnet6,
            gateway6: req.gateway6,
        })
    }

    /// The IPv6 subnet and gateway of a bridge network: the one asked for,
    /// a random unique local /64 with the `ipv6` option alone, else none.
    async fn ipv6_subnet(
        &self,
        req: &CreateNetworkRequest,
        defs: &[NetworkDef],
    ) -> NetworkResult<Option<(Subnet6, Ipv6Addr)>> {
        let asked = req.subnet6.as_deref().filter(|s| !s.is_empty());
        let wanted = asked.is_some() || req.options.get("ipv6").is_some_and(|v| v == "true");
        if !wanted {
            if req.gateway6.as_deref().is_some_and(|g| !g.is_empty()) {
                return Err(bad("an IPv6 gateway needs an IPv6 subnet"));
            }
            return Ok(None);
        }
        let subnet = match asked {
            Some(s) => {
                let s6 =
                    Subnet6::parse(s).ok_or_else(|| bad(format!("invalid IPv6 subnet `{s}`")))?;
                if let Some(o) = defs
                    .iter()
                    .find(|d| d.subnet6.is_some_and(|d6| d6.overlaps(&s6)))
                {
                    return Err(NetworkError::AlreadyExists(format!(
                        "the subnet `{s6}` overlaps with the network `{}`",
                        o.name
                    )));
                }
                self.engine.check_host6(&s6).await?;
                s6
            }
            None => {
                let mut tries = 0;
                loop {
                    let s6 = Subnet6::random_ula().map_err(NetworkError::Io)?;
                    let free = defs
                        .iter()
                        .all(|d| !d.subnet6.is_some_and(|d6| d6.overlaps(&s6)));
                    if free {
                        match self.engine.check_host6(&s6).await {
                            Ok(()) => break s6,
                            Err(NetworkError::InvalidConfig(_)) => {}
                            Err(e) => return Err(e),
                        }
                    }
                    tries += 1;
                    if tries >= 16 {
                        return Err(bad("cannot find a free IPv6 subnet"));
                    }
                }
            }
        };
        let gateway = match req.gateway6.as_deref().filter(|g| !g.is_empty()) {
            Some(g) => g
                .parse::<Ipv6Addr>()
                .ok()
                .filter(|g| subnet.is_host(*g))
                .ok_or_else(|| bad(format!("invalid gateway `{g}` for the subnet `{subnet}`")))?,
            None => subnet.first_host(),
        };
        Ok(Some((subnet, gateway)))
    }

    /// The record of a network by name, id or unique id prefix.
    async fn record(&self, key: &str) -> NetworkResult<NetworkRecord> {
        match self.db.get_network(key).await {
            Ok(r) => Ok(r),
            Err(velarx_types::DbError::NotFound(_)) => {
                let all = self.db.list_networks().await?;
                let mut m = all
                    .into_iter()
                    .filter(|n| !key.is_empty() && n.id.starts_with(key));
                match (m.next(), m.next()) {
                    (Some(r), None) => Ok(r),
                    _ => Err(NetworkError::NotFound(key.to_string())),
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Remove a network: refused while containers use it unless FORCE (the
    /// caller removes the containers first); the bridge, the rules, the DNS
    /// records and the pooled namespaces go with it.
    ///
    /// A record that cannot be read is refused, unless FORCE: then its
    /// bridge is found by the owner mark the bridge carries (its id), and
    /// what is torn down is read from the bridge itself.
    pub async fn delete(&self, id: &str, force: bool) -> NetworkResult<()> {
        let network = self.record(id).await?;
        // (read before the row goes: the bridge and its rules are named by
        // the record)
        let def = match NetworkDef::from_record(&network) {
            Ok(def) => Ok(def),
            Err(e) if force => Err(e),
            Err(NetworkError::InvalidConfig(e)) => {
                return Err(NetworkError::InvalidConfig(format!(
                    "{e} (`network rm --force` removes it)"
                )))
            }
            Err(e) => return Err(e),
        };
        // The row goes first, where the users are counted again: a container
        // that attaches meanwhile finds the network gone (it is refused), one
        // that did is counted.
        match self.db.delete_network_unused(&network.id, force).await {
            Ok(()) => {}
            Err(velarx_types::DbError::AlreadyExists(_)) => {
                return Err(NetworkError::Busy(format!(
                    "\"{}\" has associated containers with it. Use -f to forcibly delete containers and pods: network is being used",
                    network.name
                )));
            }
            Err(velarx_types::DbError::NotFound(_)) => {
                return Err(NetworkError::NotFound(id.to_string()))
            }
            Err(e) => return Err(e.into()),
        }
        match def {
            Ok(Some(def)) => self.engine.network_removed(&def).await?,
            Ok(None) => {}
            Err(e) => {
                warn!("Deleting the network {} by its bridge: {e}", network.name);
                self.engine
                    .network_removed_by_mark(&network.id, &network.name)
                    .await?
            }
        }
        info!("Deleted network {}", network.name);
        Ok(())
    }

    /// Replace the options of a network.
    async fn update_options(
        &self,
        id: &str,
        options: &HashMap<String, String>,
    ) -> NetworkResult<()> {
        let network = self.record(id).await?;
        let json = serde_json::to_string(options).unwrap_or_default();
        let nid = network.id.clone();
        self.db
            .conn()
            .call(move |conn| {
                conn.execute(
                    "UPDATE networks SET options = ?1 WHERE id = ?2",
                    rusqlite::params![json, nid],
                )?;
                Ok(())
            })
            .await
            .map_err(|e| NetworkError::Database(velarx_types::DbError::Sqlite(e)))?;
        // The running containers use the new DNS servers.
        let updated = self.record(&network.id).await?;
        if let Some(def) = NetworkDef::from_record(&updated)? {
            self.engine.network_dns_updated(&def).await?;
        }
        Ok(())
    }

    /// `network update --dns-add/--dns-drop`: removing a server the network
    /// does not have is an error.
    pub async fn update_dns(&self, id: &str, add: &[String], drop: &[String]) -> NetworkResult<()> {
        let network = self.record(id).await?;
        // (options that cannot be read are an error: they would be written
        // back as the DNS servers alone)
        let mut options: HashMap<String, String> = match network.options.as_deref() {
            Some(o) => serde_json::from_str(o).map_err(|e| {
                NetworkError::InvalidConfig(format!("the options of network {}: {e}", network.name))
            })?,
            None => HashMap::new(),
        };
        let key = "dns";
        let mut servers: Vec<String> = options
            .get(key)
            .map(|v| {
                v.split(',')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        for d in drop {
            let Some(at) = servers.iter().position(|s| s == d) else {
                return Err(NetworkError::Missing(format!(
                    "the DNS server `{d}` is not set for the network `{}`",
                    network.name
                )));
            };
            servers.remove(at);
        }
        for a in add {
            if !servers.contains(a) {
                servers.push(a.clone());
            }
        }
        if servers.is_empty() {
            options.remove(key);
        } else {
            options.insert(key.to_string(), check_dns_servers(&servers.join(","))?);
        }
        self.update_options(&network.id, &options).await
    }

    /// Connect a container to a network: its address on a bridge network
    /// (and the interface when it runs).
    pub async fn connect(
        &self,
        network_id: &str,
        request: &ConnectRequest<'_>,
    ) -> NetworkResult<Ipv4Addr> {
        let network = match self.record(network_id).await {
            Ok(r) => r,
            Err(NetworkError::NotFound(_)) => {
                // The default network.
                let def = self.engine.lookup(network_id).await?;
                return self.engine.connect(&def.id, request).await;
            }
            Err(e) => return Err(e),
        };
        let driver = stored_driver(&network.driver)?;
        if !attached_by_engine(driver.clone()) {
            return Err(NetworkError::InvalidConfig(no_interface(
                "connect to",
                &network.name,
                driver,
            )));
        }
        self.engine.connect(&network.id, request).await
    }

    /// Apply the firewall rules of the networks of the running container
    /// again; false: it has no bridge network.
    pub async fn reload(&self, container_id: &str) -> NetworkResult<bool> {
        self.engine.reload(container_id).await
    }

    pub async fn disconnect(
        &self,
        network_id: &str,
        container_id: &str,
        container_name: &str,
        force: bool,
    ) -> NetworkResult<()> {
        match self.record(network_id).await {
            Ok(r) => {
                let driver = stored_driver(&r.driver)?;
                if !attached_by_engine(driver.clone()) {
                    return Err(NetworkError::InvalidConfig(no_interface(
                        "disconnect from",
                        &r.name,
                        driver,
                    )));
                }
            }
            // (the default network)
            Err(NetworkError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        self.engine
            .disconnect(container_id, network_id, force, container_name)
            .await?;
        info!(
            "Disconnected container {} from network {}",
            container_id, network_id
        );
        Ok(())
    }
}

/// Why a container cannot be connected to (or disconnected from) a network
/// of the drivers that put no interface in it: podman has no such
/// networks, so the words are velarx's.
fn no_interface(what: &str, name: &str, driver: NetworkDriver) -> String {
    let why = match driver {
        NetworkDriver::Host => "a container shares the host's network with `--network host`",
        NetworkDriver::None => "a container without networking is made with `--network none`",
        _ => "a network provider makes its network, with `--network provider:NAME`",
    };
    format!(
        "cannot {what} the network `{name}`: the {} driver puts no interface in a container ({why})",
        driver.as_str()
    )
}

#[cfg(test)]
mod ipv6_tests {
    use super::*;
    use velarx_wire::addr::Subnets;

    #[test]
    fn bridge_options() {
        let subnet = Subnet::parse("10.89.3.0/24").unwrap();
        let o = |k: &str, v: &str| HashMap::from([(k.to_string(), v.to_string())]);
        check_bridge_options(&mut o("ipv6", "true"), &subnet).unwrap();
        for (k, v) in [
            ("ipv6", "yes"),
            ("vlan", "3"),
            ("ipam_driver", "dhcp"),
            ("mtu", "67"),
            ("mtu", "9x"),
            ("interface_name", "a/b"),
            ("interface_name", "0123456789abcdef"),
            ("dns", "bogus"),
            ("dns", "1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4"),
            ("ip_range", "10.9.0.0/24"),
            ("podman.x", "y"),
        ] {
            assert!(
                check_bridge_options(&mut o(k, v), &subnet).is_err(),
                "{k}={v}"
            );
        }
        let mut ok = o("ip_range", "10.89.3.128/25");
        check_bridge_options(&mut ok, &subnet).unwrap();
        assert_eq!(ok["ip_range"], "10.89.3.128-10.89.3.255");
        let mut ok = o("dns", " 10.0.0.53 , ::1");
        check_bridge_options(&mut ok, &subnet).unwrap();
        assert_eq!(ok["dns"], "10.0.0.53,::1");
        for (k, v) in [
            ("mtu", "1400"),
            ("label.a", "b"),
            ("ipam_driver", "host-local"),
        ] {
            assert!(check_bridge_options(&mut o(k, v), &subnet).is_ok(), "{k}");
        }
    }

    #[test]
    fn host_network_options() {
        let o = |k: &str, v: &str| HashMap::from([(k.to_string(), v.to_string())]);
        for (k, v) in [
            ("internal", "true"),
            ("ipv6", "true"),
            ("disable_dns", "true"),
            ("dns", "1.1.1.1"),
            ("ip_range", "10.0.0.0/24"),
            ("ipam_driver", "dhcp"),
        ] {
            assert!(check_other_options(&o(k, v)).is_err(), "{k}");
        }
        for (k, v) in [("k", "v"), ("label.a", "b"), ("ipam_driver", "host-local")] {
            assert!(check_other_options(&o(k, v)).is_ok(), "{k}");
        }
    }

    #[test]
    fn names_and_subnets() {
        assert!(valid_network_name("net-1_a.b"));
        for bad in ["", "-a", "a b", "a/b", &"x".repeat(65)] {
            assert!(!valid_network_name(bad), "{bad}");
        }
        let used = [Subnet::parse("10.90.0.0/16").unwrap()];
        assert_eq!(free_subnet(&used, &[]), None);
        // (the default network has 10.90.0.0/24)
        let used = [
            Subnet::parse("10.90.0.0/24").unwrap(),
            Subnet::parse("10.90.1.0/24").unwrap(),
            Subnet::parse("10.90.2.0/25").unwrap(),
        ];
        assert_eq!(free_subnet(&used, &[]).unwrap().to_string(), "10.90.3.0/24");
        let pools = [
            velarx_config::SubnetPool {
                base: "10.89.0.0/16".into(),
                size: 24,
            },
            velarx_config::SubnetPool {
                base: "10.91.0.0/15".into(),
                size: 26,
            },
        ];
        assert_eq!(
            free_subnet(&used, &pools).unwrap().to_string(),
            "10.89.0.0/24"
        );
        let full = [
            Subnet::parse("10.89.0.0/16").unwrap(),
            Subnet::parse("10.90.0.0/26").unwrap(),
        ];
        assert_eq!(
            free_subnet(&full, &pools).unwrap().to_string(),
            "10.90.0.64/26"
        );
    }

    #[test]
    fn subnets_split_by_family() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let s = split_subnets(&v(&["fd00:1::/64", "10.9.0.0/24"]), &v(&["fd00:1::9"])).unwrap();
        assert_eq!(s.subnet.as_deref(), Some("10.9.0.0/24"));
        assert_eq!(s.gateway, None);
        assert_eq!(s.subnet6.as_deref(), Some("fd00:1::/64"));
        assert_eq!(s.gateway6.as_deref(), Some("fd00:1::9"));
        assert!(split_subnets(&v(&["10.9.0.0/24", "10.8.0.0/24"]), &[]).is_err());
        assert!(split_subnets(&v(&["10.9.0.0/24"]), &v(&["fd00::1"])).is_err());
        assert!(split_subnets(&[], &v(&["10.0.0.1"])).is_err());
        assert_eq!(split_subnets(&[], &[]).unwrap(), Subnets::default());
    }
}

#[cfg(test)]
mod driver_tests {
    use super::*;

    #[test]
    fn an_unknown_driver_is_refused() {
        for d in ["bridge", "host", "none", "overlay", "macvlan"] {
            assert_eq!(d.parse::<NetworkDriver>().unwrap().as_str(), d);
        }
        let e = "bogus".parse::<NetworkDriver>().unwrap_err();
        assert!(e.to_string().contains("bogus"), "{e}");
    }

    /// A container of a macvlan network is attached by the engine, as one
    /// of a bridge: `disconnect` detaches it the same way.
    #[test]
    fn the_engine_attaches_bridges_and_macvlans() {
        for (d, attached) in [
            ("bridge", true),
            ("macvlan", true),
            ("host", false),
            ("none", false),
            ("overlay", false),
        ] {
            assert_eq!(
                attached_by_engine(stored_driver(d).unwrap()),
                attached,
                "{d}"
            );
        }
    }

    /// Options that cannot be read are an error of `network update`: the
    /// record keeps them, it is not written back with the DNS servers
    /// alone.
    #[tokio::test]
    async fn dns_servers_are_not_added_to_options_that_cannot_be_read() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_in_memory().await.unwrap();
        let config = NetworkConfig::default();
        let engine = engine::ContainerNetworks::new(
            db.clone(),
            engine::EngineOptions {
                state_dir: dir.path().to_path_buf(),
                db_path: dir.path().join("db.sqlite"),
                bridge: config.bridge.clone(),
                table: "t".into(),
                dns_exe: "velarx".into(),
                cni: config.cni.clone(),
                providers: Vec::new(),
            },
        )
        .unwrap();
        let svc = NetworkService::new(db.clone(), config, Arc::new(engine));
        db.insert_network(&NetworkRecord {
            id: "n1".repeat(32),
            name: "n1".into(),
            driver: "bridge".into(),
            subnet: Some("10.213.50.0/24".into()),
            gateway: None,
            options: Some("{not json".into()),
            created_at: "now".into(),
            subnet6: None,
            gateway6: None,
        })
        .await
        .unwrap();
        let e = svc
            .update_dns("n1", &["10.0.0.53".into()], &[])
            .await
            .unwrap_err();
        assert!(matches!(e, NetworkError::InvalidConfig(_)), "{e}");
        let kept = db.get_network(&"n1".repeat(32)).await.unwrap();
        assert_eq!(kept.options.as_deref(), Some("{not json"));
    }

    async fn service() -> (
        tempfile::TempDir,
        Database,
        NetworkService,
        Arc<engine::ContainerNetworks>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_in_memory().await.unwrap();
        let config = NetworkConfig::default();
        let engine = Arc::new(
            engine::ContainerNetworks::new(
                db.clone(),
                engine::EngineOptions {
                    state_dir: dir.path().to_path_buf(),
                    db_path: dir.path().join("db.sqlite"),
                    bridge: config.bridge.clone(),
                    table: "t".into(),
                    dns_exe: "velarx".into(),
                    cni: config.cni.clone(),
                    providers: Vec::new(),
                },
            )
            .unwrap(),
        );
        let svc = NetworkService::new(db.clone(), config, engine.clone());
        (dir, db, svc, engine)
    }

    fn row(name: &str, subnet: &str, options: Option<&str>) -> NetworkRecord {
        NetworkRecord {
            id: name.repeat(32),
            name: name.into(),
            driver: "bridge".into(),
            subnet: Some(subnet.into()),
            gateway: None,
            options: options.map(String::from),
            created_at: "now".into(),
            subnet6: None,
            gateway6: None,
        }
    }

    /// A container whose network setup cannot be read has no network
    /// setup that is empty: the error is the caller's.
    #[tokio::test]
    async fn a_container_network_spec_that_cannot_be_read_is_an_error() {
        let (_dir, db, _svc, engine) = service().await;
        assert!(engine.spec("c1").await.unwrap().is_none());
        db.insert_image(&velarx_db::ImageRecord {
            id: "img".into(),
            manifest_digest: velarx_types::digest::Digest::of(
                velarx_types::digest::Algorithm::Sha256,
                b"m",
            ),
            config_digest: velarx_types::digest::Digest::of(
                velarx_types::digest::Algorithm::Sha256,
                b"c",
            ),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: "now".into(),
            is_lazy: false,
        })
        .await
        .unwrap();
        db.insert_container(&velarx_db::ContainerRecord {
            id: "c1".into(),
            name: Some("c1".into()),
            image_id: "img".into(),
            config: "{}".into(),
            state: velarx_db::RecordState::Created,
            pid: None,
            created_at: "now".into(),
            started_at: None,
            finished_at: None,
            exit_code: None,
        })
        .await
        .unwrap();
        db.net_set_container_spec("c1", "{not json").await.unwrap();
        let e = engine.spec("c1").await.unwrap_err();
        assert!(matches!(e, NetworkError::Unreadable(_)), "{e}");
        assert!(e.to_string().contains("c1"), "{e}");
        // its teardown says so, and still undoes what needs no setup: the
        // record of its namespace goes (no later teardown could read it)
        let mine = velarx_nsid::own(velarx_nsid::Kind::Net).unwrap();
        engine.records.record("c1", &mine).unwrap();
        let e = engine.teardown("c1").await.unwrap_err();
        assert!(matches!(e, NetworkError::Unreadable(_)), "{e}");
        assert!(!engine.records.exists("c1"), "the namespace stays recorded");
    }

    /// Options that cannot be read are not the defaults: an internal network
    /// would lose `internal`, and every unreadable value of a network is the
    /// error of whoever reads the network.
    #[test]
    fn options_that_cannot_be_read_are_an_error_not_the_defaults() {
        let def = |o: Option<&str>| NetworkDef::from_record(&row("n1", "10.213.50.0/24", o));
        let d = def(Some(r#"{"internal":"true","dns":"10.0.0.53"}"#))
            .unwrap()
            .unwrap();
        assert!(d.internal);
        assert_eq!(d.dns_servers.len(), 1);
        assert!(def(None).unwrap().is_some());
        for bad in [
            "{not json",
            r#"{"internal":true}"#,
            r#"{"dns":"10.0.0.53,bogus"}"#,
            r#"{"ip_range":"bogus"}"#,
            r#"{"routes":"bogus"}"#,
        ] {
            let e = def(Some(bad)).err().unwrap_or_else(|| panic!("{bad}"));
            assert!(matches!(e, NetworkError::InvalidConfig(_)), "{bad}: {e}");
            assert!(e.to_string().contains("n1"), "{bad}: {e}");
        }
        let mut cfg = NetworkConfig::default().bridge;
        cfg.gateway = "bogus".into();
        assert!(NetworkDef::builtin(&cfg).is_err());
    }

    /// A network record that cannot be read is not a network that is not
    /// there: no network is created next to it, and it is not deleted (its
    /// bridge and rules could not be named), the row stays; `--force`
    /// removes it (by the mark of its bridge).
    #[tokio::test]
    async fn a_network_record_that_cannot_be_read_stops_create_and_delete() {
        let (_dir, db, svc, _engine) = service().await;
        db.insert_network(&row("n1", "10.213.50.0/24", Some("{not json")))
            .await
            .unwrap();
        let req = CreateNetworkRequest {
            name: "n2".into(),
            driver: NetworkDriver::Bridge,
            subnet: Some("10.213.51.0/24".into()),
            gateway: None,
            subnet6: None,
            gateway6: None,
            options: HashMap::new(),
            routes: vec![],
        };
        let e = svc.create(req).await.unwrap_err();
        assert!(matches!(e, NetworkError::InvalidConfig(_)), "{e}");
        assert!(db.get_network("n2").await.is_err(), "n2 was created");
        let e = svc.delete("n1", false).await.unwrap_err();
        assert!(matches!(e, NetworkError::InvalidConfig(_)), "{e}");
        assert!(e.to_string().contains("--force"), "{e}");
        assert!(db.get_network(&"n1".repeat(32)).await.is_ok(), "n1 went");
        svc.delete("n1", true).await.unwrap();
        assert!(db.get_network(&"n1".repeat(32)).await.is_err(), "n1 stayed");
    }

    /// The options stored with a network (its routes, the parent of a
    /// macvlan network) are not checked again with the list of the creation:
    /// the DNS servers change, the rest stays.
    #[tokio::test]
    async fn dns_servers_of_a_network_with_routes_or_a_parent_are_updated() {
        let (_dir, db, svc, _engine) = service().await;
        let routes = r#"{"routes":"10.99.0.0/24,10.213.50.77","dns":"10.0.0.1"}"#;
        db.insert_network(&row("n1", "10.213.50.0/24", Some(routes)))
            .await
            .unwrap();
        let mut macvlan = row(
            "n2",
            "10.213.51.0/24",
            Some(r#"{"parent":"eth0","mode":"bridge"}"#),
        );
        macvlan.driver = "macvlan".into();
        db.insert_network(&macvlan).await.unwrap();
        for (id, kept) in [("n1", "routes"), ("n2", "parent")] {
            svc.update_dns(id, &["10.0.0.53".into()], &[])
                .await
                .unwrap_or_else(|e| panic!("{id}: {e}"));
            let options = db
                .get_network(&id.repeat(32))
                .await
                .unwrap()
                .options
                .unwrap();
            assert!(options.contains(kept), "{options}");
            assert!(options.contains("10.0.0.53"), "{options}");
        }
        let e = svc
            .update_dns("n1", &["bogus".into()], &[])
            .await
            .unwrap_err();
        assert!(matches!(e, NetworkError::InvalidConfig(_)), "{e}");
    }

    #[test]
    fn a_network_without_an_interface_names_its_driver() {
        for (d, driver) in [
            ("host", NetworkDriver::Host),
            ("none", NetworkDriver::None),
            ("overlay", NetworkDriver::Overlay),
        ] {
            for what in ["connect to", "disconnect from"] {
                let m = no_interface(what, "n1", driver.clone());
                assert!(
                    m.starts_with(&format!("cannot {what} the network `n1`: the {d} driver")),
                    "{m}"
                );
            }
        }
    }
}
