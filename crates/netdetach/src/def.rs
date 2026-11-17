// SPDX-License-Identifier: Apache-2.0
//! The bridge networks as the setup and the teardown know them: a stored
//! network (or the one of the configuration) turned into what the bridge
//! code needs.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use velarx_config::BridgeConfig;
use velarx_db::NetworkRecord;
use velarx_netkernel::bridge::NetDef;
use velarx_netkernel::error::{NetworkError, NetworkResult};
use velarx_wire::addr::{self, Subnet, Subnet6};

/// A bridge network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkDef {
    pub id: String,
    pub name: String,
    pub bridge: String,
    pub subnet: Subnet,
    pub gateway: Ipv4Addr,
    pub internal: bool,
    pub dns: bool,
    pub dns_servers: Vec<IpAddr>,
    /// The addresses given to containers, else the whole subnet.
    pub ip_range: Option<(Ipv4Addr, Ipv4Addr)>,
    pub mtu: u32,
    /// The network of the configuration, not a row of `networks`.
    pub builtin: bool,
    /// The IPv6 subnet and gateway of a dual-stack network.
    pub subnet6: Option<Subnet6>,
    pub gateway6: Option<Ipv6Addr>,
    /// A macvlan network: its mode; `bridge` is its parent interface.
    pub macvlan: Option<String>,
    /// Static routes of the containers.
    pub routes: Vec<addr::Route>,
}

/// The value of the first of KEYS in the options of a network record.
pub fn opt<'a>(o: &'a HashMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|k| o.get(*k))
        .map(String::as_str)
        .filter(|s| !s.is_empty())
}

/// The bridge of a network without `--interface-name`.
pub fn default_bridge_name(id: &str) -> String {
    let short: String = id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(8)
        .collect();
    format!("br-{short}")
}

/// The name of the network of the configuration, as podman's: its bridge
/// keeps the name of the configuration (`velarx0`, never podman's
/// `podman0`).
pub const DEFAULT_NETWORK: &str = "podman";

/// The id of the network of the configuration (as the API shows it):
/// `builtin_id(DEFAULT_NETWORK)`, podman's.
pub fn builtin_id(name: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(name.as_bytes()))
}

impl NetworkDef {
    /// A bridge (or macvlan) network record; None for the other drivers.
    pub fn from_record(r: &NetworkRecord) -> NetworkResult<Option<Self>> {
        if r.driver != "bridge" && r.driver != "macvlan" {
            return Ok(None);
        }
        let macvlan = r.driver == "macvlan";
        let bad = |what: &str| {
            NetworkError::InvalidConfig(format!("invalid {what} for the network `{}`", r.name))
        };
        let o: HashMap<String, String> = match r.options.as_deref() {
            Some(o) => serde_json::from_str(o).map_err(|e| {
                NetworkError::InvalidConfig(format!("the options of network {}: {e}", r.name))
            })?,
            None => HashMap::new(),
        };
        let subnet = r
            .subnet
            .as_deref()
            .and_then(Subnet::parse)
            .ok_or_else(|| bad("subnet"))?;
        let gateway = match r.gateway.as_deref().filter(|g| !g.is_empty()) {
            Some(g) => g.parse().map_err(|_| bad("gateway"))?,
            None => subnet.first_host(),
        };
        let bridge = if macvlan {
            // the parent, chosen when the network was created
            opt(&o, &["parent"]).unwrap_or_default().to_string()
        } else {
            opt(&o, &["interface_name"])
                .map(String::from)
                .unwrap_or_else(|| default_bridge_name(&r.id))
        };
        let mtu = match opt(&o, &["mtu", "com.docker.network.driver.mtu"]) {
            Some(m) => m
                .parse()
                .ok()
                .filter(|m| (68..=65535).contains(m))
                .ok_or_else(|| bad("MTU"))?,
            None => 0,
        };
        let dns_servers = match opt(&o, &["dns"]) {
            Some(s) => s
                .split(',')
                .map(|s| s.trim().parse().map_err(|_| bad("DNS server")))
                .collect::<Result<_, _>>()?,
            None => Vec::new(),
        };
        let ip_range = match opt(&o, &["ip_range"]) {
            Some(r) => Some(addr::parse_ip_range(r).ok_or_else(|| bad("IP range"))?),
            None => None,
        };
        let subnet6 = match r.subnet6.as_deref().filter(|s| !s.is_empty()) {
            Some(s) => Some(Subnet6::parse(s).ok_or_else(|| bad("IPv6 subnet"))?),
            None => None,
        };
        let gateway6 = match (subnet6, r.gateway6.as_deref().filter(|g| !g.is_empty())) {
            (None, _) => None,
            (Some(_), Some(g)) => Some(g.parse().map_err(|_| bad("IPv6 gateway"))?),
            (Some(s), None) => Some(s.first_host()),
        };
        Ok(Some(Self {
            id: r.id.clone(),
            name: r.name.clone(),
            bridge,
            subnet,
            gateway,
            internal: opt(&o, &["internal"]) == Some("true"),
            dns: !macvlan && opt(&o, &["disable_dns"]) != Some("true"),
            macvlan: macvlan.then(|| opt(&o, &["mode"]).unwrap_or("bridge").to_string()),
            dns_servers,
            ip_range,
            mtu,
            builtin: false,
            subnet6,
            gateway6,
            routes: stored_routes(&o).map_err(|e| {
                NetworkError::InvalidConfig(format!(
                    "invalid routes for the network `{}`: {e}",
                    r.name
                ))
            })?,
        }))
    }

    /// The network of the configuration: no DNS, as podman's default.
    pub fn builtin(cfg: &BridgeConfig) -> NetworkResult<Self> {
        let subnet = Subnet::parse(&cfg.subnet).ok_or_else(|| {
            NetworkError::InvalidConfig(format!(
                "invalid subnet `{}` of the default network",
                cfg.subnet
            ))
        })?;
        let gateway = cfg.gateway.parse().map_err(|_| {
            NetworkError::InvalidConfig(format!(
                "invalid gateway `{}` of the default network",
                cfg.gateway
            ))
        })?;
        Ok(Self {
            id: builtin_id(DEFAULT_NETWORK),
            name: DEFAULT_NETWORK.to_string(),
            bridge: cfg.default_bridge.clone(),
            subnet,
            gateway,
            internal: false,
            dns: false,
            dns_servers: Vec::new(),
            ip_range: None,
            mtu: 0,
            builtin: true,
            subnet6: None,
            gateway6: None,
            macvlan: None,
            routes: Vec::new(),
        })
    }

    pub fn net_def(&self) -> NetDef {
        NetDef {
            id: self.id.clone(),
            name: self.name.clone(),
            bridge: self.bridge.clone(),
            subnet: self.subnet,
            gateway: self.gateway,
            internal: self.internal,
            dns: self.dns,
            mtu: self.mtu,
            dns_servers: self.dns_servers.clone(),
            subnet6: self.subnet6,
            gateway6: self.gateway6,
            macvlan: self.macvlan.clone(),
            routes: self.routes.clone(),
        }
    }
}

/// The static routes kept in OPTIONS; one that cannot be read is an error.
pub fn stored_routes(options: &HashMap<String, String>) -> Result<Vec<addr::Route>, String> {
    options
        .get("routes")
        .into_iter()
        .flat_map(|v| v.split(';'))
        .map(|r| addr::Route::parse(r).map_err(|e| format!("route `{r}`: {e}")))
        .collect()
}
