// SPDX-License-Identifier: Apache-2.0
//! Networks: libpod's and Docker's routes.  The request is decoded here (the
//! JSON bodies of a create, a connect, an update) into the typed calls of
//! the engine, which makes the networks and shapes the documents.

use super::call::{refuse_field, Call};
use super::error::{ApiError, ApiResult};
use super::reply;
use super::{route, Route};
use crate::engine::engine_call;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use velarx_proto::workload::{LeaseRange as Lease, NetworkRoute, NetworkSpec};

#[derive(Deserialize, Default)]
#[serde(default)]
struct PodmanRoute {
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    destination: String,
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    gateway: String,
    metric: Option<u32>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PodmanSubnet {
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    subnet: String,
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    gateway: String,
    lease_range: Option<LeaseRange>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LeaseRange {
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    start_ip: String,
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    end_ip: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PodmanCreate {
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    name: String,
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    driver: String,
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    network_interface: String,
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    subnets: Vec<PodmanSubnet>,
    ipv6_enabled: bool,
    internal: bool,
    dns_enabled: Option<bool>,
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    labels: HashMap<String, String>,
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    options: HashMap<String, String>,
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    network_dns_servers: Vec<String>,
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    routes: Vec<PodmanRoute>,
    /// What there is no support for: refused when set.
    ipam_options: Option<serde_json::Value>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DockerIpamConfig {
    #[serde(rename = "Subnet")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    subnet: String,
    #[serde(rename = "Gateway")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    gateway: String,
    #[serde(rename = "IPRange")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    ip_range: String,
    #[serde(rename = "AuxiliaryAddresses")]
    auxiliary_addresses: Option<serde_json::Value>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DockerIpam {
    #[serde(rename = "Config")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    config: Vec<DockerIpamConfig>,
    #[serde(rename = "Driver")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    driver: String,
    #[serde(rename = "Options")]
    options: Option<serde_json::Value>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DockerCreate {
    #[serde(rename = "Name")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    name: String,
    #[serde(rename = "Driver")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    driver: String,
    #[serde(rename = "Internal")]
    internal: bool,
    #[serde(rename = "EnableIPv6")]
    enable_ipv6: bool,
    /// velarx's networks have IPv4 always: `false` is refused
    #[serde(rename = "EnableIPv4")]
    enable_ipv4: Option<bool>,
    #[serde(rename = "IPAM")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    ipam: DockerIpam,
    #[serde(rename = "Options")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    options: HashMap<String, String>,
    #[serde(rename = "Labels")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    labels: HashMap<String, String>,
    #[serde(rename = "Scope")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    scope: String,
    #[serde(rename = "Attachable")]
    attachable: bool,
    #[serde(rename = "Ingress")]
    ingress: bool,
    #[serde(rename = "ConfigOnly")]
    config_only: bool,
    #[serde(rename = "ConfigFrom")]
    config_from: Option<serde_json::Value>,
}

/// The start and end of a CIDR range, `ip-ip` or `ip/prefix`.
fn lease_of(range: &str) -> Option<Lease> {
    if let Some((a, b)) = range.split_once('-') {
        return Some(Lease {
            start: a.to_string(),
            end: b.to_string(),
        });
    }
    let (ip, p) = range.split_once('/')?;
    let ip: Ipv4Addr = ip.parse().ok()?;
    let p: u32 = p.parse().ok().filter(|p| *p <= 32)?;
    let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
    let first = u32::from(ip) & mask;
    Some(Lease {
        start: Ipv4Addr::from(first).to_string(),
        end: Ipv4Addr::from(first | !mask).to_string(),
    })
}

/// The driver options of a network: the MTU, the isolation and those of macvlan.
fn driver_options(opts: HashMap<String, String>) -> ApiResult<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (k, v) in opts {
        match k.as_str() {
            "mtu" | "com.docker.network.driver.mtu" => {
                out.insert("mtu".to_string(), v);
            }
            // macvlan (the network refuses them for a bridge), and the
            // isolation of a bridge from the others (the engine checks it)
            "parent" | "mode" | "isolate" => {
                out.insert(k, v);
            }
            _ => {
                return Err(ApiError::bad_request(format!(
                    "unsupported network option `{k}`"
                )))
            }
        }
    }
    Ok(out)
}

/// podman decodes subnets as IPNets: an invalid one fails the decoding.
fn check_cidr(subnet: &str) -> ApiResult<()> {
    let ok = subnet.split_once('/').is_some_and(|(ip, len)| {
        match (ip.parse::<std::net::IpAddr>(), len.parse::<u8>()) {
            (Ok(std::net::IpAddr::V4(_)), Ok(l)) => l <= 32,
            (Ok(std::net::IpAddr::V6(_)), Ok(l)) => l <= 128,
            _ => false,
        }
    });
    if ok {
        Ok(())
    } else {
        let cause = format!("invalid CIDR address: {subnet}");
        // (podman answers 500: the subnet is a field of the body it decodes)
        Err(ApiError::internal(cause.clone()).with_cause(cause))
    }
}

fn parse_libpod(b: PodmanCreate) -> ApiResult<NetworkSpec> {
    // the driver is the engine's to check, the rest is refused
    let mut ipam_driver = None;
    if let Some(o) = &b.ipam_options {
        let mut o = o.clone();
        if let Some(d) = o["driver"].as_str().filter(|d| !d.is_empty()) {
            ipam_driver = Some(d.to_string());
            o["driver"] = serde_json::Value::Null;
        }
        refuse_field("ipam_options", &o)?;
    }
    for s in &b.subnets {
        check_cidr(&s.subnet)?;
    }
    let options = driver_options(b.options)?;
    let (v6, v4): (Vec<PodmanSubnet>, Vec<PodmanSubnet>) = b
        .subnets
        .into_iter()
        .filter(|s| !s.subnet.is_empty())
        .partition(|s| s.subnet.contains(':'));
    if v4.len() > 1 || v6.len() > 1 {
        return Err(ApiError::bad_request(
            "at most one IPv4 and one IPv6 subnet per network",
        ));
    }
    let six = v6.into_iter().next();
    let first = v4.into_iter().next();
    Ok(NetworkSpec {
        ipv6: b.ipv6_enabled || six.is_some(),
        subnet6: six.as_ref().map(|s| s.subnet.clone()),
        gateway6: six.map(|s| s.gateway).filter(|g| !g.is_empty()),
        name: b.name,
        driver: b.driver,
        subnet: first
            .as_ref()
            .map(|s| s.subnet.clone())
            .filter(|s| !s.is_empty()),
        gateway: first
            .as_ref()
            .map(|s| s.gateway.clone())
            .filter(|s| !s.is_empty()),
        lease: first
            .and_then(|s| s.lease_range)
            .filter(|r| !r.start_ip.is_empty() && !r.end_ip.is_empty())
            .map(|r| Lease {
                start: r.start_ip,
                end: r.end_ip,
            }),
        dns_enabled: b.dns_enabled.unwrap_or(true),
        dns_servers: b.network_dns_servers,
        labels: b.labels.into_iter().collect(),
        internal: b.internal,
        interface: Some(b.network_interface).filter(|i| !i.is_empty()),
        ipam_driver,
        options,
        routes: b
            .routes
            .into_iter()
            .map(|r| NetworkRoute {
                destination: r.destination,
                gateway: r.gateway,
                metric: r.metric,
            })
            .collect(),
    })
}

fn parse_docker(mut b: DockerCreate) -> ApiResult<NetworkSpec> {
    if !matches!(b.scope.as_str(), "" | "local") {
        return Err(ApiError::not_implemented("`Scope` is not supported"));
    }
    if b.enable_ipv4 == Some(false) {
        return Err(ApiError::not_implemented(
            "`EnableIPv4` false is not supported: a network has IPv4",
        ));
    }
    for (name, set) in [
        ("Attachable", b.attachable),
        ("Ingress", b.ingress),
        ("ConfigOnly", b.config_only),
    ] {
        refuse_field(name, &serde_json::Value::Bool(set))?;
    }
    if let Some(f) = &b.config_from {
        refuse_field("ConfigFrom", f)?;
    }
    if !matches!(b.ipam.driver.as_str(), "" | "default" | "host-local") {
        return Err(ApiError::not_implemented("`IPAM.Driver` is not supported"));
    }
    if let Some(o) = &b.ipam.options {
        refuse_field("IPAM.Options", o)?;
    }
    for c in &b.ipam.config {
        if let Some(a) = &c.auxiliary_addresses {
            refuse_field("IPAM.Config.AuxiliaryAddresses", a)?;
        }
    }
    // Docker's name of the bridge, podman's network_interface.
    let interface = b
        .options
        .remove("com.docker.network.bridge.name")
        .filter(|i| !i.is_empty());
    let options = driver_options(b.options)?;
    let driver = if b.driver == "bridge" {
        String::new()
    } else {
        b.driver
    };
    let (v6, v4): (Vec<DockerIpamConfig>, Vec<DockerIpamConfig>) = b
        .ipam
        .config
        .into_iter()
        .filter(|c| !c.subnet.is_empty())
        .partition(|c| c.subnet.contains(':'));
    if v4.len() > 1 || v6.len() > 1 {
        return Err(ApiError::bad_request(
            "at most one IPv4 and one IPv6 subnet per network",
        ));
    }
    let six = v6.into_iter().next();
    let first = v4.into_iter().next();
    Ok(NetworkSpec {
        ipv6: b.enable_ipv6 || six.is_some(),
        subnet6: six.as_ref().map(|c| c.subnet.clone()),
        gateway6: six.map(|c| c.gateway).filter(|g| !g.is_empty()),
        name: b.name,
        driver,
        subnet: first
            .as_ref()
            .map(|c| c.subnet.clone())
            .filter(|s| !s.is_empty()),
        gateway: first
            .as_ref()
            .map(|c| c.gateway.clone())
            .filter(|s| !s.is_empty()),
        lease: first.and_then(|c| lease_of(&c.ip_range)),
        dns_enabled: true,
        dns_servers: Vec::new(),
        labels: b.labels.into_iter().collect(),
        internal: b.internal,
        interface,
        ipam_driver: None,
        options,
        routes: Vec::new(),
    })
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct UpdateBody {
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    adddnsservers: Vec<String>,
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    removednsservers: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ConnectBody {
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    container: String,
    #[serde(rename = "Container")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    docker_container: String,
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    static_ips: Vec<String>,
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    aliases: Vec<String>,
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    static_mac: String,
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    interface_name: String,
    /// What there is no support for: refused when set.
    options: Option<serde_json::Value>,
    #[serde(rename = "EndpointConfig")]
    endpoint: Option<EndpointConfig>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct EndpointConfig {
    #[serde(rename = "IPAMConfig")]
    ipam: Option<IpamConfig>,
    #[serde(rename = "Aliases")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    aliases: Vec<String>,
    #[serde(rename = "MacAddress")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    mac_address: String,
    /// A static address too, as podman takes it
    #[serde(rename = "IPAddress")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    ip_address: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct IpamConfig {
    #[serde(rename = "LinkLocalIPs")]
    link_local_ips: Option<serde_json::Value>,
    #[serde(rename = "IPv4Address")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    ipv4: String,
    #[serde(rename = "IPv6Address")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    ipv6: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DisconnectBody {
    #[serde(rename = "Container")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    container: String,
    #[serde(rename = "container")]
    #[serde(deserialize_with = "velarx_proto::godecode::nullable")]
    lower: String,
    #[serde(rename = "Force")]
    force: bool,
}

/// `POST /networks/create`
async fn create(mut call: Call) -> ApiResult {
    if call.libpod && !call.at_least(4, 0) {
        let cause = "given version is not supported";
        return Err(ApiError::bad_request(format!(
            "failed to parse query parameter 'version': {:?}: {cause}",
            call.version
                .map(|(a, b)| format!("{a}.{b}.0"))
                .unwrap_or_default()
        ))
        .with_cause(cause));
    }
    let ignore = call.q_bool("ignoreIfExists", false)?;
    let spec = if call.libpod {
        parse_libpod(call.json_or_default().await?)?
    } else {
        parse_docker(call.json_or_default().await?)?
    };
    let created = engine_call!(call.engine, network_create(&spec, ignore))?;
    if !created.changed || call.libpod {
        Ok(reply::json(
            200,
            &velarx_shape::network::libpod(&created.network),
        ))
    } else {
        Ok(reply::json(
            201,
            &serde_json::json!({"Id": created.network.id, "Warning": ""}),
        ))
    }
}

/// `GET /networks/json` (libpod), `GET /networks` (Docker)
async fn list(call: Call) -> ApiResult {
    let filters = call.filters()?;
    let networks = call.engine.network_list(&filters).await?;
    let out: Vec<serde_json::Value> = networks
        .iter()
        .map(|n| {
            if call.libpod {
                velarx_shape::network::libpod(n)
            } else {
                velarx_shape::network::docker(n, None)
            }
        })
        .collect();
    Ok(reply::json(200, &out))
}

async fn inspect(call: Call) -> ApiResult {
    let n = engine_call!(call.engine, network_inspect(call.param(0)))?.network;
    Ok(reply::json(
        200,
        &if call.libpod {
            velarx_shape::network::libpod_inspect(&n)
        } else {
            velarx_shape::network::docker(&n, Some(call.param(0)))
        },
    ))
}

async fn exists(call: Call) -> ApiResult {
    engine_call!(call.engine, network_exists(call.param(0)))?;
    Ok(reply::empty(204))
}

/// `DELETE /networks/{name}`.  podman's libpod route reads `force` alone
/// (a value it cannot convert is a 500; a missing network is a 404 and one
/// in use without `force` a 500, as is any other failure); the Docker route
/// also reads `timeout` (a number below zero is a 400) and takes any word
/// but "", "0", "no", "false" and "none" for a true `force`.
async fn remove(call: Call) -> ApiResult {
    let internal = |e: ApiError| e.with_status(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    let force = call.q_flag("force");
    let timeout = if call.libpod {
        None
    } else {
        call.q_uint("timeout")?
    };
    let force = if call.libpod {
        force.map_err(internal)?
    } else {
        force?
    };
    let name = engine_call!(call.engine, network_remove(call.param(0), force, timeout))
        .map(|r| r.name)
        .map_err(|e| match e.status.as_u16() {
            // (the Docker route says no more than the error of the engine's kind)
            404 if !call.libpod => ApiError::not_found("network not found"),
            _ => e.as_podman_failure(),
        })?;
    if !call.libpod {
        return Ok(reply::empty(204));
    }
    Ok(reply::json(
        200,
        &serde_json::json!([{"Name": name, "Err": null}]),
    ))
}

async fn prune(call: Call) -> ApiResult {
    let filters = call.filters()?;
    let deleted = call.engine.network_prune(&filters).await?;
    if call.libpod {
        let out: Vec<serde_json::Value> = deleted
            .iter()
            .map(|n| serde_json::json!({"Name": n, "Error": null}))
            .collect();
        Ok(reply::json(200, &out))
    } else {
        Ok(reply::json(
            200,
            &serde_json::json!({"NetworksDeleted": deleted}),
        ))
    }
}

/// libpod: `POST /networks/{name}/update`.
async fn update(mut call: Call) -> ApiResult {
    let body: UpdateBody = call.json().await?;
    engine_call!(
        call.engine,
        network_update(call.param(0), body.adddnsservers, body.removednsservers)
    )?;
    Ok(reply::empty(204))
}

/// podman's WriteResponse of a string: the text.
fn ok_text() -> axum::response::Response {
    reply::with_type(200, "text/plain; charset=us-ascii", "OK\n")
}

async fn connect(mut call: Call) -> ApiResult {
    let body: ConnectBody = call.json_or_default().await?;
    let container = if call.libpod {
        body.container
    } else {
        body.docker_container
    };
    if container.is_empty() {
        return Err(ApiError::bad_request(
            "the container to connect must be specified",
        ));
    }
    let (ips, mac, aliases) = if call.libpod {
        refuse_field("interface_name", &body.interface_name.clone().into())?;
        if let Some(o) = &body.options {
            refuse_field("options", o)?;
        }
        (body.static_ips, body.static_mac, body.aliases)
    } else {
        let e = body.endpoint.unwrap_or_default();
        if let Some(l) = e.ipam.as_ref().and_then(|i| i.link_local_ips.as_ref()) {
            refuse_field("EndpointConfig.IPAMConfig.LinkLocalIPs", l)?;
        }
        let mut ips: Vec<String> = std::iter::once(e.ip_address)
            .chain(e.ipam.map(|i| [i.ipv4, i.ipv6]).into_iter().flatten())
            .filter(|i| !i.is_empty())
            .collect();
        ips.dedup();
        (ips, e.mac_address, e.aliases)
    };
    // one address of each family, as podman's static IPs on a network
    let (mut ip, mut ip6) = (None, None);
    for a in ips {
        let slot = match a.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(_)) => &mut ip,
            Ok(std::net::IpAddr::V6(_)) => &mut ip6,
            Err(_) => {
                return Err(ApiError::bad_request(format!(
                    "invalid static IP address `{a}`"
                )))
            }
        };
        if slot.replace(a).is_some() {
            return Err(ApiError::not_implemented(
                "more than one static IP address of a family is not supported",
            ));
        }
    }
    engine_call!(
        call.engine,
        network_connect(
            call.param(0),
            &container,
            ip.as_deref(),
            ip6.as_deref(),
            Some(mac.as_str()).filter(|m| !m.is_empty()),
            aliases
        )
    )?;
    Ok(ok_text())
}

async fn disconnect(mut call: Call) -> ApiResult {
    let body: DisconnectBody = call.json_or_default().await?;
    let container = if body.container.is_empty() {
        body.lower
    } else {
        body.container
    };
    if container.is_empty() {
        return Err(ApiError::bad_request(
            "the container to disconnect must be specified",
        ));
    }
    engine_call!(
        call.engine,
        network_disconnect(call.param(0), &container, body.force)
    )?;
    Ok(ok_text())
}

pub(super) static ROUTES: &[Route] = &[
    route!("POST", "/networks/create", BOTH, Network, create),
    route!("GET", "/networks/json", LIBPOD, Network, list),
    route!("GET", "/networks", COMPAT, Network, list),
    route!("POST", "/networks/prune", BOTH, Network, prune),
    route!("GET", "/networks/{}/json", LIBPOD, Network, inspect),
    route!("GET", "/networks/{}/exists", LIBPOD, Network, exists),
    route!("GET", "/networks/{}", BOTH, Network, inspect),
    route!("POST", "/networks/{}/update", LIBPOD, Network, update),
    route!("DELETE", "/networks/{}", BOTH, Network, remove),
    route!("POST", "/networks/{}/connect", BOTH, Network, connect),
    route!("POST", "/networks/{}/disconnect", BOTH, Network, disconnect),
];
