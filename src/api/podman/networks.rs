// SPDX-License-Identifier: Apache-2.0
//! Networks: the engine's records of them (`NetworkRecord`), with podman's
//! filters and words; `velarx_shape::network` lays out podman's and
//! Docker's documents.
//!
//! The network service keeps a name, a driver, the subnets and their
//! gateways; the rest (labels, the DNS servers, the lease range, internal,
//! the bridge) is in the options of its row, under the keys the service
//! reads (`label.NAME`, `dns`, `ip_range`, `internal`, `disable_dns`,
//! `interface_name`, `ipam_driver`).

use super::call::{label_matches, Filters};
use super::convert::record_time_ns;
use super::error::{ApiError, ApiResult};
use super::events::Event;
use crate::api::AppState;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use velarx_db::NetworkRecord as Row;
use velarx_db::RecordState;
use velarx_proto::workload::EventKind;
use velarx_proto::workload::{
    LeaseRange, NetworkDriver, NetworkMember, NetworkRecord, NetworkRoute, NetworkSpec,
    NetworkSubnet,
};
use velarx_runtime::container::ContainerConfig;
use velarx_runtime::network::{CreateNetworkRequest, NetworkDriver as Driver};
use velarx_wire::request::NetworkMode;

const LABEL: &str = "label.";

/// A network as its row has it.
#[derive(Debug, Clone)]
struct Net {
    id: String,
    name: String,
    driver: NetworkDriver,
    created_ns: i64,
    subnet: Option<String>,
    gateway: Option<String>,
    lease: Option<LeaseRange>,
    dns_enabled: bool,
    dns_servers: Vec<String>,
    labels: BTreeMap<String, String>,
    options: BTreeMap<String, String>,
    internal: bool,
    /// The bridge, when it was chosen.
    interface: Option<String>,
    ipam_driver: Option<String>,
    /// The network of the configuration, which cannot be removed.
    builtin: bool,
    /// The IPv6 subnet and gateway of a dual-stack network.
    subnet6: Option<String>,
    gateway6: Option<String>,
    routes: Vec<NetworkRoute>,
}

fn route_of(r: &velarx_wire::addr::Route) -> NetworkRoute {
    NetworkRoute {
        destination: format!("{}/{}", r.destination, r.prefix),
        gateway: r.gateway.to_string(),
        metric: r.metric,
    }
}

/// The driver of a row: rows are written from the drivers' names, so
/// another one is a corrupt row.
fn driver_of(name: &str) -> ApiResult<NetworkDriver> {
    Ok(match name {
        "bridge" => NetworkDriver::Bridge,
        "host" => NetworkDriver::Host,
        "none" => NetworkDriver::None,
        "overlay" => NetworkDriver::Overlay,
        "macvlan" => NetworkDriver::Macvlan,
        _ => {
            return Err(ApiError::internal(format!(
                "the stored network has the unknown driver `{name}`"
            )))
        }
    })
}

impl Net {
    fn from_row(r: &Row) -> ApiResult<Self> {
        let unreadable = |what: &str, e: &dyn std::fmt::Display| {
            ApiError::internal(format!("the stored network {} has {what}: {e}", r.name))
        };
        let all: HashMap<String, String> = match r.options.as_deref() {
            Some(o) => serde_json::from_str(o).map_err(|e| unreadable("unreadable options", &e))?,
            None => HashMap::new(),
        };
        let mut net = Net {
            id: r.id.clone(),
            name: r.name.clone(),
            driver: driver_of(&r.driver)?,
            created_ns: record_time_ns(&r.created_at),
            subnet: r.subnet.clone(),
            gateway: r.gateway.clone(),
            lease: None,
            dns_enabled: true,
            dns_servers: Vec::new(),
            labels: BTreeMap::new(),
            options: BTreeMap::new(),
            internal: false,
            interface: None,
            ipam_driver: None,
            builtin: false,
            subnet6: r.subnet6.clone(),
            gateway6: r.gateway6.clone(),
            routes: velarx_netdetach::def::stored_routes(&all)
                .map_err(|e| unreadable("unreadable routes", &e))?
                .iter()
                .map(route_of)
                .collect(),
        };
        for (k, v) in all {
            if let Some(l) = k.strip_prefix(LABEL) {
                net.labels.insert(l.to_string(), v);
                continue;
            }
            match k.as_str() {
                "internal" => net.internal = v == "true",
                "interface_name" => net.interface = Some(v),
                "disable_dns" => net.dns_enabled = v != "true",
                "dns" => {
                    net.dns_servers = v
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect()
                }
                "ip_range" => {
                    net.lease = v.split_once('-').map(|(a, b)| LeaseRange {
                        start: a.to_string(),
                        end: b.to_string(),
                    })
                }
                "ipam_driver" => net.ipam_driver = Some(v),
                "routes" => {}
                _ => {
                    net.options.insert(k, v);
                }
            }
        }
        Ok(net)
    }

    /// The options of the row.
    fn row_options(&self) -> HashMap<String, String> {
        let mut o: HashMap<String, String> = self
            .options
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, v) in &self.labels {
            o.insert(format!("{LABEL}{k}"), v.clone());
        }
        if !self.dns_enabled {
            o.insert("disable_dns".into(), "true".into());
        }
        if !self.dns_servers.is_empty() {
            o.insert("dns".into(), self.dns_servers.join(","));
        }
        if let Some(l) = &self.lease {
            o.insert("ip_range".into(), format!("{}-{}", l.start, l.end));
        }
        if self.internal {
            o.insert("internal".into(), "true".into());
        }
        if let Some(i) = &self.interface {
            o.insert("interface_name".into(), i.clone());
        }
        if let Some(d) = &self.ipam_driver {
            o.insert("ipam_driver".into(), d.clone());
        }
        o
    }

    fn matches_name(&self, key: &str) -> bool {
        self.name == key || self.id == key
    }

    /// The bridge, or the parent of a macvlan network.
    fn interface_name(&self) -> String {
        match self.driver {
            NetworkDriver::Bridge => match &self.interface {
                Some(i) => i.clone(),
                None => velarx_netdetach::def::default_bridge_name(&self.id),
            },
            NetworkDriver::Macvlan => self.options.get("parent").cloned().unwrap_or_default(),
            _ => String::new(),
        }
    }

    fn record(&self, containers: Vec<NetworkMember>) -> NetworkRecord {
        let mut subnets = Vec::new();
        if let Some(s) = &self.subnet {
            subnets.push(NetworkSubnet {
                subnet: s.clone(),
                gateway: self.gateway.clone().unwrap_or_default(),
                lease_range: self.lease.clone(),
            });
        }
        if let Some(s) = &self.subnet6 {
            subnets.push(NetworkSubnet {
                subnet: s.clone(),
                gateway: self.gateway6.clone().unwrap_or_default(),
                lease_range: None,
            });
        }
        NetworkRecord {
            name: self.name.clone(),
            id: self.id.clone(),
            driver: self.driver,
            interface: self.interface_name(),
            created_ns: self.created_ns,
            subnets,
            ipv6_enabled: self.subnet6.is_some(),
            internal: self.internal,
            dns_enabled: self.dns_enabled,
            dns_servers: self.dns_servers.clone(),
            labels: self.labels.clone(),
            options: self.options.clone(),
            ipam_options: BTreeMap::from([(
                "driver".to_string(),
                self.ipam_driver
                    .clone()
                    .unwrap_or_else(|| "host-local".to_string()),
            )]),
            routes: self.routes.clone(),
            builtin: self.builtin,
            containers,
        }
    }
}

fn builtin(state: &AppState) -> Net {
    let b = &state.config.network.bridge;
    Net {
        id: velarx_netdetach::def::builtin_id(velarx_netdetach::def::DEFAULT_NETWORK),
        name: velarx_netdetach::def::DEFAULT_NETWORK.to_string(),
        driver: NetworkDriver::Bridge,
        created_ns: 0,
        subnet: Some(b.subnet.clone()),
        gateway: Some(b.gateway.clone()),
        lease: None,
        dns_enabled: false,
        dns_servers: Vec::new(),
        labels: BTreeMap::new(),
        options: BTreeMap::new(),
        internal: false,
        interface: Some(b.default_bridge.clone()),
        ipam_driver: None,
        builtin: true,
        subnet6: None,
        gateway6: None,
        routes: Vec::new(),
    }
}

async fn all_networks(state: &AppState) -> ApiResult<Vec<Net>> {
    let mut nets = vec![builtin(state)];
    for r in state.db.list_networks().await? {
        nets.push(Net::from_row(&r)?);
    }
    Ok(nets)
}

/// By name, id or unique id prefix; "podman" and "bridge" are the network of
/// the configuration.
async fn find(state: &AppState, key: &str) -> ApiResult<Net> {
    let nets = all_networks(state).await?;
    let default = nets[0].name.clone();
    let key = if matches!(key, "podman" | "bridge") {
        default.as_str()
    } else {
        key
    };
    if let Some(n) = nets.iter().find(|n| n.matches_name(key)) {
        return Ok(n.clone());
    }
    let prefix: Vec<&Net> = nets
        .iter()
        .filter(|n| !key.is_empty() && n.id.starts_with(key))
        .collect();
    match prefix.as_slice() {
        [n] => Ok((*n).clone()),
        [] => Err(ApiError::not_found(format!(
            "unable to find network with name or ID {key}"
        ))),
        _ => Err(ApiError::bad_request(format!(
            "more than one network matches `{key}`"
        ))),
    }
}

/// The containers on the network, with their interfaces on it.
async fn members(state: &AppState, net: &Net) -> ApiResult<Vec<NetworkMember>> {
    let attached = state.network_service.engine().members(&net.id).await?;
    let mut out = Vec::new();
    for (id, _) in attached {
        if let Ok(c) = state.db.get_container(&id).await {
            out.push(NetworkMember {
                id: c.id,
                name: c.name.unwrap_or_default(),
                running: c.state == RecordState::Running,
                ..Default::default()
            });
        }
    }
    // The other drivers keep no attachment: the containers that name it.
    if net.driver != NetworkDriver::Bridge {
        for c in state.db.list_containers(true).await? {
            let Ok(cfg) = serde_json::from_str::<ContainerConfig>(&c.config) else {
                continue;
            };
            if cfg.networks.iter().any(|n| {
                let n = NetworkMode::network_name(n);
                n == net.name || n == net.id
            }) {
                out.push(NetworkMember {
                    running: c.state == RecordState::Running,
                    id: c.id,
                    name: c.name.unwrap_or_default(),
                    ..Default::default()
                });
            }
        }
    }
    for m in &mut out {
        let ifaces = state.network_service.engine().interfaces(&m.id).await?;
        if let Some(i) = ifaces.iter().find(|i| i.network_id == net.id) {
            m.mac_address = i.mac.clone();
            m.ipv4 =
                i.ip.map(|ip| format!("{ip}/{}", i.prefix))
                    .unwrap_or_default();
            m.ipv6 = i
                .ip6
                .map(|ip| format!("{ip}/{}", i.prefix6))
                .unwrap_or_default();
        }
    }
    Ok(out)
}

/// The filters of a list (or, with `prune`, of a prune) as podman takes
/// them: anything else is a 500, `dangling` takes one boolean.
fn check_filters(filters: &Filters, prune: bool) -> ApiResult<()> {
    for (key, values) in &filters.0 {
        let known = match key.as_str() {
            "label" | "label!" | "until" => true,
            "name" | "driver" | "id" | "type" => !prune,
            "dangling" if !prune => {
                match values.as_slice() {
                    [v] if super::call::parse_bool(v).is_some() => {}
                    [v] => {
                        return Err(ApiError::bad_request(format!(
                            "invalid dangling filter value \"{v}\""
                        )))
                    }
                    [] => {
                        return Err(ApiError::bad_request(
                            "got no values for filter key \"dangling\"",
                        ))
                    }
                    _ => {
                        return Err(ApiError::bad_request(
                            "got more than one value for filter key \"dangling\"",
                        ))
                    }
                }
                true
            }
            _ => false,
        };
        if !known {
            return Err(ApiError::bad_request(format!("invalid filter {key:?}")));
        }
        if key == "until"
            && values
                .iter()
                .any(|u| super::events::parse_since(u).is_none())
        {
            return Err(ApiError::bad_request(format!(
                "invalid until filter {values:?}"
            )));
        }
    }
    Ok(())
}

/// Whether the network was created before the `until` filter.
fn created_before(filters: &Filters, n: &Net) -> bool {
    filters
        .get("until")
        .iter()
        .filter_map(|u| super::events::parse_since(u))
        .all(|until| n.created_ns < until)
}

/// `network ls` filters; the label filters are ANDed, the values of the
/// others ORed.
fn filter_match(filters: &Filters, n: &Net, dangling: bool) -> bool {
    for (key, values) in &filters.0 {
        if values.is_empty() {
            continue;
        }
        let ok = match key.as_str() {
            "label" => values.iter().all(|v| label_matches(&n.labels, v)),
            "label!" => !values.iter().any(|v| label_matches(&n.labels, v)),
            "until" => created_before(filters, n),
            "name" => values.iter().any(|v| n.name.contains(v.as_str())),
            "id" => values.iter().any(|v| n.id.starts_with(v.as_str())),
            "driver" => values.iter().any(|v| v == n.driver.as_str()),
            "type" => values.iter().any(|v| {
                (v == "builtin") == n.builtin && matches!(v.as_str(), "builtin" | "custom")
            }),
            "dangling" => values
                .iter()
                .any(|v| super::call::parse_bool(v) == Some(dangling)),
            _ => true,
        };
        if !ok {
            return false;
        }
    }
    true
}

/// The networks `filters` selects.
pub(crate) async fn list_of(state: &AppState, filters: &Filters) -> ApiResult<Vec<NetworkRecord>> {
    check_filters(filters, false)?;
    let mut out = Vec::new();
    for n in all_networks(state).await? {
        let m = members(state, &n).await?;
        if filter_match(filters, &n, m.is_empty()) {
            out.push(n.record(m));
        }
    }
    Ok(out)
}

/// A network by name, id or unique prefix of an id.
pub(crate) async fn inspect_of(state: &AppState, name: &str) -> ApiResult<NetworkRecord> {
    let n = find(state, name).await?;
    let m = members(state, &n).await?;
    Ok(n.record(m))
}

/// The network is there.
pub(crate) async fn exists_of(state: &AppState, name: &str) -> ApiResult<()> {
    find(state, name).await.map(|_| ())
}

/// Create the network `spec` says: whether it was made (with
/// `ignore_if_exists`, one of that name is the answer), and its record.
pub(crate) async fn create_of(
    state: &Arc<AppState>,
    spec: &NetworkSpec,
    ignore_if_exists: bool,
) -> ApiResult<(bool, NetworkRecord)> {
    if spec.name.is_empty() {
        return Err(ApiError::bad_request("a network needs a name"));
    }
    if ignore_if_exists {
        if let Ok(n) = find(state, &spec.name).await {
            let m = members(state, &n).await?;
            return Ok((false, n.record(m)));
        }
    }
    let driver = match spec.driver.as_str() {
        "" | "bridge" => Driver::Bridge,
        "macvlan" => Driver::Macvlan,
        "host" => Driver::Host,
        "none" => Driver::None,
        d => {
            return Err(ApiError::not_implemented(format!(
                "the network driver `{d}` is not supported"
            )))
        }
    };
    if let Some(d) = spec.ipam_driver.as_deref().filter(|d| *d != "host-local") {
        return Err(ApiError::not_implemented(format!(
            "the IPAM driver `{d}` is not supported"
        )));
    }
    let existing = all_networks(state).await?;
    if existing.iter().any(|n| n.name == spec.name) {
        return Err(ApiError::conflict(format!(
            "network name {} already used: network already exists",
            spec.name
        ))
        .with_cause("network already exists"));
    }
    let net = Net {
        id: String::new(),
        name: spec.name.clone(),
        driver: driver_of(driver.as_str())?,
        created_ns: 0,
        subnet: spec.subnet.clone(),
        gateway: spec.gateway.clone(),
        lease: spec.lease.clone(),
        dns_enabled: spec.dns_enabled,
        dns_servers: spec.dns_servers.clone(),
        labels: spec.labels.clone(),
        options: spec.options.clone(),
        internal: spec.internal,
        interface: spec.interface.clone(),
        ipam_driver: spec.ipam_driver.clone(),
        builtin: false,
        subnet6: spec.subnet6.clone(),
        gateway6: spec.gateway6.clone(),
        routes: spec.routes.clone(),
    };
    let mut options = net.row_options();
    if spec.ipv6 {
        options.insert("ipv6".into(), "true".into());
    }
    let id = state
        .network_service
        .create(CreateNetworkRequest {
            name: spec.name.clone(),
            driver,
            subnet: spec.subnet.clone(),
            gateway: spec.gateway.clone(),
            subnet6: spec.subnet6.clone(),
            gateway6: spec.gateway6.clone(),
            options,
            routes: spec
                .routes
                .iter()
                .map(|r| {
                    let metric = r.metric.map(|m| format!(",{m}")).unwrap_or_default();
                    velarx_wire::addr::Route::parse(&format!(
                        "{},{}{metric}",
                        r.destination, r.gateway
                    ))
                    .map_err(ApiError::bad_request)
                })
                .collect::<ApiResult<_>>()?,
        })
        .await?;
    state.podman.events.emit(
        Event::new(EventKind::Network, "create", &id, &spec.name)
            .attr("network", &spec.name)
            .attr("driver", net.driver.as_str()),
    );
    let n = find(state, &id).await?;
    Ok((true, n.record(Vec::new())))
}

async fn remove_net(
    state: &std::sync::Arc<AppState>,
    n: &Net,
    force: bool,
    timeout: Option<u64>,
) -> ApiResult<Vec<String>> {
    if n.builtin {
        return Err(ApiError::internal(format!(
            "network {} is the default network and cannot be removed",
            n.name
        )));
    }
    let mut warnings = Vec::new();
    // (a container that joins while the users are removed is one more: the
    // network goes once none is left, counted where it is removed)
    for round in 1.. {
        let users = members(state, n).await?;
        if !users.is_empty() {
            if !force {
                return Err(ApiError::invalid_state(format!(
                    "\"{}\" has associated containers with it. Use -f to forcibly delete containers and pods: network is being used",
                    n.name
                ))
                .with_cause("network is being used"));
            }
            // they stop with `timeout` seconds to obey their stop signal
            for m in &users {
                let rec = super::lifecycle::resolve(state, &m.id).await?;
                warnings.extend(
                    super::lifecycle::remove_with_timeout(state, &rec, true, false, timeout)
                        .await?,
                );
            }
        }
        // (bounded: whatever still counts after that goes with the network)
        match state.network_service.delete(&n.id, round >= 10).await {
            Err(velarx_netkernel::error::NetworkError::Busy(_)) if force => {}
            r => {
                r?;
                break;
            }
        }
    }
    state.podman.events.emit(
        Event::new(EventKind::Network, "remove", &n.id, &n.name)
            .attr("network", &n.name)
            .attr("driver", n.driver.as_str()),
    );
    Ok(warnings)
}

/// Remove the network: its name, and podman's warnings of the stops of its
/// containers that needed the kill.
pub(crate) async fn remove_of(
    state: &Arc<AppState>,
    name: &str,
    force: bool,
    timeout: Option<u64>,
) -> ApiResult<(String, Vec<String>)> {
    let n = match find(state, name).await {
        // (a stored network that cannot be read is not listed: the service
        // refuses to remove it, and with FORCE removes it by its bridge)
        Err(e) if e.status == crate::api::status::StatusCode::NOT_FOUND => {
            state.network_service.delete(name, force).await?;
            return Ok((name.to_string(), Vec::new()));
        }
        r => r?,
    };
    let warnings = remove_net(state, &n, force, timeout).await?;
    Ok((n.name, warnings))
}

/// Remove the networks no container uses that `filters` selects (and the
/// pooled network namespaces): their names.
pub(crate) async fn prune_of(state: &Arc<AppState>, filters: &Filters) -> ApiResult<Vec<String>> {
    check_filters(filters, true)?;
    filters.check_prune_until()?;
    // the pooled namespaces are unused too
    state.network_service.engine().pool_drain(None).await?;
    let mut deleted = Vec::new();
    for n in all_networks(state).await? {
        if n.builtin || !members(state, &n).await?.is_empty() {
            continue;
        }
        if !filters
            .get("label")
            .iter()
            .all(|l| label_matches(&n.labels, l))
            || filters
                .get("label!")
                .iter()
                .any(|l| label_matches(&n.labels, l))
            || !created_before(filters, &n)
        {
            continue;
        }
        if remove_net(state, &n, false, Some(0)).await.is_ok() {
            deleted.push(n.name);
        }
    }
    Ok(deleted)
}

/// Add and remove DNS servers of the network.
pub(crate) async fn update_of(
    state: &Arc<AppState>,
    name: &str,
    add: &[String],
    remove: &[String],
) -> ApiResult<()> {
    let n = find(state, name).await?;
    if n.builtin {
        return Err(ApiError::bad_request(
            "the default network cannot be updated",
        ));
    }
    for s in add {
        if s.parse::<std::net::IpAddr>().is_err() {
            return Err(ApiError::bad_request(format!("invalid DNS server `{s}`")));
        }
    }
    state.network_service.update_dns(&n.id, add, remove).await?;
    state.podman.events.emit(
        Event::new(EventKind::Network, "update", &n.id, &n.name).attr("driver", n.driver.as_str()),
    );
    Ok(())
}

/// Connect the container to the network.
pub(crate) async fn connect_of(
    state: &Arc<AppState>,
    network: &str,
    container: &str,
    ip: Option<String>,
    ip6: Option<String>,
    mac: Option<String>,
    aliases: &[String],
) -> ApiResult<()> {
    let n = find(state, network).await?;
    let c = state.container_service.inspect(container).await?;
    let name = c.name.clone().unwrap_or_default();
    // (a holder of the rootless network namespace started for a container
    // without cgroups stays in the caller's cgroup)
    let request = velarx_runtime::network::ConnectRequest::parse(
        (&c.id, &name),
        ip.as_deref(),
        ip6.as_deref(),
        mac.as_deref(),
        aliases,
    )?;
    velarx_runtime::network::rootless_netns::in_caller_cgroup(
        !velarx_core::services::has_own_cgroup(&c),
        state.network_service.connect(&n.id, &request),
    )
    .await?;
    state.podman.events.emit(
        Event::new(EventKind::Network, "connect", &n.id, &n.name)
            .attr("container", c.id)
            .attr("driver", n.driver.as_str()),
    );
    Ok(())
}

/// Apply the firewall rules of the networks of the container again, as
/// podman's `network reload`: its ID.  With IF_CONFIGURED a container that
/// does not run, or without a bridge network, is none of the call's
/// business: the ID is empty.
pub(crate) async fn reload_of(
    state: &Arc<AppState>,
    container: &str,
    if_configured: bool,
) -> ApiResult<String> {
    let c = state.container_service.inspect(container).await?;
    if c.state != RecordState::Running {
        if if_configured {
            return Ok(String::new());
        }
        return Err(ApiError::invalid_state(
            "cannot reload network unless container network has been configured: container state improper",
        ));
    }
    let done = velarx_runtime::network::rootless_netns::in_caller_cgroup(
        !velarx_core::services::has_own_cgroup(&c),
        state.network_service.reload(&c.id),
    )
    .await?;
    match (done, if_configured) {
        (true, _) => Ok(c.id),
        (false, true) => Ok(String::new()),
        (false, false) => Err(ApiError::invalid_state(format!(
            "container {} network is not configured, refusing to reload: container state improper",
            c.id
        ))),
    }
}

/// Disconnect the container from the network.
pub(crate) async fn disconnect_of(
    state: &Arc<AppState>,
    network: &str,
    container: &str,
    force: bool,
) -> ApiResult<()> {
    let n = find(state, network).await?;
    let c = state.container_service.inspect(container).await?;
    let name = c.name.clone().unwrap_or_default();
    state
        .network_service
        .disconnect(&n.id, &c.id, &name, force)
        .await?;
    state.podman.events.emit(
        Event::new(EventKind::Network, "disconnect", &n.id, &n.name)
            .attr("container", c.id)
            .attr("driver", n.driver.as_str()),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(options: &str) -> Row {
        Row {
            id: "0123456789ab".into(),
            name: "n".into(),
            driver: "bridge".into(),
            subnet: Some("10.151.0.0/24".into()),
            gateway: Some("10.151.0.1".into()),
            options: Some(options.into()),
            created_at: "2026-01-02T03:04:05Z".into(),
            subnet6: None,
            gateway6: None,
        }
    }

    #[test]
    fn the_options_of_the_row_round_trip() {
        let mut n = Net::from_row(&row("{}")).unwrap();
        n.labels.insert("a".into(), "b".into());
        n.dns_servers = vec!["10.0.0.53".into()];
        n.dns_enabled = false;
        n.lease = Some(LeaseRange {
            start: "10.151.0.0".into(),
            end: "10.151.0.127".into(),
        });
        n.ipam_driver = Some("host-local".into());
        let options = serde_json::to_string(&n.row_options()).unwrap();
        let back = Net::from_row(&row(&options)).unwrap();
        assert_eq!(back.labels["a"], "b");
        assert_eq!(back.dns_servers, ["10.0.0.53"]);
        assert!(!back.dns_enabled);
        assert_eq!(back.lease, n.lease);
        assert_eq!(back.ipam_driver.as_deref(), Some("host-local"));
        assert!(back.options.is_empty());
    }

    #[test]
    fn the_record_of_a_network() {
        let mut n = Net::from_row(&row(r#"{"mtu":"1400","dns":"10.0.0.53"}"#)).unwrap();
        n.subnet6 = Some("fd00::/64".into());
        let r = n.record(Vec::new());
        assert_eq!(r.subnets[0].subnet, "10.151.0.0/24");
        assert_eq!(r.subnets[0].gateway, "10.151.0.1");
        assert_eq!(r.subnets[1].subnet, "fd00::/64");
        assert!(r.ipv6_enabled);
        assert_eq!(r.dns_servers, ["10.0.0.53"]);
        assert_eq!(r.interface, "br-01234567");
        assert_eq!(r.created_ns, 1_767_323_045_000_000_000);
        assert_eq!(r.options["mtu"], "1400");
        assert_eq!(r.ipam_options["driver"], "host-local");
        let mut bogus = row("{}");
        bogus.driver = "bogus".into();
        let e = Net::from_row(&bogus).unwrap_err();
        assert!(e.message.contains("bogus"), "{}", e.message);
    }
}
