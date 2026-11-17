// SPDX-License-Identifier: Apache-2.0
//! Networks: podman's types.Network and Docker's NetworkResource.

use crate::{string_map, time::rfc3339};
use serde_json::{json, Map, Value};
use std::net::Ipv4Addr;
use velarx_proto::workload::{NetworkRecord, NetworkSubnet};

/// The IPv4 subnet of the network (the first that is not IPv6).
fn v4(n: &NetworkRecord) -> Option<&NetworkSubnet> {
    n.subnets.iter().find(|s| !s.subnet.contains(':'))
}

fn v6(n: &NetworkRecord) -> Option<&NetworkSubnet> {
    n.subnets.iter().find(|s| s.subnet.contains(':'))
}

/// podman's types.Network, as `podman network ls` has it.
pub fn libpod(n: &NetworkRecord) -> Value {
    let subnets: Vec<Value> = n
        .subnets
        .iter()
        .map(|s| {
            let mut sn = Map::new();
            sn.insert("subnet".into(), json!(s.subnet));
            if !s.gateway.is_empty() {
                sn.insert("gateway".into(), json!(s.gateway));
            }
            if let Some(l) = &s.lease_range {
                sn.insert(
                    "lease_range".into(),
                    json!({"start_ip": l.start, "end_ip": l.end}),
                );
            }
            Value::Object(sn)
        })
        .collect();
    let mut o = json!({
        "name": n.name,
        "id": n.id,
        "driver": n.driver.as_str(),
        "network_interface": n.interface,
        "created": rfc3339(n.created_ns),
        "subnets": subnets,
        "ipv6_enabled": n.ipv6_enabled,
        "internal": n.internal,
        "dns_enabled": n.dns_enabled,
        "ipam_options": string_map(&n.ipam_options),
    });
    // (podman's omitempty: left out when empty)
    if let Some(m) = o.as_object_mut() {
        if !n.labels.is_empty() {
            m.insert("labels".into(), string_map(&n.labels));
        }
        if !n.options.is_empty() {
            m.insert("options".into(), string_map(&n.options));
        }
        if !n.dns_servers.is_empty() {
            m.insert("network_dns_servers".into(), json!(n.dns_servers));
        }
        if !n.routes.is_empty() {
            let routes: Vec<Value> = n
                .routes
                .iter()
                .map(|r| {
                    let mut o = json!({"destination": r.destination, "gateway": r.gateway});
                    if let Some(metric) = r.metric {
                        o["metric"] = json!(metric);
                    }
                    o
                })
                .collect();
            m.insert("routes".into(), Value::Array(routes));
        }
    }
    o
}

/// podman's inspect of a network: its list entry with the containers that
/// run on it and their interfaces.
pub fn libpod_inspect(n: &NetworkRecord) -> Value {
    let mut o = libpod(n);
    let gateway = |s: Option<&NetworkSubnet>| s.map(|s| s.gateway.clone()).unwrap_or_default();
    let containers: Map<String, Value> = n
        .containers
        .iter()
        .filter(|m| m.running)
        .map(|m| {
            let mut subnets = Vec::new();
            for (ipnet, gw) in [(&m.ipv4, gateway(v4(n))), (&m.ipv6, gateway(v6(n)))] {
                if !ipnet.is_empty() {
                    subnets.push(json!({"ipnet": ipnet, "gateway": gw}));
                }
            }
            let iface = json!({"subnets": subnets, "mac_address": m.mac_address});
            (
                m.id.clone(),
                json!({"name": m.name, "interfaces": {"eth0": iface}}),
            )
        })
        .collect();
    o["containers"] = Value::Object(containers);
    o
}

/// The CIDR of the range, if it is one.
fn range_cidr(start: &str, end: &str) -> Option<String> {
    let a: Ipv4Addr = start.parse().ok()?;
    let b: Ipv4Addr = end.parse().ok()?;
    let (first, last) = (u32::from(a), u32::from(b));
    if last < first {
        return None;
    }
    let size = last - first + 1;
    if size & (size - 1) != 0 || first & (size - 1) != 0 {
        return None;
    }
    Some(format!("{a}/{}", 32 - size.trailing_zeros()))
}

/// Docker's NetworkResource.  The network of the configuration is
/// `bridge` (podman's compat name), unless it was `asked` for by its own
/// name.
pub fn docker(n: &NetworkRecord, asked: Option<&str>) -> Value {
    let name = if n.builtin && asked != Some(n.name.as_str()) {
        "bridge"
    } else {
        n.name.as_str()
    };
    let cfg: Vec<Value> = n
        .subnets
        .iter()
        .map(|s| {
            let mut c = Map::new();
            c.insert("Subnet".into(), json!(s.subnet));
            c.insert("Gateway".into(), json!(s.gateway));
            if let Some(r) = s
                .lease_range
                .as_ref()
                .and_then(|l| range_cidr(&l.start, &l.end))
            {
                c.insert("IPRange".into(), json!(r));
            }
            Value::Object(c)
        })
        .collect();
    let containers: Map<String, Value> = n
        .containers
        .iter()
        .map(|m| {
            (
                m.id.clone(),
                json!({
                    "Name": m.name,
                    "EndpointID": "",
                    "MacAddress": m.mac_address,
                    "IPv4Address": m.ipv4,
                    "IPv6Address": m.ipv6,
                }),
            )
        })
        .collect();
    let mut options = Map::new();
    if let Some(mtu) = n.options.get("mtu") {
        options.insert("com.docker.network.driver.mtu".into(), json!(mtu));
    }
    json!({
        "Name": name,
        "Id": n.id,
        "Created": rfc3339(n.created_ns),
        "Scope": "local",
        "Driver": n.driver.as_str(),
        "EnableIPv4": true,
        "EnableIPv6": n.ipv6_enabled,
        "IPAM": {"Driver": "default", "Options": {}, "Config": cfg},
        "Internal": n.internal,
        "Attachable": false,
        "Ingress": false,
        "ConfigOnly": false,
        "Containers": containers,
        "Options": options,
        "Labels": string_map(&n.labels),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_proto::workload::{LeaseRange, NetworkMember, NetworkRoute};

    fn net() -> NetworkRecord {
        NetworkRecord {
            name: "n".into(),
            id: "0123456789ab".into(),
            interface: "br-01234567".into(),
            created_ns: 1_767_323_045_000_000_000,
            subnets: vec![NetworkSubnet {
                subnet: "10.151.0.0/24".into(),
                gateway: "10.151.0.1".into(),
                lease_range: None,
            }],
            dns_enabled: true,
            ipam_options: [("driver".to_string(), "host-local".to_string())].into(),
            ..Default::default()
        }
    }

    #[test]
    fn podman_routes() {
        let mut n = net();
        assert!(libpod(&n).get("routes").is_none());
        n.routes = vec![
            NetworkRoute {
                destination: "10.0.0.0/24".into(),
                gateway: "10.151.0.5".into(),
                metric: None,
            },
            NetworkRoute {
                destination: "10.1.0.0/16".into(),
                gateway: "10.151.0.6".into(),
                metric: Some(100),
            },
        ];
        let j = libpod(&n);
        assert_eq!(
            j["routes"][0],
            json!({"destination": "10.0.0.0/24", "gateway": "10.151.0.5"})
        );
        assert_eq!(j["routes"][1]["metric"], 100);
    }

    #[test]
    fn podman_shape() {
        let mut n = net();
        n.dns_servers = vec!["10.0.0.53".into()];
        let j = libpod(&n);
        assert_eq!(j["subnets"][0]["subnet"], "10.151.0.0/24");
        assert_eq!(j["subnets"][0]["gateway"], "10.151.0.1");
        assert_eq!(j["network_dns_servers"][0], "10.0.0.53");
        assert_eq!(j["network_interface"], "br-01234567");
        assert_eq!(j["created"], "2026-01-02T03:04:05Z");
        assert_eq!(j["driver"], "bridge");
        assert_eq!(j["ipam_options"]["driver"], "host-local");
        assert!(j.get("containers").is_none());
        assert!(libpod(&net()).get("network_dns_servers").is_none());
        assert_eq!(
            libpod(&NetworkRecord::default())["created"],
            "0001-01-01T00:00:00Z"
        );
    }

    #[test]
    fn podman_inspect_has_the_running_containers() {
        let mut n = net();
        n.containers = vec![
            NetworkMember {
                id: "cid".into(),
                name: "web".into(),
                running: true,
                mac_address: "0a:01:73:78:43:18".into(),
                ipv4: "10.151.0.2/24".into(),
                ipv6: String::new(),
            },
            NetworkMember {
                id: "off".into(),
                name: "down".into(),
                ..Default::default()
            },
        ];
        let j = libpod_inspect(&n);
        let c = &j["containers"]["cid"];
        assert_eq!(c["name"], "web");
        assert_eq!(c["interfaces"]["eth0"]["mac_address"], "0a:01:73:78:43:18");
        assert_eq!(
            c["interfaces"]["eth0"]["subnets"],
            json!([{"ipnet": "10.151.0.2/24", "gateway": "10.151.0.1"}])
        );
        assert!(j["containers"].get("off").is_none());
    }

    #[test]
    fn docker_shape() {
        let mut n = net();
        n.options.insert("mtu".into(), "1400".into());
        n.subnets[0].lease_range = Some(LeaseRange {
            start: "10.151.0.0".into(),
            end: "10.151.0.127".into(),
        });
        n.containers = vec![NetworkMember {
            id: "cid".into(),
            name: "web".into(),
            running: true,
            mac_address: "0a:01:73:78:43:18".into(),
            ipv4: "10.151.0.2/24".into(),
            ipv6: String::new(),
        }];
        let j = docker(&n, None);
        assert_eq!(j["Containers"]["cid"]["IPv4Address"], "10.151.0.2/24");
        assert_eq!(j["Containers"]["cid"]["MacAddress"], "0a:01:73:78:43:18");
        assert_eq!(j["IPAM"]["Config"][0]["IPRange"], "10.151.0.0/25");
        assert_eq!(j["Containers"]["cid"]["Name"], "web");
        assert_eq!(j["Options"]["com.docker.network.driver.mtu"], "1400");
        assert_eq!(j["Name"], "n");
    }

    #[test]
    fn docker_names_the_default_network_bridge() {
        let mut n = net();
        n.name = "podman".into();
        n.builtin = true;
        assert_eq!(docker(&n, None)["Name"], "bridge");
        assert_eq!(docker(&n, Some("bridge"))["Name"], "bridge");
        assert_eq!(docker(&n, Some("podman"))["Name"], "podman");
    }

    #[test]
    fn a_range_is_a_cidr_when_it_is_one() {
        assert_eq!(
            range_cidr("10.0.0.0", "10.0.0.255").as_deref(),
            Some("10.0.0.0/24")
        );
        assert_eq!(range_cidr("10.0.0.1", "10.0.0.5"), None);
        assert_eq!(range_cidr("10.0.0.5", "10.0.0.1"), None);
    }
}
