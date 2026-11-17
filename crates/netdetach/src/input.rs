// SPDX-License-Identifier: Apache-2.0
//! What the bridge setup and teardown of a container need, from the rows.

use crate::def::NetworkDef;
use crate::spec::read_spec;
use velarx_config::BridgeConfig;
use velarx_db::sync::Access;
use velarx_netkernel::bridge::{Attachment, BridgeContainer};
use velarx_netkernel::error::{NetworkError, NetworkResult};
use velarx_wire::addr;

/// The bridge network with the id (or name) `id`.
pub fn network_by_id(a: &impl Access, cfg: &BridgeConfig, id: &str) -> NetworkResult<NetworkDef> {
    let builtin = NetworkDef::builtin(cfg)?;
    if id == builtin.id {
        return Ok(builtin);
    }
    let owned = id.to_string();
    let r = a.call(move |c| velarx_db::get_network(c, &owned))?;
    NetworkDef::from_record(&r)?
        .ok_or_else(|| NetworkError::InvalidConfig(format!("`{}` is not a bridge network", r.name)))
}

/// The input of the bridge setup of the container: all its networks, or
/// ONLY one (connect/disconnect: without the published ports).
pub fn bridge_input(
    a: &impl Access,
    cfg: &BridgeConfig,
    id: &str,
    only: Option<&str>,
) -> NetworkResult<Option<BridgeContainer>> {
    let spec = read_spec(a, id)?.unwrap_or_default();
    let mut attachments = Vec::new();
    let owned = id.to_string();
    for row in a.call(move |c| velarx_db::network_ext::net_attachments_of_container(c, &owned))? {
        if only.is_some_and(|o| o != row.network_id) {
            continue;
        }
        // (a network removed meanwhile: its removal takes down its bridge
        // and rules; one that cannot be read is an error)
        let n = match network_by_id(a, cfg, &row.network_id) {
            Ok(n) => n,
            Err(NetworkError::Database(velarx_types::DbError::NotFound(_))) => continue,
            Err(e) => return Err(e),
        };
        let Some(ip) = row.ip else {
            return Err(NetworkError::InvalidConfig(format!(
                "the container has no address on the network `{}`",
                n.name
            )));
        };
        let mac = match (spec.macs.get(&row.network_id), &spec.mac, row.idx) {
            (Some(m), ..) | (None, Some(m), 0) => addr::parse_mac(m),
            _ => Some(addr::derive_mac(ip)),
        };
        attachments.push(Attachment {
            net: n.net_def(),
            ifname: format!("eth{}", row.idx),
            ip,
            mac,
            aliases: row.aliases,
            ip6: row.ip6,
        });
    }
    if attachments.is_empty() {
        return Ok(None);
    }
    Ok(Some(BridgeContainer {
        id: id.to_string(),
        name: spec.name.clone(),
        attachments,
        ports: if only.is_some() {
            Vec::new()
        } else {
            spec.port_specs()?
        },
    }))
}
