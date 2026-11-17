// SPDX-License-Identifier: Apache-2.0
//! What the network setup keeps of a container, as the database has it.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use velarx_netkernel::error::{NetworkError, NetworkResult};
use velarx_wire::addr::PortSpec;

/// How a container is connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Bridge networks (the attachments).
    Bridge,
    Pasta,
    Host,
    #[default]
    None,
    /// `cni:NAME`: the plugins of a CNI configuration.
    Cni,
    /// `container:`, `ns:`, `provider:`: not set up here.
    Other,
}

/// What the network setup keeps of a container.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetSpec {
    pub mode: Mode,
    #[serde(default)]
    pub name: String,
    /// Published ports, the host ports resolved.
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub mac: Option<String>,
    /// The MAC addresses `network connect` asked for, by network id.
    #[serde(default)]
    pub macs: BTreeMap<String, String>,
    #[serde(default)]
    pub shareable: bool,
    /// `--network pasta:OPTIONS`.
    #[serde(default)]
    pub pasta_options: Vec<String>,
    /// `cni:NAME`: the CNI network (empty: the first configuration).
    #[serde(default)]
    pub cni: String,
    /// What the CNI plugins are told of the pod: `io.kubernetes.pod.name`,
    /// `.namespace` and `.uid` of the annotations of the container.
    #[serde(default)]
    pub cni_pod: BTreeMap<String, String>,
    /// The annotations of the pod, for the bandwidth and pod annotation
    /// capabilities of the plugins.
    #[serde(default)]
    pub cni_annotations: BTreeMap<String, String>,
    /// The subnets of the node's pods, for the `ipRanges` capability.
    #[serde(default)]
    pub cni_ip_ranges: Vec<String>,
}

/// The setup of a container as the database has it.
pub fn parse_spec(id: &str, text: &str) -> NetworkResult<NetSpec> {
    serde_json::from_str(text).map_err(|e| {
        NetworkError::Unreadable(format!(
            "the network setup of container {id} cannot be read: {e}"
        ))
    })
}

impl NetSpec {
    pub fn port_specs(&self) -> NetworkResult<Vec<PortSpec>> {
        self.ports
            .iter()
            .map(|p| PortSpec::parse(p).map_err(NetworkError::InvalidConfig))
            .collect()
    }
}

/// The setup of the container `id` as the database has it.
pub fn read_spec(a: &impl velarx_db::sync::Access, id: &str) -> NetworkResult<Option<NetSpec>> {
    let owned = id.to_string();
    a.call(move |c| velarx_db::network_ext::net_container_spec(c, &owned))?
        .map(|s| parse_spec(id, &s))
        .transpose()
}
