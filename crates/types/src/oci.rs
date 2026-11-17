// SPDX-License-Identifier: Apache-2.0
use crate::digest::Digest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: i32,
    #[serde(rename = "mediaType", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub config: OciDescriptor,
    pub layers: Vec<OciDescriptor>,
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        serialize_with = "sorted"
    )]
    pub annotations: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciDescriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: Digest,
    pub size: i64,
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        serialize_with = "sorted"
    )]
    pub annotations: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciConfig {
    pub architecture: String,
    pub os: String,
    #[serde(default, deserialize_with = "nullable")]
    pub config: OciImageConfig,
    #[serde(default, deserialize_with = "nullable")]
    pub rootfs: OciRootfs,
    #[serde(default, deserialize_with = "nullable")]
    pub history: Vec<OciHistory>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OciImageConfig {
    #[serde(default, deserialize_with = "nullable", rename = "User")]
    pub user: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        serialize_with = "sorted",
        rename = "ExposedPorts"
    )]
    pub exposed_ports: HashMap<String, serde_json::Value>,
    #[serde(default, deserialize_with = "nullable", rename = "Env")]
    pub env: Vec<String>,
    #[serde(default, rename = "Entrypoint")]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default, rename = "Cmd")]
    pub cmd: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "nullable",
        serialize_with = "sorted",
        rename = "Volumes"
    )]
    pub volumes: HashMap<String, serde_json::Value>,
    #[serde(default, deserialize_with = "nullable", rename = "WorkingDir")]
    pub working_dir: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        serialize_with = "sorted",
        rename = "Labels"
    )]
    pub labels: HashMap<String, String>,
    #[serde(default, deserialize_with = "nullable", rename = "StopSignal")]
    pub stop_signal: String,
    #[serde(
        default,
        rename = "Healthcheck",
        skip_serializing_if = "Option::is_none"
    )]
    pub healthcheck: Option<OciHealthcheck>,
}

/// A map written with its keys in order, as Go writes a map: the bytes of a
/// manifest or a config, and so its digest, are the same at every write (a
/// `HashMap` iterates in another order in each process).
fn sorted<S, V>(map: &HashMap<String, V>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    V: Serialize,
{
    s.collect_map(map.iter().collect::<std::collections::BTreeMap<_, _>>())
}

/// A member that Go writes as null when it is empty (`"Labels": null`).
fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// The `HEALTHCHECK` of an image (durations in nanoseconds).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OciHealthcheck {
    #[serde(default, deserialize_with = "nullable", rename = "Test")]
    pub test: Vec<String>,
    #[serde(default, deserialize_with = "nullable", rename = "Interval")]
    pub interval: u64,
    #[serde(default, deserialize_with = "nullable", rename = "Timeout")]
    pub timeout: u64,
    #[serde(default, deserialize_with = "nullable", rename = "StartPeriod")]
    pub start_period: u64,
    #[serde(default, deserialize_with = "nullable", rename = "Retries")]
    pub retries: u32,
    #[serde(default, deserialize_with = "nullable", rename = "StartInterval")]
    pub start_interval: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OciRootfs {
    #[serde(rename = "type")]
    pub rootfs_type: String,
    #[serde(default, deserialize_with = "nullable")]
    pub diff_ids: Vec<Digest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciHistory {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(default)]
    pub empty_layer: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configs_with_null_members_parse() {
        let c: OciConfig = serde_json::from_str(
            r#"{"architecture":"amd64","os":"linux","config":{"Env":null,"Volumes":null,
               "Labels":null,"ExposedPorts":null,"WorkingDir":"","Entrypoint":null,
               "Healthcheck":{"Test":null}},"rootfs":{"type":"layers","diff_ids":null},
               "history":null}"#,
        )
        .unwrap();
        assert!(c.config.labels.is_empty() && c.config.volumes.is_empty());
        assert!(c.rootfs.diff_ids.is_empty() && c.history.is_empty());
    }

    /// The maps of a manifest and of a config are written with their keys in
    /// order: the same manifest is the same bytes, and has the same digest,
    /// at every push (a pushed manifest had one of two digests at random).
    #[test]
    fn maps_are_written_in_the_order_of_their_keys() {
        let keys: Vec<String> = (0..32).map(|i| format!("k{:02}", (i * 7) % 32)).collect();
        let map: HashMap<String, String> = keys.iter().map(|k| (k.clone(), "v".into())).collect();
        let d = OciDescriptor {
            media_type: "m".into(),
            digest: format!("sha256:{}", "a".repeat(64)).parse().unwrap(),
            size: 1,
            annotations: map.clone(),
        };
        let m = OciManifest {
            schema_version: 2,
            media_type: None,
            config: d.clone(),
            layers: vec![d],
            annotations: map.clone(),
        };
        let text = serde_json::to_string(&m).unwrap();
        let mut order: Vec<usize> = (0..32)
            .map(|i| text.find(&format!("\"k{i:02}\"")).unwrap())
            .collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{text}");
        let c = OciImageConfig {
            labels: map.clone(),
            ..Default::default()
        };
        let text = serde_json::to_string(&c).unwrap();
        order = (0..32)
            .map(|i| text.find(&format!("\"k{i:02}\"")).unwrap())
            .collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{text}");
    }
}
