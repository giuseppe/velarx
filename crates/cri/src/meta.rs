// SPDX-License-Identifier: Apache-2.0
//! What the CRI has and the engine has no field for (the metadata of a
//! sandbox or a container, the annotations of a pod, the log directory) is
//! kept in one label of the engine object. The engine would keep it in
//! annotations of its own: see the gap list.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The label that tells a pod or a container is the CRI's: `sandbox` or
/// `container`.
pub const KIND: &str = "io.velarx.cri.kind";
/// The label with the JSON of `SandboxMeta` / `ContainerMeta`.
pub const META: &str = "io.velarx.cri.meta";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SandboxMeta {
    pub name: String,
    pub uid: String,
    pub namespace: String,
    pub attempt: u32,
    pub annotations: BTreeMap<String, String>,
    pub log_directory: String,
    pub runtime_handler: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ContainerMeta {
    pub name: String,
    pub attempt: u32,
    pub annotations: BTreeMap<String, String>,
    pub log_path: String,
    pub image: String,
    pub stop_signal: i32,
    /// What the container was asked to run: a restore checks that the
    /// process it restores is the one it is told to expect
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub working_dir: String,
    /// The fingerprint of the environment the container was asked to run
    /// with (`sha256:HEX`, never the values: they may be secrets) and the
    /// user (`UID[:GID]` or a name; empty: the image's)
    #[serde(default)]
    pub env_digest: String,
    #[serde(default)]
    pub user: String,
    /// The input of the container is closed when the first attach that
    /// sends it ends
    #[serde(default)]
    pub stdin_once: bool,
}

/// The file `pod.json` of a pod checkpoint: what the pod was, and the
/// archive of each container.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PodCheckpoint {
    pub version: u32,
    /// When the checkpoint was made, in nanoseconds since the epoch
    pub checkpointed_at: i64,
    pub sandbox: SandboxMeta,
    pub labels: BTreeMap<String, String>,
    pub hostname: String,
    pub host_network: bool,
    pub host_ipc: bool,
    pub host_pid: bool,
    pub shared_pid: bool,
    /// The addresses of the pod when it was checkpointed
    pub ips: Vec<String>,
    pub containers: Vec<CheckpointedContainer>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CheckpointedContainer {
    pub meta: ContainerMeta,
    pub labels: BTreeMap<String, String>,
    /// The ID of the image the container ran
    pub image_id: String,
    /// The file of the archive, in the directory of the checkpoint
    pub archive: String,
}

/// The version of `pod.json`.
pub const POD_CHECKPOINT_VERSION: u32 = 1;

/// The metadata of an object of the CRI that cannot be had.
#[derive(Debug, thiserror::Error)]
pub enum MetaError {
    #[error("the object is of the CRI but has no metadata (label {META})")]
    Missing,
    #[error("the metadata of the object (label {META}) cannot be read: {0}")]
    Unreadable(serde_json::Error),
    #[error("the metadata of the object cannot be written: {0}")]
    Unwritable(serde_json::Error),
}

pub fn encode<T: Serialize>(
    kind: &str,
    meta: &T,
    user: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, MetaError> {
    let mut labels = user.clone();
    labels.insert(KIND.into(), kind.into());
    labels.insert(
        META.into(),
        serde_json::to_string(meta).map_err(MetaError::Unwritable)?,
    );
    Ok(labels)
}

pub fn is_kind(labels: &BTreeMap<String, String>, kind: &str) -> bool {
    labels.get(KIND).is_some_and(|k| k == kind)
}

/// The metadata of an object of the CRI (see [`is_kind`]) and the labels the
/// kubelet sent.
pub fn decode<T: for<'a> Deserialize<'a>>(
    labels: &BTreeMap<String, String>,
) -> Result<(T, BTreeMap<String, String>), MetaError> {
    let meta = labels.get(META).ok_or(MetaError::Missing)?;
    let meta = serde_json::from_str(meta).map_err(MetaError::Unreadable)?;
    let user = labels
        .iter()
        .filter(|(k, _)| *k != KIND && *k != META)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Ok((meta, user))
}

/// A name the engine takes for an object of the CRI.
pub fn engine_name(parts: &[&str]) -> String {
    let mut out = String::from("k8s");
    for p in parts {
        out.push('_');
        out.extend(p.chars().map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        }));
    }
    out
}

pub fn matches_selector(
    labels: &BTreeMap<String, String>,
    selector: &std::collections::HashMap<String, String>,
) -> bool {
    selector.iter().all(|(k, v)| labels.get(k) == Some(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let m = SandboxMeta {
            name: "n".into(),
            uid: "u".into(),
            namespace: "ns".into(),
            attempt: 2,
            annotations: [("a".to_string(), "b".to_string())].into(),
            ..Default::default()
        };
        let user: BTreeMap<_, _> = [("k".to_string(), "v".to_string())].into();
        let labels = encode("sandbox", &m, &user).unwrap();
        assert!(is_kind(&labels, "sandbox"));
        let (back, u): (SandboxMeta, _) = decode(&labels).unwrap();
        assert_eq!(back, m);
        assert_eq!(u, user);
    }

    #[test]
    fn metadata_that_cannot_be_had_is_an_error() {
        let mut labels = BTreeMap::new();
        assert!(matches!(
            decode::<SandboxMeta>(&labels),
            Err(MetaError::Missing)
        ));
        labels.insert(META.to_string(), "{\"attempt\": -1}".to_string());
        assert!(matches!(
            decode::<SandboxMeta>(&labels),
            Err(MetaError::Unreadable(_))
        ));
    }

    #[test]
    fn names() {
        assert_eq!(engine_name(&["a b", "c/d"]), "k8s_a-b_c-d");
    }
}
