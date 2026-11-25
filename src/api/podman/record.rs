// SPDX-License-Identifier: Apache-2.0
//! What the API keeps of the request that created a container: the services
//! store only the part they use, the inspect of podman and Docker show more
//! (published ports, DNS, health check...).

use crate::api::AppState;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use velarx_wire::request::CreateContainerRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiRecord {
    pub request: CreateContainerRequest,
    /// The body as the client sent it (a SpecGenerator or Docker's
    /// container config) for the fields the request has no place for.
    #[serde(default)]
    pub body: serde_json::Value,
    /// The create came from a Docker client.
    #[serde(default)]
    pub docker: bool,
    /// The image as the client named it.
    #[serde(default)]
    pub image_name: String,
    /// The request as it was asked, before the pod of the container
    /// changed it, with its secrets by name: what `container clone` asks
    /// again.  The values of the secrets are kept by no record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<CreateContainerRequest>,
}

fn dir(state: &AppState) -> PathBuf {
    dir_in(&state.config)
}

fn dir_in(config: &velarx_config::Config) -> PathBuf {
    config.server.root_dir.join("podman-api/containers")
}

fn file(state: &AppState, id: &str) -> Option<PathBuf> {
    file_in(&state.config, id)
}

fn file_in(config: &velarx_config::Config, id: &str) -> Option<PathBuf> {
    // ids are hex: never a path
    (!id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| dir_in(config).join(format!("{id}.json")))
}

pub async fn save(state: &AppState, id: &str, rec: &ApiRecord) -> std::io::Result<()> {
    let path = file(state, id)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid id"))?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let data = serde_json::to_vec(rec)?;
    // (a temporary file of its own: two saves of one record at once must
    // not write the same one)
    tokio::task::spawn_blocking(move || velarx_base::atomic_file::write(&path, &data, 0o600))
        .await
        .map_err(std::io::Error::other)?
}

pub async fn load(state: &AppState, id: &str) -> Option<ApiRecord> {
    let data = tokio::fs::read(file(state, id)?).await.ok()?;
    serde_json::from_slice(&data).ok()
}

pub async fn delete(state: &AppState, id: &str) {
    delete_in(&state.config, id).await;
}

/// [`delete`], by the configuration.
pub async fn delete_in(config: &velarx_config::Config, id: &str) {
    if let Some(path) = file_in(config, id) {
        let _ = tokio::fs::remove_file(path).await;
    }
}

/// Remove the records of the containers that are gone: a container removed
/// by a command (a process the server does not hear) leaves its record.
pub async fn forget_removed(state: &AppState) -> std::io::Result<()> {
    let mut entries = match tokio::fs::read_dir(dir(state)).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let Some(id) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".json"))
        else {
            continue;
        };
        match state.db.get_container(id).await {
            Err(velarx_types::DbError::NotFound(_)) => tokio::fs::remove_file(&path).await?,
            Err(e) => return Err(std::io::Error::other(e)),
            Ok(_) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_hex_id_names_a_file() {
        let config = velarx_config::Config::default();
        assert!(file_in(&config, "0aF9").is_some());
        for bad in ["", "..", "a/b", "xyz"] {
            assert!(file_in(&config, bad).is_none(), "{bad}");
        }
    }
}
