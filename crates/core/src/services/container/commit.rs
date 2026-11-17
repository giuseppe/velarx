// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::services::Changes;
use velarx_db::RecordState;

/// How a container is committed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommitRequest {
    /// The name of the new image.
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    /// Dockerfile instructions applied to the configuration.
    #[serde(default)]
    pub changes: Vec<String>,
    /// Freeze the container while its files are read.
    #[serde(default)]
    pub pause: bool,
    /// `sha256` or `sha512`: the algorithm of the digests of the new image;
    /// none: that of the image of the container.
    #[serde(default)]
    pub digest: Option<String>,
    /// Add the volumes of the container to the configuration.
    #[serde(default)]
    pub include_volumes: bool,
    #[serde(default)]
    pub squash: bool,
    /// Settings of the new configuration (podman's commit body, a Docker
    /// container config), applied after those of the container.
    #[serde(default)]
    pub override_config: Option<serde_json::Value>,
}

/// The edits of podman's override configuration of a commit, as buildah
/// applies it: the user, the working directory and the stop signal when
/// given, the ports, volumes, labels and variables added, and the
/// entrypoint and command together when one of them is given.
pub(super) fn override_edits(o: &serde_json::Value) -> Vec<crate::services::ConfigEdit> {
    use crate::services::ConfigEdit;
    use serde_json::{json, Value};
    let strs = |k: &str| -> Vec<String> {
        o.get(k)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let text = |k: &str| o.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let object = |k: &str| {
        o.get(k)
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default()
    };
    let mut edits = Vec::new();
    for k in ["User", "WorkingDir", "StopSignal"] {
        let v = text(k);
        if !v.is_empty() {
            edits.push(ConfigEdit::Set(k.into(), json!(v)));
        }
    }
    for k in ["ExposedPorts", "Volumes", "Labels"] {
        let m = object(k);
        if !m.is_empty() {
            edits.push(ConfigEdit::Merge(k.into(), m));
        }
    }
    let env: Vec<(String, String)> = strs("Env")
        .iter()
        .map(|e| match e.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (e.clone(), String::new()),
        })
        .collect();
    if !env.is_empty() {
        edits.push(ConfigEdit::Env(env));
    }
    let (entrypoint, cmd) = (strs("Entrypoint"), strs("Cmd"));
    if !entrypoint.is_empty() || !cmd.is_empty() {
        for (k, v) in [("Entrypoint", entrypoint), ("Cmd", cmd)] {
            edits.push(if v.is_empty() {
                ConfigEdit::Unset(k.into())
            } else {
                ConfigEdit::Set(k.into(), json!(v))
            });
        }
    }
    edits
}

impl ContainerService {
    /// The changes of the writable layer of a container (none if it was
    /// never set up), read through the storage driver, and how to read them:
    /// its owners mapped back to the container's ids, the files of the engine
    /// left out.
    pub async fn writable_diff(
        &self,
        id: &str,
    ) -> ContainerResult<(
        Option<crate::storage_driver::WritableDiff>,
        velarx_content::layer::dirtar::Options,
    )> {
        use velarx_content::layer::dirtar;
        let container = self.db.get_container(id).await?;
        let config: ContainerConfig = serde_json::from_str(&container.config)?;
        let range = |m: &crate::container::IdMapping| dirtar::IdRange {
            container: m.container_id,
            host: m.host_id,
            size: m.size,
        };
        let bundle = self.bundle_dir(&container.id);
        let writable = self.writable(&container.id);
        // the layer may say things only the image below can explain (the
        // overlay's metadata only files and redirects)
        let lower = if velarx_fuse::plan::file(&bundle, "").exists() {
            let image = self.image_service.get(&container.image_id).await?;
            let layers = self.image_layers(&image).await?;
            Some(self.image_view(&layers)?)
        } else {
            None
        };
        let diff = self
            .storage()
            .writable_exists(&writable)
            .map_err(|e| ContainerError::Io(e.into_io()))?
            .then(|| {
                crate::storage_driver::WritableDiff::new(self.storage().clone(), writable, lower)
            });
        Ok((
            diff,
            dirtar::Options {
                lower: None,
                exclude: dirtar::ENGINE_FILES.iter().map(|s| s.to_string()).collect(),
                uid_map: config.uid_mappings.iter().map(range).collect(),
                gid_map: config.gid_mappings.iter().map(range).collect(),
                mtime: dirtar::Mtime::Keep,
                unowned: None,
            },
        ))
    }

    /// Commit the changes of a container to a new image, with the settings
    /// of the container (command, environment, working directory...) on
    /// top of the configuration of its image.
    pub async fn commit(
        &self,
        id: &str,
        req: &CommitRequest,
        progress: Option<tokio::sync::mpsc::Sender<crate::services::TransferProgress>>,
    ) -> ContainerResult<String> {
        use crate::services::{CommitOptions, ConfigEdit};
        let container = self.db.get_container(id).await?;
        let config: ContainerConfig = serde_json::from_str(&container.config)?;
        let digest = match req.digest.as_deref().filter(|d| !d.is_empty()) {
            Some(d) => Some(
                velarx_types::digest::Algorithm::for_creation(d)
                    .map_err(ContainerError::Unsupported)?,
            ),
            None => None,
        };
        let mut edits = Vec::new();
        if !config.command.is_empty() {
            edits.push(ConfigEdit::Set(
                "Cmd".into(),
                serde_json::json!(config.command),
            ));
        }
        if !config.entrypoint.is_empty() {
            edits.push(ConfigEdit::Set(
                "Entrypoint".into(),
                serde_json::json!(config.entrypoint),
            ));
        }
        // The variables of the container first: they win over the image's.
        let mut seen = std::collections::HashSet::new();
        let mut env = Vec::new();
        for e in &config.env {
            if let Some((k, v)) = e.split_once('=') {
                if seen.insert(k.to_string()) {
                    env.push((k.to_string(), v.to_string()));
                }
            }
        }
        if !env.is_empty() {
            edits.push(ConfigEdit::Env(env));
        }
        if !config.working_dir.is_empty() {
            edits.push(ConfigEdit::Set(
                "WorkingDir".into(),
                serde_json::json!(config.working_dir),
            ));
        }
        if !config.user.is_empty() {
            edits.push(ConfigEdit::Set(
                "User".into(),
                serde_json::json!(config.user),
            ));
        }
        if !config.labels.is_empty() {
            let mut labels: Vec<_> = config.labels.iter().collect();
            labels.sort();
            edits.push(ConfigEdit::Merge(
                "Labels".into(),
                labels
                    .into_iter()
                    .map(|(k, v)| (k.clone(), serde_json::json!(v)))
                    .collect(),
            ));
        }
        if req.include_volumes {
            let volumes: serde_json::Map<String, serde_json::Value> = config
                .mounts
                .iter()
                .filter(|m| m.mount_type.as_deref() == Some("volume"))
                .map(|m| (m.target.clone(), serde_json::json!({})))
                .collect();
            if !volumes.is_empty() {
                edits.push(ConfigEdit::Merge("Volumes".into(), volumes));
            }
        }

        if let Some(o) = &req.override_config {
            edits.extend(override_edits(o));
        }
        let (changes, walk) = self.writable_diff(&container.id).await?;
        let opts = CommitOptions {
            edits,
            changes: req.changes.clone(),
            author: req.author.clone(),
            message: req.message.clone(),
            created_by: if config.command.is_empty() && config.entrypoint.is_empty() {
                "velarx commit".into()
            } else {
                let mut argv = config.entrypoint.clone();
                argv.extend(config.command.iter().cloned());
                argv.join(" ")
            },
            digest,
            names: req.image.iter().cloned().collect(),
            walk,
            lease: None,
            platform: None,
            progress,
            squash_all: req.squash,
            cancel: Default::default(),
            created: None,
            omit_history: false,
            ..CommitOptions::default()
        };

        let paused = req.pause && container.state == RecordState::Running;
        if paused {
            self.pause(&container.id).await?;
        }
        let result = self
            .image_service
            .commit_changes(
                Some(&container.image_id),
                changes.map(Changes::Writable),
                &opts,
            )
            .await;
        if paused {
            if let Err(e) = self.unpause(&container.id).await {
                if result.is_ok() {
                    return Err(e);
                }
                warn!("Cannot unpause {} after the commit: {e}", container.id);
            }
        }
        let image = result?;
        info!("Committed container {} as image {}", container.id, image);
        Ok(image)
    }

    /// What a container added, changed and deleted in its image, sorted by
    /// path.  The files the engine writes (`/etc/hosts`...) are not changes.
    pub async fn changes(
        &self,
        id: &str,
    ) -> ContainerResult<Vec<(String, velarx_content::layer::dirtar::Change)>> {
        let container = self.db.get_container(id).await?;
        self.image_service.get(&container.image_id).await?;
        let (diff, walk) = self.writable_diff(&container.id).await?;
        let list = tokio::task::spawn_blocking(move || -> std::io::Result<_> {
            let Some(diff) = diff else {
                return Ok(Vec::new());
            };
            diff.changes(&walk)
        })
        .await
        .map_err(|e| ContainerError::Io(std::io::Error::other(e.to_string())))??;
        Ok(list)
    }
}
