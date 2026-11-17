// SPDX-License-Identifier: Apache-2.0
//! Artifacts: podman's `/libpod/artifacts` routes on the store of
//! `services::artifact`.

use super::error::{ApiError, ApiResult};
use super::events::Event;
use crate::api::AppState;
use futures::StreamExt;
use std::sync::Arc;
use velarx_core::services::artifact::{
    AddOptions, ArtifactError, ArtifactStore, BlobFilter, NewLayer,
};
use velarx_proto::workload::ArtifactRecord;
use velarx_proto::workload::EventKind;

impl From<ArtifactError> for ApiError {
    fn from(e: ArtifactError) -> Self {
        match e {
            ArtifactError::NotFound(_) => ApiError::not_found(e.to_string()),
            ArtifactError::AlreadyExists(_) => ApiError::conflict(e.to_string()),
            ArtifactError::Invalid(_) => ApiError::bad_request(e.to_string()),
            ArtifactError::Io(_) => ApiError::internal(e.to_string()),
        }
    }
}

/// The store of the server, opened on first use.
pub(crate) async fn store(state: &AppState) -> ApiResult<Arc<ArtifactStore>> {
    state
        .podman
        .artifacts
        .get_or_try_init(|| async {
            let dir = state.config.server.root_dir.join("artifacts");
            tokio::task::spawn_blocking(move || ArtifactStore::open(&dir).map(Arc::new))
                .await
                .map_err(|e| ArtifactError::Io(std::io::Error::other(e)))?
        })
        .await
        .cloned()
        .map_err(Into::into)
}

/// `f` on the store, out of the runtime's threads.
async fn blocking<T: Send + 'static>(
    state: &AppState,
    f: impl FnOnce(&ArtifactStore) -> Result<T, ArtifactError> + Send + 'static,
) -> ApiResult<T> {
    let s = store(state).await?;
    tokio::task::spawn_blocking(move || f(&s))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .map_err(Into::into)
}

/// The record of an artifact: its manifest as typed members.
fn record(a: &velarx_core::services::artifact::Artifact) -> ArtifactRecord {
    use super::manifests::descriptor;
    let m = &a.manifest;
    ArtifactRecord {
        name: a.name.clone(),
        digest: a.digest.to_string(),
        schema_version: m["schemaVersion"].as_i64().unwrap_or(0),
        media_type: m["mediaType"].as_str().unwrap_or_default().to_string(),
        artifact_type: m["artifactType"].as_str().unwrap_or_default().to_string(),
        config: m.get("config").filter(|c| c.is_object()).map(descriptor),
        layers: a.layers().iter().map(descriptor).collect(),
        subject: m.get("subject").filter(|c| c.is_object()).map(descriptor),
        annotations: super::manifests::annotations(m),
    }
}

pub(crate) async fn list_of(state: &AppState) -> ApiResult<Vec<ArtifactRecord>> {
    let all = blocking(state, |s| s.list()).await?;
    Ok(all.iter().map(record).collect())
}

pub(crate) async fn inspect_of(state: &AppState, name: &str) -> ApiResult<ArtifactRecord> {
    let name = name.to_string();
    let a = blocking(state, move |s| s.get(&name)).await?;
    Ok(record(&a))
}

/// The file of a `local/add`: an absolute path on this host (podman's
/// `localapi.ValidatePathForLocalAPI`), cleaned as Go's filepath.Clean.
pub(crate) fn local_file(path: &str) -> ApiResult<std::path::PathBuf> {
    let p = std::path::Path::new(path);
    if !p.is_absolute() {
        return Err(ApiError::bad_request(format!(
            "path {path:?} is not absolute"
        )));
    }
    let mut clean = std::path::PathBuf::from("/");
    for c in p.components() {
        match c {
            std::path::Component::Normal(n) => clean.push(n),
            std::path::Component::ParentDir => {
                clean.pop();
            }
            _ => {}
        }
    }
    match std::fs::metadata(&clean) {
        Ok(m) if m.is_file() => Ok(clean),
        Ok(_) => Err(ApiError::bad_request(format!(
            "{:?} is not a file",
            clean.display().to_string()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(ApiError::not_found(format!(
            "file does not exist: {:?}",
            clean.display().to_string()
        ))),
        Err(e) => Err(ApiError::internal(format!("failed to access file: {e}"))),
    }
}

/// Where the file of an `add` is.
pub(crate) enum Source {
    /// A file of this host
    Local(std::path::PathBuf),
    /// A regular file the client opened
    Open(std::fs::File),
    /// The bytes of a request
    Body(crate::api::ops::ByteStream),
}

/// Add a file to an artifact: the digest of the artifact.
pub(crate) async fn add_of(
    state: &AppState,
    req: &crate::client::ArtifactAdd,
    source: Source,
) -> ApiResult<String> {
    let (name, file_name) = (req.name.clone(), req.file_name.clone());
    if name.is_empty() || file_name.is_empty() {
        return Err(ApiError::bad_request("name and fileName are required"));
    }
    let mut annotations = Vec::new();
    for a in &req.annotations {
        let Some((k, v)) = a.split_once('=') else {
            return Err(ApiError::bad_request(format!(
                "invalid annotation {a:?}: KEY=VALUE"
            )));
        };
        annotations.push((k.to_string(), v.to_string()));
    }
    let media_type = req.file_type.clone().filter(|t| !t.is_empty());
    let s = store(state).await?;
    // The digests of the artifact: an artifact that is appended to keeps its
    // own (a different one asked for is refused); a new one has the one
    // asked for, else `[build] digest`.
    let asked = req
        .digest
        .as_deref()
        .filter(|d| !d.is_empty())
        .map(velarx_types::digest::Algorithm::for_creation)
        .transpose()
        .map_err(ApiError::bad_request)?;
    let alg = match (s.get(&name).ok().filter(|_| req.append), asked) {
        (Some(have), Some(want)) if have.digest.alg() != want => {
            return Err(ApiError::bad_request(format!(
                "{name}: the artifact has {} digests, not {want}",
                have.digest.alg()
            )))
        }
        (Some(have), _) => have.digest.alg(),
        (None, Some(want)) => want,
        (None, None) => state
            .image_service
            .creation_algorithm(None)
            .map_err(|e| ApiError::bad_request(e.to_string()))?,
    };
    let opts = AddOptions {
        append: req.append,
        replace: req.replace,
        artifact_type: req.artifact_type.clone().filter(|t| !t.is_empty()),
        annotations,
        alg: Some(alg),
    };
    let mut body = match source {
        Source::Body(b) => b,
        source @ (Source::Local(_) | Source::Open(_)) => {
            let staged = s.clone();
            let blob = tokio::task::spawn_blocking(move || -> std::io::Result<_> {
                let file = match source {
                    Source::Local(path) => std::fs::File::open(&path)?,
                    Source::Open(file) => file,
                    Source::Body(_) => unreachable!("a body is staged as it comes"),
                };
                staged.stage(file, alg).map_err(std::io::Error::other)
            })
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?
            .map_err(|e| ApiError::internal(e.to_string()))?;
            return finish_add(state, s, name, file_name, media_type, opts, blob).await;
        }
    };
    // the body is staged in the store as it comes
    let (tx, rx) = std::sync::mpsc::sync_channel::<std::io::Result<bytes::Bytes>>(8);
    let staging = {
        let s = s.clone();
        tokio::task::spawn_blocking(move || s.stage(ChannelReader::new(rx), alg))
    };
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|e| std::io::Error::other(format!("the body: {e}")));
        let failed = chunk.is_err();
        if tx.send(chunk).is_err() || failed {
            break;
        }
    }
    drop(tx);
    let blob = staging
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .map_err(ApiError::from)?;
    finish_add(state, s, name, file_name, media_type, opts, blob).await
}

/// Add the staged blob to the artifact `name`: the digest of the artifact.
async fn finish_add(
    state: &AppState,
    s: Arc<ArtifactStore>,
    name: String,
    file_name: String,
    media_type: Option<String>,
    opts: AddOptions,
    blob: velarx_core::services::artifact::StagedBlob,
) -> ApiResult<String> {
    let layer = NewLayer {
        blob,
        title: file_name,
        media_type,
    };
    let event_name = name.clone();
    let digest = tokio::task::spawn_blocking(move || s.add(&name, vec![layer], &opts))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))??;
    state.podman.events.emit(Event::new(
        EventKind::Artifact,
        "add",
        &digest.to_string(),
        &event_name,
    ));
    Ok(digest.to_string())
}

pub(crate) async fn remove_one(state: &AppState, name: String) -> ApiResult<String> {
    let event_name = name.clone();
    let digest = blocking(state, move |s| s.remove(&name)).await?;
    state.podman.events.emit(Event::new(
        EventKind::Artifact,
        "remove",
        &digest.to_string(),
        &event_name,
    ));
    Ok(digest.to_string())
}

/// The tar of the blobs of an artifact `filter` selects, named by their
/// titles (by their digests with `by_digest`).
pub(crate) async fn extract_of(
    state: &AppState,
    name: &str,
    filter: BlobFilter,
    by_digest: bool,
) -> ApiResult<Vec<u8>> {
    let name = name.to_string();
    blocking(state, move |s| {
        let a = s.get(&name)?;
        let blobs = s.blob_paths(&a, &filter)?;
        let mut tar = tar::Builder::new(Vec::new());
        for b in blobs {
            let mut f = std::fs::File::open(&b.path)?;
            let mut h = tar::Header::new_gnu();
            h.set_size(f.metadata()?.len());
            h.set_mode(0o644);
            h.set_mtime(0);
            h.set_entry_type(tar::EntryType::Regular);
            let entry = if by_digest {
                b.digest.to_string().replace(':', "-")
            } else {
                b.name.clone()
            };
            tar.append_data(&mut h, &entry, &mut f)?;
        }
        Ok(tar.into_inner()?)
    })
    .await
}

/// Pull an artifact, tried again as `retry` says: its digest.
pub(crate) async fn pull_of(
    state: &AppState,
    name: &str,
    tls_verify: bool,
    access: &velarx_registry::auth::RegistryAccess,
    retry: &velarx_proto::retry::Retry,
) -> ApiResult<String> {
    if name.is_empty() {
        return Err(ApiError::bad_request("name parameter is required"));
    }
    let s = store(state).await?;
    let digest = velarx_core::services::retried(
        retry,
        || {
            state
                .image_service
                .pull_oci_artifact(s.clone(), name, tls_verify, access)
        },
        |e, at| async move {
            tracing::warn!("Pull of the artifact {name}: {}", at.note(&e));
        },
    )
    .await
    .map_err(ApiError::from)?;
    state.podman.events.emit(Event::new(
        EventKind::Artifact,
        "pull",
        &digest.to_string(),
        name,
    ));
    Ok(digest.to_string())
}

/// The artifact `name` of the store, for a push (a missing one is a 404
/// before any request to a registry): its name and the store.
pub(crate) async fn for_push(
    state: &AppState,
    name: &str,
) -> ApiResult<(
    String,
    std::sync::Arc<velarx_core::services::artifact::ArtifactStore>,
)> {
    let a = {
        let n = name.to_string();
        blocking(state, move |s| s.get(&n)).await?
    };
    Ok((a.name, store(state).await?))
}

/// A reader of the chunks a channel gives.
struct ChannelReader {
    rx: std::sync::mpsc::Receiver<std::io::Result<bytes::Bytes>>,
    cur: bytes::Bytes,
}

impl ChannelReader {
    fn new(rx: std::sync::mpsc::Receiver<std::io::Result<bytes::Bytes>>) -> Self {
        Self {
            rx,
            cur: bytes::Bytes::new(),
        }
    }
}

impl std::io::Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.cur.is_empty() {
            match self.rx.recv() {
                Ok(chunk) => self.cur = chunk?,
                Err(_) => return Ok(0),
            }
        }
        let n = buf.len().min(self.cur.len());
        buf[..n].copy_from_slice(&self.cur[..n]);
        let _ = self.cur.split_to(n);
        Ok(n)
    }
}
