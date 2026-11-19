// SPDX-License-Identifier: Apache-2.0
//! The operations on containers.

use super::{Error, Result};
use crate::api::AppState;

use crate::api::status::StatusCode;
use velarx_core::services::ContainerError;
use velarx_types::DbError;
use velarx_wire::request::{CreateContainerRequest, NetworkMode, NsMode};

/// The status of an error of the container service: a missing or a
/// duplicate resource is told apart from a failure (the client acts on it,
/// e.g. `--ignore`).
pub(crate) fn container_status(e: &ContainerError) -> StatusCode {
    use ContainerError as E;
    match e {
        // (`run` asks for the image with the create and pulls it when the
        // answer says it is not there: not an error to log)
        E::NotFound(_) | E::ImageNotFound(_) | E::Database(DbError::NotFound(_)) => {
            StatusCode::NOT_FOUND
        }
        E::AlreadyExists(_) | E::Database(DbError::AlreadyExists(_)) => StatusCode::CONFLICT,
        E::Unsupported(_) => StatusCode::NOT_IMPLEMENTED,
        E::NotRunning(_) | E::AlreadyRunning(_) | E::MonitorLost(_) | E::MonitorVersion { .. } => {
            StatusCode::CONFLICT
        }
        E::Io(e) if e.kind() == std::io::ErrorKind::InvalidInput => StatusCode::BAD_REQUEST,
        E::Network(n) => network_status(n),
        E::InvalidArgument(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// A 409 of the container service is of the state of the container (it
/// runs, it does not, its monitor is gone), not of a name.
pub(crate) fn container_state(e: &ContainerError) -> bool {
    use ContainerError as E;
    match e {
        E::NotRunning(_) | E::AlreadyRunning(_) | E::MonitorLost(_) | E::MonitorVersion { .. } => {
            true
        }
        E::Network(n) => network_state(n),
        _ => false,
    }
}

/// A 409 of a network is of its state (in use), not of a name.
fn network_state(e: &velarx_netkernel::error::NetworkError) -> bool {
    matches!(e, velarx_netkernel::error::NetworkError::Busy(_))
}

fn network_status(e: &velarx_netkernel::error::NetworkError) -> StatusCode {
    use velarx_netkernel::error::NetworkError as E;
    match e {
        E::NotFound(_) | E::Missing(_) | E::Database(DbError::NotFound(_)) => StatusCode::NOT_FOUND,
        E::AlreadyExists(_) | E::Busy(_) | E::Database(DbError::AlreadyExists(_)) => {
            StatusCode::CONFLICT
        }
        E::AlreadyConnected => StatusCode::FORBIDDEN,
        E::InvalidConfig(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// An error of the container service about the container `id`, with
/// podman's status and, for one that is not there, podman's message.
fn container_error(e: ContainerError, id: &str) -> Error {
    use ContainerError as E;
    let status = container_status(&e);
    let state = container_state(&e);
    let condition = e.condition();
    let message = match e {
        E::NotFound(_) | E::Database(DbError::NotFound(_)) => {
            format!("no container with name or ID \"{id}\" found: no such container")
        }
        e => e.to_string(),
    };
    Error::new(status, message)
        .with_state(state)
        .with_condition(condition)
}

/// An error of the container service, with its status.
fn failure(e: ContainerError) -> Error {
    let image = matches!(e, ContainerError::ImageNotFound(_));
    let mut failed = Error::new(container_status(&e), e.to_string())
        .with_state(container_state(&e))
        .with_condition(e.condition());
    if image {
        failed.no_such = Some(crate::api::podman::error::Kind::Image);
    }
    failed
}

/// Create a container: the secrets it asks for are resolved first, a
/// member of a pod joins the namespaces the pod shares.
pub(crate) async fn create(state: &AppState, mut req: CreateContainerRequest) -> Result<String> {
    // (the scope the engine resolves from `cgroups`, and a pod gives
    // its members: `cgroups` asks for one, there is no other knob)
    if let Some(mode) = req.cgroup_mode {
        return Err(Error::bad_request(format!(
            "`cgroup_mode` is not an option: `cgroups` = \"{mode}\" asks for it"
        )));
    }
    // (from the secrets' files to the container's row: see `lock_store`)
    let _store = state
        .container_service
        .lock_store()
        .await
        .map_err(Error::internal)?;
    let used = crate::api::podman::add_secrets(state, &mut req)
        .await
        .map_err(|(status, message)| Error::new(status, message))?;
    let secrets_dir = req
        .id
        .as_ref()
        .filter(|_| !used.is_empty())
        .map(|id| state.container_service.secrets_dir_of(id));
    let asked = req.with_secrets_by_name(secrets_dir.as_deref());
    let pod = state
        .pod_service
        .prepare_member(&mut req)
        .await
        .map_err(|e| Error::new(super::pod::pod_status(&e), e.to_string()))?;
    let kept = req.with_secrets_by_name(secrets_dir.as_deref());
    match state.container_service.create(req).await {
        Ok(id) => {
            crate::api::podman::mark_secrets_used(state, &used, &id).await;
            crate::api::podman::keep_native_request(state, &id, kept, asked).await;
            if let Some(pod) = pod {
                if let Err(e) = state.pod_service.add_container(pod.id(), &id).await {
                    let _ = state.container_service.delete(&id, true).await;
                    return Err(Error::new(super::pod::pod_status(&e), e.to_string()));
                }
            }
            Ok(id)
        }
        Err(e) => {
            if let Some(dir) = secrets_dir {
                let _ =
                    crate::api::off_thread(move || velarx_base::tree::remove_dir_all(dir)).await;
            }
            Err(failure(e))
        }
    }
}

/// A container made as CONTAINER was asked for, as podman's `container
/// clone`: with a new name (podman's `NAME-clone`, `NAME-clone1`... by
/// default), and the image and the pod given.  Its id.
pub(crate) async fn clone(
    state: &AppState,
    container: &str,
    name: Option<String>,
    image: Option<String>,
    pod: Option<String>,
) -> Result<String> {
    let rec = state
        .container_service
        .inspect(container)
        .await
        .map_err(|e| container_error(e, container))?;
    let mut req = crate::api::podman::asked_request(state, &rec.id)
        .await
        .ok_or_else(|| {
            Error::bad_request(format!(
                "the request that made the container {} was not kept: it cannot be cloned",
                rec.id
            ))
        })?;
    req.id = None;
    // As podman: the clone has a hostname of its own (podman's default,
    // its ID), and none of the published ports and the addresses that the
    // original holds (podman keeps those of a bridge network, and the clone
    // then cannot run beside the original).
    req.hostname.clear();
    req.ports.clear();
    req.ip_address = None;
    req.ip6_address = None;
    req.mac_address = None;
    // (the files of the original stay its own)
    req.cidfile = None;
    req.pidfile = None;
    req.conmon_pidfile = None;
    req.replace = false;
    // As podman: the anonymous volumes are the original's, as the named ones.
    let config: velarx_runtime::container::ContainerConfig =
        serde_json::from_str(&rec.config).unwrap_or_default();
    let mut anonymous = std::collections::HashMap::new();
    for m in &config.mounts {
        let Some(volume) = &m.volume else { continue };
        if state
            .volume_service
            .get(volume)
            .await
            .is_ok_and(|v| v.state.anonymous)
        {
            anonymous.insert(m.target.clone(), volume.clone());
        }
    }
    share_anonymous_volumes(&mut req, &anonymous);
    let original = rec.name.clone().unwrap_or_else(|| rec.id.clone());
    req.name = Some(match name {
        Some(n) => n,
        None => {
            let taken =
                |n: String| async move { state.container_service.inspect(&n).await.is_ok() };
            let mut n = original;
            if taken(format!("{n}-clone")).await {
                n.push_str("-clone");
            }
            clone_name(n, taken).await
        }
    });
    if let Some(image) = image {
        req.image = image;
    }
    if let Some(pod) = pod {
        // As podman: what the pod shares replaces the settings of the
        // original.
        let p = state
            .pod_service
            .get(&pod)
            .await
            .map_err(|e| Error::new(super::pod::pod_status(&e), e.to_string()))?;
        let s = &p.spec;
        if s.share_net {
            req.network_mode = NetworkMode::Unset;
            req.networks.clear();
            req.network_aliases.clear();
            req.publish_all = false;
        }
        for (shared, mode) in [
            (s.share_pid, &mut req.pid_mode),
            (s.share_ipc, &mut req.ipc_mode),
            (s.share_uts, &mut req.uts_mode),
            (s.share_cgroup, &mut req.cgroupns_mode),
        ] {
            if shared {
                *mode = NsMode::Default;
            }
        }
        req.pod = Some(pod);
    }
    create(state, req).await
}

/// The anonymous volumes of REQ named: the volume of ANONYMOUS (by the
/// destination) instead of a new one.
fn share_anonymous_volumes(
    req: &mut CreateContainerRequest,
    anonymous: &std::collections::HashMap<String, String>,
) {
    for v in &mut req.volumes {
        // `DESTINATION[:OPTIONS]`: no source
        let dest = v.split(':').next().unwrap_or_default();
        let options = v.split(':').nth(1);
        if !dest.starts_with('/') || options.is_some_and(|o| o.starts_with('/')) {
            continue;
        }
        if let Some(name) = anonymous.get(dest) {
            *v = format!("{name}:{v}");
        }
    }
    for m in &mut req.mount {
        let fields: Vec<(&str, &str)> = m
            .split(',')
            .map(|f| f.split_once('=').unwrap_or((f, "")))
            .collect();
        let is = |keys: &[&str]| {
            fields
                .iter()
                .find(|(k, _)| keys.contains(k))
                .map(|(_, v)| *v)
        };
        if is(&["type"]) != Some("volume") || is(&["source", "src"]).is_some_and(|s| !s.is_empty())
        {
            continue;
        }
        let Some(dest) = is(&["destination", "dst", "target"]) else {
            continue;
        };
        if let Some(name) = anonymous.get(dest) {
            *m = format!("{m},src={name}");
        }
    }
}

/// podman's name of a clone (`CheckName`): N with `-clone` added, or the
/// first `-cloneN` that no container has when N has one.
async fn clone_name<F, Fut>(n: String, taken: F) -> String
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let Some(at) = n.find("-clone").map(|i| i + "-clone".len()) else {
        return format!("{n}-clone");
    };
    let (mut base, mut count) = match n[at..].parse::<u64>() {
        Ok(num) => (n[..at].to_string(), num),
        Err(_) if !taken(format!("{n}1")).await => return format!("{n}1"),
        Err(_) => (n, 0),
    };
    loop {
        count += 1;
        if !taken(format!("{base}{count}")).await {
            base.push_str(&count.to_string());
            return base;
        }
    }
}

fn share_error(status: StatusCode, e: impl std::fmt::Display) -> Error {
    Error::new(status, e.to_string())
}

/// Share the checkpoint archive `input` (`checkpoint --export`) with the
/// peers: its reference, which `restore --import-from-peers` takes, and its
/// size.
pub(crate) async fn share_checkpoint(
    state: &AppState,
    mut input: super::ByteStream,
) -> Result<(String, u64)> {
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;
    let internal = |e: &dyn std::fmt::Display| share_error(StatusCode::INTERNAL_SERVER_ERROR, e);
    let dir = state.container_service.root_dir.join("checkpoint-share");
    let staging = crate::api::off_thread(move || {
        std::fs::create_dir_all(&dir)?;
        tempfile::Builder::new()
            .prefix("archive-")
            .tempfile_in(&dir)
    })
    .await
    .map_err(|e| internal(&e))?
    .into_temp_path();
    let mut out = tokio::fs::OpenOptions::new()
        .append(true)
        .open(&staging)
        .await
        .map_err(|e| internal(&e))?;
    let mut size = 0u64;
    let mut guard = velarx_content::archive::guard::Guard::new(
        velarx_content::archive::guard::Accept::Compressed,
    );
    while let Some(piece) = input.next().await {
        let piece = piece.map_err(|e| share_error(StatusCode::BAD_REQUEST, e))?;
        guard
            .feed(&piece)
            .map_err(|e| share_error(StatusCode::BAD_REQUEST, e))?;
        size += piece.len() as u64;
        if size > velarx_core::services::CHECKPOINT_UPLOAD_MAX {
            return Err(share_error(
                StatusCode::BAD_REQUEST,
                "the archive is too large",
            ));
        }
        out.write_all(&piece).await.map_err(|e| internal(&e))?;
    }
    guard
        .end()
        .map_err(|e| share_error(StatusCode::BAD_REQUEST, e))?;
    out.flush().await.map_err(|e| internal(&e))?;
    if size == 0 {
        return Err(share_error(
            StatusCode::BAD_REQUEST,
            "no archive in the body",
        ));
    }
    let path = staging.to_path_buf();
    let root = state.config.storage.root.clone();
    let shared = tokio::task::spawn_blocking(move || {
        velarx_core::services::checkpoint::SharedCheckpoints::new(&root)?.share(&path)
    })
    .await
    .map_err(|e| internal(&e))?;
    drop(staging);
    // (the store service sees the new share and announces it)
    let (reference, _) = shared.map_err(|e| internal(&e))?;
    Ok((reference.to_string(), size))
}

/// Stop sharing a checkpoint (`reference`: its manifest, the public part of
/// a reference, without the key).
pub(crate) async fn unshare_checkpoint(state: &AppState, reference: &str) -> Result<()> {
    let manifest = reference.split(':').take(2).collect::<Vec<_>>().join(":");
    if manifest.parse::<velarx_types::digest::Digest>().is_err() {
        return Err(share_error(
            StatusCode::BAD_REQUEST,
            "not the reference of a shared checkpoint",
        ));
    }
    match velarx_core::services::checkpoint::SharedCheckpoints::new(&state.config.storage.root)
        .and_then(|s| s.unshare_manifest(&manifest))
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(share_error(
            StatusCode::NOT_FOUND,
            format!("the checkpoint {manifest} is not shared"),
        )),
        Err(e) => Err(share_error(StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}
