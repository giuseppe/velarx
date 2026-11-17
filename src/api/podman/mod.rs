// SPDX-License-Identifier: Apache-2.0
//! What the typed methods of `org.velarx.Engine` that velarx-api calls do,
//! and podman's documents and errors they still answer with (the shaping
//! of a container's inspect, of the lists, of `info`...).  No HTTP: the
//! routes, their queries and bodies are velarx-api's.

pub(crate) mod archive;
pub(crate) mod artifacts;
pub(crate) mod build;
pub(crate) mod call;
pub(crate) mod cinfo;
pub(crate) mod connect;
pub(crate) mod containers;
pub mod convert;
pub(crate) mod error;
pub(crate) mod eventlog;
pub mod events;
pub(crate) mod exec;
pub(crate) mod images;
pub(crate) mod lifecycle;
mod logs;
pub(crate) mod manifests;
pub(crate) mod metrics;
pub(crate) mod networks;
pub(crate) mod pods;
mod record;
pub(crate) mod secrets;
mod spec;
mod state;
pub(crate) mod stats;
pub(crate) mod stream;
pub(crate) mod system;
pub(crate) mod systemd;
pub(crate) mod volumes;
pub(crate) mod workload;

pub(crate) use record::forget_removed as forget_removed_records;
pub use state::PodmanState;

// What the engine service (`org.velarx.Engine`) calls: the listings the
// REST API serves, shaped here.
pub(crate) use call::Filters;
pub(crate) use connect::dial as connect_port;
pub(crate) use containers::{
    init_of as container_init, kill_of as container_kill, list_of as container_list,
    pause_leased_of as container_pause_leased, pause_of as container_pause,
    remove_of as container_remove, rename_of as container_rename, restart_of as container_restart,
    start_attached_of as container_start_attached, start_of as container_start,
    stop_of as container_stop, ListQuery as ContainerListQuery, RemoveOptions,
};
pub(crate) use images::{
    distribution_of as image_distribution, found as image_exists, remove_of as image_remove,
    tag_of as image_tag, RemoveOptions as ImageRemoveOptions,
};
pub(crate) use lifecycle::{
    end_pause_lease as container_end_pause_lease, resolve as lifecycle_resolve, LeaseEnd,
};
pub(crate) use metrics::{descriptors as metric_descriptors, pods_metrics};
pub(crate) use system::login_of as registry_login;

/// The `--secret` of a container made through the native API: the files and
/// variables are added to `req`.  Returns the ids of the secrets in use, or
/// the status and the message of the failure.
pub async fn add_secrets(
    state: &AppState,
    req: &mut velarx_wire::request::CreateContainerRequest,
) -> Result<Vec<String>, (crate::api::status::StatusCode, String)> {
    let refs = std::mem::take(&mut req.secrets);
    spec::resolve_secrets(state, &refs, req)
        .await
        .map_err(|e| (e.status, e.message))
}

/// Record that the container uses the secrets, so that they are not removed.
/// Keep the request of a container that the native API created, as the
/// podman API keeps its own: podman's inspect shows what it asked for
/// (published ports, health check, restart policy...).
pub async fn keep_native_request(
    state: &AppState,
    id: &str,
    request: velarx_wire::request::CreateContainerRequest,
    asked: velarx_wire::request::CreateContainerRequest,
) {
    let rec = record::ApiRecord {
        image_name: request.image.clone(),
        request,
        body: serde_json::Value::Null,
        docker: false,
        asked: Some(asked),
    };
    if let Err(e) = record::save(state, id, &rec).await {
        tracing::warn!("cannot save the request of container {id}: {e}");
    }
}

/// The request that asked for the container ID, with what `update` changed
/// since, if it was kept.
pub async fn asked_request(
    state: &AppState,
    id: &str,
) -> Option<velarx_wire::request::CreateContainerRequest> {
    let rec = record::load(state, id).await?;
    let mut asked = rec.asked?;
    asked.resources = rec.request.resources;
    asked.pids_limit = rec.request.pids_limit;
    asked.restart_policy = rec.request.restart_policy;
    Some(asked)
}

pub async fn mark_secrets_used(state: &AppState, ids: &[String], container: &str) {
    if ids.is_empty() {
        return;
    }
    if let Ok(store) = secrets::store(state).await {
        for s in ids {
            if let Err(e) = store.mark_use(s, container).await {
                tracing::warn!("cannot record the use of secret {s}: {e}");
            }
        }
    }
}

use crate::api::AppState;

async fn name_of(state: &AppState, id: &str) -> String {
    state
        .db
        .get_container(id)
        .await
        .ok()
        .and_then(|r| r.name)
        .unwrap_or_default()
}

/// What the container service tells about a container, for the clients of
/// the API: the exit code of a container that is about to be removed, the
/// changes of its health, the kernel killing it for lack of memory.
pub async fn on_notice(state: &AppState, notice: velarx_core::services::ContainerNotice) {
    use velarx_core::services::ContainerNotice;
    match notice {
        // (the monitor wrote the events: they are for the
        // clients of this process)
        ContainerNotice::Seen(n) => notice_to_events(state, *n, false).await,
        n => notice_to_events(state, n, true).await,
    }
}

async fn notice_to_events(
    state: &AppState,
    notice: velarx_core::services::ContainerNotice,
    keep: bool,
) {
    use velarx_core::services::ContainerNotice;
    let emit = |event: events::Event| {
        if keep {
            state.podman.events.emit(event);
        } else {
            state.podman.events.emit_live(event);
        }
    };
    match notice {
        ContainerNotice::Exited {
            id,
            code,
            timed_out,
            name,
            image,
            labels,
            ..
        } => {
            state.podman.record_exit(&id, code);
            // The died event was written with the exit (by the monitor, or
            // by the process that recorded it): the clients of this process
            // are told of it.
            state
                .podman
                .events
                .emit_live(velarx_wire::events::died_event(
                    &id, &name, &image, labels, code, timed_out,
                ));
        }
        ContainerNotice::Health { id, status } => {
            let name = name_of(state, &id).await;
            emit(
                velarx_wire::events::container_event(&id, &name, "health_status")
                    .attr("health_status", status.word()),
            );
            state.podman.notify_changed();
        }
        ContainerNotice::Oom { id } => {
            let name = name_of(state, &id).await;
            emit(velarx_wire::events::container_event(&id, &name, "oom"));
        }
        ContainerNotice::Action {
            id,
            name,
            image,
            action,
            attributes,
        } => {
            let mut event = velarx_wire::events::container_event(&id, &name, action);
            if !image.is_empty() {
                event = event.image(&image);
            }
            for (k, v) in attributes {
                event = event.attr(&k, v);
            }
            emit(event);
            if action == "remove" {
                // (the request the API keeps of it goes with it)
                record::delete_in(&state.config, &id).await;
            }
            state.podman.notify_changed();
        }
        ContainerNotice::Stopping { .. } => state.podman.notify_changed(),
        ContainerNotice::Restarted { id } => {
            let name = name_of(state, &id).await;
            emit(velarx_wire::events::container_event(&id, &name, "restart"));
            state.podman.notify_changed();
        }
        ContainerNotice::Image(change) => {
            for event in velarx_wire::events::image_events(&change) {
                emit(event);
            }
        }
        ContainerNotice::Seen(n) => Box::pin(notice_to_events(state, *n, keep)).await,
    }
}

/// A daemon's state on a store of a temporary directory, for the tests of
/// what the API does when the database fails.
#[cfg(test)]
pub(crate) mod test_store {
    use crate::api::AppState;
    use std::sync::Arc;
    use velarx_db::{ContainerRecord, ImageRecord, RecordState};
    use velarx_types::digest::{Algorithm, Digest};

    /// The state of a daemon on a store in `dir` (no daemon runs).
    pub(crate) async fn state_in(dir: &std::path::Path) -> Arc<AppState> {
        let mut config = velarx_config::Config::default();
        config.server.state_dir = dir.join("run");
        config.server.root_dir = dir.join("root");
        config.server.socket = dir.join("run/velarx.sock");
        config.storage.root = dir.join("storage");
        config.storage.gc_interval_secs = 0;
        crate::daemon::build_services(
            Arc::new(config),
            &dir.join("config.toml"),
            &crate::daemon::Role::Server,
        )
        .await
        .unwrap()
    }

    /// The image `id`, of no layers, named `localhost/<id>:latest`.
    pub(crate) async fn image(state: &AppState, id: &str) -> ImageRecord {
        let rec = ImageRecord {
            id: id.into(),
            manifest_digest: Digest::of(Algorithm::Sha256, format!("m{id}").as_bytes()),
            config_digest: Digest::of(Algorithm::Sha256, format!("c{id}").as_bytes()),
            manifest: r#"{"layers":[]}"#.into(),
            config: "{}".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            is_lazy: false,
        };
        state.db.insert_image(&rec).await.unwrap();
        state
            .db
            .insert_image_tag(&velarx_db::ImageTag {
                repository: format!("localhost/{id}"),
                tag: "latest".into(),
                image_id: id.into(),
            })
            .await
            .unwrap();
        rec
    }

    /// A container `id` of the image `image`, of the configuration `config`.
    pub(crate) async fn container(state: &AppState, id: &str, image: &str, config: &str) {
        state
            .db
            .insert_container(&ContainerRecord {
                id: id.into(),
                name: Some(format!("n-{id}")),
                image_id: image.into(),
                config: config.into(),
                state: RecordState::Created,
                pid: None,
                created_at: "2026-01-01T00:00:00Z".into(),
                started_at: None,
                finished_at: None,
                exit_code: None,
            })
            .await
            .unwrap();
    }

    /// Runs `sql` on the database of the store through a connection of its
    /// own (the daemon's sees the change at its next statement).
    pub(crate) fn alter(state: &AppState, sql: &str) {
        rusqlite::Connection::open(state.config.storage.database_path())
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }
}
