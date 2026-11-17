// SPDX-License-Identifier: Apache-2.0
//! Connecting to a TCP port inside the network namespace of a container or a
//! pod (a pod's is the one of its infra container): `POST
//! /libpod/containers/{name}/connect?port=P` and `/libpod/pods/{name}/connect`.
//! The daemon makes the connection in the namespace (a thread that joins it)
//! and, when the client upgrades the connection (`Upgrade: tcp`), relays the
//! bytes both ways: the client only sees a byte stream to the port, with no
//! idea of namespaces.

use super::error::{ApiError, ApiResult, Kind};
use super::lifecycle;
use crate::api::AppState;
use std::os::fd::OwnedFd;
use std::path::PathBuf;

/// Connections being made at once.  A dial holds a blocking thread for up to
/// the connect timeout per address, so a port that drops the SYNs of many
/// requests would use them all.
const MAX_DIALS: usize = 32;

static DIALS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(MAX_DIALS);

fn too_many(what: &str, max: usize) -> ApiError {
    ApiError::new(
        503,
        format!("too many connections to ports {what} at once (the limit is {max})"),
    )
}

/// The container whose namespace is the one of `name`: itself, or the infra
/// container of a pod.
async fn target(state: &AppState, kind: Kind, name: &str) -> ApiResult<velarx_db::ContainerRecord> {
    match kind {
        Kind::Container => lifecycle::resolve(state, name).await,
        Kind::Pod => {
            let pod = super::pods::get(state, name).await?;
            let infra = pod.infra_container_id.ok_or_else(|| {
                ApiError::invalid_state(format!("pod {} has no infra container", pod.name))
            })?;
            lifecycle::resolve(state, &infra).await
        }
        _ => Err(ApiError::internal("not a container or a pod")),
    }
}

/// A connection to PORT of the loopback of the namespace of `name`.
pub(crate) async fn dial(
    state: &AppState,
    kind: Kind,
    name: &str,
    port: u16,
) -> ApiResult<OwnedFd> {
    let dial = DIALS
        .try_acquire()
        .map_err(|_| too_many("being made", MAX_DIALS))?;
    let rec = target(state, kind, name).await?;
    let status = lifecycle::status(state, &rec).await;
    if !status.alive() || status.pid <= 0 {
        return Err(ApiError::invalid_state(format!(
            "cannot connect to a port of {}: it is not running: container state improper",
            rec.id
        )));
    }
    let netns = match init_netns(state, &rec.id).await {
        Some(ns) => ns,
        None => {
            let path = PathBuf::from(format!("/proc/{}/ns/net", status.pid));
            let netns = crate::api::off_thread(move || std::fs::File::open(path))
                .await
                .map_err(|e| {
                    ApiError::invalid_state(format!("cannot connect to a port of {}: {e}", rec.id))
                })?;
            // the namespace is held open: it is the container's if the
            // container still runs with that PID (not a process that got
            // the number of an exited one)
            let again = lifecycle::status(state, &rec).await;
            if !again.alive() || again.pid != status.pid {
                return Err(ApiError::invalid_state(format!(
                    "cannot connect to a port of {}: it is not running: container state improper",
                    rec.id
                )));
            }
            netns
        }
    };
    // (the place is the blocking thread's: it holds it when the request is
    // dropped while it connects)
    tokio::task::spawn_blocking(move || {
        let _dial = dial;
        velarx_runtime::network::dial::connect_loopback(&netns, port)
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(|e| ApiError::new(502, format!("connect to port {port}: {e}")))
}

/// The network namespace of the init of container `id` through the pidfd
/// its monitor hands over (`PIDFD_GET_NET_NAMESPACE`): no number that
/// could be another process's.  None without it (a kernel before 6.11, a
/// monitor that does not answer): the caller goes through `/proc`.
async fn init_netns(state: &AppState, id: &str) -> Option<std::fs::File> {
    let dir = state.container_service.mon_dir(id);
    tokio::task::spawn_blocking(move || {
        let pidfd = velarx_wire::monitor::client::open_init(&dir).ok()?;
        velarx_sys::ns::pidfd_net_namespace(std::os::fd::AsFd::as_fd(&pidfd))
            .ok()
            .map(std::fs::File::from)
    })
    .await
    .ok()
    .flatten()
}
