// SPDX-License-Identifier: Apache-2.0
//! The operations on pods.

use super::{Error, Result};
use crate::api::status::StatusCode;
use crate::api::AppState;
use velarx_core::services::PodError;
use velarx_types::DbError;
use velarx_wire::wire::PodLogEntry;

pub(crate) fn pod_status(e: &velarx_core::services::PodError) -> StatusCode {
    use velarx_core::services::PodError as E;
    match e {
        E::NotFound(_) | E::Database(DbError::NotFound(_)) => StatusCode::NOT_FOUND,
        E::AlreadyExists(_) | E::Database(DbError::AlreadyExists(_)) => StatusCode::CONFLICT,
        E::InvalidConfig(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// What the logs of a pod are asked for.
#[derive(Debug, Default)]
pub struct LogsQuery {
    pub since_ns: Option<i64>,
    pub until_ns: Option<i64>,
    /// The last lines of each log (0: none); absent: all
    pub tail: Option<u64>,
    pub containers: Vec<String>,
}

/// Why the logs of the pod `pod` cannot be had, in podman's words.
pub(crate) fn logs_failure(pod: &str, e: PodError) -> Error {
    let (status, message) = match e {
        PodError::NotFound(_) => (
            StatusCode::NOT_FOUND,
            format!("no pod with name or ID {pod} found: no such pod"),
        ),
        PodError::Logs(m) | PodError::InvalidConfig(m) => (StatusCode::BAD_REQUEST, m),
        e => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    Error::new(status, message).with_code(82)
}

/// The lines of the logs of a pod, merged from its containers.
pub async fn logs(state: &AppState, id: &str, q: &LogsQuery) -> Result<Vec<PodLogEntry>> {
    state
        .pod_service
        .logs(id, q.since_ns, q.until_ns, q.tail, &q.containers)
        .await
        .map_err(|e| logs_failure(id, e))
}

/// The lines of the logs of a pod as they come, until the containers have
/// exited and their logs were read; the following stops when the stream is
/// dropped.
pub async fn follow_logs(
    state: &AppState,
    id: &str,
    q: &LogsQuery,
) -> Result<impl futures::Stream<Item = PodLogEntry> + Send> {
    let following = state
        .pod_service
        .follow_logs(id, q.since_ns, q.until_ns, q.tail, &q.containers)
        .await
        .map_err(|e| logs_failure(id, e))?;
    Ok(lines(following))
}

/// The lines a following of the logs of a pod gets, as they come.
pub fn lines(
    following: velarx_core::services::podlogs::Following,
) -> impl futures::Stream<Item = PodLogEntry> + Send {
    futures::stream::unfold(following, |mut f| async move {
        let e = f.rx.recv().await?;
        let line = entry(&e, f.containers);
        Some((line, f))
    })
}

/// A line of the logs of a pod being followed, as the list has them.
fn entry(e: &velarx_core::services::podlogs::Entry, containers: usize) -> PodLogEntry {
    PodLogEntry {
        container_name: e.container.clone(),
        container_id: e.container_id.clone(),
        container_index: e.index,
        containers,
        timestamp: velarx_wire::monitor::logfmt::format_rfc3339_ns(e.ts_ns),
        stream: match e.stream {
            velarx_wire::monitor::logfmt::Stream::Stdout => "stdout".to_string(),
            velarx_wire::monitor::logfmt::Stream::Stderr => "stderr".to_string(),
        },
        message: e.message.clone(),
    }
}
