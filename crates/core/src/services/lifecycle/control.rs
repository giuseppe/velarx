// SPDX-License-Identifier: Apache-2.0
//! What the engine asks of the monitor of a running container besides its
//! stop: freeze and thaw it, change its limits and what happens at its exit.
use super::*;
use velarx_wire::monitor::iface;
use velarx_wire::monitor::proto::{ExitPlan, MonitorUpdate};

/// What an error of a call to the monitor of `id` is for the engine's
/// callers.
fn monitor_failure(id: &str, e: io::Error) -> ContainerError {
    if matches!(
        client::monitor_error(&e),
        Some(client::MonitorError::Version { .. })
    ) {
        return ContainerError::MonitorVersion {
            id: id.to_string(),
            reason: e.to_string(),
        };
    }
    if super::no_monitor(&e) {
        return ContainerError::MonitorLost(id.to_string());
    }
    if client::is_error(&e, iface::error::NOT_RUNNING)
        || client::is_error(&e, iface::error::INVALID_STATE)
    {
        return ContainerError::NotRunning(id.to_string());
    }
    if client::is_error(&e, iface::error::INVALID_ARGUMENT) {
        return ContainerError::InvalidArgument(e.to_string());
    }
    io_error(e)
}

impl ContainerService {
    /// Freeze (`pause`) or thaw the container with its monitor, which runs
    /// the runtime.
    pub async fn freeze(&self, id: &str, pause: bool) -> ContainerResult<()> {
        let dir = self.mon_dir(id);
        tokio::task::spawn_blocking(move || {
            if pause {
                client::pause(&dir)
            } else {
                client::resume(&dir)
            }
        })
        .await
        .map_err(|e| io_error(io::Error::other(e)))?
        .map(|_| ())
        .map_err(|e| monitor_failure(id, e))
    }

    /// Set the size of the terminal of the container: `InvalidState` when it
    /// has none.
    pub async fn resize_terminal(&self, id: &str, rows: u16, cols: u16) -> ContainerResult<()> {
        let dir = self.mon_dir(id);
        tokio::task::spawn_blocking(move || client::resize(&dir, rows, cols))
            .await
            .map_err(|e| io_error(io::Error::other(e)))?
            .map_err(|e| monitor_failure(id, e))
    }

    /// Keep an `--rm` container when it exits (a restart, a pod stop, a
    /// checkpoint that keeps it): the plan of its monitor says it stays.  A
    /// monitor started later takes its plan from the configuration again.
    pub async fn keep(&self, id: &str) -> ContainerResult<()> {
        let dir = self.mon_dir(id);
        let update = MonitorUpdate {
            plan: Some(ExitPlan {
                remove: false,
                volumes: false,
            }),
            ..Default::default()
        };
        match tokio::task::spawn_blocking(move || client::update(&dir, &update, None, None))
            .await
            .map_err(|e| io_error(io::Error::other(e)))?
        {
            Ok(()) => Ok(()),
            // (no monitor: nothing removes the container as it exits)
            Err(e) if super::no_monitor(&e) => Ok(()),
            Err(e) => Err(monitor_failure(id, e)),
        }
    }

    /// Give the running container the limits `resources` (the OCI
    /// `linux.resources`); the runtime's refusal is an `InvalidArgument`.
    pub async fn update_resources(
        &self,
        id: &str,
        resources: &serde_json::Value,
    ) -> ContainerResult<()> {
        let file = velarx_base::sealed::sealed_memory(&serde_json::to_vec(resources)?)?;
        let dir = self.mon_dir(id);
        tokio::task::spawn_blocking(move || {
            client::update(
                &dir,
                &MonitorUpdate::default(),
                Some(std::os::fd::AsFd::as_fd(&file)),
                None,
            )
        })
        .await
        .map_err(|e| io_error(io::Error::other(e)))?
        .map_err(|e| monitor_failure(id, e))
    }

    /// Whether the `--rm` container `id` goes as it exits: when its plan
    /// says so (`remove`), and no other container depends on it (podman's
    /// removal fails then: it stays stopped).
    pub(in crate::services) async fn goes_as_it_exits(
        &self,
        id: &str,
        remove: bool,
    ) -> ContainerResult<bool> {
        Ok(remove && self.dependents(id).await?.is_empty())
    }

    /// The plan of the last exit of the container `id`: what its monitor
    /// wrote with the exit, else what the configuration says.
    pub(in crate::services) fn exit_plan_of(&self, id: &str, config: &ContainerConfig) -> bool {
        read_exit_file(&self.mon_dir(id)).map_or(config.auto_remove, |info| info.remove)
    }
}
