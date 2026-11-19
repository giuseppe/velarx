// SPDX-License-Identifier: Apache-2.0
use super::*;
use velarx_db::RecordState;

impl ContainerService {
    /// What happens to the containers.
    pub fn subscribe_notices(&self) -> tokio::sync::broadcast::Receiver<ContainerNotice> {
        self.lifecycle.notices.subscribe()
    }

    /// The service starts: observe the monitors that outlived the previous
    /// one, and look after the containers that ended without a word.
    pub async fn adopt_containers(self: &Arc<Self>) -> ContainerResult<()> {
        let containers = self.db.list_containers(true).await?;
        // (one container that cannot be looked after does not keep the
        // others from being adopted: its error is told, the first given back)
        let mut first = None;
        for container in containers {
            if let Err(e) = self.adopt_one(&container).await {
                warn!("Cannot look after container {}: {e}", container.id);
                first.get_or_insert(e);
            }
        }
        // What no record names (a bundle, logs, an anonymous volume) is
        // a leftover: after a crash of the machine the rows of the `--rm`
        // containers are gone, not their files.
        if let Err(e) = self.sweep_unowned().await {
            warn!("Cannot look for what no container record names: {e}");
            first.get_or_insert(e);
        }
        // A holder of the rootless network namespace that was killed leaves
        // its pasta, which no longer ends with it: with no container left
        // in the namespace they go now (published ports are freed).
        if let Some(engine) = self.network_manager.engine() {
            engine.release_rootless_netns_if_unused().await;
        }
        first.map_or(Ok(()), Err)
    }

    /// [`Self::adopt_containers`] of the container of `container`.
    async fn adopt_one(self: &Arc<Self>, container: &ContainerRecord) -> ContainerResult<()> {
        let dir = self.mon_dir(&container.id);
        match container.state {
            RecordState::Running
            | RecordState::Created
            | RecordState::Initialized
            | RecordState::Paused => self.adopt(container, &dir).await,
            _ => {
                // (an `--rm` container whose removal was interrupted is
                // marked in its row: `finish_removals` did it when the
                // services were built)
                if !self.bundle_dir(&container.id).join("config.json").exists() {
                    // Not running: kept if it can be started again.
                    info!(
                        "Removing stopped container {} (its bundle is gone)",
                        container.id
                    );
                    self.db.delete_container(&container.id).await?;
                    let dirs = [dir, self.log_dir(&container.id)];
                    crate::off_thread(move || {
                        dirs.iter()
                            .try_for_each(|d| velarx_runtime::settle::remove::remove_tree(d))
                    })
                    .await?;
                    Ok(())
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Observe the monitor of a container when the service starts: what the
    /// previous service left unrecorded is recorded.
    pub(in crate::services) async fn adopt(
        self: &Arc<Self>,
        container: &ContainerRecord,
        dir: &Path,
    ) -> ContainerResult<()> {
        let subscribe_dir = dir.to_path_buf();
        let subscribed =
            tokio::task::spawn_blocking(move || client::subscribe(&subscribe_dir)).await;
        match subscribed {
            Ok(Ok((conn, status))) => {
                info!(
                    "Observing the monitor of container {} ({:?})",
                    container.id, status.state
                );
                match status.state {
                    // Created by `init`: it waits to be started.
                    RunState::Created if container.state == RecordState::Initialized => {}
                    RunState::Created => {
                        // Its starter went away before it started the
                        // container.  (a monitor that cannot be told stays
                        // as it is, its container too: the error says so)
                        let quit_dir = dir.to_path_buf();
                        crate::off_thread(move || client::quit(&quit_dir)).await?;
                        self.db
                            .update_container_state(
                                &container.id,
                                RecordState::Stopped,
                                None,
                                None,
                                None,
                                Some(255),
                            )
                            .await?;
                        return Ok(());
                    }
                    RunState::Running | RunState::Paused | RunState::Stopping => {
                        // The monitor may have failed
                        // while no service looked.
                        let restarts = status.restart_count;
                        let health = status
                            .health
                            .as_ref()
                            .and_then(|h| serde_json::to_string(h).ok());
                        self.update_ext(&container.id, move |e| {
                            if health.is_some() {
                                e.health = health;
                            }
                            e.restart_count = restarts;
                        })
                        .await?;
                        if container.state != RecordState::Running || container.pid != status.pid {
                            self.db
                                .update_container_state(
                                    &container.id,
                                    RecordState::Running,
                                    status.pid,
                                    status.started_ns.map(rfc3339),
                                    None,
                                    None,
                                )
                                .await?;
                        }
                    }
                    // (the monitor itself is on it)
                    RunState::Exited | RunState::Removing | RunState::Removed => {}
                }
                let (stream, rest) = conn.into_parts();
                match MonitorConn::new(stream, rest) {
                    Ok(events) => self.watch_monitor(container.id.clone(), events),
                    Err(e) => warn!("Cannot follow the monitor of {}: {}", container.id, e),
                }
            }
            Ok(Err(e))
                if matches!(
                    client::monitor_error(&e),
                    Some(client::MonitorError::Version { .. })
                ) =>
            {
                let pid_dir = dir.to_path_buf();
                match tokio::task::spawn_blocking(move || client::monitor_pidfd(&pid_dir)).await {
                    Ok(Ok(pidfd)) => {
                        self.follow_foreign(container.id.clone(), pidfd, e.to_string())
                    }
                    _ => self.monitor_lost(container).await?,
                }
            }
            _ if container.state == RecordState::Created => {
                // Never started.
            }
            _ => {
                // No monitor: it went away with the service, or after it.
                self.monitor_lost(container).await?;
            }
        }
        Ok(())
    }

    /// Observe the monitor of a running container: its events become
    /// notices of this process.  A monitor that does not answer is looked
    /// after as `reconcile` does.
    pub(in crate::services) async fn observe(
        self: &Arc<Self>,
        container: &ContainerRecord,
    ) -> ContainerResult<()> {
        let subscribe_dir = self.mon_dir(&container.id);
        let subscribed =
            tokio::task::spawn_blocking(move || client::subscribe(&subscribe_dir)).await;
        match subscribed {
            Ok(Ok((conn, _))) => {
                let (stream, rest) = conn.into_parts();
                match MonitorConn::new(stream, rest) {
                    Ok(events) => self.watch_monitor(container.id.clone(), events),
                    Err(e) => warn!("Cannot follow the monitor of {}: {}", container.id, e),
                }
            }
            _ => {
                self.reconcile(&container.id).await?;
            }
        }
        Ok(())
    }
}
