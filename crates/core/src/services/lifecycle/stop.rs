// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::services::container::stored_config;
use velarx_db::RecordState;
use velarx_wire::monitor::iface;
use velarx_wire::monitor::proto::CoreState;

/// How a stop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// The container did not run.
    NotRunning,
    /// The stop signal stopped it.
    Stopped,
    /// It was killed: `signal` did not stop it in `seconds`.
    Killed { signal: i32, seconds: u32 },
}

/// What a stop of a container found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorStop {
    /// Nothing ran: the container was created and not started, or had ended.
    Nothing,
    /// The container ended and its exit is recorded; `killed`: SIGKILL was
    /// needed.
    Ended { killed: bool },
}

/// What a call of the core of a monitor found.
enum Core<T> {
    Answered(T),
    /// A monitor from before the core (its container is followed, and
    /// stopped by the signal that stops its unit).
    Old,
    /// No monitor answers.
    Gone,
    /// The monitor refused (an error of the interface).
    Refused(io::Error),
}

/// The lock of the restarts of a container, until it is dropped.
pub struct RestartLock {
    _file: std::fs::File,
}

impl ContainerService {
    /// Wait for a container to stop; its exit code.  The exit is recorded
    /// by its monitor, in the database: a change of it
    /// wakes the wait, whatever process made it.
    pub async fn wait(self: &Arc<Self>, id: &str) -> ContainerResult<i32> {
        self.reconcile(id).await?;
        let mut changes = self.db.watch_changes()?;
        // A monitor that ends without a word records nothing: its end wakes
        // the wait too.  Its own `Wait` is answered when the exit is
        // recorded, whatever the version of the monitor with a core; one
        // from before is watched by its process.
        let dir = self.mon_dir(id);
        let watch_dir = dir.clone();
        let monitor = match tokio::task::spawn_blocking(move || client::watch_exit(&watch_dir))
            .await
            .map_err(io::Error::other)
            .and_then(|r| r)
        {
            Ok(fd) => Some(fd),
            Err(_) => match super::monitor_alive(&dir) {
                Some(m) => Some(m.pidfd),
                None => match tokio::task::spawn_blocking(move || client::monitor_pidfd(&dir))
                    .await
                    .map_err(io::Error::other)
                    .and_then(|r| r)
                {
                    Ok(pidfd) => Some(pidfd),
                    Err(e) if super::no_monitor(&e) => None,
                    // (the wait goes on, woken by the record only)
                    Err(e) => {
                        warn!("Cannot watch the monitor of container {id}: {e}");
                        None
                    }
                },
            },
        };
        let ended = async move {
            match monitor {
                Some(pidfd) => super::ended(pidfd).await,
                None => std::future::pending::<io::Result<()>>().await,
            }
        };
        tokio::pin!(ended);
        // (the monitor ended: its future is done and is not polled again)
        let mut ended_once = false;
        let mut monitor_ended = false;
        loop {
            let notified = self.lifecycle.exited.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self.db.get_container(id).await {
                Ok(c) if c.state == RecordState::Stopped => return Ok(c.exit_code.unwrap_or(0)),
                Ok(_) => {}
                Err(e) => return Err(e.into()),
            }
            if monitor_ended {
                monitor_ended = false;
                self.reconcile(id).await?;
                continue;
            }
            tokio::select! {
                _ = notified => {}
                changed = changes.changed() => changed?,
                gone = &mut ended, if !ended_once => {
                    gone?;
                    monitor_ended = true;
                    ended_once = true;
                }
            }
        }
    }

    /// The lock of a restart, held from its stop to its start: a stop or a
    /// kill of the container takes it first.  A lock file next to the
    /// one of the start, taken with `flock`.
    pub async fn restart_lock(&self, id: &str) -> ContainerResult<RestartLock> {
        let _file = self.mon_lock(self.restart_lock_file(id)).await?;
        Ok(RestartLock { _file })
    }

    /// [`Self::restart_lock`] of the container named `key` (an ID, a name or
    /// a prefix); none for one that is not there.
    async fn restart_lock_of(&self, key: &str) -> ContainerResult<Option<RestartLock>> {
        match self.db.get_container(key).await {
            Ok(c) => self.restart_lock(&c.id).await.map(Some),
            Err(_) => Ok(None),
        }
    }

    /// The file of the lock of the restarts of a container.
    pub(in crate::services) fn restart_lock_file(&self, id: &str) -> PathBuf {
        self.mon_lock_file(id, "restart")
    }

    /// Stop a container: its stop signal, then SIGKILL after `timeout`
    /// seconds.
    pub async fn stop(self: &Arc<Self>, id: &str, timeout: u32) -> ContainerResult<()> {
        self.stop_with(id, Some(timeout)).await
    }

    /// Stop a container: its stop signal, then SIGKILL after `timeout`
    /// seconds, by default its stop timeout.  Returns once it exited.
    pub async fn stop_with(
        self: &Arc<Self>,
        id: &str,
        timeout: Option<u32>,
    ) -> ContainerResult<()> {
        self.stop_reporting(id, timeout).await.map(|_| ())
    }

    /// `stop_with`, saying when the stop signal did not stop the container
    /// in time: Some((the signal, the seconds)), as podman warns of it.
    pub async fn stop_reporting(
        self: &Arc<Self>,
        id: &str,
        timeout: Option<u32>,
    ) -> ContainerResult<Option<(i32, u32)>> {
        Ok(match self.stop_signalled(id, timeout, None).await? {
            Stop::Killed { signal, seconds } => Some((signal, seconds)),
            Stop::NotRunning | Stop::Stopped => None,
        })
    }

    /// Stop a container with `signal` (else its own), then SIGKILL after
    /// `timeout` seconds (else its own; `0` kills at once).  The monitor
    /// does it, deadline included: a client that goes away does not stop
    /// it.  A paused container is resumed first: it would not get the
    /// signal.
    pub async fn stop_signalled(
        self: &Arc<Self>,
        id: &str,
        timeout: Option<u32>,
        signal: Option<i32>,
    ) -> ContainerResult<Stop> {
        let _restarting = self.restart_lock_of(id).await?;
        self.stop_unlocked(id, timeout, signal).await
    }

    /// [`Self::stop_signalled`] for a caller that holds the restart lock.
    pub async fn stop_unlocked(
        self: &Arc<Self>,
        id: &str,
        timeout: Option<u32>,
        signal: Option<i32>,
    ) -> ContainerResult<Stop> {
        if self.reconcile(id).await? {
            return Ok(Stop::NotRunning); // it had ended, and was removed
        }
        let container = self.db.get_container(id).await?;
        // A start under way finishes first (podman holds the container's
        // lock across its start): the stop then sees what it made.  The
        // lock is not held further: the exit is recorded under it.
        let container = {
            let _lock = self.start_lock(&container.id).await?;
            self.db.get_container(&container.id).await?
        };
        let config = stored_config(&container)?;
        let (default_signal, default_timeout) = stop_settings(&config);
        let (sig, timeout) = (
            signal.unwrap_or(default_signal),
            timeout.unwrap_or(default_timeout),
        );
        let runtime = self.runtime_for(&config);
        match runtime.state(&container.id).await {
            Ok(s) if s.state == crate::container::ContainerState::Paused => {
                runtime.resume(&container.id).await?;
            }
            Ok(_) => {}
            // (the monitor deleted it as it ended)
            Err(crate::container::RuntimeError::NotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
        // This also ends a restart the monitor waits to make.
        let killed = match self
            .stop_monitor(&container, sig, Duration::from_secs(u64::from(timeout)))
            .await?
        {
            MonitorStop::Nothing => return Ok(Stop::NotRunning),
            MonitorStop::Ended { killed } => killed,
        };
        info!("Stopped container {}", container.id);
        Ok(if killed {
            Stop::Killed {
                signal: sig,
                seconds: timeout,
            }
        } else {
            Stop::Stopped
        })
    }

    /// Whether a stop of the container is in progress, as its monitor says
    /// (whatever process asked for the stop).
    pub async fn is_stopping(&self, id: &str) -> bool {
        match self.core_call(id, client::core_status).await {
            Ok(Core::Answered(status)) => status.state == CoreState::Stopping,
            _ => false,
        }
    }

    /// A call of the core of the monitor of container `id`, on a thread
    /// of its own.
    async fn core_call<T: Send + 'static>(
        &self,
        id: &str,
        call: impl FnOnce(&Path) -> io::Result<T> + Send + 'static,
    ) -> ContainerResult<Core<T>> {
        let dir = self.mon_dir(id);
        match tokio::task::spawn_blocking(move || call(&dir))
            .await
            .map_err(|e| io_error(io::Error::other(e)))?
        {
            Ok(v) => Ok(Core::Answered(v)),
            Err(e)
                if matches!(
                    client::monitor_error(&e),
                    Some(client::MonitorError::Version { .. })
                ) =>
            {
                Ok(Core::Old)
            }
            // (a monitor that ended as it was asked: its connection closes)
            Err(e) if no_monitor(&e) => Ok(Core::Gone),
            Err(e) if client::monitor_error(&e).is_some() => Ok(Core::Refused(e)),
            Err(e) => Err(io_error(e)),
        }
    }

    /// Stop the container of `container` with its monitor: `signal`, then
    /// SIGKILL after `timeout` (none: at once).  The container is as it
    /// ended, its exit recorded, when this returns; a monitor that waits to
    /// start it ends instead.
    pub async fn stop_monitor(
        self: &Arc<Self>,
        container: &ContainerRecord,
        signal: i32,
        timeout: Duration,
    ) -> ContainerResult<MonitorStop> {
        // An `unless-stopped` container stopped by its user stays stopped
        // at boot.
        self.update_ext(&container.id, move |e| e.stopped_by_user = true)
            .await?;
        let dir = self.mon_dir(&container.id);
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        let notice = ContainerNotice::Stopping {
            id: container.id.clone(),
        };
        let _ = self.lifecycle.notices.send(notice.clone());
        let stopped = self
            .core_call(&container.id, move |d| {
                client::stop(d, Some(signal), Some(timeout_ms))
            })
            .await;
        let _ = self.lifecycle.notices.send(notice);
        match stopped? {
            Core::Answered((_, killed)) => {
                // (it ends as it answers)
                self.wait_monitor_gone(&dir).await?;
                Ok(MonitorStop::Ended { killed })
            }
            // Created and waiting to be started (`init`): it never will, the
            // monitor deletes it and the container is as created.
            Core::Refused(e) if client::is_error(&e, iface::error::INVALID_STATE) => {
                let quit_dir = dir.clone();
                let _ = tokio::task::spawn_blocking(move || client::quit(&quit_dir)).await;
                self.wait_monitor_gone(&dir).await?;
                if container.state == RecordState::Initialized {
                    self.release_network(container).await;
                    self.db
                        .update_container_state(
                            &container.id,
                            RecordState::Created,
                            None,
                            None,
                            None,
                            None,
                        )
                        .await?;
                }
                Ok(MonitorStop::Nothing)
            }
            Core::Refused(e) => Err(io_error(io::Error::other(e))),
            // A monitor from before the core, or none while the container
            // runs (it was killed): the dead-or-old-monitor path.  The
            // container is signalled through its runtime and followed to its
            // end (a monitor from before the core ends with it, as it
            // always did; one that is gone left its exit for `reconcile`).
            Core::Old | Core::Gone if container.state == RecordState::Running => {
                // A monitor of another version: what stops its unit stops
                // the container on purpose (no restart).
                let pid_dir = dir.clone();
                let _ =
                    tokio::task::spawn_blocking(move || signal_monitor(&pid_dir, libc::SIGTERM))
                        .await;
                let runtime = self.runtime_for_record(container)?;
                let stopped = !timeout.is_zero() && {
                    runtime.kill_signal(&container.id, signal).await?;
                    self.ended_within(&container.id, timeout).await?
                };
                if !stopped {
                    runtime.kill_signal(&container.id, libc::SIGKILL).await?;
                    if !self
                        .ended_within(&container.id, Duration::from_secs(10))
                        .await?
                    {
                        return Err(io_error(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "the container did not stop",
                        )));
                    }
                }
                Ok(MonitorStop::Ended { killed: !stopped })
            }
            // (nothing runs: the exit was recorded by what the monitor left)
            Core::Old | Core::Gone => Ok(MonitorStop::Nothing),
        }
    }

    /// Wait up to `limit` for the container `id` to end (or to be removed,
    /// as an `--rm` container is as it ends): whether it did.
    async fn ended_within(self: &Arc<Self>, id: &str, limit: Duration) -> ContainerResult<bool> {
        match tokio::time::timeout(limit, self.wait(id)).await {
            Err(_) => Ok(false),
            Ok(Ok(_))
            | Ok(Err(ContainerError::NotFound(_)))
            | Ok(Err(ContainerError::Database(velarx_types::DbError::NotFound(_)))) => Ok(true),
            Ok(Err(e)) => Err(e),
        }
    }

    pub async fn kill(self: &Arc<Self>, id: &str, signal: &str) -> ContainerResult<()> {
        let _restarting = self.restart_lock_of(id).await?;
        if self.reconcile(id).await? {
            return Err(ContainerError::NotRunning(id.to_string()));
        }
        let container = self.db.get_container(id).await?;
        if container.state != RecordState::Running {
            return Err(ContainerError::NotRunning(id.to_string()));
        }
        let sig = parse_signal(signal).ok_or_else(|| {
            io_error(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid signal: {signal}"),
            ))
        })?;
        self.kill_container(&container, sig).await?;
        info!("Sent {} to container {}", signal, container.id);
        self.notify_action(&container, "kill", vec![("signal".into(), sig.to_string())]);
        Ok(())
    }

    /// Send `sig` to the init of a running container, through its monitor:
    /// podman's rule is that a container a user killed (with any signal) was
    /// stopped by the user, and its restart policy no longer applies (the
    /// monitor makes no restart for the exit that follows).
    pub async fn kill_container(
        &self,
        container: &ContainerRecord,
        sig: i32,
    ) -> ContainerResult<()> {
        self.update_ext(&container.id, move |e| e.stopped_by_user = true)
            .await?;
        match self
            .core_call(&container.id, move |d| client::kill(d, sig))
            .await?
        {
            Core::Answered(()) => Ok(()),
            Core::Refused(e) if client::is_error(&e, iface::error::NOT_RUNNING) => {
                Err(ContainerError::NotRunning(container.id.clone()))
            }
            Core::Refused(e) => Err(io_error(e)),
            // A monitor from before the core, or none: through the runtime
            // (the dead-or-old-monitor path).
            Core::Old | Core::Gone => {
                self.runtime_for_record(container)?
                    .kill_signal(&container.id, sig)
                    .await?;
                Ok(())
            }
        }
    }

    /// Tell the monitor of a running container its restart policy and its
    /// health check as `config` now has them (an update); a container that
    /// does not run takes them at its next start.
    pub async fn update_monitor(
        &self,
        id: &str,
        config: &ContainerConfig,
        restart: bool,
        health: bool,
    ) {
        if !restart && !health {
            return;
        }
        let u = proto::MonitorUpdate {
            restart: restart.then(|| proto::RestartUpdate {
                policy: config.restart_policy.clone(),
            }),
            health: health.then(|| proto::HealthUpdate {
                check: health_config(config),
                log_dir: None,
            }),
            ..Default::default()
        };
        let dir = self.mon_dir(id);
        let log_dir = health.then(|| open_health_log_dir(config)).flatten();
        match tokio::task::spawn_blocking(move || {
            client::update(
                &dir,
                &u,
                None,
                log_dir.as_ref().map(std::os::fd::AsFd::as_fd),
            )
        })
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => warn!("The monitor of {id} was not updated: {e}"),
            Err(e) => warn!("The update of the monitor of {id} failed: {e}"),
        }
    }

    pub async fn restart(self: &Arc<Self>, id: &str, timeout: u32) -> ContainerResult<()> {
        self.restart_with(id, Some(timeout)).await
    }

    pub async fn restart_with(
        self: &Arc<Self>,
        id: &str,
        timeout: Option<u32>,
    ) -> ContainerResult<()> {
        self.restart_checking(id, timeout, &StartCheck::Engine)
            .await
    }

    /// [`Self::restart_with`] for the start `check` says.
    pub async fn restart_checking(
        self: &Arc<Self>,
        id: &str,
        timeout: Option<u32>,
        check: &StartCheck,
    ) -> ContainerResult<()> {
        info!("Restarting container {}", id);
        let id = self.db.get_container(id).await?.id;
        self.keep(&id).await?;
        let id = id.as_str();
        // A stop or a kill meanwhile waits for the restart to end and then
        // stops what it started, as podman's (which holds the container's
        // lock).
        let _restarting = self.restart_lock(id).await?;
        // (podman's order: `restart`, then the `died` of the stop, `init`
        // and `start`)
        self.notify_action_of(id, "restart", Vec::new()).await;
        self.stop_unlocked(id, timeout, None).await?;
        self.start_checking(id, check).await?;
        Ok(())
    }

    /// Start what the container needs (`--requires`) that does not run,
    /// and what that needs: the dependencies existed when the container was
    /// made, so they form no cycle.
    pub(super) fn start_dependencies<'a>(
        self: &'a Arc<Self>,
        config: &'a ContainerConfig,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ContainerResult<()>> + Send + 'a>> {
        Box::pin(async move {
            for dep in &config.requires {
                let rec = self.db.get_container(dep).await.map_err(|_| {
                    ContainerError::NotFound(format!("{dep}, which the container requires"))
                })?;
                if rec.state == RecordState::Running {
                    continue;
                }
                info!("Starting {}, which {} requires", rec.id, config.id);
                match self.start_with(&rec.id, false).await {
                    Ok(_) | Err(ContainerError::AlreadyRunning(_)) => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        })
    }

    /// The containers that depend on `id`: they require it (`--requires`)
    /// or join a namespace of it (`--net container:ID` and the like).
    pub async fn dependents(&self, id: &str) -> ContainerResult<Vec<String>> {
        let name = match self.db.get_container(id).await {
            Ok(c) => c.name.unwrap_or_default(),
            Err(velarx_types::DbError::NotFound(_)) => String::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(self.db.container_dependents(id, &name).await?)
    }

    /// An error, as podman's removal gives, when other containers depend on
    /// the container `id`: also forced, they go first.  Before the stop of a
    /// forced removal, so that the container that stays is not stopped.
    pub async fn ensure_no_dependents(&self, id: &str) -> ContainerResult<()> {
        let dependents = self.dependents(id).await?;
        if dependents.is_empty() {
            return Ok(());
        }
        Err(ContainerError::InvalidArgument(format!(
            "container {id} has dependent containers which must be removed before it: {}: container already exists",
            dependents.join(", ")
        )))
    }

    pub async fn delete(self: &Arc<Self>, id: &str, force: bool) -> ContainerResult<()> {
        velarx_base::trace::point("delete start");
        self.delete_with_volumes(id, force, false).await
    }

    /// Have the monitor of the container remove it, stopped first with
    /// `force` (SIGKILL at once).  False when no monitor answers (it went, or
    /// is of another version of velarx): the engine removes it.
    async fn remove_by_monitor(
        &self,
        container: &ContainerRecord,
        force: bool,
        volumes: bool,
    ) -> ContainerResult<bool> {
        let dir = self.mon_dir(&container.id);
        let removed = tokio::task::spawn_blocking(move || {
            client::remove(&dir, force, force.then_some(0), volumes)
        })
        .await
        .map_err(|e| io_error(io::Error::other(e)))?;
        match removed {
            Ok(_) => Ok(true),
            Err(e) if client::is_error(&e, iface::error::INVALID_STATE) => {
                if container.state.is_alive() && !force {
                    Err(ContainerError::AlreadyRunning(container.id.clone()))
                } else {
                    // (a monitor that does not remove: the engine does)
                    Ok(false)
                }
            }
            Err(e) if client::is_error(&e, iface::error::FAILED) => {
                Err(io_error(io::Error::other(e)))
            }
            Err(_) => Ok(false),
        }
    }

    /// Remove a container, and with `volumes` (or `--rm`) the anonymous
    /// volumes it made.
    pub async fn delete_with_volumes(
        self: &Arc<Self>,
        id: &str,
        force: bool,
        volumes: bool,
    ) -> ContainerResult<()> {
        if self.reconcile(id).await? {
            return Ok(()); // it had ended, and was removed
        }
        let container = self.db.get_container(id).await?;
        self.ensure_no_dependents(&container.id).await?;
        // A container with a monitor that answers is removed by it, as it is
        // removed when it exits with `--rm`; the lock of its start is not
        // held while it works.
        let layers = self.db.container_layers(&container.id).await?;
        if self.remove_by_monitor(&container, force, volumes).await? {
            self.image_service
                .release_engine_copies(Some(&layers))
                .await;
            return Ok(());
        }
        let mut container = container;
        // A container that runs is stopped without the lock of its start:
        // its exit is recorded under it.  Whatever else it is is looked at
        // under the lock, where no start is under way: a start that comes
        // after it finds the container gone, one that ran meanwhile is
        // stopped again.
        // The run that was stopped last: still the one that runs after the
        // stop means it did not stop (another run is a start that came in
        // the meantime, stopped in its turn).
        let mut stopped_run = None;
        let lock = loop {
            if container.state.is_alive() {
                if container.state == RecordState::Running && !force {
                    return Err(ContainerError::AlreadyRunning(id.to_string()));
                }
                let run = (container.pid, container.started_at.clone());
                if stopped_run.as_ref() == Some(&run) {
                    return Err(io_error(io::Error::other(format!(
                        "container {} did not stop",
                        container.id
                    ))));
                }
                // This also ends a restart the monitor waits to make.
                self.stop_monitor(&container, libc::SIGKILL, Duration::ZERO)
                    .await?;
                stopped_run = Some(run);
            }
            let lock = self.start_lock(&container.id).await?;
            container = self.db.get_container(&container.id).await?;
            if container.state.is_alive() {
                continue;
            }
            // A monitor that waits to start the container goes.  Its last
            // exit is recorded under the lock, which is not held while it
            // is waited for: then the container is looked at again.
            drop(lock);
            self.stop_monitor(&container, libc::SIGKILL, Duration::ZERO)
                .await?;
            let lock = self.start_lock(&container.id).await?;
            container = self.db.get_container(&container.id).await?;
            if container.state.is_alive() {
                continue;
            }
            break lock;
        };
        // (a record whose configuration is not valid is removed all the
        // same: it is the way to be rid of it; what the configuration names,
        // its OCI runtime among it, stays)
        let config = match stored_config(&container) {
            Ok(config) => Some(config),
            Err(e) => {
                warn!(
                    "Removing container {} without its configuration: {e}",
                    container.id
                );
                None
            }
        };
        if config.is_some() {
            self.release_network(&container).await;
        } else if let Err(e) = self.network_manager.cleanup(&container.id).await {
            warn!("Cannot release the network of {}: {e}", container.id);
        }
        let runtime = config.as_ref().map(|c| self.runtime_for(c));
        self.remove_files_locked(&container.id, runtime, &lock, true)
            .await?;
        if let Some(config) = &config {
            remove_named_files(config)?;
        }
        let layers = self.db.container_layers(&container.id).await?;
        match self.db.delete_container(&container.id).await {
            Ok(()) | Err(velarx_types::DbError::NotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
        if let Some(config) = &config {
            if volumes || config.auto_remove {
                super::super::container::remove_anonymous_volumes(&self.volume_service, config)
                    .await;
            }
        }
        info!("Deleted container {}", container.id);
        drop(lock);
        // (the last container whose root the engine served from the copy of
        // a lazy image it made: the copy goes)
        self.image_service
            .release_engine_copies(Some(&layers))
            .await;
        let exit = container
            .exit_code
            .map(|c| vec![("containerExitCode".to_string(), c.to_string())])
            .unwrap_or_default();
        self.notify_action(&container, "remove", exit);
        Ok(())
    }
}

/// The pid files and the cidfile go with the container, as podman's.
pub(in crate::services) fn remove_named_files(config: &ContainerConfig) -> io::Result<()> {
    for p in [&config.pid_file, &config.conmon_pid_file, &config.cid_file]
        .into_iter()
        .flatten()
    {
        match std::fs::remove_file(p) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

/// Send `sig` to the monitor that serves the socket of `dir`, whatever its
/// version.
fn signal_monitor(dir: &Path, sig: i32) -> io::Result<()> {
    velarx_sys::signal::pidfd_send_signal(&client::monitor_pidfd(dir)?, sig)
}
