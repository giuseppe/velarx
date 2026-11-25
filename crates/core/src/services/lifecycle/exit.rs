// SPDX-License-Identifier: Apache-2.0
use super::start::PolicyRestart;
use super::*;
use velarx_db::RecordState;
use velarx_runtime::settle::remove::remove_tree;

impl ContainerService {
    /// What a monitor tells a process that observes it: notices, for the
    /// clients of this process.  The monitor recorded it itself.
    pub(super) async fn observe_event(&self, id: &str, event: Event) -> ContainerResult<()> {
        let notice = match event {
            Event::Exited(info) => {
                // (what the monitor does with the exit for good comes with
                // `Settled`)
                let (name, (image, labels)) = self.names_of(id).await?;
                self.lifecycle
                    .exit_codes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id.to_string(), (info.code, name.clone(), image.clone()));
                ContainerNotice::Exited {
                    id: id.to_string(),
                    code: info.code,
                    timed_out: info.timed_out,
                    name,
                    image,
                    labels,
                    restarting: false,
                }
            }
            Event::Restarting { exit, .. } => {
                let (name, (image, labels)) = self.names_of(id).await?;
                ContainerNotice::Exited {
                    id: id.to_string(),
                    code: exit.code,
                    timed_out: exit.timed_out,
                    name,
                    image,
                    labels,
                    restarting: true,
                }
            }
            Event::Health(h) => ContainerNotice::Health {
                id: id.to_string(),
                status: h.status,
            },
            Event::Oom => ContainerNotice::Oom { id: id.to_string() },
            Event::Started {
                restarted: true, ..
            } => ContainerNotice::Restarted { id: id.to_string() },
            Event::Started { .. } => return Ok(()),
            Event::Settled(settled) => {
                let exited = self
                    .lifecycle
                    .exit_codes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(id);
                if settled.removed {
                    self.lifecycle.unwatch(id);
                    // (a container that never ran has no exit: whoever asked
                    // for its removal tells it)
                    if let Some((code, name, image)) = exited {
                        let _ = self.lifecycle.notices.send(ContainerNotice::Seen(Box::new(
                            ContainerNotice::Action {
                                id: id.to_string(),
                                name,
                                image,
                                action: "remove",
                                attributes: vec![("containerExitCode".into(), code.to_string())],
                            },
                        )));
                    }
                }
                match settled.image {
                    Some(change) => {
                        // (its layers go now, as an `rmi` releases them)
                        if change.removed {
                            let (images, held) =
                                (Arc::clone(&self.image_service), self.lifecycle.hold());
                            tokio::spawn(async move {
                                images.release_removed().await;
                                drop(held);
                            });
                        }
                        ContainerNotice::Image(change)
                    }
                    None => return Ok(()),
                }
            }
        };
        let _ = self
            .lifecycle
            .notices
            .send(ContainerNotice::Seen(Box::new(notice)));
        Ok(())
    }

    /// The name, image and labels a notice of container `id` carries (none
    /// when it is removed already).
    async fn names_of(
        &self,
        id: &str,
    ) -> ContainerResult<(String, (String, Vec<(String, String)>))> {
        match self.db.get_container(id).await {
            Ok(c) => Ok((c.name.clone().unwrap_or_default(), event_details(&c))),
            Err(velarx_types::DbError::NotFound(_)) => Ok(Default::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// `monitor_gone` in a task that nobody waits for: what it cannot do is
    /// logged, unless the process closed the store meanwhile (a command that
    /// ends while the monitor of a container does): the store is empty then,
    /// and there is nothing left to look after.
    pub(super) async fn look_after_monitor_gone(self: &Arc<Self>, id: &str) {
        if let Err(e) = self.monitor_gone(id).await {
            if self.db.is_closed() {
                debug!("The monitor of container {id} ended with the process: {e}");
            } else {
                warn!("Cannot look after the monitor of container {id} that ended: {e}");
            }
        }
    }

    /// The connection to a monitor ended: if it did not report an exit, its
    /// exit file says what happened.
    pub(super) async fn monitor_gone(self: &Arc<Self>, id: &str) -> ContainerResult<()> {
        // The connection ends before the monitor does: the monitor itself
        // is working until then.
        if let Some(monitor) = super::monitor_alive(&self.mon_dir(id)) {
            super::ended(monitor.pidfd).await?;
        }
        let container = match self.db.get_container(id).await {
            Ok(c) => c,
            Err(velarx_types::DbError::NotFound(_)) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        // (an initialized container whose monitor quits is made created
        // again by the one that asked)
        if !(container.state.is_alive() || container.state == RecordState::Created) {
            // (killed after it recorded the exit of a container that goes
            // with it: a process that lives on, the engine service, does not
            // wait for the next one that builds its services)
            if self.db.removal_pending(id).await? {
                return self.finish_removal(id).await;
            }
            return Ok(());
        }
        // (last: following an orphan replaces the task that runs this)
        self.monitor_lost(&container).await
    }

    /// A container whose monitor is gone: the exit it wrote, else the
    /// container's init may still run (the monitor was killed, crashed):
    /// this process follows it until it ends; else it ended unseen (255).
    pub(in crate::services) async fn monitor_lost(
        self: &Arc<Self>,
        container: &ContainerRecord,
    ) -> ContainerResult<()> {
        // Under the lock of the start, as the monitor: what a start
        // wrote comes first, and the container is looked at as it is now
        // (it may run again, with a monitor of its own).
        let _lock = self.start_lock(&container.id).await?;
        let Some(container) = self.alive_record(&container.id).await? else {
            return Ok(());
        };
        let container = &container;
        if let Some(info) = read_exit_file(&self.mon_dir(&container.id)) {
            self.forget_in_runtime(container).await?;
            if self.record_exit(&container.id, &info).await? {
                return Ok(());
            }
            // The exit file is of an earlier run than the one recorded: that
            // one's monitor is gone too (none is alive here, and no start is
            // under way): it ended unseen unless its process runs on.
            if self.live_init(container).await?.is_none()
                && self.running_record(&container.id).await?.is_some()
            {
                warn!(
                    "The monitor of container {} is gone without the exit of its run",
                    container.id
                );
                self.record_exit(&container.id, &self.unseen_exit(&container.id, container))
                    .await?;
            }
            return Ok(());
        }
        if let Some(pidfd) = self.live_init(container).await? {
            warn!(
                "The monitor of container {} is gone, its process {} runs on: followed",
                container.id,
                container.pid.unwrap_or(0)
            );
            // (the root file system is a mount of the container's own namespace,
            // which the monitor's end does not take away: it is followed to its
            // end and its restart policy then starts it on a new monitor)
            self.follow_orphan(
                container.id.clone(),
                pidfd,
                container
                    .started_at
                    .as_deref()
                    .and_then(velarx_proto::time::parse_rfc3339),
            );
            return Ok(());
        }
        // (the monitor recorded the exit after all, while this looked)
        if self.running_record(&container.id).await?.is_none() {
            return Ok(());
        }
        warn!(
            "The monitor of container {} is gone without a trace",
            container.id
        );
        self.forget_in_runtime(container).await?;
        self.record_exit(&container.id, &self.unseen_exit(&container.id, container))
            .await?;
        Ok(())
    }

    /// The `--rm` containers whose exit was recorded and whose removal did
    /// not follow, because the process that did it was killed in between:
    /// each is finished, as the monitor would have.  Every process that
    /// builds the services calls it once (a single read of a partial index
    /// when nothing was interrupted).
    pub async fn finish_removals(self: &Arc<Self>) -> ContainerResult<()> {
        let mut first = None;
        for id in self.db.removals_pending().await? {
            if let Err(e) = self.finish_removal(&id).await {
                warn!("Cannot finish the removal of container {id}: {e}");
                first.get_or_insert(e);
            }
        }
        first.map_or(Ok(()), Err)
    }

    /// [`Self::finish_removals`] of the container `id`: the runtime's record
    /// of it, its network (a release is idempotent), its cgroups, its files
    /// and rows, and its image with `--rmi`: the steps of the monitor.
    /// Nothing is done while its monitor lives (it does it, or ends and the
    /// next process does), and what another process finished meanwhile is
    /// not done again: the state is read under the lock of the start, which
    /// the monitor holds while it removes.
    async fn finish_removal(self: &Arc<Self>, id: &str) -> ContainerResult<()> {
        if monitor_alive(&self.mon_dir(id)).is_some() {
            return Ok(());
        }
        let _lock = self.start_lock(id).await?;
        let container = match self.db.get_container(id).await {
            Ok(c) => c,
            Err(velarx_types::DbError::NotFound(_)) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        // (a start that came first: its container runs, and the exit that
        // ends it says again whether it goes)
        if container.state.is_alive()
            || container.state == RecordState::Created
            || !self.db.removal_pending(id).await?
            || monitor_alive(&self.mon_dir(id)).is_some()
        {
            return Ok(());
        }
        if let Err(e) = super::super::container::stored_config(&container) {
            // (it cannot be removed as it exited: `rm` does, once)
            self.db.clear_removal(id).await?;
            return Err(e);
        }
        // What its monitor wrote with the exit; without it (the monitor
        // directory went already) what the configuration says.
        let info = match read_exit_file(&self.mon_dir(id)) {
            Some(info) => ExitInfo {
                remove: true,
                ..info
            },
            None => {
                let unseen = self.unseen_exit(id, &container);
                ExitInfo {
                    code: container.exit_code.unwrap_or(unseen.code),
                    remove: true,
                    ..unseen
                }
            }
        };
        info!("Finishing the removal of container {id} that its monitor left");
        // (as the monitor: a runtime that fails to forget it does not keep
        // the container, nor have every next command try again)
        if let Err(e) = self.forget_in_runtime(&container).await {
            warn!("Cannot delete container {id} in its runtime: {e}");
        }
        self.forget_cgroups(id);
        let (_, removed) = self.settle_container(&container, &info).await?;
        if removed {
            self.notice_removed(&container, info.code);
        }
        self.lifecycle.exited.notify_waiters();
        Ok(())
    }

    /// The empty cgroups of a container whose monitor is gone (it removes
    /// them at its end).
    fn forget_cgroups(&self, id: &str) {
        let Some(cm) = &self.cgroup_manager else {
            return;
        };
        match std::fs::read_to_string(self.mon_dir(id).join(CGROUP_FILE)) {
            Ok(path) => cm.remove_container(&path),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => warn!("Cannot read the cgroup of container {id}: {e}"),
        }
    }

    /// The record of container `id` if it is running, paused or created.
    async fn alive_record(&self, id: &str) -> ContainerResult<Option<ContainerRecord>> {
        match self.db.get_container(id).await {
            Ok(c) if (c.state.is_alive() || c.state == RecordState::Created) => Ok(Some(c)),
            Ok(_) | Err(velarx_types::DbError::NotFound(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The record of container `id` if it is running or paused.
    async fn running_record(&self, id: &str) -> ContainerResult<Option<ContainerRecord>> {
        Ok(self.alive_record(id).await?.filter(|c| c.state.is_alive()))
    }

    /// What the runtime keeps of a container whose monitor died with it (the
    /// monitor deletes it when it ends): else the next start finds it there.
    async fn forget_in_runtime(&self, container: &ContainerRecord) -> ContainerResult<()> {
        self.runtime_for_record(container)?
            .delete(&container.id, true)
            .await?;
        Ok(())
    }

    /// The end of a container that nothing saw (no status): 255, as an
    /// exit no monitor reported.  A monitor that died left what it mounted
    /// where the engine sees it only when it mounted in its starting
    /// namespace (a container whose mounts reach the host): detached now,
    /// as the removal would.  A monitor with a namespace of its own took its
    /// mounts with it.
    pub(super) fn unseen_exit(&self, id: &str, container: &ContainerRecord) -> ExitInfo {
        velarx_runtime::settle::mounts::detach_mounts_below(&self.bundle_dir(id));
        velarx_runtime::settle::mounts::detach_mounts_below(&self.mon_dir(id));
        ExitInfo {
            code: 255,
            finished_ns: velarx_wire::monitor::logfmt::now_ns(),
            oom: false,
            health_restart: false,
            stop_requested: false,
            timed_out: false,
            checkpointed: false,
            started_ns: None,
            // (what its configuration says: no monitor said otherwise)
            remove: super::super::container::stored_config(container)
                .is_ok_and(|config| config.auto_remove),
            volumes: true,
        }
    }

    /// A pidfd of the init of `container` while it runs: the recorded pid,
    /// which the OCI runtime still gives as the container's running (or
    /// paused) process once the pidfd is open (the runtime checks the start
    /// time of the process it made: a reused pid is not it).
    pub(super) async fn live_init(
        &self,
        container: &ContainerRecord,
    ) -> ContainerResult<Option<OwnedFd>> {
        let Some(pid) = container.pid.filter(|p| *p > 0) else {
            return Ok(None);
        };
        let Some(raw) = rustix::process::Pid::from_raw(pid) else {
            return Ok(None);
        };
        let pidfd = match rustix::process::pidfd_open(raw, rustix::process::PidfdFlags::NONBLOCK) {
            Ok(fd) => fd,
            // (no such process)
            Err(rustix::io::Errno::SRCH) => return Ok(None),
            Err(e) => return Err(io::Error::from(e).into()),
        };
        let st = match self
            .runtime_for_record(container)?
            .state(&container.id)
            .await
        {
            Ok(st) => st,
            Err(crate::container::RuntimeError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok((st.pid == Some(pid)
            && matches!(
                st.state,
                crate::container::ContainerState::Running
                    | crate::container::ContainerState::Paused
            ))
        .then_some(pidfd))
    }

    /// Follow the init of a container whose monitor is gone (`pidfd`), in
    /// place of the monitor: its exit is recorded when it ends (with its
    /// died event; with no status: 255) and its restart policy applied.
    /// The container stays running meanwhile: stop and kill reach it
    /// through the OCI runtime.
    ///
    /// `started_ns`: when the run it follows started (its end is the end of
    /// that run only).
    pub(super) fn follow_orphan(
        self: &Arc<Self>,
        id: String,
        pidfd: OwnedFd,
        started_ns: Option<i64>,
    ) {
        let svc = Arc::clone(self);
        let key = id.clone();
        self.lifecycle.set_orphan(&id, true);
        let task = tokio::spawn(async move {
            let _end = svc.lifecycle.followed_end(&id);
            if let Err(e) = svc.follow_to_the_end(&id, pidfd, started_ns).await {
                warn!("Cannot follow the process of container {}: {}", id, e);
            }
        });
        self.lifecycle.watch(&key, task.abort_handle());
    }

    /// The task of [`Self::follow_orphan`].  A process that cannot be
    /// followed is not one that ended: the container stays as it is.
    async fn follow_to_the_end(
        self: &Arc<Self>,
        id: &str,
        pidfd: OwnedFd,
        started_ns: Option<i64>,
    ) -> ContainerResult<()> {
        // readable once the process ended
        drop(
            velarx_sys::fd::register(pidfd, tokio::io::Interest::READABLE)?
                .readable()
                .await?,
        );
        let container = match self.db.get_container(id).await {
            Ok(c) => c,
            Err(velarx_types::DbError::NotFound(_)) => {
                self.lifecycle.set_orphan(id, false);
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        // what the monitor would do once it ended: the runtime's container
        // goes (a restart makes it again); the exit is recorded all the same
        let config = super::super::container::stored_config(&container);
        let deleted = match &config {
            Ok(config) => self.runtime_for(config).delete(id, true).await,
            Err(_) => Ok(()),
        };
        self.lifecycle.set_orphan(id, false);
        let config = config?;
        let ext = self.db.get_container_ext(id).await?;
        let mut info = self.unseen_exit(id, &container);
        info.started_ns = started_ns;
        // a stop or a kill of a user ended it
        info.stop_requested = ext.stopped_by_user;
        info!("The process of container {} (its monitor gone) ended", id);
        // Another process that looked at the container may have recorded
        // the end first (a command found its process gone): it applies no
        // restart policy, so this one does, if the container is still
        // stopped from the run that was followed.  A second follower
        // that restarts it finds it running.
        let recorded = {
            let _lock = self.start_lock(id).await?;
            self.record_exit(id, &info).await?
        };
        let still_that_run = !recorded
            && started_ns.is_some()
            && matches!(
                self.db.get_container(id).await,
                Ok(c) if c.state == RecordState::Stopped
                    && c.started_at == started_ns.map(rfc3339)
            );
        // (the restart makes the container in the runtime again: not over
        // one that could not be deleted)
        deleted?;
        if recorded || still_that_run {
            let run = PolicyRestart {
                run: container.started_at.clone(),
                count: ext.restart_count + 1,
            };
            self.restart_orphan(id, &config, &info, &run).await?;
        }
        Ok(())
    }

    /// The restart policy of a container whose monitor was gone, applied by
    /// this process: the container starts again (with a new monitor) when
    /// the policy says so, after the monitor's delay.  A stop or a start of
    /// the container during the delay ends the restart (`run`: the run that
    /// ended, and the count of the restart).
    pub(super) async fn restart_orphan(
        self: &Arc<Self>,
        id: &str,
        config: &ContainerConfig,
        info: &ExitInfo,
        run: &PolicyRestart,
    ) -> ContainerResult<()> {
        let restarts = run.count - 1;
        let policy = crate::monitor::restart::RestartConfig {
            policy: config.restart_policy.clone(),
            count: restarts,
        };
        if !crate::monitor::restart::should_restart(&policy, info, restarts) {
            return Ok(());
        }
        let delay = crate::monitor::restart::delay(restarts);
        if !restart_stands(&self.db, id, &run.run, delay).await? {
            return Ok(());
        }
        info!("Restarting container {} by its policy", id);
        // (looked at again under the lock of the start: a stop or a start
        // that came after the wait, a second process that follows it and
        // restarted it first)
        match self
            .start_checked(id, false, Some(run), &StartCheck::Engine)
            .await
        {
            Ok(Some(_)) => {}
            Ok(None) | Err(ContainerError::AlreadyRunning(_)) => return Ok(()),
            Err(e) => return Err(e),
        }
        let _ = self
            .lifecycle
            .notices
            .send(ContainerNotice::Restarted { id: id.to_string() });
        Ok(())
    }

    /// An error when the monitor of container `id` is gone while it runs
    /// (followed by this process): what needs the monitor (exec, attach,
    /// health checks, following its log) cannot be done.
    pub fn check_monitor(&self, id: &str) -> ContainerResult<()> {
        let foreign = self
            .lifecycle
            .foreign
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(id)
            .cloned();
        if let Some(reason) = foreign {
            return Err(ContainerError::MonitorVersion {
                id: id.to_string(),
                reason,
            });
        }
        let lost = self
            .lifecycle
            .orphans
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(id);
        if lost {
            return Err(ContainerError::MonitorLost(id.to_string()));
        }
        Ok(())
    }

    /// Follow the monitor `pid` of container `id`, which is of another
    /// version of velarx (`why` says which): nothing is asked of it; once
    /// it ended, its exit file says how the container did.  A stop or a
    /// kill goes through the runtime and this monitor ends then, as it
    /// always did (a stop also signals the monitor: no restart).  The exit
    /// may be recorded by another process (one that found the monitor
    /// gone): whoever waits here looks again.
    pub(in crate::services) fn follow_foreign(
        self: &Arc<Self>,
        id: String,
        pidfd: std::os::fd::OwnedFd,
        why: String,
    ) {
        info!("Container {id}: {why}");
        let svc = Arc::clone(self);
        let key = id.clone();
        self.lifecycle.set_foreign(&id, Some(why));
        let task = tokio::spawn(async move {
            let _end = svc.lifecycle.followed_end(&id);
            let ended = super::ended(pidfd).await;
            svc.lifecycle.set_foreign(&id, None);
            // (a monitor that cannot be waited for is not one that ended)
            match ended {
                Ok(()) => {
                    svc.look_after_monitor_gone(&id).await;
                }
                Err(e) => warn!("Cannot follow the monitor of container {}: {}", id, e),
            }
            svc.lifecycle.exited.notify_waiters();
        });
        self.lifecycle.watch(&key, task.abort_handle());
    }

    /// Undo the network of a container that is not running any more: the
    /// release of `NetworkManager::cleanup` also tells the providers its
    /// networks name.
    pub(super) async fn release_network(&self, container: &velarx_db::ContainerRecord) {
        let id = &container.id;
        if let Err(e) = self.network_manager.cleanup(id).await {
            debug!("Network cleanup of {}: {}", id, e);
        }
    }

    /// `remove_files`, by the holder of the lock of the start `lock`: the
    /// file of the lock goes too, with the lock held (a start that waits for
    /// it finds it gone and takes the lock again on a new file).  All of it
    /// is tried and the first error is given back, except with `listed` (the
    /// record of the container is deleted after this returns, `rm`): then a
    /// writable layer the driver cannot remove keeps the rest of the
    /// container as it was, so that it can still be started and the next
    /// removal does all of it.  Without a record nothing would remove those
    /// files later (its secrets among them), so they go; the layer no record
    /// names is the driver's to collect.
    pub(in crate::services) async fn remove_files_locked(
        &self,
        id: &str,
        runtime: Option<Arc<crate::container::OciRuntime>>,
        _lock: &super::start::StartLock,
        listed: bool,
    ) -> ContainerResult<()> {
        velarx_base::trace::point("remove start");
        // (a collection of the store waits for the removal of the root of a
        // container, as for its creation: the driver is never told to
        // collect while it removes one.  The row goes before the files for
        // an `--rm` container and after them for `rm`: a collection between
        // the two keeps a root that is gone (harmless), or does not name one
        // that is about to be removed, which the driver keeps for
        // `Keep::grace` and this removal then removes)
        let _store = self.lock_store().await?;
        let mut first = None;
        let mut note = |r: ContainerResult<()>| {
            if let Err(e) = r {
                first.get_or_insert(e);
            }
        };
        if let Some(runtime) = runtime {
            note(runtime.delete(id, true).await.map_err(Into::into));
        }
        velarx_base::trace::point("remove runtime deleted");
        // where a monitor that was killed left the root file system bound
        let public = crate::userns::rootless::own_public_rootfs(id);
        let (bundle_path, mon_dir) = (self.bundle_dir(id), self.mon_dir(id));
        // (the unmounts and the removes of the bundle, which holds what the
        // container wrote, in one turn of the blocking pool)
        let mon = mon_dir.clone();
        let (driver, writable) = (self.storage().clone(), self.writable(id));
        let removed_layer = crate::off_thread(move || {
            if let Some(public) = public.filter(|p| p.exists()) {
                velarx_runtime::settle::mounts::detach_mounts_below(&public);
                let _ = std::fs::remove_dir(&public);
            }
            // What a monitor that was killed left mounted: the root file
            // system, the images bound in it, and the FUSE file systems
            // under them.
            velarx_runtime::settle::mounts::detach_mounts_below(&bundle_path);
            velarx_runtime::settle::mounts::detach_mounts_below(&mon);
            velarx_base::trace::point("remove unmounted");
            // the writable layer, where the driver has it, and the bundle:
            // for a listed container the bundle (the configuration it is
            // started from) stays while the layer does
            let layer = driver.writable_remove(&writable).map_err(|e| e.into_io());
            if listed {
                if let Err(e) = layer {
                    return Ok(Err(e));
                }
                return Ok(Ok((
                    std::fs::read_to_string(mon.join(CGROUP_FILE)),
                    remove_tree(&bundle_path),
                )));
            }
            Ok(Ok((
                std::fs::read_to_string(mon.join(CGROUP_FILE)),
                layer.and(remove_tree(&bundle_path)),
            )))
        })
        .await?;
        // A driver that cannot remove the layer of a listed container now (a
        // storage service that is down) leaves the container as it was, not
        // one that is listed and cannot be started: nothing else of it is
        // removed, and the next removal does all of it.
        let (cgroup, bundle) = match removed_layer {
            Ok(done) => done,
            Err(e) => {
                note(Err(e.into()));
                velarx_base::trace::point("remove kept");
                return first.map_or(Ok(()), Err);
            }
        };
        note(bundle.map_err(Into::into));
        let cgroup = match cgroup {
            Ok(path) => Some(path),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => {
                warn!("Cannot read the cgroup of container {id}: {e}");
                None
            }
        };
        if let (Some(cm), Some(path)) = (&self.cgroup_manager, cgroup) {
            cm.remove_container(&path);
        }
        let dirs = [
            self.log_dir(id),
            mon_dir,
            // The files of its secrets
            self.secrets_dir_of(id),
        ];
        let files = [
            self.start_lock_file(id),
            self.pause_lock_file(id),
            self.restart_lock_file(id),
        ];
        let removed = crate::off_thread(move || {
            let mut first = None;
            for d in &dirs {
                if let Err(e) = remove_tree(d) {
                    first.get_or_insert(e);
                }
            }
            for f in &files {
                match std::fs::remove_file(f) {
                    Err(e) if e.kind() != io::ErrorKind::NotFound => {
                        first.get_or_insert(e);
                    }
                    _ => {}
                }
            }
            Ok(first)
        })
        .await?;
        note(removed.map_or(Ok(()), |e| Err(e.into())));
        self.lifecycle.unwatch(id);
        velarx_base::trace::point("remove done");
        first.map_or(Ok(()), Err)
    }
}

/// Wait the `delay` before a restart that nobody monitors: false when the
/// container was stopped by a user meanwhile (the stop sets
/// `stopped_by_user`, and every change of the database wakes this), started
/// again (it is not the run that started at `run` any more) or removed.
async fn restart_stands(
    db: &velarx_db::Database,
    id: &str,
    run: &Option<String>,
    delay: Duration,
) -> ContainerResult<bool> {
    // (watched before the record is read: a change in between wakes it)
    let mut changes = db.watch_changes()?;
    let end = tokio::time::sleep(delay);
    tokio::pin!(end);
    loop {
        match db.get_container(id).await {
            Ok(c) if c.state.has_ended() && &c.started_at == run => {}
            Ok(_) | Err(velarx_types::DbError::NotFound(_)) => return Ok(false),
            Err(e) => return Err(e.into()),
        }
        if db.get_container_ext(id).await?.stopped_by_user {
            return Ok(false);
        }
        if end.is_elapsed() {
            return Ok(true);
        }
        tokio::select! {
            _ = &mut end => {}
            changed = changes.changed() => changed?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store_with_container() -> (tempfile::TempDir, velarx_db::Database) {
        let dir = tempfile::tempdir().unwrap();
        let db = velarx_db::Database::open(dir.path().join("db.sqlite"))
            .await
            .unwrap();
        db.insert_image(&velarx_db::ImageRecord {
            id: "i".into(),
            manifest_digest: velarx_types::digest::Digest::of(
                velarx_types::digest::Algorithm::Sha256,
                b"m",
            ),
            config_digest: velarx_types::digest::Digest::of(
                velarx_types::digest::Algorithm::Sha256,
                b"c",
            ),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: "now".into(),
            is_lazy: false,
        })
        .await
        .unwrap();
        db.insert_container(&ContainerRecord {
            id: "c1".into(),
            name: Some("c1".into()),
            image_id: "i".into(),
            config: "{}".into(),
            state: RecordState::Stopped,
            created_at: "now".into(),
            exit_code: Some(1),
            ..Default::default()
        })
        .await
        .unwrap();
        (dir, db)
    }

    /// The delay of a restart nobody monitors ends when it is over and
    /// nothing changed.
    #[tokio::test]
    async fn a_restart_stands_when_nobody_stops_the_container() {
        let (_dir, db) = store_with_container().await;
        assert!(restart_stands(&db, "c1", &None, Duration::from_millis(1))
            .await
            .unwrap());
    }

    /// A stop during the delay ends the restart at once: the wait is for
    /// the change of the database, not for the delay (an hour here).
    #[tokio::test]
    async fn a_stop_during_the_delay_ends_the_restart() {
        let (_dir, db) = store_with_container().await;
        let waiting = tokio::spawn({
            let db = db.clone();
            async move { restart_stands(&db, "c1", &None, Duration::from_secs(3600)).await }
        });
        db.update_container_ext("c1", |e| e.stopped_by_user = true)
            .await
            .unwrap();
        let stands = tokio::time::timeout(Duration::from_secs(30), waiting)
            .await
            .expect("the restart waited for its delay")
            .unwrap()
            .unwrap();
        assert!(!stands);
    }

    /// A stop that was made before the wait began is seen too, and a
    /// container that is removed meanwhile is not restarted.
    #[tokio::test]
    async fn a_removed_container_is_not_restarted() {
        let (_dir, db) = store_with_container().await;
        db.update_container_ext("c1", |e| e.stopped_by_user = true)
            .await
            .unwrap();
        assert!(!restart_stands(&db, "c1", &None, Duration::from_secs(3600))
            .await
            .unwrap());
        assert!(
            !restart_stands(&db, "gone", &None, Duration::from_secs(3600))
                .await
                .unwrap()
        );
    }

    /// A start during the delay ends the restart at once too: the run that
    /// ended is not the container's last any more, whatever it is now
    /// (running, or ended again).
    #[tokio::test]
    async fn a_start_during_the_delay_ends_the_restart() {
        let (_dir, db) = store_with_container().await;
        let waiting = tokio::spawn({
            let db = db.clone();
            async move { restart_stands(&db, "c1", &None, Duration::from_secs(3600)).await }
        });
        db.update_container_state(
            "c1",
            RecordState::Running,
            Some(7),
            Some("then".into()),
            None,
            None,
        )
        .await
        .unwrap();
        db.update_container_state(
            "c1",
            RecordState::Stopped,
            None,
            None,
            Some("later".into()),
            Some(0),
        )
        .await
        .unwrap();
        let stands = tokio::time::timeout(Duration::from_secs(30), waiting)
            .await
            .expect("the restart waited for its delay")
            .unwrap()
            .unwrap();
        assert!(!stands);
    }
}
