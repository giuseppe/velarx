// SPDX-License-Identifier: Apache-2.0
//! The plan the monitor of a container records and releases it with, and the
//! same steps for a container whose monitor is gone.

use super::*;
use velarx_db::sync::BlockingDb;
use velarx_runtime::settle::{self, RemovalPlan, SettlePlan};
use velarx_wire::events::log::EventLog;

impl ContainerService {
    /// Where the events are kept (the engine sets it once: the monitors write
    /// the events of their containers there).
    pub fn set_event_log(&self, log: EventLog) {
        let _ = self.lifecycle.events.set(log);
    }

    /// What the monitor of `container` records and releases with.
    pub(in crate::services) async fn settle_plan(
        &self,
        container: &ContainerRecord,
        config: &ContainerConfig,
    ) -> SettlePlan {
        let id = &container.id;
        let db = self.db.path().map(Path::to_path_buf).unwrap_or_default();
        let events = self
            .lifecycle
            .events
            .get()
            .cloned()
            .unwrap_or(EventLog::None);
        // (the monitor's thread that writes the events may not make the
        // directory of their file: it is made here)
        if let EventLog::File { path, .. } = &events {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
        }
        let image = self.rmi_of(container, config).await;
        SettlePlan {
            id: id.clone(),
            image,
            cgroup: None,
            storage_lock: self
                .supervision
                .store_lock
                .clone()
                .unwrap_or_else(|| db.with_file_name("storage.lock")),
            db,
            start_lock: self.start_lock_file(id),
            events,
            pod: crate::services::pod::pod_of(self, id)
                .map(|p| crate::services::pod::plan_of(self, &p)),
            network: self.network_manager.engine().map(|e| e.detach().clone()),
            removal: self.removal_plan(id, config),
        }
    }

    /// What goes with the container `id` (`config`: what its row says, or
    /// the default of a container no row names, whose files then are the
    /// only ones the engine made for it).
    pub(in crate::services) fn removal_plan(
        &self,
        id: &str,
        config: &ContainerConfig,
    ) -> RemovalPlan {
        RemovalPlan {
            bundle: self.bundle_dir(id),
            mon_dir: self.mon_dir(id),
            log_dir: self.log_dir(id),
            secrets_dir: self.secrets_dir_of(id),
            public_rootfs: crate::userns::rootless::own_public_rootfs(id),
            named_files: [&config.pid_file, &config.conmon_pid_file, &config.cid_file]
                .into_iter()
                .flatten()
                .map(PathBuf::from)
                .collect(),
            api_record: id.bytes().all(|b| b.is_ascii_hexdigit()).then(|| {
                self.root_dir
                    .join("podman-api/containers")
                    .join(format!("{id}.json"))
            }),
            volumes_dir: self.volume_service.volumes_dir().to_path_buf(),
            volumes_lock: self.volume_service.lock_path().to_path_buf(),
            lock_files: vec![
                self.start_lock_file(id),
                self.pause_lock_file(id),
                self.restart_lock_file(id),
            ],
            writable: self.storage().writable_release(&self.writable(id)),
        }
    }

    /// `--rmi`: the image the container goes with, and the name it was made
    /// with.  None for an image of a read-only store, or a name that no
    /// longer is the image's.
    async fn rmi_of(
        &self,
        container: &ContainerRecord,
        config: &ContainerConfig,
    ) -> Option<settle::ImageRef> {
        if !config.auto_remove_image {
            return None;
        }
        let images = &self.image_service;
        let record = match images.get(&config.image).await {
            Ok(i) if i.id == container.image_id => i,
            _ => return None,
        };
        if self.db.read_only_store_of(&record.id).await.is_some() {
            return None;
        }
        // (a reference by the id, or a prefix of it: the whole image goes)
        let by_id = container
            .image_id
            .starts_with(velarx_types::digest::without_algorithm(&config.image));
        let name = if by_id {
            None
        } else {
            Some(images.tag_of(&config.image, &record.id).await?)
        };
        Some(settle::ImageRef {
            id: record.id.clone(),
            event_id: record.config_digest.hex(),
            name,
        })
    }

    /// The end of `container` as `info` says it: the network released, the
    /// exit recorded (when it is not yet), and an `--rm` container removed
    /// (the steps of the monitor, `velarx_runtime::settle`).  Whether the
    /// exit was recorded here, and whether the container is gone.  The
    /// caller holds the lock of the container's start.
    pub(super) async fn settle_container(
        self: &Arc<Self>,
        container: &ContainerRecord,
        info: &ExitInfo,
    ) -> ContainerResult<(bool, bool)> {
        let id = container.id.as_str();
        let config = super::super::container::stored_config(container)?;
        let plan = self.settle_plan(container, &config).await;
        let held = self.network_manager.engine().and_then(|e| e.held(id));
        let (db, info_owned) = (self.db.clone(), info.clone());
        let done = tokio::task::spawn_blocking(move || -> ContainerResult<(bool, bool)> {
            let a = BlockingDb::new(&db);
            let exiting = settle::exit::begin(&a, &plan, Some(&info_owned), held)
                .map_err(|e| io_error(io::Error::other(e)))?;
            let exited = settle::exit::finish(&a, &plan, exiting)
                .map_err(|e| io_error(io::Error::other(e)))?;
            let (recorded, known) = (exited.recorded, exited.known);
            let mut removed = false;
            // (`prepare` leaves a container others depend on, as podman's
            // removal does)
            if info_owned.remove && known {
                if let settle::remove::Prepare::Go(prepared) =
                    settle::remove::prepare(&a, &plan, info_owned.volumes)
                        .map_err(|e| io_error(io::Error::other(e)))?
                {
                    removed =
                        settle::remove::finish(&a, &plan, *prepared, Some(info_owned.code)).removed;
                }
            }
            Ok((recorded, removed))
        })
        .await
        .map_err(|e| io_error(io::Error::other(e)))??;
        Ok(done)
    }

    /// Record the exit of a container whose monitor is gone, as the monitor
    /// does (`velarx_runtime::settle`): the network released, the exit and its
    /// `died` event in the store, and an `--rm` container removed.  True when
    /// this process recorded it (another one that follows the same container
    /// may have).
    pub(super) async fn record_exit(
        self: &Arc<Self>,
        id: &str,
        info: &ExitInfo,
    ) -> ContainerResult<bool> {
        // Until its notice is sent: a command that ends once it sees the
        // exit in the database (a wait) has its died event first.
        let _recording = self.lifecycle.hold();
        let container = match self.db.get_container(id).await {
            Ok(c) => c,
            Err(velarx_types::DbError::NotFound(_)) => {
                // Removed already (its /dev/shm goes all the same: the remover
                // may be in another mount namespace, or of another store).
                if id.len() >= 12 {
                    velarx_runtime::settle::mounts::release_shm_dir(&self.mon_dir(id).join("shm"));
                }
                self.lifecycle.exited.notify_waiters();
                return Ok(false);
            }
            Err(e) => return Err(e.into()),
        };
        let (recorded, removed) = self.settle_container(&container, info).await?;
        let (image, labels) = event_details(&container);
        let name = container.name.clone().unwrap_or_default();
        // (the died event was written with the exit: the clients of this
        // process are told of it)
        let _ = self.lifecycle.notices.send(ContainerNotice::Exited {
            id: container.id.clone(),
            code: info.code,
            timed_out: info.timed_out,
            name,
            image,
            labels,
            restarting: false,
        });
        if removed {
            self.notice_removed(&container, info.code);
        }
        self.lifecycle.exited.notify_waiters();
        Ok(recorded)
    }

    /// Tell the clients of this process that the `--rm` container `container`
    /// went with its exit `code` (the `remove` event was written with the
    /// row).
    pub(super) fn notice_removed(&self, container: &ContainerRecord, code: i32) {
        let (image, _) = event_details(container);
        let _ =
            self.lifecycle
                .notices
                .send(ContainerNotice::Seen(Box::new(ContainerNotice::Action {
                    id: container.id.clone(),
                    name: container.name.clone().unwrap_or_default(),
                    image,
                    action: "remove",
                    attributes: vec![("containerExitCode".into(), code.to_string())],
                })));
        self.lifecycle.unwatch(&container.id);
    }
}
