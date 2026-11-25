// SPDX-License-Identifier: Apache-2.0
//! Checkpoint and restore through the OCI runtime: the monitor of a
//! running container runs `crun checkpoint` (CRIU), and a new monitor runs
//! `crun restore --detach` in place of `crun create`, adopting the restored
//! process: logs, attach, exit code and restart policy go on as for a
//! started container.
//!
//! The images of CRIU are in `<bundle>/checkpoint` (0700: they hold the
//! memory of the processes), what is known of them in
//! `<bundle>/checkpoint.json`.  A pre-checkpoint (a dump of the memory
//! that leaves the container running) is in `<bundle>/pre-checkpoint`; the
//! checkpoint `--with-previous` builds on it.  CRIU's logs and statistics
//! are in the directory of the images they belong to.

use super::container::{ContainerError, ContainerResult, ContainerService};
use super::crarchive;
use crate::container::ContainerConfig;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use velarx_db::RecordState;
use velarx_wire::monitor::proto::CheckpointRequest;
use velarx_wire::request::{CreateContainerRequest, NetworkMode};
use velarx_wire::wire::{CheckpointOptions, CheckpointRecord, RestoreOptions};

/// The file of the layer of a checkpoint image: the archive of
/// `checkpoint --export`.
const CHECKPOINT_IMAGE_ARCHIVE: &str = "checkpoint.tar";

/// The annotations of podman's checkpoint images that say the name of the
/// container and the runtime that checkpointed it.
const ANNOTATION_NAME: &str = "io.podman.annotations.checkpoint.name";
const ANNOTATION_RUNTIME: &str = "io.podman.annotations.checkpoint.runtime.name";

/// The directory of a pre-checkpoint, in the bundle (podman's name).
const PRE_CHECKPOINT: &str = "pre-checkpoint";

fn invalid(m: impl Into<String>) -> ContainerError {
    ContainerError::InvalidArgument(m.into())
}

fn runtime_error(m: String) -> ContainerError {
    ContainerError::Runtime(crate::container::RuntimeError::Runtime(m))
}

/// CRIU needs CAP_CHECKPOINT_RESTORE (or CAP_SYS_ADMIN) in the initial user
/// namespace: a rootless engine has neither.
pub fn need_root() -> ContainerResult<()> {
    if velarx_base::ids::host_uid()? != 0 {
        return Err(ContainerError::Unsupported(
            "checkpoint and restore need root: CRIU needs CAP_CHECKPOINT_RESTORE \
             in the initial user namespace"
                .into(),
        ));
    }
    Ok(())
}

/// `dir` made again, empty: 0700, whatever the umask.
/// The directory `dir`, opened: the monitor is given it as a descriptor.
fn open_directory(dir: &std::path::Path) -> ContainerResult<OwnedFd> {
    Ok(rustix::fs::open(
        dir,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)?)
}

fn fresh_dir(dir: &std::path::Path) -> ContainerResult<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    match velarx_base::tree::remove_dir_all(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    std::fs::DirBuilder::new().mode(0o700).create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(dir.to_path_buf())
}

/// A pre-checkpoint needs CRIU to track the pages the processes write.
async fn need_mem_track() -> ContainerResult<()> {
    let tracked = tokio::task::spawn_blocking(|| {
        std::process::Command::new("criu")
            .args(["check", "--feature", "mem_dirty_track"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
    .await
    .unwrap_or(false);
    if !tracked {
        return Err(ContainerError::Unsupported(
            "system (architecture/kernel/CRIU) does not support memory tracking".into(),
        ));
    }
    Ok(())
}

/// What CRIU reports in `dir` (`file`), as podman words its failure.
fn criu_stats(
    dir: &std::path::Path,
    file: &str,
    what: &str,
) -> ContainerResult<velarx_proto::workload::CriuStatistics> {
    super::crstats::read(dir, file)
        .map_err(|e| runtime_error(format!("displaying {what} statistics not possible: {e}")))
}

impl ContainerService {
    /// The images of the checkpoint of a container.
    pub fn checkpoint_dir(&self, id: &str) -> PathBuf {
        self.bundle_dir(id).join("checkpoint")
    }

    /// The images of the pre-checkpoint of a container.
    pub fn pre_checkpoint_dir(&self, id: &str) -> PathBuf {
        self.bundle_dir(id).join(PRE_CHECKPOINT)
    }

    fn checkpoint_record_path(&self, id: &str) -> PathBuf {
        self.bundle_dir(id).join("checkpoint.json")
    }

    /// What is known of the checkpoint of a container (nothing: default).
    pub fn checkpoint_record(&self, id: &str) -> CheckpointRecord {
        std::fs::read(self.checkpoint_record_path(id))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn write_checkpoint_record(&self, id: &str, r: &CheckpointRecord) -> ContainerResult<()> {
        let path = self.checkpoint_record_path(id);
        velarx_base::atomic_file::write(&path, &serde_json::to_vec(r)?, 0o666)?;
        Ok(())
    }

    /// A new, empty directory for the images: 0700, whatever the umask.
    fn fresh_checkpoint_dir(&self, id: &str) -> ContainerResult<PathBuf> {
        fresh_dir(&self.checkpoint_dir(id))
    }

    /// Checkpoint a running container with the runtime; unless it is left
    /// running it ends (stopped, not restarted), and `restore` starts it
    /// again from there.
    pub async fn checkpoint(
        self: &Arc<Self>,
        id: &str,
        opts: &CheckpointOptions,
    ) -> ContainerResult<CheckpointRecord> {
        need_root()?;
        if opts.with_previous && opts.pre_checkpoint {
            return Err(invalid(
                "--with-previous can not be used with --pre-checkpoint",
            ));
        }
        if opts.create_image.is_some()
            && (opts.export.is_some() || opts.with_previous || opts.pre_checkpoint)
        {
            return Err(invalid(
                "--create-image goes without --export, --pre-checkpoint and --with-previous",
            ));
        }
        if opts.with_previous || opts.pre_checkpoint {
            need_mem_track().await?;
        }
        let container = self.db.get_container(id).await?;
        if !container.state.is_alive() {
            return Err(ContainerError::NotRunning(container.id));
        }
        // (the freezer keeps a paused container's processes still while
        // CRIU reads them: a pod is checkpointed with all its containers
        // paused, for one cut of it)
        if container.state == RecordState::Paused && !opts.leave_running && !opts.pre_checkpoint {
            return Err(invalid(
                "a paused container is checkpointed with --leave-running: it stays paused",
            ));
        }
        let config: ContainerConfig = serde_json::from_str(&container.config)?;
        if config.tty {
            return Err(invalid(
                "a container with a terminal cannot be checkpointed (CRIU cannot hand the terminal over)",
            ));
        }
        let archiving = opts.export.is_some() || opts.create_image.is_some();
        if config.auto_remove && !archiving {
            return Err(invalid(
                "cannot checkpoint containers that have been started with '--rm' unless '--export' is used",
            ));
        }
        let compress = crarchive::Compress::parse(opts.compress.as_deref()).map_err(invalid)?;
        if let Some(path) = &opts.export {
            if !path.is_absolute() {
                return Err(invalid("the archive of --export must be an absolute path"));
            }
        }
        if archiving {
            if !opts.ignore_volumes && config.mounts.iter().any(|m| m.volume.is_some()) {
                return Err(invalid(
                    "the volumes of the container are not exported: with --ignore-volumes it is \
                     exported without them",
                ));
            }
            let saved: Option<SavedRequest> =
                std::fs::read(self.bundle_dir(&container.id).join(CREATE_REQUEST))
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok());
            // (its spec.dump would hold their values, and an import cannot
            // give them back)
            if saved.as_ref().is_some_and(|s| !s.secrets.is_empty()) {
                return Err(invalid(
                    "a container with secrets cannot be exported: the archive would hold their values",
                ));
            }
            if saved.is_none() {
                return Err(invalid(
                    "the request that made the container is not in its bundle: it cannot be exported",
                ));
            }
        } else if opts.compress.is_some() || opts.ignore_rootfs || opts.ignore_volumes {
            return Err(invalid(
                "--compress, --ignore-rootfs and --ignore-volumes go with --export",
            ));
        }
        let pre_dir = self.pre_checkpoint_dir(&container.id);
        if opts.with_previous && !pre_dir.is_dir() {
            return Err(invalid(format!(
                "the container {} has no pre-checkpoint to build on",
                container.name.as_deref().unwrap_or(&container.id)
            )));
        }
        let dir = if opts.pre_checkpoint {
            fresh_dir(&pre_dir)?
        } else {
            self.fresh_checkpoint_dir(&container.id)?
        };
        let req = CheckpointRequest {
            image_dir: 0,
            leave_running: opts.leave_running,
            tcp_established: opts.tcp_established,
            file_locks: opts.file_locks,
            pre_dump: opts.pre_checkpoint,
            parent_dir: None,
        };
        // An `--rm` container is removed once it is checkpointed and
        // exported, not as it exits: the archive is made of its files.
        if config.auto_remove && !opts.pre_checkpoint {
            self.keep(&container.id).await?;
        }
        let mon = self.mon_dir(&container.id);
        // The network namespace of the engine is left out of the images
        // (CRIU cannot make the host side of its veth pair again): the
        // runtime takes the namespace its spec names as an external one.
        // (the copy of the spec the runtime keeps of a running container)
        let state_spec = self
            .runtime
            .state_dir()
            .join(&container.id)
            .join("config.json");
        let outside = self
            .name_netns_for_dump(&container, &config, &state_spec)
            .await?;
        // (the directories are the runtime's: the monitor gives it their
        // places among its own descriptors)
        let images = open_directory(&dir)?;
        let previous = opts
            .with_previous
            .then(|| open_directory(&pre_dir))
            .transpose()?;
        let began = std::time::Instant::now();
        let reply = tokio::task::spawn_blocking(move || {
            velarx_wire::monitor::client::checkpoint(
                &mon,
                &req,
                images.as_fd(),
                previous.as_ref().map(AsFd::as_fd),
            )
        })
        .await
        .map_err(|e| ContainerError::Io(std::io::Error::other(e)))?;
        let took = began.elapsed().as_micros() as i64;
        // (the runtime deleted the copy of a container that ended)
        if let (Some(previous), true) = (outside, state_spec.exists()) {
            if let Err(e) = velarx_runtime::network::spec_netns::swap_spec_netns(
                &state_spec,
                previous.as_deref(),
            ) {
                tracing::warn!("Cannot put back the network of {}: {}", container.id, e);
            }
        }
        let failed = match reply {
            Ok(_) => None,
            Err(e) => Some(match velarx_wire::monitor::client::monitor_error(&e) {
                Some(velarx_wire::monitor::client::MonitorError::Remote { reason, .. }) => {
                    reason.clone()
                }
                _ => format!("the monitor of the container: {e}"),
            }),
        };
        if let Some(why) = failed {
            remove_tree(&dir).await;
            return Err(runtime_error(why));
        }
        // (read now, the images may go; a failure is told once the
        // checkpoint is recorded)
        let criu_statistics = opts
            .print_stats
            .then(|| criu_stats(&dir, super::crstats::STATS_DUMP, "checkpointing"));
        if opts.pre_checkpoint {
            // the container goes on, with no checkpoint to restore
            if let Some(path) = &opts.export {
                // (the changes of the root file system are those of the
                // checkpoint that follows)
                self.export_archive(&container.id, path, compress, true, true)
                    .await?;
            }
            self.notify_action(&container, "checkpoint", Vec::new());
            return Ok(CheckpointRecord {
                id: container.id.clone(),
                runtime_duration: took * i64::from(opts.print_stats),
                criu_statistics: criu_statistics.transpose()?,
                ..Default::default()
            });
        }
        let mut exit_code = 0;
        if !opts.leave_running {
            // CRIU ended it: once the exit is recorded it is stopped
            self.update_ext(&container.id, move |e| e.stopped_by_user = true)
                .await?;
            exit_code = self.wait(&container.id).await?;
        }
        let mut record = CheckpointRecord {
            checkpointed: true,
            checkpointed_at: Some(chrono::Utc::now().to_rfc3339()),
            restored: false,
            restored_at: None,
            path: Some(dir.clone()),
            id: container.id.clone(),
            restore_on_start: false,
            runtime_duration: took * i64::from(opts.print_stats),
            criu_statistics: None,
        };
        if archiving {
            let exported = match (&opts.export, &opts.create_image) {
                (Some(path), _) => {
                    self.export_archive(&container.id, path, compress, opts.ignore_rootfs, false)
                        .await
                }
                (None, Some(name)) => {
                    self.create_checkpoint_image(&container, name, compress, opts.ignore_rootfs)
                        .await
                }
                (None, None) => Ok(()),
            };
            if let Err(e) = exported {
                // the images stay, to restore in place
                self.write_checkpoint_record(&container.id, &record)?;
                return Err(e);
            }
            if !opts.keep {
                remove_tree(&dir).await;
                record.checkpointed = false;
                record.path = None;
            }
        }
        self.write_checkpoint_record(&container.id, &record)?;
        self.notify_action(&container, "checkpoint", Vec::new());
        if config.auto_remove && !opts.leave_running {
            // (the exit of a checkpoint keeps the container: it goes now)
            let _ = exit_code;
            self.delete(&container.id, true).await?;
        }
        record.criu_statistics = criu_statistics.transpose()?;
        Ok(record)
    }

    /// Restore a container from its checkpoint, in a new monitor that
    /// adopts the restored processes.  A restore that fails leaves the
    /// container stopped, its checkpoint in place.
    pub async fn restore(
        self: &Arc<Self>,
        id: &str,
        opts: &RestoreOptions,
    ) -> ContainerResult<CheckpointRecord> {
        need_root()?;
        if opts.import.is_some() {
            return self.restore_import(opts, None).await;
        }
        self.restore_in_place(id, opts).await
    }

    /// `restore` of an import, a container of the pod `opts.pod` if it names
    /// one (the pods are the pod service's).
    pub async fn restore_into(
        self: &Arc<Self>,
        opts: &RestoreOptions,
        pods: &super::pod::PodService,
    ) -> ContainerResult<CheckpointRecord> {
        need_root()?;
        self.restore_import(opts, Some(pods)).await
    }

    /// Restore an existing container from the images of its checkpoint.
    pub(super) async fn restore_in_place(
        self: &Arc<Self>,
        id: &str,
        opts: &RestoreOptions,
    ) -> ContainerResult<CheckpointRecord> {
        let container = self.db.get_container(id).await?;
        let _lock = self.start_lock(&container.id).await?;
        // (the command that restores gives the digests: the engine goes by
        // none it records)
        let check = crate::services::StartCheck::User {
            digests: crate::services::verify_image_digests(&opts.verify_image)?,
            option: true,
        };
        self.restore_in_place_locked(&container.id, opts, &check)
            .await
    }

    /// `restore_in_place` by the holder of the lock of the start; `check`
    /// the start it is (a start of a user restores a staged checkpoint with
    /// the digests typed on it).
    pub(super) async fn restore_in_place_locked(
        self: &Arc<Self>,
        id: &str,
        opts: &RestoreOptions,
        check: &crate::services::StartCheck,
    ) -> ContainerResult<CheckpointRecord> {
        if opts.name.is_some()
            || opts.pod.is_some()
            || !opts.publish.is_empty()
            || opts.ignore_rootfs
            || opts.ignore_static_ip
            || opts.ignore_static_mac
        {
            return Err(invalid(
                "--name, --pod, --publish, --ignore-rootfs, --ignore-static-ip and --ignore-static-mac go with --import or an image",
            ));
        }
        let container = self.db.get_container(id).await?;
        if container.state.is_alive() {
            return Err(ContainerError::AlreadyRunning(container.id));
        }
        let config: ContainerConfig = serde_json::from_str(&container.config)?;
        if config.tty {
            return Err(invalid("a container with a terminal cannot be restored"));
        }
        let dir = self.checkpoint_dir(&container.id);
        if !dir.join("inventory.img").is_file() {
            return Err(ContainerError::NoCheckpoint(format!(
                "the container {} has no checkpoint to restore",
                container.name.as_deref().unwrap_or(&container.id)
            )));
        }
        let mon = self.mon_dir(&container.id);
        let req = velarx_wire::monitor::client::Restore {
            image_dir: std::fs::File::open(&dir)?.into(),
            tcp_established: opts.tcp_established,
            tcp_close: opts.tcp_close,
            file_locks: opts.file_locks,
        };
        let bundle = self.bundle_dir(&container.id);
        // (the network namespace it is restored into is the spec's for the
        // restore only)
        let netns =
            velarx_runtime::network::spec_netns::spec_netns(&bundle.join("config.json")).ok();
        let began = std::time::Instant::now();
        let restored = self
            .create_in_monitor_with(&container, &config, &mon, Some(req), check)
            .await;
        let took = began.elapsed().as_micros() as i64;
        if let Some(netns) = netns {
            if let Err(e) = velarx_runtime::network::spec_netns::swap_spec_netns(
                &bundle.join("config.json"),
                netns.as_deref(),
            ) {
                tracing::warn!("Cannot put back the network of {}: {}", container.id, e);
            }
        }
        let (events, pid) = restored?;
        let criu_statistics = opts
            .print_stats
            .then(|| criu_stats(&mon, super::crstats::STATS_RESTORE, "restore"));
        // (the start the monitor says, which its exit then names)
        let status_dir = mon.clone();
        let started_ns =
            tokio::task::spawn_blocking(move || velarx_wire::monitor::client::status(&status_dir))
                .await
                .ok()
                .and_then(Result::ok)
                .and_then(|s| s.started_ns);
        let now = started_ns
            .map(velarx_runtime::settle::rfc3339)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        if let Err(e) = self
            .db
            .update_container_state(
                &container.id,
                RecordState::Running,
                Some(pid),
                Some(now.clone()),
                None,
                None,
            )
            .await
        {
            // the monitor ends the restored container, which stays stopped
            let quit = mon.clone();
            // (killed through the pidfd the monitor holds of it: the monitor
            // may have reaped the process already, its pid is not ours to use)
            let _ = tokio::task::spawn_blocking(move || {
                velarx_wire::monitor::client::kill(&quit, libc::SIGKILL)
            })
            .await;
            return Err(e.into());
        }
        self.watch_monitor(container.id.clone(), events);
        self.update_ext(&container.id, move |e| e.stopped_by_user = false)
            .await?;
        let mut record = self.checkpoint_record(&container.id);
        record.restored = true;
        record.restored_at = Some(now);
        if !opts.keep {
            remove_tree(&dir).await;
            remove_tree(&self.pre_checkpoint_dir(&container.id)).await;
            record.checkpointed = false;
            record.path = None;
        }
        record.restore_on_start = false;
        record.id = container.id.clone();
        record.runtime_duration = took * i64::from(opts.print_stats);
        self.write_checkpoint_record(&container.id, &record)?;
        self.notify_action(&container, "restore", Vec::new());
        record.criu_statistics = criu_statistics.transpose()?;
        Ok(record)
    }

    /// Make the spec at SPEC name the network namespace of the running
    /// container for the checkpoint, when it joins one by a path (the engine
    /// made it and set it up, or the container joins another's): the runtime
    /// takes the namespace its spec names as an external one, and the path
    /// the container was created with (`/proc/PID/fd/N` of its monitor)
    /// names a descriptor, not the namespace of the process that is dumped.
    /// The path the spec had, to put back (`Some(None)`: none), None when it
    /// was left alone.
    async fn name_netns_for_dump(
        &self,
        container: &velarx_db::ContainerRecord,
        config: &ContainerConfig,
        spec: &std::path::Path,
    ) -> ContainerResult<Option<Option<PathBuf>>> {
        if !config.uid_mappings.is_empty() {
            return Ok(None);
        }
        let named = {
            let spec = spec.to_path_buf();
            tokio::task::spawn_blocking(move || {
                velarx_runtime::network::spec_netns::spec_netns(&spec)
            })
            .await
            .map_err(|e| ContainerError::Io(std::io::Error::other(e)))?
        };
        // (nothing joined: the container made its own namespace, which the
        // images have)
        if !matches!(named, Ok(Some(_))) {
            return Ok(None);
        }
        // (its own entry in /proc)
        let Some(pid) = container.pid else {
            return Ok(None);
        };
        let netns = Some(PathBuf::from(format!("/proc/{pid}/ns/net")));
        let spec = spec.to_path_buf();
        let previous = tokio::task::spawn_blocking(move || {
            velarx_runtime::network::spec_netns::swap_spec_netns(&spec, netns.as_deref())
        })
        .await
        .map_err(|e| ContainerError::Io(std::io::Error::other(e)))??;
        Ok(Some(previous))
    }

    /// Write the archive of the checkpoint of a container (podman's
    /// layout) to `path`: its images, what makes it again, its spec and,
    /// unless `ignore_rootfs`, the changes of its root file system.
    async fn export_archive(
        &self,
        id: &str,
        path: &std::path::Path,
        compress: crarchive::Compress,
        ignore_rootfs: bool,
        pre: bool,
    ) -> ContainerResult<()> {
        let container = self.db.get_container(id).await?;
        let bundle = self.bundle_dir(&container.id);
        let saved: SavedRequest =
            serde_json::from_slice(&std::fs::read(bundle.join(CREATE_REQUEST))?)?;
        let config: crate::container::ContainerConfig = serde_json::from_str(&container.config)?;
        let dump = ConfigDump {
            version: 1,
            name: container.name.clone().unwrap_or_default(),
            request: saved.request,
            secrets: saved.secrets,
            selinux_level: config.selinux.and_then(|s| s.level),
        };
        let config_dump = serde_json::to_vec_pretty(&dump)?;
        let spec = std::fs::read(bundle.join("config.json"))?;
        let (diff, walk) = self.writable_diff(&container.id).await?;
        let (name, images) = if pre {
            (
                crarchive::PRE_IMAGES,
                self.pre_checkpoint_dir(&container.id),
            )
        } else {
            (crarchive::IMAGES, self.checkpoint_dir(&container.id))
        };
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let mut diff = match (diff, ignore_rootfs) {
                (Some(diff), false) => {
                    // (the holes of sparse files stay holes of the copy)
                    let mut f = velarx_content::layer::holes::SparseFile::new(
                        tempfile::tempfile_in(&images)?,
                    );
                    diff.write(&walk, &mut f)?;
                    Some(f.finish()?)
                }
                _ => None,
            };
            // (process memory: for its owner only)
            // (a link is not followed: a file that was made for the archive is
            // written, nothing a link points to)
            let out = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)
                .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
            let out = std::io::BufWriter::with_capacity(1 << 20, out);
            crarchive::write_as(
                out,
                compress,
                name,
                &images,
                &config_dump,
                &spec,
                diff.as_mut(),
            )
        })
        .await
        .map_err(|e| ContainerError::Io(std::io::Error::other(e)))??;
        Ok(())
    }

    /// Make the image `name` of the checkpoint of a container: its one
    /// layer holds the archive of `export_archive` as `checkpoint.tar`, and
    /// its annotations are podman's (`restore NAME` takes it).
    async fn create_checkpoint_image(
        &self,
        container: &velarx_db::ContainerRecord,
        name: &str,
        compress: crarchive::Compress,
        ignore_rootfs: bool,
    ) -> ContainerResult<()> {
        let staging_root = self.root_dir.join("checkpoint-export");
        std::fs::create_dir_all(&staging_root)?;
        let staging = tempfile::Builder::new()
            .prefix("image-")
            .tempdir_in(&staging_root)?;
        self.export_archive(
            &container.id,
            &staging.path().join(CHECKPOINT_IMAGE_ARCHIVE),
            compress,
            ignore_rootfs,
            false,
        )
        .await?;
        let annotations = std::collections::HashMap::from([
            (
                ANNOTATION_NAME.to_string(),
                container.name.clone().unwrap_or_default(),
            ),
            (
                "io.podman.annotations.checkpoint.rootfsImageID".to_string(),
                container.image_id.clone(),
            ),
            (ANNOTATION_RUNTIME.to_string(), self.runtime.name()),
            (
                "io.podman.annotations.checkpoint.host.arch".to_string(),
                velarx_registry::target::host_arch().to_string(),
            ),
        ]);
        let opts = crate::services::image::CommitOptions {
            names: vec![name.to_string()],
            annotations,
            created_by: "velarx container checkpoint".into(),
            ..Default::default()
        };
        self.image_service
            .commit_dir(None, Some(staging.path()), &opts)
            .await
            .map_err(|e| runtime_error(format!("the checkpoint image {name}: {e}")))?;
        Ok(())
    }

    /// `restore IMAGE`: a new container from the archive in the checkpoint
    /// image `image` (made by `checkpoint --create-image`), restored.
    pub async fn restore_image(
        self: &Arc<Self>,
        image: &str,
        opts: &RestoreOptions,
        pods: &super::pod::PodService,
    ) -> ContainerResult<CheckpointRecord> {
        need_root()?;
        let record = self.image_service.get(image).await?;
        let manifest: velarx_types::oci::OciManifest = serde_json::from_str(&record.manifest)?;
        if !manifest.annotations.contains_key(ANNOTATION_NAME) {
            return Err(invalid(format!("image is not a checkpoint: {}", record.id)));
        }
        let runtime = manifest
            .annotations
            .get(ANNOTATION_RUNTIME)
            .map_or("", String::as_str);
        if runtime != self.runtime.name() {
            return Err(invalid(format!(
                "container image \"{}\" requires runtime: \"{runtime}\"",
                record.id
            )));
        }
        let layers = self.db.get_image_layers(&record.id).await?;
        let staging_root = self.root_dir.join("checkpoint-import");
        std::fs::create_dir_all(&staging_root)?;
        let staging = tempfile::Builder::new()
            .prefix("image-")
            .tempdir_in(&staging_root)?;
        let view = self.image_view(&layers)?;
        let dest = rustix::fs::open(
            staging.path(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        let translate = self.translation(&[], &[]);
        let image_service = self.image_service.clone();
        let layer_keys: Vec<String> = layers.iter().map(|l| l.key.to_string()).collect();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            use crate::services::imagecopy::ImageSource;
            let objects = image_service.objects();
            crate::services::imagecopy::TreeSource {
                tree: &*view,
                layers: &layer_keys,
                objects: &objects,
                verity: image_service.verity(),
                fetcher: Some(&*image_service),
                translate: &translate,
            }
            .copy_into("/", &dest, None)
        })
        .await
        .map_err(|e| ContainerError::Io(std::io::Error::other(e)))??;
        let mut opts = opts.clone();
        opts.import = Some(staging.path().join(CHECKPOINT_IMAGE_ARCHIVE));
        self.restore_import(&opts, Some(pods)).await
    }

    /// Extract an archive of a checkpoint into a directory of its own, and
    /// read its `config.dump`.  An archive made by someone else is
    /// extracted within the limits of [`crarchive::Limits`].
    async fn extract_archive(
        &self,
        file: std::fs::File,
    ) -> ContainerResult<(tempfile::TempDir, ConfigDump)> {
        let staging = self.extract_images(file, crarchive::IMAGES).await?;
        let dump: ConfigDump =
            serde_json::from_slice(&std::fs::read(staging.path().join(crarchive::CONFIG_DUMP))?)
                .map_err(|e| invalid(format!("the config.dump of the archive: {e}")))?;
        if dump.version != 1 {
            return Err(invalid(format!(
                "the archive is of version {} of velarx's config.dump",
                dump.version
            )));
        }
        if !dump.secrets.is_empty() {
            return Err(invalid(format!(
                "the container used secrets ({}): they are not in the archive",
                dump.secrets.join(", ")
            )));
        }
        Ok((staging, dump))
    }

    /// Extract an archive, its images in the directory `name`, as
    /// `extract_archive` does.
    async fn extract_images(
        &self,
        file: std::fs::File,
        name: &'static str,
    ) -> ContainerResult<tempfile::TempDir> {
        let staging_root = self.root_dir.join("checkpoint-import");
        std::fs::create_dir_all(&staging_root)?;
        let staging = tempfile::Builder::new()
            .prefix("import-")
            .tempdir_in(&staging_root)?;
        let dest = staging.path().to_path_buf();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let dir = rustix::fs::open(
                &dest,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?;
            crarchive::extract_as(
                file,
                rustix::fd::AsFd::as_fd(&dir),
                name,
                &crarchive::Limits::default(),
            )
        })
        .await
        .map_err(|e| ContainerError::Io(std::io::Error::other(e)))?
        .map_err(|e| invalid(format!("the archive: {e}")))?;
        Ok(staging)
    }

    /// Put the images of an archive, and the changes of its root file system
    /// unless `ignore_rootfs`, in the container `id`, which was never
    /// started: its start restores them (the CRI's `RestorePod` creates the
    /// containers of a pod and the kubelet starts them).  The container
    /// keeps what it was made with; the archive gives the process state and
    /// the files.
    pub async fn stage_restore(
        self: &Arc<Self>,
        id: &str,
        archive: std::fs::File,
        ignore_rootfs: bool,
    ) -> ContainerResult<CheckpointRecord> {
        need_root()?;
        let container = self.db.get_container(id).await?;
        if container.state != RecordState::Created {
            return Err(ContainerError::InvalidArgument(format!(
                "the container {} is {}: a checkpoint is staged in a container that was never started",
                container.id, container.state
            )));
        }
        let config: ContainerConfig = serde_json::from_str(&container.config)?;
        if config.tty {
            return Err(invalid("a container with a terminal cannot be restored"));
        }
        let (staging, _) = self.extract_archive(archive).await?;
        let staged = async {
            let diff = staging.path().join(crarchive::ROOTFS_DIFF);
            if !ignore_rootfs && diff.is_file() {
                self.apply_rootfs_diff(&container.id, &diff).await?;
            }
            let images = self.fresh_checkpoint_dir(&container.id)?;
            std::fs::remove_dir(&images)?;
            std::fs::rename(staging.path().join(crarchive::IMAGES), &images)?;
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&images, std::fs::Permissions::from_mode(0o700))?;
            }
            let record = CheckpointRecord {
                checkpointed: true,
                path: Some(images),
                id: container.id.clone(),
                restore_on_start: true,
                ..Default::default()
            };
            self.write_checkpoint_record(&container.id, &record)?;
            ContainerResult::Ok(record)
        }
        .await;
        if staged.is_err() {
            remove_tree(&self.checkpoint_dir(&container.id)).await;
        }
        staged
    }

    /// `restore --import`: a new container from the archive, its root file
    /// system changes applied, then restored.  Whatever fails removes the
    /// container made and what was extracted.
    async fn restore_import(
        self: &Arc<Self>,
        opts: &RestoreOptions,
        pods: Option<&super::pod::PodService>,
    ) -> ContainerResult<CheckpointRecord> {
        let path = opts.import.clone().unwrap_or_default();
        if !path.is_absolute() {
            return Err(invalid("the archive of --import must be an absolute path"));
        }
        let file = std::fs::File::open(&path)
            .map_err(|e| invalid(format!("the archive: {}: {e}", path.display())))?;
        let (staging, dump) = self.extract_archive(file).await?;
        let previous = match &opts.import_previous {
            Some(path) => {
                let file = std::fs::File::open(path)
                    .map_err(|e| invalid(format!("the archive: {}: {e}", path.display())))?;
                Some(self.extract_images(file, crarchive::PRE_IMAGES).await?)
            }
            None => None,
        };
        let mut req = import_request(dump.request, opts).map_err(invalid)?;
        // the archive does not attach volumes of this host
        let names = req
            .volumes
            .iter()
            .filter_map(|v| v.split_once(':').map(|(n, _)| n.to_string()))
            .chain(req.mount.iter().filter_map(|m| {
                m.split(',')
                    .find_map(|p| p.strip_prefix("src="))
                    .map(str::to_string)
            }))
            .collect::<Vec<_>>();
        for name in names {
            if self.volume_service.get(&name).await.is_ok() {
                return Err(invalid(format!(
                    "the archive asks for the volume {name}, which exists on this host: \
                     an import does not attach volumes it has not made"
                )));
            }
        }
        req.name = opts
            .name
            .clone()
            .or(Some(dump.name).filter(|n| !n.is_empty()));
        // the level of the archive if it is of the allocator's form and no
        // container's level overlaps it (create checks, in its lock), else
        // one of its own: the restore gives the processes the new label
        req.preferred_selinux_level = dump
            .selinux_level
            .filter(|l| crate::container::selinux::is_allocated_form(l));
        // (the pod's namespaces are the container's; the container is one of
        // its members from its creation until it is removed)
        let pod = match (pods, &opts.pod) {
            (Some(pods), Some(_)) => pods
                .prepare_member(&mut req)
                .await
                .map_err(|e| invalid(e.to_string()))?,
            (None, Some(_)) => return Err(invalid("--pod: the pods are not at hand")),
            _ => None,
        };
        let id = self.create(req).await?;
        if let (Some(pods), Some(pod)) = (pods, &pod) {
            if let Err(e) = pods.add_container(pod.id(), &id).await {
                let _ = self.delete(&id, true).await;
                return Err(invalid(e.to_string()));
            }
        }
        // (the lock of the pod is not held while the container is restored)
        let pod = pod.map(|p| p.id().to_string());
        let made = async {
            let diff = staging.path().join(crarchive::ROOTFS_DIFF);
            if !opts.ignore_rootfs && diff.is_file() {
                self.apply_rootfs_diff(&id, &diff).await?;
            }
            // the images, 0700 as those of a checkpoint
            let images = self.fresh_checkpoint_dir(&id)?;
            std::fs::remove_dir(&images)?;
            std::fs::rename(staging.path().join(crarchive::IMAGES), &images)?;
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&images, std::fs::Permissions::from_mode(0o700))?;
            }
            if let Some(previous) = &previous {
                // (what CRIU read pages of the pre-checkpoint through: the
                // link is not in an archive)
                let pre = self.pre_checkpoint_dir(&id);
                std::fs::rename(previous.path().join(crarchive::PRE_IMAGES), &pre)?;
                std::os::unix::fs::symlink(format!("../{PRE_CHECKPOINT}"), images.join("parent"))?;
            }
            self.write_checkpoint_record(
                &id,
                &CheckpointRecord {
                    checkpointed: true,
                    path: Some(images),
                    id: id.clone(),
                    ..Default::default()
                },
            )?;
            self.restore_in_place(
                &id,
                &RestoreOptions {
                    tcp_established: opts.tcp_established,
                    tcp_close: opts.tcp_close,
                    file_locks: opts.file_locks,
                    keep: opts.keep,
                    print_stats: opts.print_stats,
                    verify_image: opts.verify_image.clone(),
                    ..Default::default()
                },
            )
            .await
        }
        .await;
        match made {
            Ok(r) => Ok(r),
            Err(e) => {
                if let (Some(pods), Some(pod)) = (pods, &pod) {
                    let _ = pods.forget_container(pod, &id).await;
                }
                if let Err(e) = self.delete_with_volumes(&id, true, true).await {
                    tracing::warn!(
                        "Cannot remove the container {} of a failed import: {}",
                        id,
                        e
                    );
                }
                Err(e)
            }
        }
    }

    /// Apply the changes of `rootfs-diff.tar` (a layer: its whiteouts,
    /// opaque directories and hard links) to the upper directory of the
    /// container, its owners translated to the host's.
    async fn apply_rootfs_diff(&self, id: &str, diff: &std::path::Path) -> ContainerResult<()> {
        let (writable, walk) = self.writable_diff(id).await?;
        let writable = writable.ok_or_else(|| invalid("the container has no upper directory"))?;
        let diff = diff.to_path_buf();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            writable.apply(&walk, &mut std::fs::File::open(&diff)?)
        })
        .await
        .map_err(|e| ContainerError::Io(std::io::Error::other(e)))?
        .map_err(|e| invalid(format!("the rootfs-diff.tar of the archive: {e}")))?;
        Ok(())
    }
}

/// The largest archive a restore takes in a request's body.
pub const CHECKPOINT_UPLOAD_MAX: u64 = 16 << 30;

/// The directories of archives in transit: what a daemon that ended left
/// there is removed when the next one starts.
pub const CHECKPOINT_STAGING: &[&str] = &["checkpoint-import", "checkpoint-export"];

pub fn sweep_checkpoint_staging(root_dir: &std::path::Path) {
    for d in CHECKPOINT_STAGING {
        match velarx_base::tree::remove_dir_all(root_dir.join(d)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!("Cannot sweep {}: {}", root_dir.join(d).display(), e),
        }
    }
}

/// The request a container was made from, in its bundle: what `restore
/// --import` makes it again from.
pub(super) const CREATE_REQUEST: &str = "create-request.json";

/// What is kept: the request, its secrets by name (their values are not).
#[derive(serde::Serialize, serde::Deserialize)]
struct SavedRequest {
    request: CreateContainerRequest,
    #[serde(default)]
    secrets: Vec<String>,
}

pub(super) fn save_create_request(
    bundle: &std::path::Path,
    req: &CreateContainerRequest,
    secrets: &[crate::services::SecretRef],
) -> std::io::Result<()> {
    use std::io::Write;
    let saved = SavedRequest {
        request: req.clone(),
        secrets: secrets.iter().map(|s| s.name.clone()).collect(),
    };
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(bundle.join(CREATE_REQUEST))?;
    f.write_all(&serde_json::to_vec(&saved)?)
}

/// The `config.dump` of velarx's archives.
#[derive(serde::Serialize, serde::Deserialize)]
struct ConfigDump {
    version: u32,
    #[serde(default)]
    name: String,
    request: CreateContainerRequest,
    /// Its secrets, by name
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    secrets: Vec<String>,
    /// The SELinux level of the container: the restored processes keep
    /// their labels, so the new container takes it (as podman's) when no
    /// other container has it
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selinux_level: Option<String>,
}

/// A `-v` (or, `mount`, a `--mount`) of the archive, made again: a named
/// volume or a tmpfs, its target, read-only or not.  Host paths, images,
/// devices, `U`, idmap, overlays and subpaths are refused.
fn import_volume(arg: &str, mount: bool) -> Result<String, String> {
    use crate::services::{MountSpec, MountType};
    let spec = if mount {
        MountSpec::parse_mount_arg(arg)
    } else {
        MountSpec::parse_volume_arg(arg)
    }
    .map_err(|e| format!("the archive's mount {arg:?}: {e}"))?;
    let o = &spec.options;
    let refused = || {
        Err(format!(
            "the archive asks for the mount {arg:?}, which an import does not give: \
             named volumes and tmpfs only, without U, idmap or overlays"
        ))
    };
    if o.chown
        || o.idmap.is_some()
        || o.overlay
        || o.upperdir.is_some()
        || o.workdir.is_some()
        || o.subpath.is_some()
    {
        return refused();
    }
    match (spec.mount_type, spec.source) {
        (MountType::Volume, Some(name)) if crate::services::valid_volume_name(&name) => {
            Ok(if mount {
                let ro = if o.read_only { ",ro" } else { "" };
                format!("type=volume,src={name},dst={}{ro}", spec.target)
            } else {
                let ro = if o.read_only { ":ro" } else { "" };
                format!("{name}:{}{ro}", spec.target)
            })
        }
        // an anonymous volume: a new one
        (MountType::Volume, None) if !mount => Ok(spec.target),
        (MountType::Tmpfs, _) if mount => Ok(format!(
            "type=tmpfs,dst={}{}",
            spec.target,
            if o.read_only { ",ro" } else { "" }
        )),
        _ => refused(),
    }
}

/// The request of a container made from an archive: what the archive
/// may ask for, the rest left to the defaults.  It cannot ask for more than
/// a container gets by default: privileges, host paths and devices,
/// capabilities, the host's namespaces, looser confinement are refused;
/// what names host files or other objects of the engine is dropped.
pub(crate) fn import_request(
    mut a: CreateContainerRequest,
    opts: &RestoreOptions,
) -> Result<CreateContainerRequest, String> {
    // (podman's: the container of a pod is restored into a pod, and only it)
    match (&a.pod, &opts.pod) {
        (Some(_), None) => return Err("cannot restore pod container without --pod".into()),
        (None, Some(_)) => return Err("cannot restore non pod container into pod".into()),
        (Some(_), Some(_)) => {
            // the namespaces it joined (its pod's) and the hostname of the
            // pod it was in: those of the pod it joins replace them
            for mode in [
                &mut a.pid_mode,
                &mut a.ipc_mode,
                &mut a.uts_mode,
                &mut a.cgroupns_mode,
            ] {
                if matches!(mode, velarx_proto::modes::NsMode::Container(_)) {
                    *mode = Default::default();
                }
            }
            if matches!(a.network_mode, NetworkMode::Container(_)) {
                a.network_mode = NetworkMode::Unset;
            }
            a.hostname.clear();
        }
        (None, None) => {}
    }
    let refuse = |what: &str| {
        Err(format!(
            "the archive asks for {what}, which an import does not give"
        ))
    };
    if a.privileged {
        return refuse("a privileged container");
    }
    if !a.cap_add.is_empty() {
        return refuse(&format!("capabilities ({})", a.cap_add.join(", ")));
    }
    if !a.devices.is_empty() || !a.device_cgroup_rules.is_empty() {
        return refuse("devices");
    }
    for (what, mode) in [
        ("the pid", &a.pid_mode),
        ("the ipc", &a.ipc_mode),
        ("the uts", &a.uts_mode),
        ("the cgroup", &a.cgroupns_mode),
    ] {
        if mode.is_joined() {
            return refuse(&format!("{what} namespace {mode}"));
        }
    }
    if a.network_mode.is_joined() {
        return refuse(&format!("the network namespace {}", a.network_mode));
    }
    if let Some(n) = a
        .networks
        .iter()
        .find(|n| NetworkMode::parse(n).is_joined())
    {
        return refuse(&format!("the network {n}"));
    }
    // ("host", the default: no user namespace of its own)
    if !a.userns_mode.is_host()
        || !a.uid_mappings.is_empty()
        || !a.gid_mappings.is_empty()
        || !a.uidmap.is_empty()
        || !a.gidmap.is_empty()
        || a.subuidname.is_some()
        || a.subgidname.is_some()
    {
        return refuse("a user namespace of its own");
    }
    let so = &a.security_opt;
    if so.seccomp_unconfined
        || so.seccomp_profile.is_some()
        || so.seccomp_bpf.is_some()
        || so.apparmor_unconfined
        || so.apparmor_profile.is_some()
        || so.selinux_label.is_some()
        || so.selinux_user.is_some()
        || so.selinux_role.is_some()
        || so.selinux_type.is_some()
        || so.selinux_filetype.is_some()
        || so.proc_opts.is_some()
        || !so.unmask_paths.is_empty()
        || a.security_opts.iter().any(|o| {
            // (those that hold the container to more are kept: the digests
            // of its images, the signatures)
            !(o.starts_with("no-new-privileges")
                || matches!(
                    o.as_str(),
                    "verity=enforce" | "signature=check" | "signature=require"
                ))
        })
    {
        return refuse("a looser confinement (security options)");
    }
    // Volumes and tmpfs only, made again from the parsed name, target and
    // read-only flag: no host path, no `U` or idmap; `mounts` (resolved
    // forms that carry host paths) is never taken.
    if !a.mounts.is_empty() {
        return refuse("mounts in their resolved form (bind mounts of host paths)");
    }
    if !a.bind_mounts.is_empty() {
        return refuse("bind mounts of host paths");
    }
    if !a.image_mounts.is_empty() {
        return refuse("mounts of images");
    }
    let volumes = a
        .volumes
        .iter()
        .map(|v| import_volume(v, false))
        .collect::<Result<Vec<_>, _>>()?;
    let mount = a
        .mount
        .iter()
        .map(|m| import_volume(m, true))
        .collect::<Result<Vec<_>, _>>()?;
    // the default network only: the archive does not join the networks of
    // this host
    if !matches!(
        a.network_mode,
        NetworkMode::Unset | NetworkMode::Off | NetworkMode::Bridge(None) | NetworkMode::Private
    ) || a
        .networks
        .iter()
        .any(|n| !matches!(n.as_str(), "bridge" | "podman" | "none"))
    {
        return refuse("networks of this host (an import has the default network)");
    }
    let mut r = CreateContainerRequest {
        image: a.image,
        command: a.command,
        entrypoint: a.entrypoint,
        env: a.env,
        working_dir: a.working_dir,
        user: a.user,
        group_add: a.group_add,
        labels: a.labels,
        hostname: a.hostname,
        ports: a.ports,
        expose: a.expose,
        resources: a.resources,
        pids_limit: a.pids_limit,
        shm_size: a.shm_size,
        stop_signal: a.stop_signal,
        stop_timeout: a.stop_timeout,
        restart_policy: a.restart_policy,
        // (podman's restored container is `--rm` when the checkpointed one
        // was)
        auto_remove: a.auto_remove,
        auto_remove_image: a.auto_remove_image,
        healthcheck: a.healthcheck,
        no_healthcheck: a.no_healthcheck,
        network_mode: a.network_mode,
        networks: a.networks,
        network_aliases: a.network_aliases,
        cni_annotations: Default::default(),
        cni_ip_ranges: Vec::new(),
        dns: a.dns,
        dns_search: a.dns_search,
        dns_options: a.dns_options,
        add_hosts: a.add_hosts,
        tty: a.tty,
        stdin_open: a.stdin_open,
        init: a.init,
        read_only_rootfs: a.read_only_rootfs,
        tmpfs: a.tmpfs,
        cap_drop: a.cap_drop,
        volumes,
        mount,
        // (the modes the container was made with, not the defaults of this
        // engine: one made with cgroups is restored with them, limits and
        // all, one made without without)
        cgroups: a.cgroups.or_enabled(),
        cgroup_mode: a.cgroup_mode,
        // (podman's keeps the log driver; the file is the new container's)
        log_config: a.log_config.map(|mut l| {
            l.config.remove("path");
            l
        }),
        ..Default::default()
    };
    // (not readonly_paths: they would replace the defaults)
    r.security_opt.no_new_privileges = so.no_new_privileges;
    r.security_opt.mask_paths = so.mask_paths.clone();
    r.security_opt.verity_enforce = so.verity_enforce;
    r.security_opt.verity_off = so.verity_off;
    r.security_opt.signature = so.signature.clone();
    if let Some(res) = r.resources.as_mut() {
        // raw cgroup files
        res.cgroup_conf = None;
    }
    r.security_opts = a.security_opts;
    if !opts.ignore_static_ip {
        r.ip_address = a.ip_address;
        r.ip6_address = a.ip6_address;
    }
    if !opts.ignore_static_mac {
        r.mac_address = a.mac_address;
    }
    if opts.pod.is_some() {
        if !opts.publish.is_empty() {
            return Err("--publish: the ports of a pod are those of the pod".into());
        }
        // (the pod's network is the container's: it has none of its own)
        r.pod = opts.pod.clone();
        r.network_mode = NetworkMode::Unset;
        r.networks.clear();
        r.network_aliases.clear();
        r.ports.clear();
        r.ip_address = None;
        r.ip6_address = None;
        r.mac_address = None;
    }
    if !opts.publish.is_empty() {
        r.ports = opts
            .publish
            .iter()
            .map(|p| velarx_wire::addr::PortSpec::parse(p).map(|s| s.mappings()))
            .collect::<Result<Vec<_>, _>>()?
            .concat();
    }
    // (not: id, name, replace, pidfile, conmon_pidfile, cidfile, pod,
    // no_monitor, lazy, annotations, init_path, cgroup_parent, sysctls,
    // the log path, timezone, systemd...)
    Ok(r)
}

/// Remove the directory of checkpoint images `dir` (and what is in it, off
/// the async threads), if it is there.
async fn remove_tree(dir: &std::path::Path) {
    let dir = dir.to_path_buf();
    let _ = crate::off_thread(move || velarx_base::tree::remove_dir_all(dir)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_record_round_trips_and_defaults() {
        let r = CheckpointRecord {
            checkpointed: true,
            checkpointed_at: Some("2026-01-01T00:00:00Z".into()),
            path: Some("/x/checkpoint".into()),
            ..Default::default()
        };
        let back: CheckpointRecord =
            serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        let empty: CheckpointRecord = serde_json::from_str("{}").unwrap();
        assert!(!empty.checkpointed && !empty.restored);
    }

    fn dumped(f: impl FnOnce(&mut CreateContainerRequest)) -> CreateContainerRequest {
        let mut r = CreateContainerRequest {
            image: "alpine".into(),
            command: vec!["sleep".into(), "1".into()],
            volumes: vec!["data:/data".into()],
            ..Default::default()
        };
        f(&mut r);
        r
    }

    /// The modes of the cgroups are the container's, not the defaults of
    /// the engine that restores it: one made with cgroups (the
    /// default then) keeps them, explicitly, whatever the default is now.
    #[test]
    fn an_import_keeps_the_cgroup_modes_of_the_container() {
        let opts = RestoreOptions::default();
        use velarx_wire::request::{CgroupMode, CgroupsMode};
        let import = |cgroups: CgroupsMode, mode: Option<CgroupMode>| {
            let r = import_request(
                dumped(|r| {
                    r.cgroups = cgroups;
                    r.cgroup_mode = mode;
                    r.resources = Some(velarx_wire::request::ResourceLimits {
                        memory: Some(64 << 20),
                        ..Default::default()
                    });
                }),
                &opts,
            )
            .unwrap();
            (r.cgroups, r.cgroup_mode)
        };
        let scope = Some(CgroupMode::Scope);
        assert_eq!(
            import(CgroupsMode::Unset, scope),
            (CgroupsMode::Enabled, scope)
        );
        assert_eq!(import(CgroupsMode::Split, None), (CgroupsMode::Split, None));
        assert_eq!(
            import(CgroupsMode::NoConmon, None),
            (CgroupsMode::NoConmon, None)
        );
        assert_eq!(
            import(CgroupsMode::Disabled, None),
            (CgroupsMode::Disabled, None)
        );
    }

    #[test]
    fn an_import_keeps_the_log_driver_not_the_path() {
        let r = import_request(
            dumped(|r| {
                r.log_config = Some(velarx_wire::request::LogConfig {
                    driver: "k8s-file".into(),
                    config: [("path", "/x.log"), ("max-size", "1m")]
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .into(),
                })
            }),
            &RestoreOptions::default(),
        )
        .unwrap();
        let l = r.log_config.unwrap();
        assert_eq!(l.driver, "k8s-file");
        assert_eq!(l.config.keys().collect::<Vec<_>>(), ["max-size"]);
    }

    #[test]
    fn an_import_of_a_rm_container_is_one() {
        let opts = RestoreOptions::default();
        let r = import_request(dumped(|r| r.auto_remove = true), &opts).unwrap();
        assert!(r.auto_remove);
        let r = import_request(dumped(|_| {}), &opts).unwrap();
        assert!(!r.auto_remove);
    }

    #[test]
    fn an_import_has_the_pod_and_the_ports_it_is_given() {
        let opts = RestoreOptions {
            publish: vec!["8080:80".into(), "5000-5001".into()],
            ..Default::default()
        };
        let r = import_request(dumped(|r| r.hostname = "h".into()), &opts).unwrap();
        assert_eq!(r.ports.len(), 3);
        assert_eq!(r.ports[0].host_port, Some(8080));
        assert!(r.pod.is_none());
        let opts = RestoreOptions {
            pod: Some("p".into()),
            ..Default::default()
        };
        let member = || {
            dumped(|r| {
                r.pod = Some("old".into());
                r.network_mode = NetworkMode::parse("container:infra");
                r.ipc_mode = velarx_proto::modes::NsMode::Container("infra".into());
                r.hostname = "old".into();
            })
        };
        let r = import_request(member(), &opts).unwrap();
        assert_eq!(r.pod.as_deref(), Some("p"));
        assert_eq!(r.network_mode, NetworkMode::Unset);
        assert!(!r.ipc_mode.is_joined());
        assert!(r.hostname.is_empty());
        let e = import_request(member(), &RestoreOptions::default()).unwrap_err();
        assert_eq!(e, "cannot restore pod container without --pod");
        let e = import_request(dumped(|_| {}), &opts).unwrap_err();
        assert_eq!(e, "cannot restore non pod container into pod");
        let both = RestoreOptions {
            pod: Some("p".into()),
            publish: vec!["80".into()],
            ..Default::default()
        };
        assert!(import_request(member(), &both).is_err());
        let bad = RestoreOptions {
            publish: vec!["x".into()],
            ..Default::default()
        };
        assert!(import_request(dumped(|_| {}), &bad).is_err());
    }

    #[test]
    fn an_import_takes_what_a_default_container_gets() {
        let opts = RestoreOptions::default();
        // what names the engine's objects or host files is dropped
        let r = import_request(
            dumped(|r| {
                r.id = Some("/etc".into());
                r.replace = true;
                r.pidfile = Some("/etc/passwd".into());
                r.conmon_pidfile = Some("/etc/shadow".into());
                r.cidfile = Some("/etc/group".into());
                r.no_monitor = true;
                r.lazy = true;
                r.init_path = Some("/bin/evil".into());
                r.cgroup_parent = Some("/".into());
                r.annotations.insert("org.criu.config".into(), "/x".into());
                r.sysctls.insert("net.ipv4.ip_forward".into(), "1".into());
            }),
            &opts,
        )
        .unwrap();
        assert!(r.id.is_none() && !r.replace && !r.no_monitor && !r.lazy);
        assert!(r.pidfile.is_none() && r.conmon_pidfile.is_none() && r.cidfile.is_none());
        assert!(r.pod.is_none() && r.init_path.is_none() && r.cgroup_parent.is_none());
        assert!(r.annotations.is_empty() && r.sysctls.is_empty());
        assert_eq!(r.image, "alpine");
        assert_eq!(r.volumes, ["data:/data"]);
        // what gives more than a default container is refused
        type Change = Box<dyn Fn(&mut CreateContainerRequest)>;
        let bad: Vec<(&str, Change)> = vec![
            ("privileged", Box::new(|r| r.privileged = true)),
            (
                "capabilities",
                Box::new(|r| r.cap_add = vec!["SYS_ADMIN".into()]),
            ),
            (
                "devices",
                Box::new(|r| r.device_cgroup_rules = vec!["a *:* rwm".into()]),
            ),
            (
                "pid namespace host",
                Box::new(|r| r.pid_mode = "host".parse().unwrap()),
            ),
            (
                "network namespace container:x",
                Box::new(|r| r.network_mode = NetworkMode::parse("container:x")),
            ),
            (
                "the network host",
                Box::new(|r| r.networks = vec!["host".into()]),
            ),
            (
                "user namespace",
                Box::new(|r| r.userns_mode = "keep-id".parse().unwrap()),
            ),
            (
                "user namespace",
                Box::new(|r| r.uidmap = vec!["0:0:65536".into()]),
            ),
            (
                "security options",
                Box::new(|r| r.security_opt.seccomp_unconfined = true),
            ),
            (
                "security options",
                Box::new(|r| r.security_opt.selinux_label = Some("disable".into())),
            ),
            (
                "security options",
                Box::new(|r| r.security_opts = vec!["unmask=ALL".into()]),
            ),
            (
                "mount",
                Box::new(|r| r.volumes = vec!["/etc:/host-etc".into()]),
            ),
            (
                "mount",
                Box::new(|r| r.mount = vec!["type=bind,src=/,dst=/h".into()]),
            ),
            (
                "mount",
                Box::new(|r| {
                    r.mounts = vec![crate::container::MountConfig {
                        source: "/".into(),
                        target: "/h".into(),
                        mount_type: Some("bind".into()),
                        ..Default::default()
                    }]
                }),
            ),
        ];
        for (what, f) in bad {
            let e = import_request(dumped(|r| f(r)), &opts).unwrap_err();
            assert!(e.contains(what), "{what}: {e}");
        }
        // what holds the container to more is kept
        let tighter = ["verity=enforce", "signature=require", "no-new-privileges"];
        let r = import_request(
            dumped(|r| r.security_opts = tighter.map(String::from).to_vec()),
            &opts,
        )
        .unwrap();
        assert_eq!(r.security_opts, tighter);
        // the static addresses go when asked
        let r = import_request(
            dumped(|r| {
                r.ip_address = Some("10.0.0.2".into());
                r.mac_address = Some("aa:bb:cc:dd:ee:ff".into());
            }),
            &RestoreOptions {
                ignore_static_ip: true,
                ignore_static_mac: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(r.ip_address.is_none() && r.mac_address.is_none());
    }

    #[test]
    fn only_levels_with_categories_are_taken() {
        assert!(crate::container::selinux::is_allocated_form("s0:c1,c2"));
        assert!(crate::container::selinux::is_allocated_form("s0:c0,c1023"));
        for bad in [
            "s0",
            "s0-s0:c0.c1023",
            "s0:",
            "s0:c1,",
            "x0:c1",
            "s0:c1.c3",
            "s0:c1,d2",
        ] {
            assert!(!crate::container::selinux::is_allocated_form(bad), "{bad}");
        }
        for bad in [
            "s0:c2,c1",
            "s0:c1,c1",
            "s0:c1,c2,c3",
            "s0:c1,c1024",
            "s0:c1023",
        ] {
            assert!(!crate::container::selinux::is_allocated_form(bad), "{bad}");
        }
    }

    #[test]
    fn an_import_takes_volumes_and_tmpfs_only_made_again() {
        let opts = RestoreOptions::default();
        let ok = import_request(
            dumped(|r| {
                r.volumes = vec!["data:/data:ro".into(), "/anon".into()];
                r.mount = vec![
                    "type=volume,source=v2,target=/v2".into(),
                    "type=tmpfs,destination=/t,tmpfs-size=1m".into(),
                ];
                r.security_opt.readonly_paths = vec!["/nothing".into()];
                r.resources = Some(crate::services::ResourceLimits {
                    cgroup_conf: Some([("io.max".to_string(), "x".to_string())].into()),
                    ..Default::default()
                });
            }),
            &opts,
        )
        .unwrap();
        assert_eq!(ok.volumes, ["data:/data:ro", "/anon"]);
        assert_eq!(
            ok.mount,
            ["type=volume,src=v2,dst=/v2", "type=tmpfs,dst=/t"]
        );
        assert!(ok.security_opt.readonly_paths.is_empty());
        assert!(ok.resources.unwrap().cgroup_conf.is_none());
        for (what, f) in [
            // A: a resolved mount of host / named after a volume
            (
                "resolved form",
                Box::new(|r: &mut CreateContainerRequest| {
                    r.mounts = vec![crate::container::MountConfig {
                        source: "/".into(),
                        target: "/host".into(),
                        mount_type: Some("bind".into()),
                        volume: Some("v".into()),
                        chown: true,
                        ..Default::default()
                    }]
                }) as Box<dyn Fn(&mut CreateContainerRequest)>,
            ),
            // C: the last type= wins in the parser
            (
                "type=volume,type=bind",
                Box::new(|r| r.mount = vec!["type=volume,type=bind,src=/,dst=/host".into()]),
            ),
            ("U", Box::new(|r| r.volumes = vec!["data:/data:U".into()])),
            (
                "idmap",
                Box::new(|r| r.mount = vec!["type=volume,src=v,dst=/v,idmap".into()]),
            ),
            (
                "image",
                Box::new(|r| r.mount = vec!["type=image,src=alpine,dst=/i".into()]),
            ),
            (
                "networks",
                Box::new(|r| r.networks = vec!["othernet".into()]),
            ),
            // the typed mounts of the CRI: not dropped, refused
            (
                "bind_mounts",
                Box::new(|r| {
                    r.bind_mounts = vec![velarx_proto::request::BindMountRequest {
                        source: "/".into(),
                        target: "/host".into(),
                        options: vec![],
                    }]
                }),
            ),
            (
                "image_mounts",
                Box::new(|r| {
                    r.image_mounts = vec![velarx_proto::request::ImageMountRequest {
                        image: "alpine".into(),
                        target: "/i".into(),
                        subpath: None,
                    }]
                }),
            ),
        ] {
            assert!(import_request(dumped(|r| f(r)), &opts).is_err(), "{what}");
        }
    }
}
