// SPDX-License-Identifier: Apache-2.0
//! What no container record owns.
//!
//! The rows of a container run with `--rm` are volatile (`velarx_db::volatile`):
//! after a crash of the machine they are gone, and what the container made in
//! the root directory is not: its bundle (with the upper layer of its
//! overlay), its logs, its secrets, the record the API kept of it and the
//! anonymous volumes its create made (their state names the container: a
//! volume that `rm` without `-v` kept is not one of them, its container left
//! no file).  A process killed between the first of those files and the
//! insertion of the row leaves the same.
//!
//! [`ContainerService::sweep_unowned`] removes them, with the steps of the
//! removal of a container (`velarx_runtime::settle::remove::files`), under the
//! exclusive lock of the store: a container create holds it shared from its
//! first file (the secrets a request resolves before the create included) to
//! its row, so what no row names while the sweep holds the lock is not on
//! its way to one.  The sweep never waits for the lock: when another process
//! holds it, it does nothing (a create that holds it may be waiting for this
//! very process, the engine service it started for a lazy pull).  It runs in
//! the first process that makes the services of a boot (under the boot lock,
//! [`super::boot`]: nothing of the boot holds the store yet) and in the engine
//! service when it starts (the commands that run meanwhile wait for the lock,
//! or made their rows before it).  Any other command does not look: it costs
//! nothing on the path of `run`.

use super::container::{valid_container_id, ContainerResult, ContainerService};
use std::collections::BTreeSet;
use std::io;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};
use velarx_runtime::settle::{self, mounts};

/// The names in `dir` that are the id of a container, or `<id>.json` of
/// `suffix`: none when the directory is not there.
fn ids_in(dir: &Path, suffix: &str) -> io::Result<Vec<String>> {
    let entries = match std::fs::read_dir(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        entries => entries?,
    };
    let mut ids = Vec::new();
    for entry in entries {
        let name = entry?.file_name();
        if let Some(id) = name.to_str().and_then(|n| n.strip_suffix(suffix)) {
            if valid_container_id(id) {
                ids.push(id.to_string());
            }
        }
    }
    Ok(ids)
}

impl ContainerService {
    /// Remove the files of the containers no row names, and the anonymous
    /// volumes their creates made that no other container mounts.  The number of containers whose files
    /// went.  An error of one does not keep the others from going: the first
    /// is given back.
    pub async fn sweep_unowned(self: &Arc<Self>) -> ContainerResult<usize> {
        // (never waited for: a process that holds it shared may wait for
        // this one, a create that starts the engine service for a lazy pull
        // and calls it, or a command that waits for the boot lock; what is
        // left stays for the next boot or start of the service)
        let _store = match &self.supervision.store_lock {
            Some(path) => match velarx_storage::StorageLock::try_exclusive(path)? {
                Some(lock) => Some(lock),
                None => {
                    debug!("The store is in use: what no container record names is left for now");
                    return Ok(0);
                }
            },
            None => None,
        };
        let known: BTreeSet<String> = self
            .db
            .list_containers(true)
            .await?
            .into_iter()
            .map(|c| c.id)
            .collect();
        let dirs = [
            (self.bundles_dir(), ""),
            (self.log_dir(""), ""),
            (self.secrets_dir(), ""),
            (self.root_dir.join("podman-api/containers"), ".json"),
        ];
        let unowned = crate::off_thread(move || {
            let mut ids = BTreeSet::new();
            for (dir, suffix) in dirs {
                ids.extend(ids_in(&dir, suffix)?);
            }
            Ok(ids)
        })
        .await?;
        let unowned: Vec<String> = unowned
            .into_iter()
            .filter(|id| !known.contains(id))
            .collect();
        if unowned.is_empty() {
            return Ok(0);
        }
        // the anonymous volumes their creates made (not one a removal kept,
        // as `rm` without `-v` does: its container left no file)
        let mut made_for: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        for volume in self.volume_service.list().await? {
            if let Some(id) = volume.state.container.filter(|_| volume.state.anonymous) {
                made_for.entry(id).or_default().push(volume.name);
            }
        }
        let mut first = None;
        let mut removed = 0;
        for id in unowned {
            let volumes = made_for.remove(&id).unwrap_or_default();
            match self.sweep_files_of(&id, volumes).await {
                Ok(true) => removed += 1,
                Ok(false) => {}
                Err(e) => {
                    warn!("Cannot remove what is left of container {id}: {e}");
                    first.get_or_insert(e);
                }
            }
        }
        first.map_or(Ok(removed), Err)
    }

    /// The files of the container `id`, which no row names, and the
    /// anonymous `volumes` its create made (first: what a crash in between
    /// leaves is found again by its files).  False when its monitor lives (it
    /// is not unowned: the row went while it ran) or a mount is left under
    /// its bundle.
    async fn sweep_files_of(
        self: &Arc<Self>,
        id: &str,
        volumes: Vec<String>,
    ) -> ContainerResult<bool> {
        if super::lifecycle::monitor_alive(&self.mon_dir(id)).is_some() {
            return Ok(false);
        }
        info!("Removing what is left of container {id}, which no record names");
        let plan = self.removal_plan(id, &Default::default());
        let detached = {
            let (bundle, public) = (plan.bundle.clone(), plan.public_rootfs.clone());
            crate::off_thread(move || {
                let mut all = mounts::detach_mounts_below(&bundle);
                if let Some(public) = public.as_deref().filter(|p| p.exists()) {
                    all &= mounts::detach_mounts_below(public);
                }
                Ok(all)
            })
            .await?
        };
        if !detached {
            warn!("Something stays mounted for container {id}: its files are kept");
            return Ok(false);
        }
        for name in volumes {
            // (one that another container mounts stays: `remove` refuses it)
            match self.volume_service.remove(&name, false).await {
                Ok(()) => info!("Removed the anonymous volume {name} of container {id}"),
                Err(super::volume::VolumeError::InUse(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        crate::off_thread(move || settle::remove::files(&plan, &[])).await?;
        Ok(true)
    }
}
