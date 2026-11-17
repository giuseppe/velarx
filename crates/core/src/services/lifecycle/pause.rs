// SPDX-License-Identifier: Apache-2.0
//! The pause of a container and its lease: a pause that ends by itself at
//! a deadline unless somebody unpaused the container before.  The deadline
//! is in the database (`container_ext`), so every process that pauses or
//! unpauses cancels it, and the engine that restarts arms it again.
use super::*;

/// The lock of the pauses of a container, until it is dropped.
pub struct PauseLock {
    _file: std::fs::File,
}

impl ContainerService {
    /// Serialise what pauses or unpauses the container `id`, in every
    /// process (the engine and the commands): a lease is recorded, or
    /// ended, in the same step as the pause it belongs to.  A lock file next
    /// to the one of the start, taken with `flock`.
    pub async fn pause_lock(&self, id: &str) -> ContainerResult<PauseLock> {
        let dir = self.state_dir.join("mon");
        let path = self.pause_lock_file(id);
        tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&dir)?;
            super::start::lock_file(&path)
        })
        .await
        .map_err(|e| io_error(io::Error::other(e)))?
        .map(|_file| PauseLock { _file })
        .map_err(io_error)
    }

    /// The file of the lock of the pauses of a container.
    pub(in crate::services) fn pause_lock_file(&self, id: &str) -> PathBuf {
        self.state_dir
            .join("mon")
            .join(format!("{}.pause", &id[..id.len().min(12)]))
    }

    /// When (milliseconds since the epoch) the pause of the container is
    /// ended by the engine, if it has a lease.
    pub async fn pause_lease(&self, id: &str) -> ContainerResult<Option<i64>> {
        Ok(self.db.pause_lease(id).await?)
    }

    /// Record the lease of the pause of the container, or with `None` end
    /// it.  Call it with the lock of [`ContainerService::pause_lock`].
    pub async fn set_pause_lease(&self, id: &str, until: Option<i64>) -> ContainerResult<()> {
        Ok(self.db.set_pause_lease(id, until).await?)
    }

    /// The containers that have a lease, and when it ends.
    pub async fn pause_leases(&self) -> ContainerResult<Vec<(String, i64)>> {
        Ok(self.db.pause_leases().await?)
    }
}
