// SPDX-License-Identifier: Apache-2.0
//! After a reboot: what the database says runs does not, and nothing
//! of the state directory is left.  The first process that makes the
//! services after a boot (the server or the engine, whichever comes first)
//! sets things right once: the containers that were running are stopped,
//! with no exit code (as podman), a container that was only created (or
//! initialized) is created, the `--rm` ones that had exited go, the runtime state of the
//! others is cleaned; no other container is removed.  A boot is told by the
//! boot id of the kernel, kept in `<state>/boot-id`.

use super::container::{stored_config, ContainerError, ContainerResult, ContainerService};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};
use velarx_db::RecordState;

use velarx_nsid::store::boot_id as current_boot_id;

/// Whether the marker in `state_dir` says another boot (or there is none).
fn is_new_boot(state_dir: &Path, boot_id: &str) -> bool {
    std::fs::read_to_string(state_dir.join("boot-id"))
        .map(|s| s.trim() != boot_id)
        .unwrap_or(true)
}

fn write_marker(state_dir: &Path, boot_id: &str) -> std::io::Result<()> {
    // (two engines of one store may start together)
    velarx_base::atomic_file::write(
        &state_dir.join("boot-id"),
        format!("{boot_id}\n").as_bytes(),
        0o666,
    )
}

/// What was found the kernel does (in `state_dir`) is forgotten when a boot is
/// new: the kernel of this boot may do otherwise.  The engine does it when it
/// starts, before it finds out a feature of its own (the kernel mount of the
/// layers, `composefs`), and not when the containers are set right, which would
/// forget what it found.
pub fn forget_features_of_a_new_boot(state_dir: &Path) {
    match current_boot_id() {
        Ok(boot_id) if is_new_boot(state_dir, &boot_id) => forget_features(state_dir),
        Ok(_) => {}
        Err(e) => warn!("Cannot tell the boot, the features found are kept: {e}"),
    }
}

fn forget_features(state_dir: &Path) {
    if let Err(e) = velarx_runtime::monitor::features::forget(state_dir) {
        warn!(
            "Cannot forget the features found in {}: {}",
            state_dir.display(),
            e
        );
    }
}

/// The pass of a new boot over ITEMS (the containers, named by NAME): each is
/// set right by ONE in turn, and the failure of one (logged here, once, with
/// its cause, the container left as it is) never stops the others.  The
/// marker that says this boot was reconciled is written once the pass is
/// over: a container that keeps failing is reported by the pass of the boot
/// and does not make every start of the engine run it again.
async fn reconcile_pass<T, E, Fut>(
    state_dir: &Path,
    boot_id: &str,
    items: Vec<T>,
    name: impl Fn(&T) -> String,
    mut one: impl FnMut(T) -> Fut,
) -> std::io::Result<()>
where
    E: std::fmt::Display,
    Fut: std::future::Future<Output = Result<(), E>>,
{
    for item in items {
        let id = name(&item);
        if let Err(e) = one(item).await {
            warn!("Cannot reconcile container {id} with this boot: {e}");
        }
    }
    write_marker(state_dir, boot_id)
}

/// The policies that start a container at boot (podman's
/// `should-start-on-boot`): `always`, and `unless-stopped` that its user
/// did not stop.
pub fn should_start_on_boot(policy: Option<&str>, stopped_by_user: bool) -> bool {
    match policy {
        Some("always") => true,
        Some("unless-stopped") => !stopped_by_user,
        _ => false,
    }
}

impl ContainerService {
    /// Set things right after a reboot, once per boot (see the module).
    /// Whether it was a new boot.
    pub async fn reconcile_boot(self: &Arc<Self>) -> ContainerResult<bool> {
        let state_dir = self.state_dir.clone();
        std::fs::create_dir_all(&state_dir)?;
        // One process does it; the others wait for it and find the marker.
        let lock_path = state_dir.join("boot.lock");
        velarx_base::trace::point("boot lock");
        let _lock = tokio::task::spawn_blocking(move || {
            velarx_storage::StorageLock::exclusive_blocking(&lock_path)
        })
        .await
        .map_err(std::io::Error::other)??;
        let boot_id = current_boot_id()?;
        if !is_new_boot(&state_dir, &boot_id) {
            return Ok(false);
        }
        // A marker that is missing is no proof of a reboot: a store of a
        // version without it, a state directory emptied by hand or not on a
        // tmpfs.  Whatever still runs is left alone either way.
        info!("A new boot, or a state directory without its marker: the containers that ran are stopped");
        // What a crash of the machine left of the containers whose rows it
        // lost (once per boot, before any other process of the boot made a
        // container: they wait for the boot lock)
        if let Err(e) = self.sweep_unowned().await {
            warn!("Cannot remove what no container record names: {e}");
        }
        // (a container that cannot be set right is reported and left as it
        // is; it does not keep the others as they are, nor this boot
        // unreconciled)
        let containers = self.db.list_containers(true).await?;
        reconcile_pass(
            &self.state_dir,
            &boot_id,
            containers,
            |c| c.id.clone(),
            |c| {
                let service = Arc::clone(self);
                async move { service.reconcile_boot_of(&c).await }
            },
        )
        .await?;
        Ok(true)
    }

    /// [`Self::reconcile_boot`] of the container `c`.
    async fn reconcile_boot_of(
        self: &Arc<Self>,
        c: &velarx_db::ContainerRecord,
    ) -> ContainerResult<()> {
        if self.still_runs(c).await? {
            debug!("Container {} still runs: left alone", c.id);
            return Ok(());
        }
        // (as podman's: what ran is exited, a container that was only created
        // stays created and can be started)
        let ran = c.state.is_alive();
        if ran {
            let now = chrono::Utc::now().to_rfc3339();
            self.db
                .update_container_state(&c.id, RecordState::Stopped, None, None, Some(now), None)
                .await?;
        } else if c.state == RecordState::Initialized {
            // (`container init`: the runtime's container went with the boot,
            // it is created again, as podman's Created becomes Configured)
            self.db
                .update_container_state(&c.id, RecordState::Created, None, None, None, None)
                .await?;
        }
        let config = stored_config(c)?;
        self.clean_runtime_state(c).await?;
        // (an `--rm` container goes when it had exited, not when it was only
        // created)
        let exited = ran || c.state.has_ended();
        if exited
            && self
                .goes_as_it_exits(&c.id, self.exit_plan_of(&c.id, &config))
                .await?
        {
            self.delete_with_volumes(&c.id, true, true).await?;
        }
        Ok(())
    }

    /// Stop a container for the service manager (a shutdown): unlike a stop
    /// of its user, an `unless-stopped` container starts at the next boot.
    pub async fn stop_as_service(
        self: &Arc<Self>,
        id: &str,
        timeout: Option<u32>,
    ) -> ContainerResult<()> {
        let before = self.container_ext(id).await?.stopped_by_user;
        let result = self.stop_with(id, timeout).await;
        // (a container that is gone has no flag to put back)
        let restored = match self.db.get_container(id).await {
            Ok(c) => {
                self.update_ext(&c.id, move |e| e.stopped_by_user = before)
                    .await
            }
            Err(velarx_types::DbError::NotFound(_)) => Ok(()),
            Err(e) => Err(ContainerError::from(e)),
        };
        result.and(restored)
    }

    /// Whether something of a container still runs: its monitor answers on
    /// its socket, the monitor of its pid file is alive, or its process is
    /// (pinned, and its root tells that it is the container's: a pid that
    /// was reused by another process does not count).
    async fn still_runs(&self, c: &velarx_db::ContainerRecord) -> ContainerResult<bool> {
        let dir = self.mon_dir(&c.id);
        let pid = c.pid.filter(|p| *p > 0);
        let monitored = tokio::task::spawn_blocking(move || {
            velarx_wire::monitor::client::monitor_pidfd(&dir).is_ok()
                || super::lifecycle::monitor_alive(&dir).is_some()
        })
        .await
        .map_err(std::io::Error::other)?;
        let Some(pid) = pid.filter(|_| !monitored) else {
            return Ok(monitored);
        };
        // (what its root is: the configuration tells)
        let rootfs = stored_config(c)?.rootfs;
        let (driver, writable) = (self.storage().clone(), self.writable(&c.id));
        let mon_dir = self.mon_dir(&c.id);
        Ok(tokio::task::spawn_blocking(move || {
            super::procpin::container_process_runs(
                pid,
                super::procpin::ContainerRoot::of(rootfs.as_ref(), &*driver, &writable, &mon_dir),
            )
        })
        .await
        .map_err(std::io::Error::other)??)
    }

    /// What the processes of a container left in the state directory and
    /// below its bundle: the monitor's run directory, the runtime's state
    /// (the runtime deletes it), mounts (none after a real reboot, some when
    /// the state directory is not a tmpfs).
    async fn clean_runtime_state(&self, c: &velarx_db::ContainerRecord) -> ContainerResult<()> {
        let (bundle, mon) = (self.bundle_dir(&c.id), self.mon_dir(&c.id));
        crate::off_thread(move || {
            velarx_runtime::settle::mounts::detach_mounts_below(&bundle);
            velarx_runtime::settle::mounts::detach_mounts_below(&mon);
            match velarx_base::tree::remove_dir_all_confined(&mon) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            }
        })
        .await?;
        self.runtime_for_record(c)?.delete(&c.id, true).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_boot_is_told_by_the_marker() {
        let d = tempfile::tempdir().unwrap();
        assert!(is_new_boot(d.path(), "b1"));
        write_marker(d.path(), "b1").unwrap();
        assert!(!is_new_boot(d.path(), "b1"));
        assert!(is_new_boot(d.path(), "b2"));
        assert!(!current_boot_id().unwrap().is_empty());
    }

    /// One container that cannot be set right is reported and does not stop
    /// the others; the marker is written after the pass, whatever failed, so
    /// that the next start does not do it all again.
    #[tokio::test]
    async fn a_container_that_fails_does_not_keep_the_boot_unreconciled() {
        let d = tempfile::tempdir().unwrap();
        let visited = std::sync::Mutex::new(Vec::new());
        reconcile_pass(
            d.path(),
            "b1",
            vec!["a", "bad", "c"],
            |c| c.to_string(),
            |c| {
                // (the marker is for the end of the pass)
                assert!(is_new_boot(d.path(), "b1"), "{c}: the marker came early");
                visited.lock().unwrap().push(c);
                async move {
                    if c == "bad" {
                        Err("it cannot be cleaned")
                    } else {
                        Ok(())
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(*visited.lock().unwrap(), ["a", "bad", "c"]);
        assert!(!is_new_boot(d.path(), "b1"), "the boot is reconciled");
    }

    /// The features found are forgotten at the start of the first engine of a
    /// boot, and kept by the pass that sets the containers right, so that what
    /// the engine found out after its start stays found.
    #[tokio::test]
    async fn a_new_boot_forgets_the_features_before_the_pass_not_in_it() {
        use velarx_runtime::monitor::features::cached;
        let d = tempfile::tempdir().unwrap();
        let ask = |answer: bool| cached(d.path(), "a-feature", "", || Ok(Some(answer))).unwrap();
        assert_eq!(ask(true), Some(true));
        // the same boot: the marker of the boot says so
        write_marker(d.path(), &current_boot_id().unwrap()).unwrap();
        forget_features_of_a_new_boot(d.path());
        assert_eq!(ask(false), Some(true), "kept in the same boot");
        // another boot: forgotten, found again, and kept by the pass
        write_marker(d.path(), "another-boot").unwrap();
        forget_features_of_a_new_boot(d.path());
        assert_eq!(ask(false), Some(false), "found again in the new boot");
        reconcile_pass(
            d.path(),
            &current_boot_id().unwrap(),
            Vec::<&str>::new(),
            |c| c.to_string(),
            |_| async { Ok::<(), String>(()) },
        )
        .await
        .unwrap();
        assert_eq!(ask(true), Some(false), "the pass keeps what was found");
    }

    #[test]
    fn a_boot_forgets_the_features_found() {
        let d = tempfile::tempdir().unwrap();
        forget_features(d.path());
        let ask = || {
            velarx_runtime::monitor::features::cached(d.path(), "a-feature", "", || Ok(Some(true)))
                .unwrap()
        };
        ask();
        // (kept: not asked again)
        let kept = velarx_runtime::monitor::features::cached(d.path(), "a-feature", "", || {
            panic!("asked")
        });
        assert_eq!(kept.unwrap(), Some(true));
        forget_features(d.path());
        let again = velarx_runtime::monitor::features::cached(d.path(), "a-feature", "", || {
            Ok(Some(false))
        });
        assert_eq!(again.unwrap(), Some(false));
    }

    #[test]
    fn what_starts_at_boot() {
        assert!(should_start_on_boot(Some("always"), false));
        assert!(should_start_on_boot(Some("always"), true));
        assert!(should_start_on_boot(Some("unless-stopped"), false));
        assert!(!should_start_on_boot(Some("unless-stopped"), true));
        assert!(!should_start_on_boot(Some("on-failure"), false));
        assert!(!should_start_on_boot(Some("no"), false));
        assert!(!should_start_on_boot(None, false));
    }
}
