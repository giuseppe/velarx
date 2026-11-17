// SPDX-License-Identifier: Apache-2.0
//! Shareable network namespaces.  A container with the annotation
//! `io.velarx.shareableNetworkNamespace=true` gives its bridge network
//! namespace to a pool when it stops instead of tearing it down, and takes
//! one from the pool when it starts: no bridge setup and teardown.  The
//! namespace is not cleaned in between (connection tracking, neighbours,
//! counters): it sandboxes the container from the host, not the containers
//! from each other, hence the opt-in.
//!
//! ```text
//! <run>/netns-pool/<slot>.netns        the pinned namespace (a pooled
//!                                      namespace has no container to
//!                                      hold it: the only pins left)
//! <run>/netns-pool/<key>-<slot>.json   available: {"key", "input"}; KEY
//!                                      identifies the networks, INPUT is
//!                                      for the final teardown
//! <run>/netns-pool/<slot>.claim        the same while a process takes,
//!                                      returns or drains the slot: the
//!                                      rename is the lock
//! ```
//!
//! Bridge networks only, without published ports, static address or MAC
//! (checked at create), and without DNS (the records are per container).
//! The addresses of a pooled namespace move from the container to the
//! `netns_pool` table and back to the container that takes it.  At most
//! `POOL_MAX` namespaces per set of networks.

use super::engine::{ContainerNetworks, NetworkStatus};
use std::fs;
use tracing::{debug, warn};
use velarx_netdetach::pool::entry_slot;
use velarx_netdetach::spec::Mode;
use velarx_netkernel::bridge;
use velarx_netkernel::error::{NetworkError, NetworkResult};
use velarx_netkernel::netns::Netns;

impl ContainerNetworks {
    async fn drain_slot(&self, slot: &str, claim: &std::path::Path) {
        let (slot, claim) = (slot.to_string(), claim.to_path_buf());
        let _ = self
            .blocking(move |db, d| d.pool_drain_slot(db, &slot, &claim))
            .await;
    }

    async fn pool_gc(&self) {
        let _ = self.blocking(|db, d| d.pool_gc(db)).await;
    }

    /// Take a pooled namespace for the container, open (its slot is
    /// unpinned): None if there is none for its networks.
    async fn pool_take(&self, id: &str) -> NetworkResult<Option<Netns>> {
        let owned = id.to_string();
        let Some(key) = self.blocking(move |db, d| d.pool_key(db, &owned)).await?? else {
            return Ok(None);
        };
        let Ok(entries) = fs::read_dir(&self.detach.pool_dir) else {
            return Ok(None);
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(slot) = entry_slot(&name, Some(&key)).map(String::from) else {
                continue;
            };
            let entry = self.detach.pool_dir.join(&name);
            let claim = self.detach.claim_path(&slot);
            if fs::rename(&entry, &claim).is_err() {
                continue;
            }
            let slot_path = self.detach.slot_path(&slot);
            if !bridge::is_nsfs(&slot_path) {
                self.drain_slot(&slot, &claim).await;
                continue;
            }
            match self.db.netns_pool_take(&slot, id).await {
                Ok(true) => {}
                Ok(false) | Err(_) => {
                    if fs::rename(&claim, &entry).is_err() {
                        self.drain_slot(&slot, &claim).await;
                    }
                    continue;
                }
            }
            let opened = velarx_nsid::open_file(&slot_path.to_string_lossy());
            bridge::unpin_netns(&slot_path);
            let _ = fs::remove_file(&claim);
            match opened {
                Ok(fd) => return Ok(Some(Netns::from(fd))),
                // The container has the addresses: it sets up a new one.
                Err(e) => {
                    warn!("take the pooled namespace {slot}: {e}");
                    return Ok(None);
                }
            }
        }
        Ok(None)
    }

    /// Before the runtime creates a container with a shareable namespace:
    /// make one for it (from the pool or a new one set up) and hold it.  None
    /// for the other containers.
    pub async fn prepare(&self, id: &str) -> NetworkResult<Option<NetworkStatus>> {
        let Some(spec) = self.spec(id).await? else {
            return Ok(None);
        };
        if spec.mode != Mode::Bridge || !spec.shareable {
            return Ok(None);
        }
        self.opts().await?;
        self.pool_gc().await;
        let status = if let Some(ns) = self.pool_take(id).await? {
            debug!("{id} takes a pooled network namespace");
            self.hold(id, &ns);
            NetworkStatus {
                mode: Mode::Bridge,
                interfaces: self.interfaces(id).await?,
                prepared: true,
            }
        } else {
            let ns = tokio::task::spawn_blocking(Netns::create)
                .await
                .map_err(|e| NetworkError::Netlink(e.to_string()))??;
            self.hold(id, &ns);
            self.setup_in(id, &spec, &ns, None)
                .await?
                .ok_or_else(|| NetworkError::InvalidConfig("no network to set up".into()))?
        };
        self.mark_prepared(id);
        Ok(Some(status))
    }
}
