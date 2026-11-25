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
//! `POOL_MAX` namespaces per set of networks.  The give-back and the drain
//! are here (the engine and the monitor of the container both run them);
//! taking a namespace is the engine's.

use crate::input::{bridge_input, network_by_id};
use crate::teardown::Detach;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use tracing::{debug, warn};
use velarx_db::sync::Access;
use velarx_netkernel::bridge::{self, BridgeContainer, NetnsFate};
use velarx_netkernel::error::{NetworkError, NetworkResult};

pub const POOL_MAX: usize = 4;
pub const ID_LEN: usize = 16;

#[derive(Serialize, Deserialize)]
pub struct Meta {
    pub key: String,
    pub input: BridgeContainer,
}

/// The slot of an available entry `<key>-<slot>.json` (for KEY, or any).
pub fn entry_slot<'a>(name: &'a str, key: Option<&str>) -> Option<&'a str> {
    let stem = name.strip_suffix(".json")?;
    let (k, slot) = stem.split_once('-')?;
    let hex = |s: &str| s.len() == ID_LEN && s.bytes().all(|c| c.is_ascii_hexdigit());
    if !hex(k) || !hex(slot) || key.is_some_and(|key| key != k) {
        return None;
    }
    Some(slot)
}

fn random_slot() -> NetworkResult<String> {
    let mut b = [0u8; ID_LEN / 2];
    rustix::rand::getrandom(&mut b, rustix::rand::GetRandomFlags::empty())
        .map_err(|e| NetworkError::Io(e.into()))?;
    Ok(hex::encode(b))
}

impl Detach {
    fn pool_lock(&self) -> NetworkResult<fs::File> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.pool_dir)?;
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.pool_dir.join(".lock"))?;
        velarx_sys::flock::flock_retrying(&f, rustix::fs::FlockOperation::LockExclusive)
            .map_err(NetworkError::Io)?;
        Ok(f)
    }

    /// The networks and interfaces of the container: what a pooled
    /// namespace must have to be taken.
    pub fn pool_key(&self, a: &impl Access, id: &str) -> NetworkResult<Option<String>> {
        use sha2::{Digest, Sha256};
        let owned = id.to_string();
        let rows =
            a.call(move |c| velarx_db::network_ext::net_attachments_of_container(c, &owned))?;
        if rows.is_empty() {
            return Ok(None);
        }
        let mut s = String::new();
        for r in &rows {
            // The records of DNS networks belong to a container.
            if network_by_id(a, &self.cfg, &r.network_id)?.dns {
                return Ok(None);
            }
            s.push_str(&format!("{}:{},", r.network_id, r.idx));
        }
        Ok(Some(
            hex::encode(Sha256::digest(s.as_bytes()))[..ID_LEN].to_string(),
        ))
    }

    pub fn slot_path(&self, slot: &str) -> PathBuf {
        self.pool_dir.join(format!("{slot}.netns"))
    }

    pub fn claim_path(&self, slot: &str) -> PathBuf {
        self.pool_dir.join(format!("{slot}.claim"))
    }

    /// Tear down the slot whose metadata was renamed to CLAIM.
    pub fn pool_drain_slot(&self, a: &impl Access, slot: &str, claim: &Path) {
        let path = self.slot_path(slot);
        if path.exists() {
            let meta = fs::read(claim)
                .map_err(|e| e.to_string())
                .and_then(|b| serde_json::from_slice::<Meta>(&b).map_err(|e| e.to_string()))
                .map_err(|e| {
                    warn!("tear down the pooled namespace {slot}: claim unusable, skipped: {e}");
                })
                .ok();
            let opts = self.opts_if_any().unwrap_or_else(|e| {
                warn!("tear down the pooled namespace {slot}: {e}");
                None
            });
            if let (Some(m), Some(opts)) = (meta, opts) {
                if let Err(e) = bridge::teardown(&opts, Some(&path), &m.input, NetnsFate::Released)
                {
                    warn!("tear down the pooled namespace {slot}: {e}");
                }
            }
            bridge::unpin_netns(&path);
        }
        let owned = slot.to_string();
        if let Err(e) = a.call(move |c| velarx_db::network_ext::netns_pool_remove(c, &owned)) {
            warn!("forget the addresses of the pooled namespace {slot}: {e}");
        }
        match fs::remove_file(claim) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                warn!("remove {}: {e}", claim.display());
            }
            _ => {}
        }
    }

    /// Forget the pooled addresses of the slots that are gone: the run root is
    /// cleared at boot, and a pin ends with the mount namespace of the
    /// command that made it (a rootless pool lasts while one lives).
    pub fn pool_gc(&self, a: &impl Access) {
        let slots = match a.call(|c| velarx_db::network_ext::netns_pool_slots(c, None)) {
            Ok(slots) => slots,
            Err(e) => {
                warn!("list the pooled namespaces: {e}");
                return;
            }
        };
        for s in slots {
            if !bridge::is_nsfs(&self.slot_path(&s)) {
                let slot = s.clone();
                if let Err(e) = a.call(move |c| velarx_db::network_ext::netns_pool_remove(c, &s)) {
                    warn!("forget the addresses of the pooled namespace {slot}: {e}");
                }
            }
        }
    }

    /// Give the namespace opened as PIN (a path of the descriptor of this
    /// process) to the pool: false if it must be torn down instead.
    pub fn pool_return(&self, a: &impl Access, id: &str, pin: &Path) -> NetworkResult<bool> {
        let Some(key) = self.pool_key(a, id)? else {
            return Ok(false);
        };
        let owned = id.to_string();
        if a.call(move |c| velarx_db::network_ext::net_attachments_of_container(c, &owned))?
            .iter()
            .any(|r| r.ip.is_none())
        {
            return Ok(false);
        }
        let Some(input) = bridge_input(a, &self.cfg, id, None)? else {
            return Ok(false);
        };
        // Another container joined it (`container:`, a pod member): it is
        // not given to a stranger.  The containers whose configuration
        // refers to this one are recorded.
        let owned = id.to_string();
        let name = a
            .call(move |c| velarx_db::get_container(c, &owned))?
            .name
            .unwrap_or_default();
        let (owned, named) = (id.to_string(), name);
        if !a
            .call(move |c| velarx_db::container_dependents(c, &owned, &named))?
            .is_empty()
        {
            return Ok(false);
        }
        // The count and the new entry under one lock: containers that stop
        // at the same time would all see room in the pool.
        let _lock = self.pool_lock()?;
        let count = fs::read_dir(&self.pool_dir)?
            .flatten()
            .filter(|e| entry_slot(&e.file_name().to_string_lossy(), Some(&key)).is_some())
            .count();
        if count >= POOL_MAX {
            return Ok(false);
        }
        let slot = random_slot()?;
        let slot_path = self.slot_path(&slot);
        let claim = self.claim_path(&slot);
        let entry = self.pool_dir.join(format!("{key}-{slot}.json"));
        let meta = serde_json::to_vec(&Meta { key, input })
            .map_err(|e| NetworkError::InvalidConfig(e.to_string()))?;
        fs::write(&claim, meta)?;
        if let Err(e) = bridge::bind_netns(pin, &slot_path) {
            let _ = fs::remove_file(&claim);
            return Err(e.into());
        }
        let (put_slot, put_id) = (slot.clone(), id.to_string());
        if let Err(e) =
            a.call(move |c| velarx_db::network_ext::netns_pool_put(c, &put_slot, &put_id))
        {
            bridge::unpin_netns(&slot_path);
            let _ = fs::remove_file(&claim);
            return Err(e.into());
        }
        if fs::rename(&claim, &entry).is_err() {
            self.pool_drain_slot(a, &slot, &claim);
        }
        debug!("the namespace of {id} went to the pool as {slot}");
        Ok(true)
    }

    /// Tear down the pooled namespaces of the network NETWORK_ID (all of
    /// them when None).
    pub fn pool_drain(&self, a: &impl Access, network_id: Option<&str>) -> NetworkResult<()> {
        self.pool_gc(a);
        let net = network_id.map(String::from);
        let slots = a.call(move |c| velarx_db::network_ext::netns_pool_slots(c, net.as_deref()))?;
        let Ok(entries) = fs::read_dir(&self.pool_dir) else {
            return Ok(());
        };
        let names: Vec<String> = entries
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        for name in names {
            let Some(slot) = entry_slot(&name, None).map(String::from) else {
                continue;
            };
            if network_id.is_some() && !slots.contains(&slot) {
                continue;
            }
            let claim = self.claim_path(&slot);
            if fs::rename(self.pool_dir.join(&name), &claim).is_ok() {
                self.pool_drain_slot(a, &slot, &claim);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries() {
        let k = "0123456789abcdef";
        let s = "fedcba9876543210";
        let name = format!("{k}-{s}.json");
        assert_eq!(entry_slot(&name, Some(k)), Some(s));
        assert_eq!(entry_slot(&name, None), Some(s));
        assert_eq!(entry_slot(&name, Some("ffffffffffffffff")), None);
        for bad in [
            ".lock",
            "x.claim",
            "0123-4567.json",
            &format!("{k}-{s}.claim"),
            &format!("{k}/{s}.json"),
        ] {
            assert_eq!(entry_slot(bad, None), None, "{bad}");
        }
        assert_eq!(random_slot().unwrap().len(), ID_LEN);
    }

    /// A claim that cannot be read skips the teardown in the namespace, not
    /// the rest: the pin, the addresses and the claim go.
    #[test]
    fn a_slot_with_a_bad_claim_is_still_drained() {
        let dir = tempfile::tempdir().unwrap();
        let d = crate::teardown::tests::detach(dir.path());
        let db = dir.path().join("db.sqlite");
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                velarx_db::Database::open(&db)
                    .await
                    .unwrap()
                    .close()
                    .await
                    .unwrap();
            });
        let store = velarx_db::sync::Store::open(&db).unwrap();
        let slot = "fedcba9876543210";
        store
            .call(move |c| {
                c.execute(
                    "INSERT INTO netns_pool (slot, network_id, idx, ip) VALUES (?1, 'n', 0, '10.0.0.2')",
                    [slot],
                )?;
                Ok(())
            })
            .unwrap();
        fs::create_dir_all(&d.pool_dir).unwrap();
        fs::write(d.slot_path(slot), "").unwrap();
        let claim = d.claim_path(slot);
        fs::write(&claim, "{not json").unwrap();
        d.pool_drain_slot(&store, slot, &claim);
        assert!(!d.slot_path(slot).exists());
        assert!(!claim.exists());
        let left = store
            .call(|c| velarx_db::network_ext::netns_pool_slots(c, None))
            .unwrap();
        assert!(left.is_empty(), "{left:?}");
    }
}
