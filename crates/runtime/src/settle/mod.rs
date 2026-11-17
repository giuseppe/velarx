// SPDX-License-Identifier: Apache-2.0
//! What happens to a container's rows, network and files when it runs, exits
//! and goes: one implementation, blocking, over `velarx_db::sync::Access`.
//!
//! The monitor of the container calls it from its job threads (the engine
//! need not live), and the engine calls the same functions for the
//! containers whose monitor is gone.  The plan ([`SettlePlan`]) is built
//! once by the engine when the container starts and handed to the monitor.

pub mod cgroup;
pub mod exit;
pub mod lock;
pub mod mounts;
pub mod record;
pub mod remove;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use velarx_netdetach::teardown::Detach;
use velarx_wire::events::log::EventLog;

/// Why a step of the end of a container failed.
#[derive(Debug, thiserror::Error)]
pub enum SettleError {
    #[error("{0}")]
    Db(#[from] velarx_types::DbError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

pub type SettleResult<T> = Result<T, SettleError>;

/// What the monitor of one container needs to record and release it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlePlan {
    pub id: String,
    /// `StorageConfig::database_path()`
    pub db: PathBuf,
    /// The lock of the container's start (`<state>/mon/<id>.lock`): held
    /// while the monitor records, as the engine's start and removal hold it
    pub start_lock: PathBuf,
    /// The lock of the store (`<root>/storage.lock`): held shared while the
    /// container's files are removed
    pub storage_lock: PathBuf,
    /// Where the events are kept
    pub events: EventLog,
    /// The release of the network; none: the engine sets none up
    pub network: Option<Detach>,
    pub removal: RemovalPlan,
    /// `--rmi`: the image the container goes with
    pub image: Option<ImageRef>,
    /// The pod the container is a member of: its exit policy runs with the
    /// exit
    pub pod: Option<crate::pods::exit::PodPlan>,
    /// The cgroups the monitor leaves and removes at its end (none: systemd
    /// removes its scope, or the container has none of the engine's)
    pub cgroup: Option<cgroup::CgroupPlan>,
}

/// The image `--rmi` removes with the container (a name of it, or all of
/// it).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageRef {
    /// The image's id (its row)
    pub id: String,
    /// The hex digest of its configuration, which the events name it by
    pub event_id: String,
    /// The name the container was made with: its repository and tag.  None:
    /// by the id, the whole image goes.
    pub name: Option<(String, String)>,
}

/// What an `--rm` container leaves to remove.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemovalPlan {
    pub bundle: PathBuf,
    pub mon_dir: PathBuf,
    pub log_dir: PathBuf,
    pub secrets_dir: PathBuf,
    /// Where a killed monitor leaves the root file system bound
    pub public_rootfs: Option<PathBuf>,
    /// `pid_file`, `conmon_pid_file` and `cid_file` of the configuration
    pub named_files: Vec<PathBuf>,
    /// The request the API kept of the container
    pub api_record: Option<PathBuf>,
    /// The directory of the volumes the volume service made
    pub volumes_dir: PathBuf,
    /// The lock files of the container that go with it (`<state>/mon`)
    pub lock_files: Vec<PathBuf>,
    /// How its writable layer goes when the driver keeps it elsewhere than
    /// in the bundle (a storage service), and the pin of the lazy phase
    pub writable: velarx_graph::WritableRelease,
}

/// The rfc 3339 time of nanoseconds since the epoch, as the rows keep it.
pub fn rfc3339(ns: i64) -> String {
    chrono::DateTime::from_timestamp_nanos(ns).to_rfc3339()
}
