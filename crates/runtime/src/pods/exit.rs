// SPDX-License-Identifier: Apache-2.0
//! The exit policy of a pod, applied by the monitor of the member that
//! exited: with no engine alive a pod with the policy `stop` stops when its
//! containers are gone, and a pod whose members are all gone is stopped.

use super::slice;
use super::store::{settled_state, MemberRun, PodState, PodStore, StoreError};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use velarx_db::sync::Access;
use velarx_db::RecordState;
use velarx_proto::pod::PodExitPolicy;
use velarx_wire::monitor::{client, iface, proto};

/// How long a monitor may take to say what its container does.
const ASK: Duration = Duration::from_secs(2);

/// How long the infra container of a pod whose containers are gone has to
/// stop.
const STOP_TIMEOUT_MS: u64 = 10_000;

/// The pod a container is a member of, as its monitor needs it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PodPlan {
    pub id: String,
    /// `<root_dir>/pods`
    pub pods_dir: PathBuf,
    /// The slice of the pod's limits, when it has one
    pub slice: Option<String>,
    /// `<state>/mon`: the monitor directories of the members
    pub mon_root: PathBuf,
}

/// What a member does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Activity {
    Idle,
    Running,
    Paused,
}

impl Activity {
    fn active(self) -> bool {
        self != Activity::Idle
    }
}

/// The monitor directory of the container `id` (its first 12 characters).
fn mon_dir(plan: &PodPlan, id: &str) -> PathBuf {
    plan.mon_root.join(&id[..id.len().min(12)])
}

/// What the monitor in `dir` says of its container, within [`ASK`].
fn status_of(dir: &Path) -> io::Result<proto::Status> {
    let mut conn = client::connect(dir)?;
    conn.set_deadline(Instant::now() + ASK);
    conn.call_method(&iface::GetStatus {}, &[])
        .map(|(r, _)| r.status)
        .map_err(io::Error::other)
}

/// Whether the member `id` runs, is paused, or is idle: its row says so, and
/// between two runs of its restart policy its monitor knows better.  A
/// monitor that wrote the exit of the last run (no restart comes) is not
/// asked: one that ends serves no call, and holds a connection it will not
/// take until it exits.  A monitor that does not answer counts as active.
fn activity(a: &impl Access, plan: &PodPlan, id: &str) -> Activity {
    let owned = id.to_string();
    let Ok(row) = a.call(move |c| velarx_db::get_container(c, &owned)) else {
        return Activity::Idle;
    };
    match row.state {
        RecordState::Paused => return Activity::Paused,
        RecordState::Running | RecordState::Stopping => return Activity::Running,
        _ => {}
    }
    let dir = mon_dir(plan, &row.id);
    if dir.join(proto::EXIT_FILE).exists() {
        return Activity::Idle;
    }
    match status_of(&dir) {
        Ok(s) if s.restarting.is_some() || s.state == proto::RunState::Running => Activity::Running,
        Ok(_) => Activity::Idle,
        // (a monitor that is not there, or refuses: the row is what is known)
        Err(e)
            if e.kind() == io::ErrorKind::NotFound
                || e.kind() == io::ErrorKind::ConnectionRefused =>
        {
            Activity::Idle
        }
        Err(_) => Activity::Running,
    }
}

/// Ask the monitor of the infra container to stop it, and go: the monitor
/// owns the deadline.
fn stop_infra(plan: &PodPlan, infra: &str) -> io::Result<()> {
    let mut conn = client::connect(&mon_dir(plan, infra))?;
    conn.set_deadline(Instant::now() + ASK);
    conn.send_method(
        &iface::StopParams {
            signal: None,
            timeout_ms: Some(STOP_TIMEOUT_MS),
        },
        &[],
    )
}

/// What the exit of the member `me` of the pod does to the pod.
///
/// * The policy `stop` with every container but the infra one gone: the
///   infra container is told to stop.
/// * Every member gone, the infra container too: the state of the pod is
///   settled, and the slice of its limits is stopped.
pub fn on_member_exit(a: &impl Access, plan: &PodPlan, me: &str) -> io::Result<()> {
    let store = PodStore {
        dir: plan.pods_dir.clone(),
    };
    let lock = match store.lock_file(&plan.id, "lock") {
        Ok(l) => l,
        // (a pod that is gone has nothing to settle)
        Err(StoreError::NotFound(_)) => return Ok(()),
        Err(StoreError::Io(e)) => return Err(e),
        Err(e) => return Err(io::Error::other(e)),
    };
    let pod = match store.list() {
        Ok(pods) => pods.into_iter().find(|p| p.id == plan.id),
        Err(StoreError::Io(e)) => return Err(e),
        Err(e) => return Err(io::Error::other(e)),
    };
    let Some(pod) = pod else {
        return Ok(());
    };
    let infra = pod.infra_container_id.clone();
    let mut runs = Vec::new();
    let mut containers_active = false;
    let mut infra_active = false;
    for id in pod.container_ids.iter().chain(&infra) {
        let act = if id == me {
            Activity::Idle
        } else {
            activity(a, plan, id)
        };
        if Some(id) == infra.as_ref() {
            infra_active = act.active();
        } else {
            containers_active |= act.active();
        }
        runs.push(match act {
            Activity::Idle => MemberRun::Idle,
            Activity::Running => MemberRun::Running,
            Activity::Paused => MemberRun::Paused,
        });
    }
    if pod.spec.exit_policy == PodExitPolicy::Stop && !containers_active && infra_active {
        // (the lock is not held across the call: the infra container's own
        // exit settles the pod under it)
        drop(lock);
        if let Some(infra) = &infra {
            return stop_infra(plan, infra);
        }
        return Ok(());
    }
    if containers_active || infra_active {
        return Ok(());
    }
    let ended = PodState::Stopped;
    store
        .modify(&plan.id, move |p| {
            p.state = settled_state(&runs, ended, &p.state);
        })
        .map_err(io::Error::other)?;
    drop(lock);
    if let Some(name) = &plan.slice {
        if !slice::populated(name).map_err(io::Error::other)? {
            slice::stop(name)?;
        }
    }
    Ok(())
}
