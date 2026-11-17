// SPDX-License-Identifier: Apache-2.0
//! The end of a container for good: its network released, its `/dev/shm`
//! given up and the exit recorded with its `died` event.
//!
//! The caller holds the lock of the container's start (`lock::exclusive`):
//! the engine's `monitor_lost` does, the monitor's exit job takes it.
//!
//! [`begin`] does what a confined thread may not (mounts, the pool's bind
//! mount, the exec of the CNI plugins); [`finish`] the rest.

use super::record::{announce_exit, row, update_ext};
use super::{mounts, rfc3339, SettlePlan, SettleResult};
use velarx_db::sync::Access;
use velarx_db::ContainerRecord;
use velarx_netdetach::teardown::Begun;
use velarx_netkernel::netns::Netns;
use velarx_wire::monitor::proto::ExitInfo;

/// An exit that was begun.
pub struct Exiting {
    container: Option<ContainerRecord>,
    begun: Option<NetworkBegun>,
    info: Option<ExitInfo>,
}

enum NetworkBegun {
    Begun(Box<Begun>),
    Failed(velarx_netkernel::error::NetworkError),
}

/// The container exited for good with `info`: the row's extras, the pool
/// and the CNI plugins, the `/dev/shm`.  `netns`: the namespace as the caller
/// holds it.
pub fn begin(
    a: &impl Access,
    plan: &SettlePlan,
    info: Option<&ExitInfo>,
    netns: Option<Netns>,
) -> SettleResult<Exiting> {
    let container = row(a, &plan.id)?;
    let shm = plan.removal.mon_dir.join("shm");
    let mut begun = None;
    if container.is_some() {
        // Before the state: who sees it stopped sees why.
        if let Some(info) = info {
            let (oom, timed_out) = (info.oom, info.timed_out);
            update_ext(a, &plan.id, move |e| {
                e.oom_killed |= oom;
                e.timed_out = timed_out;
            })?;
        }
        if let Some(detach) = &plan.network {
            begun = Some(match detach.begin(a, &plan.id, netns) {
                Ok(b) => NetworkBegun::Begun(Box::new(b)),
                Err(e) => NetworkBegun::Failed(e),
            });
        }
    }
    // (its /dev/shm goes all the same when the row is gone: the remover may
    // be in another mount namespace, or of another store)
    mounts::release_shm_dir(&shm);
    Ok(Exiting {
        container,
        begun,
        info: info.cloned(),
    })
}

/// What the end of the container came to.
pub struct Exited {
    /// The exit is in the row
    pub recorded: bool,
    /// The row was there
    pub known: bool,
    /// What the release of the network said when it failed: the exit is
    /// recorded all the same, the next release finishes what is left
    pub network_failure: Option<String>,
    /// What the pod's exit policy said when it failed
    pub pod_failure: Option<String>,
}

/// The rest: the network, then the exit with its `died` event in the
/// transaction.
pub fn finish(a: &impl Access, plan: &SettlePlan, exiting: Exiting) -> SettleResult<Exited> {
    let Exiting {
        container,
        begun,
        info,
    } = exiting;
    let Some(container) = container else {
        return Ok(Exited {
            recorded: false,
            known: false,
            network_failure: None,
            pod_failure: None,
        });
    };
    // The network goes before the state: whoever sees the container stopped
    // finds it detached.  A failure is logged: the exit is recorded all the
    // same, the next release finishes what is left.
    let network_failure = match (&plan.network, begun) {
        (Some(detach), Some(NetworkBegun::Begun(b))) => {
            detach.finish(a, *b, &|| {}).err().map(|e| e.to_string())
        }
        (_, Some(NetworkBegun::Failed(e))) => Some(e.to_string()),
        _ => None,
    };
    if let Some(e) = &network_failure {
        tracing::warn!("Network cleanup of {}: {e}", plan.id);
    }
    velarx_base::trace::point("exit network released");
    // (a container that never ran has no exit to record: its network only)
    let Some(info) = info else {
        return Ok(Exited {
            recorded: false,
            known: true,
            network_failure,
            pod_failure: None,
        });
    };
    let announce = announce_exit(&plan.events, &container, &info, !info.remove);
    let (id, finished, code) = (plan.id.clone(), rfc3339(info.finished_ns), info.code);
    let started = info.started_ns.map(rfc3339);
    let recorded = a.call(move |c| {
        velarx_db::record_container_exit_announcing(
            c,
            &id,
            &finished,
            code,
            started.as_deref(),
            info.remove,
            announce,
        )
    })?;
    tracing::info!("Container {} exited with code {}", plan.id, info.code);
    if info.timed_out {
        tracing::info!(
            "Container {} was killed at the end of its time limit",
            plan.id
        );
    }
    velarx_base::trace::point("exit recorded");
    // (the pod's policy after the exit: its other members may have gone, and
    // with them the pod)
    let pod_failure = plan.pod.as_ref().and_then(|pod| {
        crate::pods::exit::on_member_exit(a, pod, &plan.id)
            .err()
            .map(|e| format!("the pod {} after the exit of {}: {e}", pod.id, plan.id))
    });
    if let Some(e) = &pod_failure {
        tracing::warn!("{e}");
    }
    Ok(Exited {
        pod_failure,
        recorded,
        known: true,
        network_failure,
    })
}
