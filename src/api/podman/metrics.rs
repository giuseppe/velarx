// SPDX-License-Identifier: Apache-2.0
//! The metrics of pods and their containers in the names of cAdvisor:
//! `GET /libpod/metrics/descriptors`, `GET /libpod/pods/metrics` (the pods
//! that run) and `GET /libpod/pods/{name}/metrics`.  The samples are those of
//! `services::metrics`, with the values of the labels in the order of the
//! descriptor.

use super::error::{ApiError, ApiResult};
use super::events::now_nanos;
use super::{lifecycle, pods};
use crate::api::AppState;
use std::path::PathBuf;
use velarx_core::services::metrics::{self, Filesystem, Identity, Reading};
use velarx_core::services::Pod;
use velarx_db::ContainerRecord;
use velarx_wire::wire::{ContainerMetrics, Descriptor, PodMetrics};

pub fn descriptors() -> Vec<Descriptor> {
    metrics::descriptors()
}

/// The samples of a container that runs; None when it does not.
async fn container_of(
    state: &AppState,
    rec: &ContainerRecord,
    pid: i32,
    started_ns: i64,
) -> Option<ContainerMetrics> {
    // (`--cgroups=disabled`: the cgroup it is in is not its own)
    if !velarx_core::services::has_own_cgroup(rec) {
        return None;
    }
    let manager = state.container_service.cgroup_manager.as_ref()?;
    let dir = manager.cgroup_dir_of_pid(pid).ok()?;
    let stats = manager.get_stats_from_path(&dir).ok()?;
    let upper = state.container_service.writable_paths(&rec.id).upper;
    let (used, _) = super::archive::upper_usage(state, &rec.id).await;
    let filesystem: Option<Filesystem> = {
        let upper = upper.clone();
        tokio::task::spawn_blocking(move || metrics::filesystem_of(&upper, used.max(0) as u64))
            .await
            .ok()
            .flatten()
    };
    let name = rec.name.clone().unwrap_or_default();
    let image = match lifecycle::config_of(rec) {
        Ok(cfg) => cfg.image,
        Err(e) => {
            // (the container is left out of the metrics, not given an empty image)
            tracing::warn!("No metrics for container {}: {}", rec.id, e.message);
            return None;
        }
    };
    let id = rec.id.clone();
    let samples = tokio::task::spawn_blocking(move || {
        let reading = Reading {
            who: Identity {
                id: &id,
                name: &name,
                image: &image,
            },
            stats: &stats,
            dir: &dir,
            started_ns,
            now_ns: now_nanos(),
            filesystem,
        };
        (metrics::container_samples(&reading), name)
    })
    .await
    .ok()?;
    Some(ContainerMetrics {
        id: rec.id.clone(),
        name: samples.1,
        samples: samples.0,
    })
}

/// What the cgroup of the pod has used, when the pod has a cgroup of its
/// own (a pod with limits): the pod's directory above the cgroup of its infra
/// container (`<pod>/<infra>/container` in the server's tree) or its slice
/// (the scope of the infra container is in it).
fn pod_usage(state: &AppState, pod: &Pod, infra_pid: i32) -> Option<velarx_proto::pod::PodUsage> {
    pod.spec.resources.as_ref()?;
    let manager = state.container_service.cgroup_manager.as_ref()?;
    let dir = manager.cgroup_dir_of_pid(infra_pid).ok()?;
    let slice = format!("-velarx_pod_{}.slice", pod.id);
    let pod_dir = dir.ancestors().skip(1).take(2).find(|d| {
        d.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == pod.id || n.ends_with(&slice))
    })?;
    let s = manager.get_stats_from_path(pod_dir).ok()?;
    Some(velarx_proto::pod::PodUsage {
        cpu_usage_ns: s.cpu_usage_usec.saturating_mul(1000),
        memory_usage: s.memory_usage,
        memory_working_set: s.memory_usage.saturating_sub(s.memory_inactive_file),
        memory_rss: s.memory_anon,
        memory_limit: s.memory_limit.unwrap_or(0),
        swap_usage: s.memory_swap_usage,
        swap_limit: s.memory_swap_limit.unwrap_or(0),
        pressure: s.pressure,
    })
}

/// The metrics of a pod: its network (the namespace of its infra container)
/// and its containers that run, the infra container left out.
pub(crate) async fn pod_metrics_of(state: &AppState, pod: &Pod) -> PodMetrics {
    let mut out = PodMetrics {
        id: pod.id.clone(),
        name: pod.name.clone(),
        time_ns: now_nanos(),
        samples: Vec::new(),
        containers: Vec::new(),
        usage: None,
    };
    for (rec, asked) in pods::records_observed(state, pod).await {
        let st = lifecycle::status_from(state, &rec, asked).await;
        if !st.alive() || st.pid <= 0 {
            continue;
        }
        if Some(&rec.id) == pod.infra_container_id.as_ref() {
            let dev = PathBuf::from(format!("/proc/{}/net/dev", st.pid));
            let text = match tokio::fs::read_to_string(&dev).await {
                Ok(text) => Some(text),
                // (the infra container ended meanwhile)
                Err(e)
                    if e.kind() == std::io::ErrorKind::NotFound
                        || e.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error()) =>
                {
                    None
                }
                Err(e) => {
                    tracing::warn!("Cannot read {}: {e}", dev.display());
                    None
                }
            };
            if let Some(text) = text {
                let name = rec.name.clone().unwrap_or_default();
                match lifecycle::config_of(&rec) {
                    Ok(cfg) => {
                        out.samples = metrics::network_samples(
                            &Identity {
                                id: &rec.id,
                                name: &name,
                                image: &cfg.image,
                            },
                            &text,
                        );
                    }
                    Err(e) => tracing::warn!("No network metrics for the pod: {}", e.message),
                }
            }
            out.usage = pod_usage(state, pod, st.pid);
            continue;
        }
        if let Some(c) = container_of(state, &rec, st.pid, st.started_ns).await {
            out.containers.push(c);
        }
    }
    out
}

/// The pods that run, or the pod `name`.
pub(crate) async fn pods_metrics(
    state: &AppState,
    name: Option<&str>,
) -> ApiResult<Vec<PodMetrics>> {
    let list = match name {
        Some(n) => vec![pods::get(state, n).await?],
        None => state
            .pod_service
            .list()
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?,
    };
    let mut out = Vec::new();
    for pod in &list {
        out.push(pod_metrics_of(state, pod).await);
    }
    Ok(out)
}
