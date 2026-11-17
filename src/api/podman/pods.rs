// SPDX-License-Identifier: Apache-2.0
//! Pods (libpod only): PodSpecGenerator, ListPodsReport, InspectPodData and
//! the `{Errs, Id}` reports of the operations.

use super::call::{id_matches, label_matches, Filters};
use super::error::{ApiError, ApiResult, Kind};
use super::events::Event;
use super::lifecycle;
use crate::api::AppState;
use std::collections::HashMap;
use std::sync::Arc;
use velarx_core::services::StartCheck;
use velarx_core::services::{Pod, PodError, PodResources, PodSpec, PodState};
use velarx_proto::pod::PodAction;

use velarx_proto::workload::EventKind;
use velarx_proto::workload::{PodMember, PodRecord, PodStatus, RunState};
use velarx_wire::wire::TopResult;

/// The pod of a container: (pod id, pod name, is the infra container).
pub(super) type PodOf = (String, String, bool);

/// The pod of every container that is in one, from a single listing.
pub(super) async fn pod_index(state: &AppState) -> HashMap<String, PodOf> {
    let mut index = HashMap::new();
    let pods = state.pod_service.list().await.unwrap_or_else(|e| {
        tracing::warn!("Cannot list the pods: {e}");
        Vec::new()
    });
    for p in pods {
        if let Some(infra) = &p.infra_container_id {
            index.insert(infra.clone(), (p.id.clone(), p.name.clone(), true));
        }
        for c in &p.container_ids {
            index.insert(c.clone(), (p.id.clone(), p.name.clone(), false));
        }
    }
    index
}

/// The pod of a container, for the container list and inspect.
pub(super) async fn pod_of_container(state: &AppState, container_id: &str) -> Option<PodOf> {
    pod_index(state).await.remove(container_id)
}

/// The containers of a pod, the infra container first, with their records.
pub(super) async fn records(state: &AppState, p: &Pod) -> Vec<velarx_db::ContainerRecord> {
    records_observed(state, p)
        .await
        .into_iter()
        .map(|(rec, _)| rec)
        .collect()
}

/// [`records`], each with the state the runtime gave when it was found (see
/// `lifecycle::status_from`).
pub(super) async fn records_observed(
    state: &AppState,
    p: &Pod,
) -> Vec<(
    velarx_db::ContainerRecord,
    Option<velarx_runtime::container::ContainerStatus>,
)> {
    let mut out = Vec::new();
    for id in p.infra_container_id.iter().chain(p.container_ids.iter()) {
        if let Ok(found) = state.container_service.inspect_observed(id).await {
            out.push(found);
        }
    }
    out
}

async fn members(state: &AppState, p: &Pod) -> Vec<PodMember> {
    let mut out = Vec::new();
    for (rec, asked) in records_observed(state, p).await {
        let status = lifecycle::status_from(state, &rec, asked).await;
        let restart_count = state
            .container_service
            .container_ext(&rec.id)
            .await
            .map(|e| e.restart_count)
            .unwrap_or_default();
        out.push(PodMember {
            init: velarx_core::services::init_kind(&rec).is_some(),
            id: rec.id,
            name: rec.name.unwrap_or_default(),
            state: status.state,
            restart_count: i64::from(restart_count),
        });
    }
    out
}

/// podman's pod states, from the states of the containers.
fn pod_status(p: &Pod, members: &[PodMember]) -> PodStatus {
    // (an init container runs to its end at the start: it does not count)
    let members: Vec<&PodMember> = members.iter().filter(|m| !m.init).collect();
    let running = members
        .iter()
        .filter(|m| m.state == RunState::Running)
        .count();
    if members.iter().any(|m| m.state == RunState::Paused) && running == 0 {
        return PodStatus::Paused;
    }
    if !members.is_empty() && running == members.len() {
        return PodStatus::Running;
    }
    if running > 0 {
        return PodStatus::Degraded;
    }
    if p.started_at.is_none() && p.state == PodState::Created {
        PodStatus::Created
    } else {
        PodStatus::Exited
    }
}

/// The networks a pod is on: those its spec names, or the default bridge of
/// a rootful pod with an infra container; none for a pod on pasta (rootless,
/// the default) or without an infra container, as podman's.
fn networks(spec: &PodSpec) -> Vec<String> {
    networks_of(spec, velarx_base::conf::rootless().unwrap_or(true))
}

fn networks_of(spec: &PodSpec, rootless: bool) -> Vec<String> {
    if spec.networks.is_empty() {
        if spec.no_infra || rootless {
            Vec::new()
        } else {
            vec![velarx_netdetach::def::DEFAULT_NETWORK.to_string()]
        }
    } else {
        spec.networks
            .iter()
            .filter(|n| !matches!(n.as_str(), "host" | "none") && !n.contains(':'))
            .cloned()
            .collect()
    }
}

/// The record of the pod `p` whose containers are `members`.
fn record(p: &Pod, members: Vec<PodMember>) -> PodRecord {
    PodRecord {
        id: p.id.clone(),
        name: p.name.clone(),
        created_ns: super::convert::record_time_ns(&p.created_at),
        status: pod_status(p, &members),
        infra_id: p.infra_container_id.clone().unwrap_or_default(),
        members,
        networks: networks(&p.spec),
        host_network: p.spec.networks.iter().any(|n| n == "host"),
        spec: p.spec.clone(),
        devices: device_nodes(&p.spec.devices),
        ..PodRecord::default()
    }
}

/// The devices of a pod (`--device` as typed) as the nodes of the host are.
fn device_nodes(devices: &[String]) -> Vec<velarx_proto::workload::DeviceNode> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    devices
        .iter()
        .map(|d| {
            let device = velarx_wire::request::DeviceMapping::parse(d);
            let mut node = velarx_proto::workload::DeviceNode {
                path: device.path_in_container,
                ..Default::default()
            };
            if let Ok(meta) = std::fs::metadata(&device.path_on_host) {
                let rdev = meta.rdev();
                node.kind = if meta.file_type().is_block_device() {
                    "b"
                } else {
                    "c"
                }
                .into();
                node.major = u64::from(rustix::fs::major(rdev));
                node.minor = u64::from(rustix::fs::minor(rdev));
                node.file_mode = u64::from(meta.mode() & 0o7777);
            }
            node
        })
        .collect()
}

fn pod_error(e: PodError) -> ApiError {
    match e {
        // podman's words, which its clients show
        PodError::NotFound(ref name) => {
            ApiError::not_found(format!("no pod with name or ID {name} found: no such pod"))
                .with_cause("no such pod")
        }
        PodError::Running | PodError::InvalidState(_) => {
            ApiError::invalid_state(e.to_string()).with_cause("pod state improper")
        }
        PodError::ImageNotFound(_) => ApiError::no_such(Kind::Image, e.to_string()),
        PodError::AlreadyExists(_) => {
            ApiError::conflict(e.to_string()).with_cause("pod already exists")
        }
        PodError::Container(_) => ApiError::invalid_state(e.to_string()),
        e => e.into(),
    }
}

/// The volumes and bind mounts of the containers `spec.volumes_from` names,
/// as `--volume` values of the pod after its own (a later container replaces
/// an earlier one; the pod's own volumes win at a destination).
pub(crate) async fn resolve_volumes_from(state: &AppState, spec: &mut PodSpec) -> ApiResult<()> {
    let clean = |d: &str| format!("/{}", d.trim_matches('/'));
    let taken: std::collections::HashSet<String> = spec
        .volumes
        .iter()
        .map(|v| {
            let mut parts = v.split(':');
            let first = parts.next().unwrap_or_default();
            clean(parts.next().unwrap_or(first))
        })
        .collect();
    let mut found: Vec<(String, String)> = Vec::new();
    for entry in &spec.volumes_from {
        let (name, options) = entry.split_once(':').unwrap_or((entry, ""));
        let info = super::containers::inspect_of(state, name, false)
            .await
            .map_err(|mut e| {
                if e.status == crate::api::status::StatusCode::NOT_FOUND {
                    e.message = format!(
                        "looking up container {name:?} for volumes-from: {}",
                        e.message
                    );
                }
                e
            })?;
        for (dest, arg) in velarx_wire::request::volumes_from_args(&info.mounts, options)
            .map_err(ApiError::bad_request)?
        {
            if taken.contains(&dest) {
                continue;
            }
            found.retain(|(d, _)| *d != dest);
            found.push((dest, arg));
        }
    }
    spec.volumes.extend(found.into_iter().map(|(_, arg)| arg));
    Ok(())
}

/// Create the pod `spec` describes: its id (a name of its own if it has
/// none).
pub(crate) async fn create_spec(state: &AppState, mut spec: PodSpec) -> ApiResult<String> {
    resolve_volumes_from(state, &mut spec).await?;
    if spec.name.is_empty() {
        spec.name = velarx_core::services::generated_pod_name();
    }
    let name = spec.name.clone();
    let id = state.pod_service.create(spec).await.map_err(pod_error)?;
    state
        .podman
        .events
        .emit(Event::new(EventKind::Pod, "create", &id, &name));
    Ok(id)
}

/// podman's GeneratePodFilterFunc: a filter it does not know, and a
/// status that is not one, are errors (a 400 for a list) even when there
/// is no pod to filter.
fn check_filters(filters: &Filters) -> ApiResult<()> {
    for (key, values) in &filters.0 {
        let bad = |msg: String| ApiError::bad_request(msg);
        match key.as_str() {
            "ctr-ids" | "ctr-names" | "ctr-number" | "id" | "name" | "label" | "label!"
            | "until" | "network" => {}
            "ctr-status" => {
                if let Some(v) = values.iter().find(|v| {
                    ![
                        "created", "running", "paused", "stopped", "exited", "unknown",
                    ]
                    .contains(&v.as_str())
                }) {
                    return Err(bad(format!("{v} is not a valid status")));
                }
            }
            "status" => {
                if let Some(v) = values.iter().find(|v| {
                    ![
                        "stopped", "running", "paused", "exited", "dead", "created", "degraded",
                    ]
                    .contains(&v.as_str())
                }) {
                    return Err(bad(format!("{v} is not a valid pod status")));
                }
            }
            _ => return Err(bad(format!("{key} is an invalid filter"))),
        }
    }
    Ok(())
}

/// podman's match of a filter value: a regular expression found anywhere in
/// the text (a value that is none matches nothing).
fn regex_matches(value: &str, text: &str) -> bool {
    regex_lite::Regex::new(value).is_ok_and(|r| r.is_match(text))
}

fn filter_match(filters: &Filters, p: &PodRecord) -> bool {
    let status = velarx_shape::pod::status_word(p.status);
    let members = &p.members;
    for (key, values) in &filters.0 {
        if values.is_empty() {
            continue;
        }
        let ok = match key.as_str() {
            "name" => values.iter().any(|v| regex_matches(v, &p.name)),
            "id" => values.iter().any(|v| id_matches(&p.id, v)),
            "status" => values.iter().any(|v| v.eq_ignore_ascii_case(status)),
            "label" => values.iter().any(|v| label_matches(&p.spec.labels, v)),
            "label!" => !values.iter().any(|v| label_matches(&p.spec.labels, v)),
            "until" => values
                .iter()
                .any(|v| super::events::parse_since(v).is_some_and(|t| p.created_ns < t)),
            "ctr-ids" => members
                .iter()
                .any(|m| values.iter().any(|v| id_matches(&m.id, v))),
            "ctr-names" => members
                .iter()
                .any(|m| values.iter().any(|v| regex_matches(v, &m.name))),
            "ctr-number" => values
                .iter()
                .any(|v| v.parse::<usize>().is_ok_and(|n| n == members.len())),
            "ctr-status" => members.iter().any(|m| {
                values.iter().any(|v| {
                    let want = if v == "stopped" { "exited" } else { v.as_str() };
                    velarx_shape::container::state_word(m.state) == want
                })
            }),
            "network" => values.iter().any(|v| p.spec.networks.contains(v)),
            _ => true,
        };
        if !ok {
            return false;
        }
    }
    true
}

/// The pods `filters` (podman's of `pod ps`) selects.
pub(crate) async fn list_of(state: &AppState, filters: &Filters) -> ApiResult<Vec<PodRecord>> {
    check_filters(filters)?;
    let mut out = Vec::new();
    for p in state.pod_service.list().await.map_err(pod_error)? {
        let r = record(&p, members(state, &p).await);
        if filter_match(filters, &r) {
            out.push(r);
        }
    }
    Ok(out)
}

pub(super) async fn get(state: &AppState, key: &str) -> ApiResult<Pod> {
    state.pod_service.get(key).await.map_err(pod_error)
}

/// A pod, with what its infra container says of its network.
pub(crate) async fn inspect_of(state: &Arc<AppState>, name: &str) -> ApiResult<PodRecord> {
    let p = get(state, name).await?;
    let mut pod = record(&p, members(state, &p).await);
    pod.cgroup_path = state.pod_service.cgroup_path(&p).map_err(pod_error)?;
    if pod.infra_id.is_empty() {
        return Ok(pod);
    }
    if let Ok(infra) = super::containers::inspect_of(state, &pod.infra_id, false).await {
        for i in &infra.network.interfaces {
            for ip in [&i.ip, &i.ip6] {
                if !ip.is_empty() {
                    pod.ips.push(ip.clone());
                }
            }
        }
        pod.infra_pid = infra.pid;
        pod.oci_runtime = infra.oci_runtime;
        pod.netns_path = infra.network.sandbox_key;
        pod.host_ipc = infra.host.ipc_mode == "host";
        pod.host_pid = infra.host.pid_mode == "host";
    }
    Ok(pod)
}

/// The pod is there.
pub(crate) async fn exists_of(state: &AppState, name: &str) -> ApiResult<()> {
    get(state, name).await.map(|_| ())
}

/// Replace the limits of the cgroup of the pod `name` with `resources`:
/// the pod's id.
pub(crate) async fn update_of(
    state: &AppState,
    name: &str,
    resources: PodResources,
) -> ApiResult<String> {
    let p = get(state, name).await?;
    state
        .pod_service
        .update_resources(&p.id, resources)
        .await
        .map_err(pod_error)
}

/// Apply `f` to the containers of the pod; the errors are the report's.
async fn each<'a, F, Fut>(
    recs: impl Iterator<Item = &'a velarx_db::ContainerRecord>,
    mut f: F,
) -> Vec<String>
where
    F: FnMut(&'a velarx_db::ContainerRecord) -> Fut,
    Fut: std::future::Future<Output = ApiResult<()>>,
{
    let mut errs = Vec::new();
    for rec in recs {
        if let Err(e) = f(rec).await {
            errs.push(e.message);
        }
    }
    errs
}

/// Pause the running containers of a pod, all or none: when one cannot
/// be paused (no cgroup freezer for a rootless container), the ones
/// paused before it are unpaused, and the pod stays as it was.
async fn pause_all(state: &Arc<AppState>, recs: &[velarx_db::ContainerRecord]) -> Vec<String> {
    let mut paused: Vec<&velarx_db::ContainerRecord> = Vec::new();
    for rec in recs {
        if !lifecycle::status(state, rec).await.alive() {
            continue;
        }
        if let Err(e) = lifecycle::pause(state, rec).await {
            for done in paused.iter().rev() {
                if let Err(u) = lifecycle::unpause(state, done).await {
                    tracing::warn!(
                        "Cannot unpause {} after a failed pod pause: {}",
                        done.id,
                        u.message
                    );
                }
            }
            return vec![e.message];
        }
        paused.push(rec);
    }
    Vec::new()
}

/// The check of the start of a pod: the digests of the command that starts
/// it (none: the engine starts it, the CRI), whatever the record says.
fn pod_check(verify: &Option<Vec<velarx_types::digest::Digest>>) -> StartCheck {
    match verify {
        Some(digests) => StartCheck::Pod {
            digests: digests.clone(),
        },
        None => StartCheck::Engine,
    }
}

/// Refuse by name, before the first container starts, the digests `check`
/// has when they do not fit the images of the members of the pod `recs`
/// that start (see [`velarx_core::services::pod_digests_refusal`]; `option`:
/// they were given by `--verify-image`).  The infra container is not one of
/// them: its image is made by velarx, there is no digest to type for it.
fn check_members(
    state: &Arc<AppState>,
    pod: &Pod,
    recs: &[velarx_db::ContainerRecord],
    check: &StartCheck,
    option: bool,
) -> ApiResult<()> {
    let members: Vec<_> = recs
        .iter()
        .filter(|r| Some(&r.id) != pod.infra_container_id.as_ref())
        .cloned()
        .collect();
    state
        .container_service
        .check_pod_digests(&members, check.typed(), option)
        .map_err(|e| ApiError::bad_request(e.to_string()))
}

/// Start the containers of a pod: the infra container, the init containers
/// one after the other to their end (a `once` one is removed when it
/// succeeded; one that fails fails the start), then the others.
///
/// `check`: the digests the command typed (or the engine's own for a start
/// that has none) which the members are started with; the infra container
/// goes by the engine's: its image is made by velarx, there is no digest to
/// type for it.
async fn start_all(
    state: &Arc<AppState>,
    pod: &Pod,
    recs: &[velarx_db::ContainerRecord],
    check: &StartCheck,
) -> Vec<String> {
    use velarx_core::services::{init_kind, InitKind};
    let mut errs = Vec::new();
    let (infra, rest): (Vec<_>, Vec<_>) = recs
        .iter()
        .partition(|r| Some(&r.id) == pod.infra_container_id.as_ref());
    for rec in infra {
        if let Err(e) = lifecycle::start(state, rec, &StartCheck::Engine).await {
            return vec![e.message];
        }
    }
    let (inits, others): (Vec<_>, Vec<_>) = rest.into_iter().partition(|r| init_kind(r).is_some());
    for rec in inits {
        if let Err(e) = lifecycle::start(state, rec, check).await {
            return vec![e.message];
        }
        let code = match crate::api::ops::wait::wait(
            state,
            &rec.id,
            &[velarx_proto::wait::WaitCondition::Exited],
            0,
            || {},
        )
        .await
        {
            Ok(met) => met.code,
            Err(e) => return vec![e.message],
        };
        if code != 0 {
            return vec![format!("init container {} exited with code {code}", rec.id)];
        }
        if init_kind(rec) == Some(InitKind::Once) {
            if let Err(e) = lifecycle::remove(state, rec, true, false).await {
                return vec![e.message];
            }
            if let Err(e) = state.pod_service.forget_container(&pod.id, &rec.id).await {
                return vec![e.to_string()];
            }
        }
    }
    errs.extend(
        each(others.into_iter(), |rec| async move {
            lifecycle::start(state, rec, check).await.map(|_| ())
        })
        .await,
    );
    errs
}

async fn stop_all(
    state: &Arc<AppState>,
    recs: &[velarx_db::ContainerRecord],
    timeout: Option<u64>,
) -> Vec<String> {
    // the infra container last
    each(recs.iter().rev(), |rec| async move {
        // podman's `pod stop` leaves its `--rm` members stopped
        let keep = lifecycle::config_of(rec)?.auto_remove;
        if keep {
            state.container_service.keep(&rec.id).await?;
        }
        lifecycle::stop(state, rec, timeout, None).await.map(|_| ())
    })
    .await
}

/// Apply `op` to the containers of the pod `name`: its id and the errors
/// of its containers, none when the pod is already as asked.  `timeout` is
/// that of a stop (none: each container's own), `signal` that of a kill
/// (none: `SIGKILL`).
pub(crate) async fn run_named(
    state: &Arc<AppState>,
    name: &str,
    op: PodAction,
    timeout: Option<u64>,
    signal: Option<&str>,
    verify: Option<Vec<velarx_types::digest::Digest>>,
) -> ApiResult<Option<(String, Vec<String>)>> {
    let signal = match signal.filter(|s| !s.is_empty() && op == PodAction::Kill) {
        None => 9,
        Some(s) => lifecycle::parse_signal(s)
            .ok_or_else(|| ApiError::bad_request(format!("invalid signal `{s}`")))?,
    };
    if let Some(d) = verify.iter().flatten().next() {
        if !matches!(op, PodAction::Start | PodAction::Restart) {
            return Err(ApiError::bad_request(format!(
                "--verify-image {}: the digests are of a start or a restart of the pod",
                d
            )));
        }
    }
    run_of(state, name, op, timeout, signal, verify).await
}

/// Apply `op` to the containers of the pod `name` (`timeout`: of a stop,
/// `signal`: of a kill): the pod's ID and the errors of its containers;
/// none when the pod is already as asked.
async fn run_of(
    state: &Arc<AppState>,
    name: &str,
    op: PodAction,
    timeout: Option<u64>,
    sig: i32,
    verify: Option<Vec<velarx_types::digest::Digest>>,
) -> ApiResult<Option<(String, Vec<String>)>> {
    let state = state.clone();
    // (one operation on a pod at a time: what a start or a stop finds is
    // what the one before it left)
    // (a pod removed meanwhile has no lock: the pod of that name, if one was
    // made again, is another one)
    let gone = |e| match e {
        PodError::NotFound(_) => pod_error(PodError::NotFound(name.to_string())),
        e => pod_error(e),
    };
    let id = get(&state, name).await?.id;
    let _op = state.pod_service.lock_operation(&id).await.map_err(gone)?;
    let p = state.pod_service.get(&id).await.map_err(gone)?;
    let recs = records(&state, &p).await;
    let m = members(&state, &p).await;
    let status = pod_status(&p, &m);
    let svc = &state.pod_service;
    let (id, name) = (p.id.as_str(), p.name.as_str());
    // (`ended`: the state of the pod if none of its containers runs once the
    // operation is done; otherwise the pod takes what its containers are)
    // (podman's: a pod without an infra container needs a member to start)
    if matches!(op, PodAction::Start | PodAction::Restart) && recs.is_empty() {
        return Err(ApiError::internal(format!(
            "no containers in pod {id} have no dependencies, cannot start pod: no such container"
        )));
    }
    let (action, errs, ended) = match op {
        PodAction::Start => {
            if status == PodStatus::Running {
                if let Some(d) = verify.iter().flatten().next() {
                    return Err(ApiError::bad_request(format!(
                        "pod {name}: --verify-image {}: it runs, on the file systems the monitors of its containers mounted when they started: nothing would be checked now; stop it, then start it with --verify-image",
                        d
                    )));
                }
                return Ok(None);
            }
            let check = pod_check(&verify);
            // (those that run are not started: their digests are not asked)
            let mut waiting = Vec::new();
            for rec in &recs {
                if !lifecycle::status(&state, rec).await.alive() {
                    waiting.push(rec.clone());
                }
            }
            check_members(&state, &p, &waiting, &check, true)?;
            state.pod_service.ensure_slice(&p).map_err(pod_error)?;
            (
                "start",
                start_all(&state, &p, &recs, &check).await,
                PodState::Exited,
            )
        }
        PodAction::Stop => {
            if !matches!(
                status,
                PodStatus::Running | PodStatus::Degraded | PodStatus::Paused
            ) {
                return Ok(None);
            }
            (
                "stop",
                stop_all(&state, &recs, timeout).await,
                PodState::Stopped,
            )
        }
        PodAction::Restart => {
            let check = pod_check(&verify);
            check_members(&state, &p, &recs, &check, true)?;
            // (its `--rm` members are kept by the stop, and throw-away
            // again once started)
            let mut errs = stop_all(&state, &recs, timeout).await;
            state.pod_service.ensure_slice(&p).map_err(pod_error)?;
            errs.extend(start_all(&state, &p, &recs, &check).await);
            ("restart", errs, PodState::Exited)
        }
        PodAction::Kill => {
            let st = &state;
            let errs = each(recs.iter().rev(), |rec| async move {
                if lifecycle::status(st, rec).await.alive() {
                    lifecycle::kill(st, rec, sig).await
                } else {
                    Ok(())
                }
            })
            .await;
            ("kill", errs, PodState::Exited)
        }
        PodAction::Pause => ("pause", pause_all(&state, &recs).await, PodState::Stopped),
        PodAction::Unpause => {
            let st = &state;
            // what is not paused is left alone: a second unpause is fine
            let errs = each(recs.iter(), |rec| async move {
                if lifecycle::status(st, rec).await.state == RunState::Paused {
                    lifecycle::unpause(st, rec).await
                } else {
                    Ok(())
                }
            })
            .await;
            ("unpause", errs, PodState::Exited)
        }
    };
    // (also after a failure: the containers that did change are recorded)
    svc.settle(id, ended).await.map_err(pod_error)?;
    if matches!(op, PodAction::Stop) {
        svc.stop_slice(id).await.map_err(pod_error)?;
    }
    if errs.is_empty() {
        state
            .podman
            .events
            .emit(Event::new(EventKind::Pod, action, id, name));
    }
    Ok(Some((id.to_string(), errs)))
}

/// go-multierror's text of the errors `errs`.
fn multierror(errs: &[String]) -> String {
    let s = if errs.len() == 1 { "" } else { "s" };
    let mut out = format!("{} error{s} occurred:", errs.len());
    for e in errs {
        out.push_str("\n\t* ");
        out.push_str(e);
    }
    out.push_str("\n\n");
    out
}

/// Remove the pod `id` with its containers (forced: the running ones are
/// stopped): podman's warnings of the stops that needed the kill.
pub(super) async fn remove_pod_by_id(state: &Arc<AppState>, id: &str) -> ApiResult<Vec<String>> {
    let p = get(state, id).await?;
    remove_pod(state, &p, true, None)
        .await
        .map(|(_, warnings)| warnings)
}

/// Remove a pod and its containers; with force the running ones stop,
/// with `timeout` seconds to obey their stop signal (none: their own).  The
/// ids of the containers removed, and podman's warnings of the stops that
/// needed the kill.
pub(super) async fn remove_pod(
    state: &Arc<AppState>,
    p: &Pod,
    force: bool,
    timeout: Option<u64>,
) -> ApiResult<(Vec<String>, Vec<String>)> {
    let _op = state
        .pod_service
        .lock_operation(&p.id)
        .await
        .map_err(pod_error)?;
    // (what the operation before this one left)
    let p = &get(state, &p.id).await?;
    let recs = records(state, p).await;
    // (podman's words: the pod's error, then the errors of the containers
    // as go-multierror writes them: one for each running one, and one for
    // the infra container that cannot stop while they run)
    let mut busy = Vec::new();
    for rec in &recs {
        // the infra container goes with the pod, running or not
        if Some(&rec.id) == p.infra_container_id.as_ref() {
            continue;
        }
        if force {
            continue;
        }
        let st = lifecycle::status(state, rec).await;
        if st.alive() {
            busy.push(lifecycle::not_removed_alive(&rec.id, st.state));
        }
    }
    if let (false, Some(infra)) = (busy.is_empty(), &p.infra_container_id) {
        busy.push(format!(
            "a container that depends on container {infra} could not be stopped: container state improper"
        ));
    }
    if !busy.is_empty() {
        return Err(ApiError::internal(format!(
            "not all containers could be removed from pod {}: removing pod containers. {}",
            p.id,
            multierror(&busy)
        ))
        .with_cause("removing pod containers"));
    }
    // From here no container joins the pod (a create of one meanwhile is
    // refused): its members are removed until none is left, the infra
    // container last.
    state
        .pod_service
        .begin_removal(&p.id)
        .await
        .map_err(pod_error)?;
    let removing = async {
        let mut removed = Vec::new();
        let mut warnings = Vec::new();
        let mut pod = p.clone();
        // the running containers stop together, as podman's removal stops
        // them (each by its own stop signal and timeout, unless `timeout`
        // is given); the removals that follow find them stopped
        if force {
            let running: Vec<_> = records(state, &pod)
                .await
                .into_iter()
                .filter(|r| Some(&r.id) != pod.infra_container_id.as_ref())
                .collect();
            let stops = futures::future::join_all(running.iter().map(|rec| async move {
                if lifecycle::status(state, rec).await.state == RunState::Running {
                    // (a failure is the removal's to tell)
                    let stopped = lifecycle::stop_reporting(state, rec, timeout, None).await;
                    stopped.ok().and_then(|s| lifecycle::kill_warning(rec, &s))
                } else {
                    None
                }
            }))
            .await;
            warnings.extend(stops.into_iter().flatten());
        }
        loop {
            let members: Vec<_> = records(state, &pod)
                .await
                .into_iter()
                .filter(|r| Some(&r.id) != pod.infra_container_id.as_ref())
                .collect();
            if members.is_empty() {
                break;
            }
            for rec in members.iter().rev() {
                warnings.extend(
                    lifecycle::remove_with_timeout(state, rec, true, false, timeout).await?,
                );
                removed.push(rec.id.clone());
            }
            pod = get(state, &p.id).await?;
        }
        if let Some(infra) = &pod.infra_container_id {
            // (a container that requires the infra container and is no
            // member of the pod goes first)
            for dep in state
                .container_service
                .dependents(infra)
                .await
                .unwrap_or_default()
            {
                if let Ok(rec) = state.container_service.inspect(&dep).await {
                    warnings.extend(
                        lifecycle::remove_with_timeout(state, &rec, true, false, timeout).await?,
                    );
                    removed.push(rec.id.clone());
                }
            }
        }
        for rec in records(state, &pod).await {
            warnings
                .extend(lifecycle::remove_with_timeout(state, &rec, true, false, timeout).await?);
            removed.push(rec.id.clone());
        }
        state
            .pod_service
            .remove(&p.id, true)
            .await
            .map_err(pod_error)?;
        Ok::<_, ApiError>((removed, warnings))
    }
    .await;
    let removed = match removing {
        Ok(removed) => removed,
        Err(e) => {
            // (the pod is what it was: it takes containers again)
            let _ = state.pod_service.cancel_removal(&p.id).await;
            return Err(e);
        }
    };
    state
        .podman
        .events
        .emit(Event::new(EventKind::Pod, "remove", &p.id, &p.name));
    Ok(removed)
}

/// Remove the pod `name` and its containers: its id, the ids of the
/// containers removed and the warnings of the stops that needed the kill.
pub(crate) async fn remove_named(
    state: &Arc<AppState>,
    name: &str,
    force: bool,
    timeout: Option<u64>,
) -> ApiResult<(String, Vec<String>, Vec<String>)> {
    let p = get(state, name).await?;
    let (removed, warnings) = remove_pod(state, &p, force, timeout).await?;
    Ok((p.id, removed, warnings))
}

/// Remove the pods that do not run: their ids.
pub(crate) async fn prune_of(state: &Arc<AppState>) -> ApiResult<Vec<String>> {
    let mut out = Vec::new();
    for p in state.pod_service.list().await.map_err(pod_error)? {
        let m = members(state, &p).await;
        if matches!(
            pod_status(&p, &m),
            PodStatus::Running | PodStatus::Degraded | PodStatus::Paused
        ) {
            continue;
        }
        if remove_pod(state, &p, false, Some(0)).await.is_ok() {
            out.push(p.id);
        }
    }
    Ok(out)
}

/// The processes of the running containers of a pod, the infra container
/// first, as podman lists them, of `ps_args`: podman's descriptors or the
/// arguments of ps.
pub(crate) async fn processes_of(
    state: &AppState,
    pod: &str,
    ps_args: &[String],
) -> ApiResult<TopResult> {
    let p = get(state, pod).await?;
    let descriptors = velarx_core::services::top_descriptor_list(&ps_args.join(" "));
    let mut titles: Vec<String> = Vec::new();
    let mut processes: Vec<Vec<String>> = Vec::new();
    let mut ms = members(state, &p).await;
    ms.sort_by_key(|m| Some(&m.id) != p.infra_container_id.as_ref());
    for m in ms {
        if m.state != RunState::Running {
            continue;
        }
        let t = match &descriptors {
            Some(d) => state.container_service.top_descriptors(&m.id, d).await,
            None => state.container_service.top(&m.id, ps_args).await,
        };
        let t = match t {
            Ok(t) => t,
            Err(velarx_core::services::ContainerError::InvalidArgument(e)) => {
                return Err(ApiError::internal(e))
            }
            Err(_) => continue,
        };
        if titles.is_empty() {
            titles = t.titles;
        }
        processes.extend(t.processes);
    }
    Ok(TopResult { titles, processes })
}

/// podman's report of the processes of a pod.
#[cfg(test)]
mod tests {
    #[test]
    fn multierror_is_go_multierrors_text() {
        assert_eq!(
            super::multierror(&["a".into()]),
            "1 error occurred:\n\t* a\n\n"
        );
        assert_eq!(
            super::multierror(&["a".into(), "b".into()]),
            "2 errors occurred:\n\t* a\n\t* b\n\n"
        );
    }

    #[test]
    fn an_id_filter_is_a_prefix_or_a_regular_expression() {
        let id = "d1a3a0d0bb4e44b055401d99dd40e6f6e85769eba1d074ad44e2bc9913e5f809";
        assert!(id_matches(id, "d1"));
        assert!(id_matches(id, "D1A3"));
        // (hexadecimal: a prefix, not a place in the ID)
        assert!(!id_matches(id, "a3a0"));
        assert!(id_matches(id, "^d1"));
        assert!(id_matches(id, "^[^0]"));
        assert!(!id_matches(id, "^[^d]"));
        assert!(id_matches(id, "a3a0.*bb"));
        assert!(!id_matches(id, "["));
    }

    use super::*;

    #[test]
    fn pod_filters_that_are_not_are_refused_and_podman_options_it_lacks_too() {
        let f = |j: &str| Filters::parse(j).unwrap();
        assert!(check_filters(&f(r#"{"ctr-names":["a"],"label!":["a"],"network":["n"]}"#)).is_ok());
        for bad in [
            r#"{"bogus":["1"]}"#,
            r#"{"status":["nope"]}"#,
            r#"{"ctr-status":["nope"]}"#,
        ] {
            assert!(check_filters(&f(bad)).is_err(), "{bad}");
        }
    }

    fn pod(state: PodState, started: bool) -> Pod {
        Pod {
            id: "p".into(),
            name: "n".into(),
            state,
            infra_container_id: Some("i".into()),
            container_ids: vec![],
            spec: PodSpec::default(),
            created_at: "2026-01-01T00:00:00Z".into(),
            started_at: started.then(|| "2026-01-01T00:00:01Z".into()),
            exit_code: None,
            removing: false,
        }
    }

    fn m(state: RunState) -> PodMember {
        PodMember {
            id: "i".into(),
            name: "n".into(),
            state,
            restart_count: 0,
            init: false,
        }
    }

    #[test]
    fn status_from_the_containers() {
        use RunState::{Created, Exited, Paused, Running};
        let created = pod(PodState::Created, false);
        assert_eq!(pod_status(&created, &[m(Created)]), PodStatus::Created);
        let started = pod(PodState::Running, true);
        assert_eq!(pod_status(&started, &[m(Running)]), PodStatus::Running);
        assert_eq!(
            pod_status(&started, &[m(Running), m(Exited)]),
            PodStatus::Degraded
        );
        assert_eq!(pod_status(&started, &[m(Exited)]), PodStatus::Exited);
        assert_eq!(pod_status(&started, &[m(Paused)]), PodStatus::Paused);
    }

    #[test]
    fn the_filters_read_the_record() {
        let f = |j: &str| Filters::parse(j).unwrap();
        let mut p = pod(PodState::Running, true);
        p.spec.labels.insert("app".into(), "web".into());
        let r = record(&p, vec![m(RunState::Running), m(RunState::Exited)]);
        assert_eq!(r.status, PodStatus::Degraded);
        assert_eq!(r.created_ns, 1_767_225_600_000_000_000);
        assert_eq!(
            networks_of(&p.spec, false),
            [velarx_netdetach::def::DEFAULT_NETWORK]
        );
        assert!(networks_of(&p.spec, true).is_empty());
        let mut bare = p.spec.clone();
        bare.no_infra = true;
        assert!(networks_of(&bare, false).is_empty());
        assert_eq!(r.networks, networks(&p.spec));
        for (filter, matches) in [
            (r#"{"status":["degraded"]}"#, true),
            (r#"{"status":["running"]}"#, false),
            (r#"{"label":["app=web"]}"#, true),
            (r#"{"label!":["app"]}"#, false),
            (r#"{"ctr-status":["stopped"]}"#, true),
            (r#"{"ctr-number":["2"]}"#, true),
            (r#"{"until":["2025-12-31T00:00:00Z"]}"#, false),
        ] {
            assert_eq!(filter_match(&f(filter), &r), matches, "{filter}");
        }
    }
}
