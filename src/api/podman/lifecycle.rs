// SPDX-License-Identifier: Apache-2.0
//! Starting, stopping and waiting for containers through the services.
//!
//! A start goes through the monitor of the container, which looks after the
//! container from then on (its log, its restart policy, the record of its
//! exit); the clients that want its output attach to the monitor.

use super::convert::record_time_ns;
use super::error::{ApiError, ApiResult};
use crate::api::AppState;
use std::sync::Arc;
use velarx_core::services::StartCheck;
use velarx_db::{ContainerRecord, RecordState};
use velarx_proto::workload as typed;
use velarx_runtime::container::{ContainerConfig, ContainerStatus as RuntimeStatus};
use velarx_wire::monitor::logsel::Snapshot;
use velarx_wire::monitor::proto::RunState;

/// The state of a container as the clients see it.
#[derive(Debug, Clone, PartialEq)]
pub struct Status {
    pub state: typed::RunState,
    pub pid: i32,
    pub exit_code: i32,
    pub started_ns: i64,
    pub finished_ns: i64,
}

impl Status {
    pub fn alive(&self) -> bool {
        matches!(
            self.state,
            typed::RunState::Running | typed::RunState::Paused | typed::RunState::Stopping
        )
    }
}

/// The configuration stored with a container; one that does not parse is an
/// error (a default one would hide the options the container was made with).
pub fn config_of(rec: &ContainerRecord) -> ApiResult<ContainerConfig> {
    serde_json::from_str(&rec.config).map_err(|e| {
        ApiError::internal(format!(
            "the configuration of container {} is not valid: {e}",
            rec.id
        ))
    })
}

/// A container by name, id or id prefix.
pub async fn resolve(state: &AppState, name: &str) -> ApiResult<ContainerRecord> {
    Ok(resolve_observed(state, name).await?.0)
}

/// A container as [`resolve`] gives it, with the state of the runtime that
/// finding it asked for, to give to [`status_from`].
pub async fn resolve_observed(
    state: &AppState,
    name: &str,
) -> ApiResult<(ContainerRecord, Option<RuntimeStatus>)> {
    let name = name.strip_prefix('/').unwrap_or(name);
    if let Ok(found) = state.container_service.inspect_observed(name).await {
        return Ok(found);
    }
    let missing = || {
        ApiError::not_found(format!(
            "no container with name or ID \"{name}\" found: no such container"
        ))
    };
    if name.is_empty() {
        return Err(missing());
    }
    let all = state.db.list_containers(true).await?;
    let mut hits = all.iter().filter(|c| c.id.starts_with(name));
    match (hits.next(), hits.next()) {
        (Some(c), None) => Ok(state.container_service.inspect_observed(&c.id).await?),
        (Some(_), Some(_)) => Err(ApiError::internal(format!(
            "more than one result for container {name}"
        ))),
        _ => Err(missing()),
    }
}

/// The monitor of the container holds it between two runs of its restart
/// policy (it waits to start it again, or started it again and the record
/// does not say so yet).
async fn monitor_holds(state: &AppState, id: &str) -> bool {
    state
        .container_service
        .monitor_status(id)
        .await
        .is_some_and(|s| {
            s.restarting.is_some() || (s.state == RunState::Running && s.exit.is_none())
        })
}

/// The monitor runs the container (its restart policy started it again)
/// while the record says it stopped.
async fn monitor_runs(state: &AppState, id: &str) -> bool {
    state
        .container_service
        .monitor_status(id)
        .await
        .is_some_and(|s| s.restarting.is_none() && s.state == RunState::Running && s.exit.is_none())
}

pub async fn status(state: &AppState, rec: &ContainerRecord) -> Status {
    // (a record whose runtime cannot be told has no state of the runtime,
    // like one the runtime fails to answer for)
    let asked = match rec.state {
        RecordState::Running | RecordState::Paused => {
            match state.container_service.runtime_for_record(rec) {
                Ok(runtime) => runtime.state(&rec.id).await.ok(),
                Err(_) => None,
            }
        }
        _ => None,
    };
    status_from(state, rec, asked).await
}

/// The status of a container given the state its OCI runtime has for it
/// (none: the runtime was not asked, could not tell, or has no such
/// container).
pub async fn status_from(
    state: &AppState,
    rec: &ContainerRecord,
    asked: Option<RuntimeStatus>,
) -> Status {
    let started = rec.started_at.as_deref().map_or(0, record_time_ns);
    let finished = rec.finished_at.as_deref().map_or(0, record_time_ns);
    let exited = |code: i32| Status {
        state: typed::RunState::Exited,
        pid: 0,
        exit_code: code,
        started_ns: started,
        finished_ns: finished,
    };
    match rec.state {
        RecordState::Running | RecordState::Paused => {
            match asked {
                Some(s) if s.state == velarx_runtime::container::ContainerState::Running => {
                    Status {
                        state: if state.container_service.is_stopping(&rec.id).await {
                            typed::RunState::Stopping
                        } else {
                            typed::RunState::Running
                        },
                        pid: s.pid.unwrap_or(0),
                        exit_code: 0,
                        started_ns: started,
                        finished_ns: 0,
                    }
                }
                Some(s) if s.state == velarx_runtime::container::ContainerState::Paused => Status {
                    state: typed::RunState::Paused,
                    pid: s.pid.unwrap_or(0),
                    exit_code: 0,
                    started_ns: started,
                    finished_ns: 0,
                },
                // (the runtime has no process: the monitor saw the exit before
                // the record says so, which may still have the code of the
                // previous run)
                // (a container its restart policy is restarting is between two
                // runs: its monitor holds it, and records the exit when it
                // gives up; a monitor that is gone holds nothing)
                _ if rec.state == RecordState::Running && monitor_holds(state, &rec.id).await => {
                    Status {
                        state: typed::RunState::Running,
                        pid: 0,
                        exit_code: 0,
                        started_ns: started,
                        finished_ns: 0,
                    }
                }
                _ => {
                    // (`rec` was read before the monitor
                    // recorded the exit, and the monitor ended since: the
                    // code it recorded; or before an `--rm` removal that took
                    // the run with it: the code the run recorded, not 0)
                    let gone = || async {
                        match state.db.get_container(&rec.id).await {
                            Err(_) => state.podman.exit_of(&rec.id),
                            Ok(now) => now.exit_code.filter(|_| now.state == RecordState::Stopped),
                        }
                    };
                    let code = match state.container_service.monitor_status(&rec.id).await {
                        Some(s) if s.exit.is_some() => s.exit.map(|e| e.code),
                        _ => gone().await,
                    };
                    exited(code.or(rec.exit_code).unwrap_or(0))
                }
            }
        }
        RecordState::Stopped | RecordState::Exited => exited(rec.exit_code.unwrap_or(0)),
        // created in the runtime by `init`, not started
        RecordState::Initialized => Status {
            state: typed::RunState::Initialized,
            pid: rec.pid.unwrap_or(0),
            exit_code: 0,
            started_ns: 0,
            finished_ns: 0,
        },
        _ => Status {
            state: typed::RunState::Created,
            pid: 0,
            exit_code: 0,
            started_ns: 0,
            finished_ns: 0,
        },
    }
}

#[derive(Debug, PartialEq)]
pub enum Started {
    Started,
    AlreadyRunning,
}

pub async fn start(
    state: &Arc<AppState>,
    rec: &ContainerRecord,
    check: &StartCheck,
) -> ApiResult<Started> {
    if status(state, rec).await.alive() || monitor_runs(state, &rec.id).await {
        check.refuse_running(
            rec.name.as_deref().unwrap_or(&rec.id),
            "it runs, on the file systems its monitor mounted when it started",
        )?;
        return Ok(Started::AlreadyRunning);
    }
    // A client that attached before the start (a Docker client attaches,
    // then starts) gets the output from the first byte: the monitor waits
    // for it to attach.
    let attach = state.podman.has_attach_waiter(&rec.id);
    match state
        .container_service
        .start_as(&rec.id, attach, check)
        .await
    {
        // its monitor started it again in the meantime
        Err(velarx_core::services::ContainerError::AlreadyRunning(_)) => {
            Ok(Started::AlreadyRunning)
        }
        Err(e) => {
            state.podman.cancel_attach_waiters(&rec.id);
            Err(e.into())
        }
        // the container service tells of the start (events)
        Ok(_) => {
            state.podman.ready_attach_waiters(&rec.id);
            Ok(Started::Started)
        }
    }
}

/// The log of a container, its rotated files (decompressed as they are
/// read) first, as it is now: read it with `logs::select_lines`.  Empty
/// when it cannot be read.  `allow` is the directory of the allowlist of
/// log paths the file is below (`--log-opt path`): the file is opened
/// beneath it.
pub async fn read_log(loc: &velarx_wire::wire::LogLocation) -> Snapshot {
    let path = loc.path.clone();
    let allow = loc.allow_dir.clone();
    tokio::task::spawn_blocking(move || Snapshot::open(&path, allow.as_deref()))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_else(Snapshot::empty)
}

pub use velarx_core::services::{parse_signal, signal_name};

pub async fn kill(state: &Arc<AppState>, rec: &ContainerRecord, sig: i32) -> ApiResult<()> {
    let st = status(state, rec).await;
    if !st.alive() {
        return Err(ApiError::invalid_state(format!(
            "can only kill running containers. {} is in state {}: container state improper",
            rec.id, st.state
        )));
    }
    state.container_service.kill_container(rec, sig).await?;
    state
        .container_service
        .notify_action_of(&rec.id, "kill", vec![("signal".into(), sig.to_string())])
        .await;
    Ok(())
}

/// Stop: the stop signal, then SIGKILL after `timeout` seconds.  False when
/// the container was not running.
pub async fn stop(
    state: &Arc<AppState>,
    rec: &ContainerRecord,
    timeout: Option<u64>,
    signal: Option<i32>,
) -> ApiResult<bool> {
    let stopped = stop_reporting(state, rec, timeout, signal).await?;
    Ok(stopped != velarx_core::services::Stop::NotRunning)
}

/// [`stop`], saying how it ended.
pub async fn stop_reporting(
    state: &Arc<AppState>,
    rec: &ContainerRecord,
    timeout: Option<u64>,
    signal: Option<i32>,
) -> ApiResult<velarx_core::services::Stop> {
    Ok(state
        .container_service
        .stop_signalled(
            &rec.id,
            timeout.map(|t| t.min(u32::MAX as u64) as u32),
            signal,
        )
        .await?)
}

/// What podman warns of when the stop signal did not stop the container in
/// time (none with a timeout of 0: the kill is what was asked).
pub fn kill_warning(
    rec: &ContainerRecord,
    stopped: &velarx_core::services::Stop,
) -> Option<String> {
    match stopped {
        velarx_core::services::Stop::Killed { signal, seconds } if *seconds > 0 => Some(format!(
            "StopSignal {} failed to stop container {} in {seconds} seconds, resorting to SIGKILL",
            signal_name(*signal),
            rec.name.as_deref().unwrap_or(&rec.id)
        )),
        _ => None,
    }
}

/// Replace the rlimits of the bundle's spec, for the next start; a limit
/// above what this process may give is lowered to it (podman clamps them
/// for a rootless container: `nproc=-1` is the host's limit).
pub async fn update_rlimits(
    state: &AppState,
    id: &str,
    rlimits: &[serde_json::Value],
) -> ApiResult<()> {
    let spec_path = state.container_service.bundle_dir(id).join("config.json");
    let mut spec: serde_json::Value = serde_json::from_slice(&tokio::fs::read(&spec_path).await?)?;
    let defaults = velarx_wire::options::default_rlimits()?;
    // (root of the host may raise them)
    let can_raise = rustix::process::geteuid().is_root() && !velarx_base::ids::in_user_namespace()?;
    let mut list: Vec<serde_json::Value> = Vec::new();
    for r in rlimits {
        let typ = r["type"].as_str().unwrap_or_default();
        let (mut soft, mut hard) = (
            r["soft"].as_u64().unwrap_or(0),
            r["hard"].as_u64().unwrap_or(0),
        );
        if let Some(max) = defaults
            .iter()
            .find(|d| d.typ == typ)
            .map(|d| d.hard)
            .filter(|_| !can_raise)
        {
            hard = hard.min(max);
            soft = soft.min(hard);
        }
        list.push(serde_json::json!({"type": typ, "soft": soft, "hard": hard}));
    }
    // podman's: what it does not set, the defaults
    for d in defaults {
        if !list.iter().any(|r| r["type"] == d.typ.as_str()) {
            list.push(serde_json::json!({"type": d.typ, "soft": d.soft, "hard": d.hard}));
        }
    }
    spec["process"]["rlimits"] = serde_json::Value::Array(list);
    write_spec(&spec_path, spec).await
}

/// Write the spec of a bundle (the keys in the OCI order).
async fn write_spec(path: &std::path::Path, spec: serde_json::Value) -> ApiResult<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || velarx_runtime::container::spec_file::write(&path, &spec))
        .await
        .map_err(std::io::Error::other)??;
    Ok(())
}

/// `env` with the entries of `set` (`NAME=VALUE`, or a bare `NAME`: an
/// empty value) in place of those of the same name or after the others, and
/// without the names of `unset`.
pub fn merge_env(env: &mut Vec<String>, set: &[String], unset: &[String]) {
    let name = |e: &str| {
        e.split_once('=')
            .map_or(e.to_string(), |(n, _)| n.to_string())
    };
    for e in set {
        let entry = if e.contains('=') {
            e.clone()
        } else {
            format!("{e}=")
        };
        match env.iter_mut().find(|x| name(x) == name(&entry)) {
            Some(old) => *old = entry,
            None => env.push(entry),
        }
    }
    env.retain(|e| !unset.iter().any(|u| *u == name(e)));
}

/// Change the environment of the bundle's spec, for the next start.
pub async fn update_env(
    state: &AppState,
    id: &str,
    set: &[String],
    unset: &[String],
) -> ApiResult<()> {
    let spec_path = state.container_service.bundle_dir(id).join("config.json");
    let mut spec: serde_json::Value = serde_json::from_slice(&tokio::fs::read(&spec_path).await?)?;
    let mut env: Vec<String> = spec["process"]["env"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| e.as_str().map(str::to_string))
        .collect();
    merge_env(&mut env, set, unset);
    spec["process"]["env"] = serde_json::json!(env);
    write_spec(&spec_path, spec).await
}

/// The resources of a container changed by `update`: merged into the
/// `linux.resources` of its bundle (a later start uses them), given to the
/// runtime (`crun update --resources`) when it runs with a cgroup.  Device
/// rules are allows that go after the rules there are; a container without
/// a device list (privileged) has every device already.
pub async fn update_resources(
    state: &AppState,
    id: &str,
    patch: &serde_json::Value,
    device_rules: &[serde_json::Value],
    running: bool,
) -> ApiResult<()> {
    let bundle = state.container_service.bundle_dir(id);
    let spec_path = bundle.join("config.json");
    let mut spec: serde_json::Value = serde_json::from_slice(&tokio::fs::read(&spec_path).await?)?;
    if !spec["linux"]["resources"].is_object() {
        spec["linux"]["resources"] = serde_json::json!({});
    }
    let before = spec["linux"]["resources"].clone();
    let res = &mut spec["linux"]["resources"];
    if let Some(p) = patch.as_object() {
        for (k, v) in p {
            match (
                res.get_mut(k).and_then(|r| r.as_object_mut()),
                v.as_object(),
            ) {
                // memory, cpu, pids, blockIO: the fields given replace theirs
                (Some(cur), Some(new)) => {
                    for (fk, fv) in new {
                        cur.insert(fk.clone(), fv.clone());
                    }
                }
                _ => res[k] = v.clone(),
            }
        }
    }
    if !device_rules.is_empty() {
        if let Some(list) = res.get_mut("devices").and_then(|d| d.as_array_mut()) {
            list.extend(device_rules.iter().cloned());
        }
    }
    let resources = res.clone();
    // the runtime first: what it refuses is not kept for the next start.
    // It writes the files of the cgroup one by one: those it wrote before
    // the one it refused get back what the bundle had.
    if running {
        if let Err(e) = runtime_update_resources(state, id, &resources).await {
            if let Err(back) = runtime_update_resources(state, id, &before).await {
                tracing::warn!(
                    "Cannot give container {id} its limits back after a refused update: {}",
                    back.message
                );
            }
            return Err(e);
        }
    }
    write_spec(&spec_path, spec).await
}

/// The resources of a running container, through its monitor (which gives
/// them to the runtime's update).
async fn runtime_update_resources(
    state: &AppState,
    id: &str,
    resources: &serde_json::Value,
) -> ApiResult<()> {
    state
        .container_service
        .update_resources(id, resources)
        .await
        .map_err(|e| match e {
            velarx_core::services::ContainerError::InvalidArgument(why) => {
                runtime_refused_update(why.as_bytes())
            }
            e => e.into(),
        })
}

/// The runtime ran and refused the new resources (the kernel did not take a
/// value): the request is what is wrong, not the engine.  The runtime's
/// words are the message, not the way to tell the refusal.
fn runtime_refused_update(stderr: &[u8]) -> ApiError {
    ApiError::bad_request(format!(
        "update: {}",
        String::from_utf8_lossy(stderr).trim()
    ))
    .with_condition(velarx_proto::engine::Condition::InvalidArgument)
}

#[cfg(test)]
mod update_tests {
    use super::*;

    #[test]
    fn a_refusal_of_the_runtime_is_an_invalid_argument() {
        let e = runtime_refused_update(b"writing file `cpuset.cpus`: Invalid argument\n");
        assert_eq!(e.status.as_u16(), 400);
        assert_eq!(
            e.condition(),
            Some(velarx_proto::engine::Condition::InvalidArgument)
        );
        assert!(e.message.starts_with("update: writing file"));
    }
}

pub async fn remove_now(state: &Arc<AppState>, id: &str) -> Result<(), ApiError> {
    remove_now_with(state, id, false).await
}

/// `volumes`: the anonymous volumes of the container go with it.
pub async fn remove_now_with(
    state: &Arc<AppState>,
    id: &str,
    volumes: bool,
) -> Result<(), ApiError> {
    // A `--rm` container is removed by the daemon as soon as it exits.
    match state
        .container_service
        .delete_with_volumes(id, true, volumes)
        .await
    {
        Ok(())
        | Err(velarx_core::services::ContainerError::Database(velarx_types::DbError::NotFound(
            _,
        ))) => {}
        Err(e) => return Err(e.into()),
    }
    super::record::delete(state, id).await;
    let secrets = super::spec::secrets_dir(state, id);
    let dir = secrets.clone();
    match crate::api::off_thread(move || velarx_base::tree::remove_dir_all(dir)).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!("Cannot remove {}: {e}", secrets.display()),
    }
    match super::secrets::store(state).await {
        Ok(store) => {
            if let Err(e) = store.release(id).await {
                tracing::warn!("Cannot release the secrets of container {id}: {e}");
            }
        }
        Err(e) => tracing::warn!(
            "Cannot open the secret store to release container {id}: {}",
            e.message
        ),
    }
    state.podman.notify_changed();
    Ok(())
}

/// Remove a container; a running one only with `force`, stopped as podman's
/// removal stops it (its stop signal, its stop timeout).
pub async fn remove(
    state: &Arc<AppState>,
    rec: &ContainerRecord,
    force: bool,
    volumes: bool,
) -> ApiResult<()> {
    remove_with_timeout(state, rec, force, volumes, None)
        .await
        .map(|_| ())
}

/// podman's refusal to remove without force the container `id`, alive in
/// `state` (`running`, `paused`, `stopping`).
pub fn not_removed_alive(id: &str, state: typed::RunState) -> String {
    format!(
        "cannot remove container {id} as it is {state} - running or paused containers cannot be removed without force: container state improper"
    )
}

/// The seconds a forced removal gives the container in `state` to stop (none:
/// its own stop timeout).  podman kills a paused one at once: it would not
/// get the stop signal.
fn removal_timeout(state: typed::RunState, timeout: Option<u64>) -> Option<u64> {
    if state == typed::RunState::Paused {
        Some(0)
    } else {
        timeout
    }
}

/// Remove a container; a running one only with `force`, stopped with
/// `timeout` seconds to obey its stop signal (none: its own).  The warning
/// podman gives when the signal did not stop it in time, if so.
pub async fn remove_with_timeout(
    state: &Arc<AppState>,
    rec: &ContainerRecord,
    force: bool,
    volumes: bool,
    timeout: Option<u64>,
) -> ApiResult<Option<String>> {
    let st = status(state, rec).await;
    let mut warning = None;
    if st.alive() {
        if !force {
            return Err(ApiError::invalid_state(not_removed_alive(
                &rec.id, st.state,
            )));
        }
        // (nothing is stopped that stays)
        state
            .container_service
            .ensure_no_dependents(&rec.id)
            .await?;
        let timeout = removal_timeout(st.state, timeout);
        warning = kill_warning(rec, &stop_reporting(state, rec, timeout, None).await?);
    }
    // the container service tells of the removal (events)
    remove_now_with(state, &rec.id, volumes).await?;
    Ok(warning)
}

pub async fn pause(state: &Arc<AppState>, rec: &ContainerRecord) -> ApiResult<()> {
    let _lock = state.container_service.pause_lock(&rec.id).await?;
    pause_locked(state, rec).await?;
    state
        .container_service
        .set_pause_lease(&rec.id, None)
        .await?;
    Ok(())
}

/// Pause the container for a lease that ends at `until` (milliseconds since
/// the epoch): the lease is recorded in the step of the pause, so an unpause
/// of anybody, in any process, ends it.
pub async fn pause_leased(
    state: &Arc<AppState>,
    rec: &ContainerRecord,
    until: i64,
) -> ApiResult<()> {
    let _lock = state.container_service.pause_lock(&rec.id).await?;
    pause_locked(state, rec).await?;
    state
        .container_service
        .set_pause_lease(&rec.id, Some(until))
        .await?;
    Ok(())
}

/// What the end of the lease of a pause did.
#[derive(Debug)]
pub enum LeaseEnd {
    /// The container was resumed.
    Resumed,
    /// The lease was ended or replaced before: nothing to do.
    Gone,
    /// The lease could not be read or ended in the database: it is still
    /// there, for another try.
    Unrecorded(velarx_core::services::ContainerError),
}

/// The lease of the pause of the container ends: unpause it, unless the
/// lease was ended or replaced (`until` is the deadline it was armed for).
pub async fn end_pause_lease(state: &Arc<AppState>, id: &str, until: i64) -> ApiResult<LeaseEnd> {
    let _lock = state.container_service.pause_lock(id).await?;
    match state.container_service.pause_lease(id).await {
        Ok(lease) if lease == Some(until) => {}
        Ok(_) => return Ok(LeaseEnd::Gone),
        Err(e) => return Ok(LeaseEnd::Unrecorded(e)),
    }
    if let Err(e) = state.container_service.set_pause_lease(id, None).await {
        return Ok(LeaseEnd::Unrecorded(e));
    }
    let rec = resolve(state, id).await?;
    unpause_locked(state, &rec).await?;
    Ok(LeaseEnd::Resumed)
}

async fn pause_locked(state: &Arc<AppState>, rec: &ContainerRecord) -> ApiResult<()> {
    let st = status(state, rec).await;
    if st.state != typed::RunState::Running {
        return Err(ApiError::invalid_state(format!(
            "{} is not running, can't pause: container state improper",
            rec.id
        )));
    }
    if let Some(why) = state.container_service.no_freezer_of(&rec.id).await? {
        return Err(ApiError::not_implemented(why));
    }
    state.container_service.freeze(&rec.id, true).await?;
    state.podman.notify_changed();
    state
        .container_service
        .notify_action_of(&rec.id, "pause", Vec::new())
        .await;
    Ok(())
}

pub async fn unpause(state: &Arc<AppState>, rec: &ContainerRecord) -> ApiResult<()> {
    let _lock = state.container_service.pause_lock(&rec.id).await?;
    let unpaused = unpause_locked(state, rec).await;
    state
        .container_service
        .set_pause_lease(&rec.id, None)
        .await?;
    unpaused
}

async fn unpause_locked(state: &Arc<AppState>, rec: &ContainerRecord) -> ApiResult<()> {
    let st = status(state, rec).await;
    if st.state != typed::RunState::Paused {
        return Err(ApiError::invalid_state(format!(
            "{} is not paused, can't unpause: container state improper",
            rec.id
        )));
    }
    state.container_service.freeze(&rec.id, false).await?;
    state.podman.notify_changed();
    state
        .container_service
        .notify_action_of(&rec.id, "unpause", Vec::new())
        .await;
    Ok(())
}

/// Create the container in the runtime without starting it (podman's
/// init): false when it is running or initialized already.
pub async fn init(state: &Arc<AppState>, rec: &ContainerRecord, announce: bool) -> ApiResult<bool> {
    let st = status(state, rec).await;
    if !matches!(st.state, typed::RunState::Created | typed::RunState::Exited) {
        return Ok(false);
    }
    state.container_service.init_with(&rec.id, announce).await?;
    state.podman.notify_changed();
    Ok(true)
}

/// The exit code of a container that is gone.  An auto-remove container is
/// removed by its monitor as it exits: the service that
/// observed the monitor knows the code it ended with.
pub(crate) async fn gone_exit(state: &AppState, id: &str) -> Option<i32> {
    state.podman.exit_of(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_corrupt_configuration_is_an_error() {
        let rec = ContainerRecord {
            id: "c1".into(),
            name: None,
            image_id: String::new(),
            config: "{not json".into(),
            state: RecordState::Created,
            ..Default::default()
        };
        let e = config_of(&rec).unwrap_err();
        assert_eq!(
            e.status,
            crate::api::status::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(e.message.contains("c1"), "{}", e.message);
    }

    /// A forced removal stops with the time it was given, else the
    /// container's own; a paused container is killed at once.
    #[test]
    fn a_forced_removal_gives_the_time_asked_or_the_containers_own() {
        assert_eq!(removal_timeout(typed::RunState::Running, None), None);
        assert_eq!(removal_timeout(typed::RunState::Running, Some(5)), Some(5));
        assert_eq!(removal_timeout(typed::RunState::Running, Some(0)), Some(0));
        assert_eq!(
            removal_timeout(typed::RunState::Running, Some(u64::MAX)),
            Some(u64::MAX)
        );
        assert_eq!(removal_timeout(typed::RunState::Paused, None), Some(0));
        assert_eq!(removal_timeout(typed::RunState::Paused, Some(5)), Some(0));
    }

    /// The warning is podman's, naming the signal and the seconds; none for
    /// a stop that worked or a kill that was asked (0 seconds).
    #[test]
    fn the_kill_of_a_stop_is_warned_of_but_not_the_one_asked_for() {
        use velarx_core::services::Stop;
        let mut rec = ContainerRecord {
            id: "c1".into(),
            name: Some("web".into()),
            image_id: String::new(),
            config: String::new(),
            state: RecordState::Running,
            ..Default::default()
        };
        let killed = Stop::Killed {
            signal: libc::SIGUSR1,
            seconds: 2,
        };
        assert_eq!(
            kill_warning(&rec, &killed).as_deref(),
            Some("StopSignal SIGUSR1 failed to stop container web in 2 seconds, resorting to SIGKILL")
        );
        rec.name = None;
        assert!(kill_warning(&rec, &killed)
            .unwrap()
            .contains("container c1 in"));
        assert_eq!(kill_warning(&rec, &Stop::Stopped), None);
        assert_eq!(kill_warning(&rec, &Stop::NotRunning), None);
        let at_once = Stop::Killed {
            signal: libc::SIGTERM,
            seconds: 0,
        };
        assert_eq!(kill_warning(&rec, &at_once), None);
    }

    /// An update writes the process before the seccomp rules of `linux`
    /// (the init of a krun VM runs the first `args` of the file).
    #[tokio::test]
    async fn an_update_keeps_the_process_first() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("config.json");
        let spec = serde_json::json!({"linux": {"seccomp": {"syscalls": [{"args": [{"index": 0}]}]}},
            "process": {"args": ["true"]}});
        write_spec(&path, spec).await.unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.find("\"args\"").unwrap() < text.find("\"linux\"").unwrap(),
            "{text}"
        );
    }

    #[test]
    fn the_environment_of_an_update() {
        let list = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let mut env = list(&["A=1", "B=2", "PATH=/bin"]);
        merge_env(&mut env, &list(&["B=3", "C=4", "D"]), &list(&["A", "none"]));
        assert_eq!(env, list(&["B=3", "PATH=/bin", "C=4", "D="]));
        // set, then unset: unset wins, as podman's order
        merge_env(&mut env, &list(&["E=5"]), &list(&["E"]));
        assert_eq!(env, list(&["B=3", "PATH=/bin", "C=4", "D="]));
    }

    #[test]
    fn signals() {
        assert_eq!(parse_signal("SIGTERM"), Some(15));
        assert_eq!(parse_signal("kill"), Some(9));
        assert_eq!(parse_signal("10"), Some(10));
        assert_eq!(parse_signal("0"), None);
        assert_eq!(parse_signal("bogus"), None);
        assert_eq!(signal_name(2), "SIGINT");
        assert_eq!(signal_name(40), "40");
    }
}
