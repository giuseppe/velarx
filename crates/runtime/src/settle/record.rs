// SPDX-License-Identifier: Apache-2.0
//! What the store and the events say while a container runs: health results,
//! the kernel's out of memory kills, the restarts of its policy.

use super::{rfc3339, SettlePlan};
use crate::container::ContainerConfig;
use velarx_db::sync::Access;
use velarx_db::{ContainerRecord, RecordState};
use velarx_proto::health::Health;
use velarx_types::{DbError, DbResult};
use velarx_wire::events::{container_event, died_event, log::EventLog};
use velarx_wire::monitor::proto::ExitInfo;

/// The row of the container; none when it is removed.
pub(super) fn row(a: &impl Access, id: &str) -> DbResult<Option<ContainerRecord>> {
    let owned = id.to_string();
    match a.call(move |c| velarx_db::get_container(c, &owned)) {
        Ok(c) => Ok(Some(c)),
        Err(DbError::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The image and labels an event of the container carries.
pub(super) fn event_details(container: &ContainerRecord) -> (String, Vec<(String, String)>) {
    let Ok(cfg) = serde_json::from_str::<ContainerConfig>(&container.config) else {
        return (container.image_id.clone(), Vec::new());
    };
    let image = if cfg.image.is_empty() {
        container.image_id.clone()
    } else {
        cfg.image
    };
    let mut labels: Vec<(String, String)> = cfg.labels.into_iter().collect();
    labels.sort();
    (image, labels)
}

pub(super) fn update_ext(
    a: &impl Access,
    id: &str,
    f: impl FnOnce(&mut velarx_db::ContainerExt) + Send + 'static,
) -> DbResult<()> {
    let owned = id.to_string();
    a.call(move |c| velarx_db::container_ext::update_container_ext(c, &owned, f))
}

/// The event written to `log`; a failure is logged, never fatal.
pub(super) fn write_event(log: &EventLog, event: &velarx_wire::events::Event) {
    if let Err(e) = log.write(event) {
        tracing::debug!(
            "Cannot keep the event {} {}: {e}",
            event.kind.word(),
            event.action
        );
    }
}

/// The died event of an exit, written inside the transaction that records
/// it, and (with `cleanup`: the container ends for good and stays) the
/// `cleanup` that follows it.
pub(super) fn announce_exit(
    log: &EventLog,
    container: &ContainerRecord,
    info: &ExitInfo,
    cleanup: bool,
) -> velarx_db::Announce {
    let (image, labels) = event_details(container);
    let name = container.name.clone().unwrap_or_default();
    let event = died_event(
        &container.id,
        &name,
        &image,
        labels.clone(),
        info.code,
        info.timed_out,
    );
    let cleaned = cleanup.then(|| {
        labels
            .into_iter()
            .fold(
                container_event(&container.id, &name, "cleanup"),
                |e, (k, v)| e.attr(&k, v),
            )
            .image(&image)
    });
    let log = log.clone();
    Box::new(move || {
        write_event(&log, &event);
        if let Some(cleaned) = &cleaned {
            write_event(&log, cleaned);
        }
    })
}

/// A health result: the row's health and a `health_status` event.  Nothing
/// for a container that is gone.
pub fn health(a: &impl Access, plan: &SettlePlan, h: &Health) -> DbResult<()> {
    let Some(container) = row(a, &plan.id)? else {
        return Ok(());
    };
    let json = serde_json::to_string(h).ok();
    update_ext(a, &plan.id, move |e| e.health = json)?;
    write_event(
        &plan.events,
        &container_event(
            &container.id,
            &container.name.clone().unwrap_or_default(),
            "health_status",
        )
        .attr("health_status", h.status.word()),
    );
    Ok(())
}

/// The kernel killed a process of the container for lack of memory.
pub fn oom(a: &impl Access, plan: &SettlePlan) -> DbResult<()> {
    let Some(container) = row(a, &plan.id)? else {
        return Ok(());
    };
    update_ext(a, &plan.id, |e| e.oom_killed = true)?;
    write_event(
        &plan.events,
        &container_event(
            &container.id,
            &container.name.clone().unwrap_or_default(),
            "oom",
        ),
    );
    Ok(())
}

/// The container exited and its restart policy starts it again: it is
/// stopped meanwhile, with its `died` event.
pub fn restarting(
    a: &impl Access,
    plan: &SettlePlan,
    info: &ExitInfo,
    restart_count: u32,
) -> DbResult<()> {
    let Some(container) = row(a, &plan.id)? else {
        return Ok(());
    };
    let (oom, timed_out) = (info.oom, info.timed_out);
    update_ext(a, &plan.id, move |e| {
        e.restart_count = restart_count;
        e.oom_killed |= oom;
        e.timed_out = timed_out;
    })?;
    let announce = announce_exit(&plan.events, &container, info, false);
    let (id, finished, code) = (plan.id.clone(), rfc3339(info.finished_ns), info.code);
    a.call(move |c| velarx_db::record_container_restarting(c, &id, &finished, code, announce))?;
    tracing::info!(
        "Container {} exited with code {}, restart {} by its policy",
        plan.id,
        info.code,
        restart_count
    );
    Ok(())
}

/// The monitor started the container again (the first start is the
/// starter's to write).
pub fn started(
    a: &impl Access,
    plan: &SettlePlan,
    pid: i32,
    started_ns: i64,
    restart_count: u32,
) -> DbResult<()> {
    let Some(container) = row(a, &plan.id)? else {
        return Ok(());
    };
    let (id, at) = (plan.id.clone(), rfc3339(started_ns));
    a.call(move |c| {
        velarx_db::update_container_state(
            c,
            &id,
            RecordState::Running,
            Some(pid),
            Some(at),
            None,
            None,
        )
    })?;
    update_ext(a, &plan.id, move |e| {
        e.restart_count = restart_count;
        e.oom_killed = false;
        e.timed_out = false;
        e.health = None;
    })?;
    tracing::info!("Container {} restarted with PID {}", plan.id, pid);
    // (podman's: `died` when it exited, then these)
    for action in ["restart", "init", "start"] {
        write_event(
            &plan.events,
            &container_event(
                &container.id,
                &container.name.clone().unwrap_or_default(),
                action,
            ),
        );
    }
    Ok(())
}
