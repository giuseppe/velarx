// SPDX-License-Identifier: Apache-2.0
//! The wait of a container for conditions ([`WaitCondition`]): the one
//! implementation behind `ContainerWait`, which the command line (in this
//! process or through the engine) and velarx-api (libpod's and Docker's
//! routes) all call.
//!
//! The wait follows what the engine knows (the notices of the container
//! service, the changes of the state and of the database): it does not
//! poll.  As podman's:
//! * `exited`, `stopped` and `not-running` are met by the end of a run, and
//!   by a container that was made and never started (0, podman #27423);
//! * `next-exit` is met by the next exit, whatever the state is when the
//!   wait starts; the removal of the container ends it too;
//! * `removed` is met once the container is gone: the code of its last exit,
//!   0 if it never ran; `removing` too, with -1 if it never ran;
//! * `healthy` and `unhealthy` need a health check, and fail once the
//!   container stopped;
//! * the other conditions are states, met with -1.

use crate::api::podman::error::{ApiError, ApiResult};
use crate::api::podman::lifecycle::{config_of, gone_exit, resolve, status};
use crate::api::AppState;
use std::sync::Arc;
use tokio::sync::broadcast::error::RecvError;
use velarx_core::services::ContainerNotice;
use velarx_proto::wait::WaitCondition;
use velarx_proto::workload::RunState;

/// What ended a wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Met {
    /// The exit code; -1 for a condition that is no exit
    pub code: i32,
    /// The condition met, one of those asked
    pub condition: WaitCondition,
}

/// The conditions of a wait, sorted by how they are met.
struct Wanted {
    /// Those met by the end of a run (`exited`...), the first of them
    exit: Option<WaitCondition>,
    next_exit: bool,
    removed: bool,
    removing: bool,
    /// The states and the health conditions
    states: Vec<WaitCondition>,
    /// No condition was given: podman's default, which also answers the
    /// recorded exit code of a container that is gone already
    default: bool,
}

impl Wanted {
    fn of(conditions: &[WaitCondition]) -> Self {
        let mut w = Wanted {
            exit: None,
            next_exit: false,
            removed: false,
            removing: false,
            states: Vec::new(),
            default: conditions.is_empty(),
        };
        if conditions.is_empty() {
            w.exit = Some(WaitCondition::Stopped);
        }
        for &c in conditions {
            match c {
                c if c.is_exit() => {
                    w.exit.get_or_insert(c);
                }
                WaitCondition::NextExit => w.next_exit = true,
                WaitCondition::Removed => w.removed = true,
                WaitCondition::Removing => w.removing = true,
                c => w.states.push(c),
            }
        }
        w
    }

    /// Only the end of a run can meet the wait.
    fn exit_only(&self) -> bool {
        self.exit.is_some()
            && !self.next_exit
            && !self.removed
            && !self.removing
            && self.states.is_empty()
    }

    /// What a container that is gone meets: `code` is its recorded exit.
    fn gone(&self, code: Option<i32>) -> Option<Met> {
        let met = |code, condition| Some(Met { code, condition });
        match (self.exit, code) {
            (Some(condition), Some(code)) => met(code, condition),
            _ if self.removed => met(code.unwrap_or(0), WaitCondition::Removed),
            _ if self.next_exit => met(code.unwrap_or(0), WaitCondition::NextExit),
            _ if self.removing => met(code.unwrap_or(-1), WaitCondition::Removing),
            _ => None,
        }
    }
}

/// Check the interval of a wait: 0 is its default, a
/// negative one is refused.  The wait follows events and polls nothing,
/// so it is never slower than any interval.
fn check_interval(interval_ns: i64) -> ApiResult<()> {
    if interval_ns < 0 {
        return Err(ApiError::bad_request(format!(
            "the interval of a wait must not be negative: {interval_ns}ns"
        )));
    }
    Ok(())
}

fn no_such(name: &str) -> ApiError {
    ApiError::not_found(format!(
        "no container with name or ID \"{name}\" found: no such container"
    ))
}

/// Wait until the container `name` meets one of `conditions` (none: its
/// exit).  `armed` is called once the wait follows the container: an exit
/// after it is not missed (a client that starts the container once told
/// does not race the wait).
pub(crate) async fn wait(
    state: &Arc<AppState>,
    name: &str,
    conditions: &[WaitCondition],
    interval_ns: i64,
    armed: impl FnOnce(),
) -> ApiResult<Met> {
    check_interval(interval_ns)?;
    let wanted = Wanted::of(conditions);
    // (every watch exists before the first look: no change is missed)
    let mut notices = state.container_service.subscribe_notices();
    let mut changes = state.podman.subscribe_changes();
    let mut stored = state
        .db
        .watch_changes()
        .map_err(|e| ApiError::internal(format!("cannot watch the containers: {e}")))?;
    let name = name.strip_prefix('/').unwrap_or(name);
    let rec = match resolve(state, name).await {
        Ok(r) => r,
        // the recorded exit code of a container that is gone answers
        // podman's default wait (`run --rm` races its removal)
        Err(e) if wanted.default => {
            return match gone_exit(state, name).await {
                Some(code) => Ok(Met {
                    code,
                    condition: WaitCondition::Stopped,
                }),
                None => Err(e),
            }
        }
        Err(e) => return Err(e),
    };
    // (podman's: a health condition needs a health check)
    let health = wanted
        .states
        .iter()
        .find(|c| matches!(c, WaitCondition::Healthy | WaitCondition::Unhealthy));
    if let Some(c) = health {
        let checked = config_of(&rec)?
            .healthcheck
            .is_some_and(|h| h.command().is_some());
        if !checked {
            return Err(ApiError::internal(format!(
                "cannot use condition {:?}: container {} has no healthcheck",
                c.name(),
                rec.id
            )));
        }
    }
    // the exit before the wait is not the next one, nor the exit of a run
    // that the monitor saw before the wait and records after it (the record
    // says it runs, the runtime has no process: its start time tells it)
    let first = status(state, &rec).await;
    let mut finished_before = first.finished_ns;
    let mut unrecorded =
        (rec.state.is_alive() && first.state == RunState::Exited).then_some(first.started_ns);
    let id = rec.id;
    armed();
    loop {
        let rec = match state.container_service.inspect(&id).await {
            Ok(r) => r,
            Err(_) => {
                let code = gone_exit(state, &id).await;
                return wanted.gone(code).ok_or_else(|| no_such(name));
            }
        };
        let st = status(state, &rec).await;
        if let Some(started) = unrecorded {
            if st.started_ns != started {
                // (a later run)
                unrecorded = None;
            } else if !rec.state.is_alive() {
                // (its exit is recorded now)
                finished_before = finished_before.max(st.finished_ns);
                unrecorded = None;
            }
        }
        if let Some(condition) = wanted.exit {
            if matches!(st.state, RunState::Exited | RunState::Created) {
                return Ok(Met {
                    code: st.exit_code,
                    condition,
                });
            }
        }
        // an exit that this process did not see: another one recorded it
        if wanted.next_exit && st.finished_ns > finished_before {
            return Ok(Met {
                code: rec.exit_code.unwrap_or(st.exit_code),
                condition: WaitCondition::NextExit,
            });
        }
        for &c in &wanted.states {
            let met = match c {
                WaitCondition::Running => st.state == RunState::Running,
                WaitCondition::Paused => st.state == RunState::Paused,
                WaitCondition::Created | WaitCondition::Configured => st.state == RunState::Created,
                WaitCondition::Initialized => st.state == RunState::Initialized,
                WaitCondition::Stopping => st.state == RunState::Stopping,
                WaitCondition::Healthy | WaitCondition::Unhealthy => {
                    let ext = state.db.get_container_ext(&id).await.unwrap_or_default();
                    crate::api::podman::cinfo::health_of(&ext)
                        .is_some_and(|h| h.status.word() == c.name())
                }
                _ => false,
            };
            if met {
                return Ok(Met {
                    code: -1,
                    condition: c,
                });
            }
        }
        // a container that stopped is no longer checked: its health stays
        if health.is_some() && st.state == RunState::Exited {
            return Err(ApiError::internal("container is stopped"));
        }
        // The monitor records the exit in the database, whatever process
        // started the container; this process observes it, to know the code
        // of a container the exit removes (`--rm`).
        if st.alive() {
            state.container_service.follow(&id).await?;
        }
        if st.alive() && wanted.exit_only() {
            match state.container_service.wait(&id).await {
                Ok(code) => {
                    return Ok(Met {
                        code,
                        condition: wanted.exit.unwrap_or(WaitCondition::Stopped),
                    })
                }
                // removed meanwhile (`run --rm`): the exit this process saw
                Err(_) if state.container_service.inspect(&id).await.is_err() => {
                    let code = gone_exit(state, &id).await;
                    return wanted.gone(code).ok_or_else(|| no_such(name));
                }
                Err(e) => return Err(e.into()),
            }
        }
        tokio::select! {
            r = changes.changed() => {
                if r.is_err() {
                    return Err(ApiError::internal("the engine is shutting down"));
                }
            }
            r = stored.changed() => {
                r.map_err(|e| ApiError::internal(format!("cannot watch the containers: {e}")))?;
            }
            n = notices.recv() => match n.map(|n| match n {
                ContainerNotice::Seen(seen) => *seen,
                n => n,
            }) {
                // (an exit its restart policy follows with a start is not
                // recorded; any other is, before its notice: the record
                // tells whether it is the next one)
                Ok(ContainerNotice::Exited {
                    id: exited,
                    code,
                    restarting: true,
                    ..
                }) if wanted.next_exit && exited == id => {
                    return Ok(Met {
                        code,
                        condition: WaitCondition::NextExit,
                    });
                }
                Ok(_) | Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) if wanted.next_exit => {
                    return Err(ApiError::internal(
                        "the events of the containers ended before the container exited",
                    ));
                }
                Err(RecvError::Closed) => {
                    return Err(ApiError::internal("the engine is shutting down"));
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::{build_services, Role};
    use velarx_config::Config;
    use velarx_db::{ContainerRecord, RecordState};
    use WaitCondition as W;

    async fn state_in(dir: &std::path::Path) -> Arc<AppState> {
        let mut config = Config::default();
        config.server.state_dir = dir.join("run");
        config.server.root_dir = dir.join("root");
        config.server.socket = dir.join("run/velarx.sock");
        config.storage.root = dir.join("storage");
        config.storage.gc_interval_secs = 0;
        build_services(Arc::new(config), &dir.join("config.toml"), &Role::Server)
            .await
            .unwrap()
    }

    /// A container record: `exit` is its last exit (code, time).
    async fn record(state: &AppState, id: &str, st: RecordState, exit: Option<(i32, &str)>) {
        let config = serde_json::to_string(&velarx_runtime::container::ContainerConfig {
            id: id.into(),
            ..Default::default()
        })
        .unwrap();
        record_of(state, id, st, exit, &config).await;
    }

    /// A container record of the configuration `config`.
    async fn record_of(
        state: &AppState,
        id: &str,
        st: RecordState,
        exit: Option<(i32, &str)>,
        config: &str,
    ) {
        if state.db.get_image("i").await.is_err() {
            state
                .db
                .insert_image(&velarx_db::ImageRecord {
                    id: "i".into(),
                    manifest_digest: velarx_types::digest::Digest::of(
                        velarx_types::digest::Algorithm::Sha256,
                        b"m",
                    ),
                    config_digest: velarx_types::digest::Digest::of(
                        velarx_types::digest::Algorithm::Sha256,
                        b"c",
                    ),
                    manifest: "{}".into(),
                    config: "{}".into(),
                    created_at: "2026-01-01T00:00:00Z".into(),
                    is_lazy: false,
                })
                .await
                .unwrap();
        }
        state
            .db
            .insert_container(&ContainerRecord {
                id: id.into(),
                name: Some(format!("n-{id}")),
                image_id: "i".into(),
                config: config.into(),
                state: st,
                pid: None,
                created_at: "2026-01-01T00:00:00Z".into(),
                started_at: exit.map(|_| "2026-01-01T00:00:01Z".into()),
                finished_at: exit.map(|(_, at)| at.into()),
                exit_code: exit.map(|(code, _)| code),
            })
            .await
            .unwrap();
    }

    /// The wait of `conditions` started; `then` runs once it is armed.
    async fn wait_then(
        state: &Arc<AppState>,
        name: &str,
        conditions: &[WaitCondition],
        then: impl std::future::Future<Output = ()>,
    ) -> ApiResult<Met> {
        let (armed, is_armed) = tokio::sync::oneshot::channel();
        let waited = wait(state, name, conditions, 0, move || {
            let _ = armed.send(());
        });
        let then = async move {
            if is_armed.await.is_ok() {
                then.await;
            }
            std::future::pending::<()>().await
        };
        tokio::select! {
            met = waited => met,
            () = then => unreachable!(),
        }
    }

    fn met(code: i32, condition: WaitCondition) -> Met {
        Met { code, condition }
    }

    #[test]
    fn conditions_sort() {
        let w = Wanted::of(&[]);
        assert!(w.default && w.exit_only() && w.exit == Some(W::Stopped));
        let w = Wanted::of(&[W::Running, W::NotRunning]);
        assert!(!w.default && !w.exit_only() && w.exit == Some(W::NotRunning));
        assert_eq!(w.states, [W::Running]);
        // gone: the recorded code, else what each condition says of it
        assert_eq!(
            Wanted::of(&[W::Exited]).gone(Some(4)),
            Some(met(4, W::Exited))
        );
        assert_eq!(Wanted::of(&[W::Exited]).gone(None), None);
        assert_eq!(
            Wanted::of(&[W::Removed]).gone(None),
            Some(met(0, W::Removed))
        );
        assert_eq!(
            Wanted::of(&[W::Removed]).gone(Some(3)),
            Some(met(3, W::Removed))
        );
        assert_eq!(
            Wanted::of(&[W::NextExit]).gone(None),
            Some(met(0, W::NextExit))
        );
        assert_eq!(
            Wanted::of(&[W::Removing]).gone(None),
            Some(met(-1, W::Removing))
        );
        assert_eq!(Wanted::of(&[W::Running]).gone(Some(1)), None);
    }

    /// A container that was made and never started is not running: the
    /// conditions of an exit are met at once with 0 (podman #27423); a
    /// state is met with -1.
    #[tokio::test]
    async fn a_created_container_meets_the_exit_conditions() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_in(dir.path()).await;
        record(&state, "c1", RecordState::Created, None).await;
        for (asked, answer) in [
            (vec![], met(0, W::Stopped)),
            (vec![W::Exited], met(0, W::Exited)),
            (vec![W::Stopped], met(0, W::Stopped)),
            (vec![W::NotRunning], met(0, W::NotRunning)),
            (vec![W::Running, W::NotRunning], met(0, W::NotRunning)),
            (vec![W::Created], met(-1, W::Created)),
            (vec![W::Configured], met(-1, W::Configured)),
        ] {
            assert_eq!(
                wait(&state, "n-c1", &asked, 0, || {}).await.unwrap(),
                answer,
                "{asked:?}"
            );
        }
        // an exited one answers its code
        record(
            &state,
            "c2",
            RecordState::Exited,
            Some((3, "2026-01-01T00:00:02Z")),
        )
        .await;
        let m = wait(&state, "c2", &[W::NotRunning], 0, || {})
            .await
            .unwrap();
        assert_eq!(m, met(3, W::NotRunning));
    }

    /// `next-exit` waits for the next exit, not the one before the wait:
    /// one that another process recorded, or the notice of one.
    #[tokio::test]
    async fn next_exit_waits_for_the_next_exit() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_in(dir.path()).await;
        record(
            &state,
            "c1",
            RecordState::Exited,
            Some((3, "2026-01-01T00:00:02Z")),
        )
        .await;
        let s = state.clone();
        let m = wait_then(&state, "c1", &[W::NextExit], async move {
            s.db.update_container_state(
                "c1",
                RecordState::Exited,
                None,
                None,
                Some("2026-01-01T00:00:09Z".into()),
                Some(7),
            )
            .await
            .unwrap();
        })
        .await
        .unwrap();
        assert_eq!(m, met(7, W::NextExit));

        // a created container: its first exit
        record(&state, "c2", RecordState::Created, None).await;
        let s = state.clone();
        let m = wait_then(&state, "c2", &[W::NextExit, W::Exited], async move {
            s.db.update_container_state(
                "c2",
                RecordState::Exited,
                None,
                Some("2026-01-01T00:00:08Z".into()),
                Some("2026-01-01T00:00:09Z".into()),
                Some(5),
            )
            .await
            .unwrap();
        })
        .await;
        // (`exited` is met at once by a container that never ran)
        assert_eq!(m.unwrap(), met(0, W::Exited));
    }

    /// `next-exit` of a container whose exit the monitor saw and has not
    /// recorded yet (the record says it runs, there is no process) is not
    /// met by that exit once recorded (here by this process, which finds no
    /// monitor): the one after it.
    #[tokio::test]
    async fn next_exit_is_not_the_exit_recorded_after_the_wait() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_in(dir.path()).await;
        record(
            &state,
            "c1",
            RecordState::Running,
            Some((0, "2026-01-01T00:00:00Z")),
        )
        .await;
        let s = state.clone();
        let mut notices = state.container_service.subscribe_notices();
        let m = wait_then(&state, "c1", &[W::NextExit], async move {
            // (the exit the monitor saw is noticed first)
            loop {
                match notices.recv().await.unwrap() {
                    ContainerNotice::Exited { id, .. } if id == "c1" => break,
                    _ => {}
                }
            }
            // (a later run)
            s.db.update_container_state(
                "c1",
                RecordState::Exited,
                None,
                Some("2099-01-01T00:00:05Z".into()),
                Some("2099-01-01T00:00:06Z".into()),
                Some(4),
            )
            .await
            .unwrap();
        })
        .await
        .unwrap();
        assert_eq!(m, met(4, W::NextExit));
    }

    /// `removed` waits for the removal: the code of the last exit, 0 for a
    /// container that never ran; the removal ends `next-exit` too.
    #[tokio::test]
    async fn removed_waits_for_the_removal() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_in(dir.path()).await;
        for (id, exit, asked, answer) in [
            ("c1", None, W::Removed, met(0, W::Removed)),
            (
                "c2",
                Some((9, "2026-01-01T00:00:02Z")),
                W::Removed,
                met(9, W::Removed),
            ),
            ("c3", None, W::NextExit, met(0, W::NextExit)),
            ("c4", None, W::Removing, met(-1, W::Removing)),
        ] {
            record(
                &state,
                id,
                if exit.is_some() {
                    RecordState::Exited
                } else {
                    RecordState::Created
                },
                exit,
            )
            .await;
            let s = state.clone();
            let m = wait_then(&state, id, &[asked], async move {
                if let Some((code, _)) = exit {
                    // (the exit the engine kept for the containers that are gone)
                    s.podman.record_exit(id, code);
                }
                s.db.delete_container(id).await.unwrap();
            })
            .await
            .unwrap();
            assert_eq!(m, answer, "{id}");
        }
    }

    /// `healthy` and `unhealthy` need a health check, as podman's, and
    /// fail once the container stopped.
    #[tokio::test]
    async fn health_conditions_need_a_check_and_a_running_container() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_in(dir.path()).await;
        record(&state, "c1", RecordState::Created, None).await;
        for asked in [W::Healthy, W::Unhealthy] {
            let e = wait(&state, "c1", &[asked], 0, || {}).await.unwrap_err();
            assert_eq!(e.status.as_u16(), 500);
            assert_eq!(
                e.message,
                format!(
                    "cannot use condition {:?}: container c1 has no healthcheck",
                    asked.name()
                )
            );
        }
        let checked = velarx_runtime::container::ContainerConfig {
            healthcheck: Some(velarx_proto::health::Healthcheck {
                test: vec!["CMD".into(), "true".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let checked = serde_json::to_string(&checked).unwrap();
        let exit = Some((1, "2026-01-01T00:00:02Z"));
        record_of(&state, "c2", RecordState::Exited, exit, &checked).await;
        let e = wait(&state, "c2", &[W::Healthy], 0, || {})
            .await
            .unwrap_err();
        assert_eq!(
            (e.status.as_u16(), e.message.as_str()),
            (500, "container is stopped")
        );
        // an exit condition beside it is met first
        let m = wait(&state, "c2", &[W::Healthy, W::Exited], 0, || {})
            .await
            .unwrap();
        assert_eq!(m, met(1, W::Exited));
    }

    /// What is refused: a negative interval, a container that is not there
    /// (but podman's default wait answers the code kept of one that is
    /// gone), a state of a container that goes away meanwhile.
    #[tokio::test]
    async fn the_errors_of_a_wait() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_in(dir.path()).await;
        record(&state, "c1", RecordState::Created, None).await;
        let e = wait(&state, "c1", &[], -1, || {}).await.unwrap_err();
        assert!(e.message.contains("negative"), "{}", e.message);
        assert_eq!(e.status.as_u16(), 400);
        for asked in [vec![], vec![W::Removed], vec![W::NextExit]] {
            let e = wait(&state, "nosuch", &asked, 0, || {}).await.unwrap_err();
            assert_eq!(e.status.as_u16(), 404, "{asked:?}");
        }
        state.podman.record_exit("gone0123", 12);
        let m = wait(&state, "gone0123", &[], 0, || {}).await.unwrap();
        assert_eq!(m, met(12, W::Stopped));
        let e = wait(&state, "gone0123", &[W::NotRunning], 0, || {})
            .await
            .unwrap_err();
        assert_eq!(e.status.as_u16(), 404);
        let s = state.clone();
        let e = wait_then(&state, "c1", &[W::Running], async move {
            s.db.delete_container("c1").await.unwrap();
        })
        .await
        .unwrap_err();
        assert_eq!(e.status.as_u16(), 404);
    }
}
