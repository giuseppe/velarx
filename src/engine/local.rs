// SPDX-License-Identifier: Apache-2.0
//! The engine of a command, in the process of the command: the services of
//! the API built for it, which the engine service of the command serves to
//! the client the command asks it through (`process`).

use super::{follow_containers, runtime, Follower};
use crate::api::AppState;
use crate::client::EngineClient;
use crate::daemon::{build_services, Role};
use std::path::Path;
use std::sync::Arc;
use velarx_config::Config;

/// The engine of a command.
pub struct Local {
    rt: tokio::runtime::Runtime,
    state: Arc<AppState>,
    /// Until the command is done
    follower: std::sync::Mutex<Option<Follower>>,
}

impl Local {
    /// The services of `config` (read from `config_path`) for a command,
    /// as `role` says.
    pub fn start(config: Arc<Config>, config_path: &Path, role: &Role) -> anyhow::Result<Self> {
        let rt = runtime()?;
        let state = rt.block_on(build_services(config, config_path, role))?;
        // The lazy pulls whose completer is gone (a kill, a crash, a
        // reboot) go on: any command of the store resumes them, as the
        // daemon does at its start (one readdir and a lock per pull).
        state.image_service.resume_pulls();
        let follower = std::sync::Mutex::new(Some(follow_containers(&rt, &state)));
        Ok(Self {
            rt,
            state,
            follower,
        })
    }

    /// The engine service over the services of this engine, served from a
    /// thread of this process to this process only (a socket pair for each
    /// connection: no name in the file system or in the abstract namespace,
    /// which any process of the network namespace could connect to, a
    /// container of the host network included; nothing left by a command
    /// that is killed): the client of the service sees what a client of the
    /// engine service of the user sees.
    pub fn serve(&self) -> std::io::Result<(crate::engine_service::Server, EngineClient)> {
        let _guard = self.rt.enter();
        let engine =
            crate::engine_service::Engine::new(self.state.clone(), Default::default()).in_process();
        let (server, hand) = crate::engine_service::spawn_in_process(engine)?;
        Ok((server, EngineClient::in_process(hand)))
    }

    /// The builds of this engine end as builds asked to stop do, as those of
    /// the engine service at its end: their RUN containers are the builds'
    /// own, and nothing would end them after this process.
    pub fn stop_builds(&self) {
        let limit = std::time::Duration::from_secs(self.state.config.server.shutdown_timeout_secs);
        let left = self.rt.block_on(self.state.build_service.stop_all(limit));
        if left > 0 {
            tracing::warn!(
                "{left} builds did not stop in {}s: `system prune --build` removes their containers",
                limit.as_secs()
            );
        }
    }

    /// Wait until no connection holds the service [`Local::serve`] made (the
    /// work the calls still do after their replies, such as the release of
    /// a lease, is done before the command ends).
    pub fn drain(&self, activity: &velarx_content::activation::Activity) {
        self.rt.block_on(async {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(30), activity.wait_idle())
                .await;
        });
    }

    /// The end of the command: the cleanups under way are waited for and
    /// what this process did is in the events.  The containers it started
    /// are their monitors' (they record what happens to them).
    pub fn finish(&self) {
        self.rt.block_on(self.state.container_service.settle());
        let follower = self
            .follower
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(f) = follower {
            f.finish(&self.rt);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::EngineClient;
    use velarx_db::RecordState;

    /// An engine of a store of its own (in /var/tmp: /tmp is a small
    /// tmpfs).
    fn engine(dir: &Path) -> Local {
        engine_with(dir, "file")
    }

    /// [`engine`], its events kept by `events_logger`.
    fn engine_with(dir: &Path, events_logger: &str) -> Local {
        let mut config = Config::default();
        config.server.events_logger = events_logger.into();
        config.server.socket = dir.join("api.sock");
        config.server.state_dir = dir.join("state");
        config.server.root_dir = dir.join("root");
        config.storage.root = dir.join("storage");
        let role = Role::Engine {
            notify_socket: None,
            listen_fds: Vec::new(),
            preserve_holes: Vec::new(),
            split_cgroup: None,
            in_process: None,
            systemd_cgroups: velarx_core::services::SystemdCgroups::known(false),
        };
        Local::start(Arc::new(config), &dir.join("config.toml"), &role).unwrap()
    }

    /// The engine service of the same services, served on a socket of
    /// `dir`: what a client of the service sees.
    fn server(local: &Local) -> EngineClient {
        let (server, client) = local.serve().unwrap();
        std::mem::forget(server);
        client
    }

    fn scratch() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("velarx-local-")
            .tempdir_in("/var/tmp")
            .unwrap()
    }

    /// A follow of the service of a command reads the events kept, where
    /// every engine of the store writes: it sees those of another engine,
    /// which the memory of this one does not have.
    #[test]
    fn a_follow_of_a_command_sees_the_events_of_another_engine() {
        use crate::api::podman::events::Event;
        use velarx_proto::workload::{Event as Record, EventKind};
        use velarx_wire::events::log::EventLog;
        type Follow<'a> = Box<dyn FnOnce(&mut dyn FnMut(Record) -> bool) + Send + 'a>;
        let dir = scratch();
        let local = engine(dir.path());
        let server = server(&local);
        let other = EventLog::from_config("file", "", 0, &dir.path().join("root"));
        let follows: [Follow; 1] = [Box::new(move |each| {
            server.follow_events(&[], None, None, each).unwrap()
        })];
        for follow in follows {
            std::thread::scope(|s| {
                let (seen, saw) = std::sync::mpsc::channel();
                s.spawn(move || {
                    follow(&mut |event| {
                        let ours = event.name == "other-engine";
                        if ours {
                            let _ = seen.send(event);
                        }
                        !ours
                    })
                });
                // (written until the follow is taken: it shows what is kept
                // after)
                let event = loop {
                    other
                        .write(&Event::new(
                            EventKind::Container,
                            "create",
                            "abc",
                            "other-engine",
                        ))
                        .unwrap();
                    if let Ok(event) = saw.recv_timeout(std::time::Duration::from_millis(100)) {
                        break event;
                    }
                };
                assert_eq!(event.action, "create");
            });
        }
    }

    /// A daemon, which every command goes through, follows the events of
    /// its memory: not what another engine writes where they are kept.
    #[test]
    fn a_follow_of_a_daemon_is_its_memory() {
        use crate::api::podman::events::Event;
        use velarx_proto::workload::EventKind;
        use velarx_wire::events::log::EventLog;
        let dir = scratch();
        let local = engine(dir.path());
        let socket = dir.path().join("daemon.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        {
            let _guard = local.rt.enter();
            let engine =
                crate::engine_service::Engine::new(local.state.clone(), Default::default());
            std::mem::forget(crate::engine_service::spawn(engine, listener, None).unwrap());
        }
        let client = EngineClient::new(&socket).unwrap();
        let other = EventLog::from_config("file", "", 0, &dir.path().join("root"));
        let (seen, saw) = std::sync::mpsc::channel();
        let follower = std::thread::spawn(move || {
            client
                .follow_events(&[], None, None, &mut |event| {
                    let ours = event.name == "this-engine";
                    let _ = seen.send(event.name);
                    !ours
                })
                .unwrap();
        });
        // (told until the follow is taken: it shows what is told after)
        let mut names = Vec::new();
        for _ in 0..100 {
            other
                .write(&Event::new(
                    EventKind::Container,
                    "create",
                    "abc",
                    "other-engine",
                ))
                .unwrap();
            local.state.podman.events.emit_live(Event::new(
                EventKind::Container,
                "create",
                "def",
                "this-engine",
            ));
            names.extend(saw.try_iter());
            if names.iter().any(|n| n == "this-engine") {
                break;
            }
            names.extend(saw.recv_timeout(std::time::Duration::from_millis(100)));
        }
        assert!(names.iter().any(|n| n == "this-engine"), "{names:?}");
        assert!(!names.iter().any(|n| n == "other-engine"), "{names:?}");
        follower.join().unwrap();
    }

    /// An engine served from the process of one command reads no events
    /// when none are kept: they would go with the command.
    #[test]
    fn the_service_of_a_command_reads_no_events_without_a_backend() {
        let dir = scratch();
        let local = engine_with(dir.path(), "none");
        let server = server(&local);
        for stream in [false, true] {
            let err = if stream {
                server.follow_events(&[], None, None, &mut |_| true)
            } else {
                server.events(&[], None, None).map(|_| ())
            }
            .unwrap_err();
            assert_eq!(
                err.to_string(),
                "cannot read events with the \"none\" backend"
            );
        }
    }

    /// A container record of `config` in the store of `local` (and the
    /// image it names).
    fn container_of(local: &Local, id: &str, state: RecordState, config: String) {
        let db = &local.state.db;
        local.rt.block_on(async {
            if db.get_image("i").await.is_err() {
                db.insert_image(&velarx_db::ImageRecord {
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
            db.insert_container(&velarx_db::ContainerRecord {
                id: id.into(),
                name: Some(id.into()),
                image_id: "i".into(),
                config,
                state,
                created_at: "2026-01-01T00:00:00Z".into(),
                started_at: Some("2026-01-01T00:00:01Z".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        });
    }

    fn valid_config(id: &str) -> String {
        serde_json::to_string(&velarx_runtime::container::ContainerConfig {
            id: id.into(),
            ..Default::default()
        })
        .unwrap()
    }

    /// The exit of an `--rm` container was recorded and the process that
    /// removes it was killed: the next engine of the store (any command)
    /// finishes the removal when it starts, and leaves alone what is not due:
    /// a container others depend on stays, and is not looked at again.
    #[test]
    fn a_removal_that_was_interrupted_is_finished_by_the_next_engine() {
        let dir = scratch();
        let local = engine(dir.path());
        for id in ["gone", "kept", "plain"] {
            container_of(&local, id, RecordState::Running, valid_config(id));
        }
        let db = &local.state.db;
        local.rt.block_on(async {
            for (id, removal) in [("gone", true), ("kept", true), ("plain", false)] {
                db.record_container_exit_announcing(id, "t".into(), 3, None, removal, Box::new(|| {}))
                    .await
                    .unwrap();
            }
            // (`dependent` has to be there as the container of `kept`)
            db.conn()
                .call(|c| {
                    c.execute_batch(
                        "INSERT INTO containers (id, name, image_id, config, created_at, state)
                           VALUES ('dependent','dependent','i','{}','now','created');
                         INSERT INTO container_deps (container_id, target) VALUES ('dependent','kept');",
                    )?;
                    Ok(())
                })
                .await
                .unwrap();
            let mut pending = db.removals_pending().await.unwrap();
            pending.sort();
            assert_eq!(pending, ["gone", "kept"]);
        });
        let svc = local.state.container_service.clone();
        local.rt.block_on(async {
            svc.finish_removals().await.unwrap();
            assert!(matches!(
                svc.inspect("gone").await,
                Err(velarx_core::services::ContainerError::Database(
                    velarx_types::DbError::NotFound(_)
                ))
            ));
            assert_eq!(
                svc.inspect("kept").await.unwrap().state,
                RecordState::Stopped
            );
            svc.inspect("plain").await.unwrap();
            // (nothing is due any more: the next engine does not try again)
            assert!(db.removals_pending().await.unwrap().is_empty());
        });
    }

    /// The files of the containers whose rows a crash of the machine lost
    /// (the volatile rows of the `--rm` ones) are removed by the first
    /// engine of the next boot, and only by it: those of a container with a
    /// row stay, as do the other things of the root directory; the anonymous
    /// volume its create made goes with them, one that `rm` kept and a named
    /// one stay; the engines of the same boot leave what they find alone.
    #[test]
    fn the_first_engine_of_a_boot_removes_what_no_row_names() {
        let dir = scratch();
        let first = engine(dir.path());
        let root = dir.path().join("root");
        let ids: Vec<String> = (b'a'..=b'd')
            .map(|c| (c as char).to_string().repeat(64))
            .collect();
        let (lost, kept) = (&ids[0], &ids[1]);
        let leave = |id: &str| {
            for (sub, name) in [
                ("bundles", "config.json"),
                ("bundles", "overlay/upper/data"),
                ("logs", "container.log"),
                ("secrets", "s"),
            ] {
                let file = root.join(sub).join(id).join(name);
                std::fs::create_dir_all(file.parent().unwrap()).unwrap();
                std::fs::write(file, b"x").unwrap();
            }
            let record = root
                .join("podman-api/containers")
                .join(format!("{id}.json"));
            std::fs::create_dir_all(record.parent().unwrap()).unwrap();
            std::fs::write(record, b"{}").unwrap();
        };
        let has = |id: &str| {
            ["bundles", "logs", "secrets"]
                .iter()
                .any(|d| root.join(d).join(id).exists())
                || root
                    .join("podman-api/containers")
                    .join(format!("{id}.json"))
                    .exists()
        };
        leave(lost);
        leave(kept);
        container_of(&first, kept, RecordState::Created, valid_config(kept));
        // (not made by the engine: not an id of a container, left alone)
        std::fs::create_dir_all(root.join("bundles/not-an-id")).unwrap();
        let volumes = first.state.volume_service.clone();
        let (anonymous, kept_by_rm, named) = first.rt.block_on(async {
            let anonymous = volumes
                .create_with(velarx_core::services::CreateVolume {
                    anonymous: true,
                    container: Some(lost.clone()),
                    ..Default::default()
                })
                .await
                .unwrap();
            // (made for a container that `rm` without `-v` removed: no file of
            // it is left, the volume stays as podman's)
            let kept_by_rm = volumes
                .create_with(velarx_core::services::CreateVolume {
                    anonymous: true,
                    container: Some(ids[2].clone()),
                    ..Default::default()
                })
                .await
                .unwrap();
            let named = volumes
                .create_with(velarx_core::services::CreateVolume {
                    name: Some("data".into()),
                    ..Default::default()
                })
                .await
                .unwrap();
            (anonymous, kept_by_rm, named)
        });
        // (the same boot: another engine of the store leaves it all)
        let same = engine(dir.path());
        assert!(has(lost) && has(kept), "an engine of the same boot swept");
        assert!(anonymous.mountpoint.exists());
        drop(same);
        // (a reboot empties the state directory, the marker with it)
        drop(first);
        std::fs::remove_dir_all(dir.path().join("state")).unwrap();
        let next = engine(dir.path());
        assert!(!has(lost), "the files of a lost row stay");
        assert!(has(kept), "the files of a container with a row went");
        assert!(root.join("bundles/not-an-id").exists());
        assert!(!anonymous.mountpoint.exists(), "the anonymous volume stays");
        assert!(kept_by_rm.mountpoint.exists(), "a volume `rm` kept went");
        assert!(named.mountpoint.exists(), "a named volume went");
        next.rt.block_on(async {
            assert!(next
                .state
                .volume_service
                .get(&anonymous.name)
                .await
                .is_err());
            next.state.container_service.inspect(kept).await.unwrap();
        });
    }

    /// The engine service sweeps too when it starts (what a process killed
    /// while it made a container left, with no reboot), and what it removes
    /// is told once: the next sweep finds nothing.
    #[test]
    fn a_sweep_finds_nothing_the_second_time() {
        let dir = scratch();
        let local = engine(dir.path());
        let id = "e".repeat(64);
        let bundle = dir.path().join("root/bundles").join(&id);
        std::fs::create_dir_all(bundle.join("overlay/upper")).unwrap();
        let svc = local.state.container_service.clone();
        local.rt.block_on(async {
            assert_eq!(svc.sweep_unowned().await.unwrap(), 1);
            assert_eq!(svc.sweep_unowned().await.unwrap(), 0);
        });
        assert!(!bundle.exists());
    }

    /// A command that ends once it sees the exit of a container in the
    /// database (a wait) has the died event of the exit first, whichever of
    /// its tasks records it (one that follows a container whose monitor is
    /// gone: the process records the exit as its monitor would have): the
    /// recording is a cleanup the end of the command waits for.
    #[test]
    fn the_end_of_a_command_waits_for_the_exit_it_records() {
        use std::task::Poll;
        let dir = scratch();
        let local = engine(dir.path());
        // (a running container with no monitor: its exit is recorded unseen)
        container_of(&local, "c1", RecordState::Running, valid_config("c1"));
        let svc = local.state.container_service.clone();
        let waited = local.rt.block_on(async {
            let recording = svc.observe_unobserved();
            let mut recording = std::pin::pin!(recording);
            // The recording a step at a time: the end of the command is
            // held while it is under way.
            let mut waited = false;
            loop {
                if let Poll::Ready(r) = futures::poll!(recording.as_mut()) {
                    r.unwrap();
                    break;
                }
                waited |= futures::poll!(std::pin::pin!(svc.settle())).is_pending();
                tokio::task::yield_now().await;
            }
            waited
        });
        assert!(
            waited,
            "the end of the command did not wait for the recording"
        );
        local.finish();
        let died = server(&local)
            .events(&["event=died".into()], None, None)
            .unwrap();
        assert_eq!(died.len(), 1, "{died:?}");
    }

    /// A record whose configuration does not parse: the listing of the
    /// others is not refused for it, and it can be removed.
    #[test]
    fn a_record_whose_configuration_is_not_valid_can_be_removed() {
        let dir = scratch();
        let local = engine(dir.path());
        container_of(&local, "good", RecordState::Running, valid_config("good"));
        container_of(&local, "bad", RecordState::Running, "{not json".into());
        container_of(
            &local,
            "badstopped",
            RecordState::Stopped,
            "{not json".into(),
        );
        let svc = local.state.container_service.clone();
        local.rt.block_on(async {
            let mut listed: Vec<_> = svc
                .list(true)
                .await
                .unwrap()
                .into_iter()
                .map(|c| c.id)
                .collect();
            listed.sort();
            assert_eq!(listed, ["bad", "badstopped", "good"]);
            svc.delete("badstopped", true).await.unwrap();
            assert!(matches!(
                svc.inspect("badstopped").await,
                Err(velarx_core::services::ContainerError::Database(
                    velarx_types::DbError::NotFound(_)
                ))
            ));
        });
    }
}
