// SPDX-License-Identifier: Apache-2.0
//! The REST frontend against an engine that is only an interface: a mock of
//! `org.velarx.Engine` with canned answers, served on a unix socket.  What
//! is tried is the frontend's: the routes, the decoding of the query into the
//! typed arguments of the call, documents inline and in a pipe, the errors as
//! podman's, and an engine that is absent or of another version.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use velarx_api::engine::Engine;
use velarx_api::serve::router;
use velarx_proto::buildspec::{
    BuildClient, BuildContextKind, BuildContextSpec, BuildEntitlement, BuildEvent, BuildEventKind,
    BuildFlags, BuildOutput, BuildOutputKind, BuildPair, BuildPull, BuildSecretKind,
    BuildSecretSpec, BuildSpec, BuildStream, SbomFlags,
};
use velarx_proto::engine::EngineProxy;
use velarx_proto::engine::{
    Ack, Changed, EngineError, Filter, Id, InfoReply, InstanceSpec, LogOptions, LoginReply,
    ManifestArtifactSpec, NetworkRemoved, PlatformSpec, PodRan, PodRemoved, Processes, PullPolicy,
    PullSpec, PushSpec, Removed, RemovedContainer, Restarted, SessionOpened, SessionPhase,
    SessionReply, SessionStreams, Stream, VolumeRemoved, Waited,
};
use velarx_proto::health::{
    Health, HealthResult, HealthStatus, Healthcheck, OnFailure, StartupHealthcheck,
};
use velarx_proto::request as req;
use velarx_proto::system::{
    CheckReport, CheckSpec, DiskUsageInspected, DiskUsageRecord, StoreRecord, SystemChecked,
    SystemInspected, SystemPruneReport, SystemPruned, SystemRecord, VersionInspected,
    VersionRecord,
};
use velarx_proto::wait::WaitCondition;
use velarx_proto::workload::{
    ArtifactInspected, ArtifactRecord, BuildPruned, CheckpointState, ContainerInterface,
    ContainerListed, ContainerMetrics, ContainerMount, ContainerNetwork, ContainerPaths,
    ContainerPort, ContainerRecord, Event, EventKind, EventListed, ExecInspected, ExecRecord,
    ExecSpec, HealthChecked, HostSettings, ImageConfigRecord, ImageHealthcheck, ImageHistoryEntry,
    ImageInspected, ImageListed, ImagePlatform, ImagePruneListed, ImageRecord, ImageRemoved,
    InterfaceStats, LeaseRange, ManifestDescriptor, ManifestInstance, ManifestListRecord,
    ManifestRemoved, MetricDescriptor, MetricDescriptorListed, MetricSample, MountKind,
    NetworkCreated, NetworkDriver, NetworkMember, NetworkRecord, NetworkSpec, NetworkSubnet,
    PodInspected, PodMember, PodMetrics, PodMetricsListed, PodRecord, ProcessConfig, PrunedImage,
    Pulled, PulledImage, Pushed, PushedImage, PushedTag, RemoteImage, Resources, RunState,
    SecretInspected, SecretRecord, StatsListed, StatsRecord, TransferProgress, TransferStats,
    TransferStatus, Ulimit, VolumeListed, VolumeRecord,
};
use velarx_proto::{DIGEST, INLINE_MAX, PROTO};

/// What the mock saw of the last list call.
#[derive(Default, Debug, Clone, PartialEq)]
struct Seen {
    libpod: bool,
    all: bool,
    size: bool,
    namespace: bool,
    limit: i64,
    filters: Vec<(String, Vec<String>)>,
}

#[derive(Clone)]
struct Mock {
    version: String,
    digest: String,
    seen: Arc<Mutex<Seen>>,
    /// The calls of the lifecycle, as the engine saw them
    calls: Arc<Mutex<Vec<String>>>,
    /// How many documents a list has
    count: usize,
    fail: bool,
    /// A ping takes this long
    slow: std::time::Duration,
    /// The disk usage answers an empty store (all sizes zero)
    empty_usage: bool,
    /// The write ends of the streams that stay open
    held: Arc<Mutex<Vec<OwnedFd>>>,
    /// The engine's ends of the sessions of `exec_start`, with the engine's
    /// end of their output
    sessions: Arc<Mutex<Vec<(velarx_proto::stream::Out, OwnedFd)>>>,
    /// The pings in progress
    open: Arc<Open>,
}

mod service {
    use super::*;

    #[zlink::service(
        interface = "org.velarx.Engine",
        vendor = "org.velarx",
        product = "mock",
        version = "0",
        url = "https://example.org",
        types = [
            BuildSpec, BuildEvent, BuildEventKind, BuildStream, BuildClient, BuildPair, BuildEntitlement, BuildPull, BuildSecretKind, BuildSecretSpec, BuildContextKind, BuildContextSpec, BuildOutputKind, BuildOutput, BuildFlags, SbomFlags, req::BuildRun,
            Filter, RemovedContainer, LeaseRange, NetworkSpec, LogOptions, SessionPhase, SessionOpened, SessionStreams, SessionReply, ExecSpec, ExecRecord, ImagePlatform, InstanceSpec, ManifestArtifactSpec, ManifestDescriptor, ManifestInstance, ArtifactRecord,
            NetworkDriver, NetworkSubnet, NetworkMember, NetworkRecord, SecretRecord, MetricDescriptor, MetricSample,
            ContainerMetrics, PodMetrics, WaitCondition, ContainerRecord, RunState, MountKind,
            ContainerMount, StartupHealthcheck, HealthStatus, HealthResult, Health,
            Healthcheck, OnFailure, CheckpointState, ProcessConfig, Ulimit, HostSettings, ContainerPort,
            ContainerInterface, ContainerNetwork, ContainerPaths, Resources, VolumeRecord,
            ImageRecord, ImageConfigRecord, ImageHealthcheck, ImageHistoryEntry, PrunedImage, PullSpec, PulledImage,
            PlatformSpec, PullPolicy, TransferProgress, TransferStatus, TransferStats, PushSpec, PushedImage,
            PushedTag, Event, EventKind, StatsRecord, InterfaceStats, PodRecord, PodMember,
            VersionRecord, SystemRecord, StoreRecord, DiskUsageRecord, SystemPruneReport, CheckSpec,
            CheckReport
        ]
    )]
    impl Mock {
        async fn get_info(&self) -> InfoReply {
            InfoReply {
                name: "mock".into(),
                version: self.version.clone(),
                interface: PROTO,
                digest: self.digest.clone(),
                rootful: false,
            }
        }

        async fn restart(&self) -> Restarted {
            self.calls.lock().unwrap().push("restart".into());
            Restarted { restarted: false }
        }

        async fn ping(&self) -> Result<Ack, EngineError> {
            use std::sync::atomic::Ordering;
            let now = self.open.now.fetch_add(1, Ordering::SeqCst) + 1;
            self.open.most.fetch_max(now, Ordering::SeqCst);
            // (a slow engine)
            tokio::time::sleep(self.slow).await;
            self.open.now.fetch_sub(1, Ordering::SeqCst);
            if self.fail {
                return Err(EngineError::failed("the mock is told to fail".into()));
            }
            Ok(Ack {})
        }

        async fn image_exists(&self, name: String) -> Result<Ack, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("image exists {name}"));
            Ok(Ack {})
        }

        async fn image_inspect(&self, name: String) -> Result<ImageInspected, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("image inspect {name}"));
            Ok(ImageInspected {
                image: ImageRecord {
                    id: name,
                    ..Default::default()
                },
            })
        }

        /// `tty`: frames then the end; `idle`: a frame, then the stream
        /// stays open (the test holds the write end)
        #[zlink(return_fds)]
        async fn container_logs(
            &self,
            name: String,
            opts: LogOptions,
        ) -> (Result<Stream, EngineError>, Vec<OwnedFd>) {
            self.calls.lock().unwrap().push(format!(
                "logs {name} tail={:?} since={:?} until={:?} follow={} ts={} out={} err={}",
                opts.tail,
                opts.since_ns,
                opts.until_ns,
                opts.follow,
                opts.timestamps,
                opts.stdout,
                opts.stderr
            ));
            let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
            let frame = |s: u8, d: &[u8]| {
                let mut v = vec![s, 0, 0, 0];
                v.extend_from_slice(&(d.len() as u32).to_be_bytes());
                v.extend_from_slice(d);
                v
            };
            let mut file = std::fs::File::from(write);
            std::io::Write::write_all(&mut file, &frame(1, b"out\n")).unwrap();
            std::io::Write::write_all(&mut file, &frame(2, b"err\n")).unwrap();
            if name == "idle" {
                self.held.lock().unwrap().push(file.into());
            }
            (Ok(Stream { tty: name == "tty" }), vec![read])
        }

        /// The session of `spec`, as the frontend decoded podman's body.
        async fn exec_create(&self, name: String, spec: ExecSpec) -> Result<Id, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("exec create {name} {spec:?}"));
            Ok(Id { id: "e1".into() })
        }

        /// A session that ran and failed.
        async fn exec_inspect(&self, id: String) -> Result<ExecInspected, EngineError> {
            Ok(ExecInspected {
                exec: ExecRecord {
                    id,
                    container_id: "c1".into(),
                    exit_code: Some(3),
                    pid: 42,
                    command: vec!["sh".into(), "-c".into(), "exit 3".into()],
                    user: "bin".into(),
                    stdout: true,
                    ..Default::default()
                },
            })
        }

        async fn exec_remove(&self, id: String, force: bool) -> Result<Ack, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("exec remove {id} {force}"));
            Ok(Ack {})
        }

        /// The streams of a session: `out\n` as its output, then the engine's
        /// end stays open (the test holds it) unless the id is `short`, which
        /// ends with its output.
        #[zlink(more, return_fds)]
        async fn exec_start(
            &self,
            more: bool,
            id: String,
            input: bool,
            detach: bool,
            height: i64,
            width: i64,
        ) -> impl futures::Stream<
            Item = (
                Result<zlink::Reply<SessionReply>, EngineError>,
                Vec<OwnedFd>,
            ),
        > + Unpin {
            use futures::StreamExt;
            assert!(more);
            self.calls
                .lock()
                .unwrap()
                .push(format!("exec start {id} {input} {detach} {height}x{width}"));
            let opened = SessionOpened {
                session: id.clone(),
                tty: false,
                stdin: false,
                stdout: true,
                stderr: true,
                logs: None,
                detach_keys: Vec::new(),
                keep_open: false,
            };
            let (out, replies, _controls) = velarx_proto::stream::out(opened, None);
            let (mine, output) = std::os::unix::net::UnixStream::pair().unwrap();
            std::io::Write::write_all(&mut &mine, b"out\n").unwrap();
            let mine = OwnedFd::from(mine);
            let output = OwnedFd::from(output);
            if !detach {
                tokio::task::spawn_local({
                    let sessions = self.sessions.clone();
                    let short = id == "short";
                    async move {
                        out.send_streams(None, Some(output), None).await.unwrap();
                        if !short {
                            sessions.lock().unwrap().push((out, mine));
                        }
                    }
                });
            }
            futures::stream::unfold(replies, |mut rx| async move {
                let (reply, fds) = rx.recv().await?;
                let last = reply.phase == SessionPhase::Ended;
                Some((
                    (
                        Ok(zlink::Reply::new(Some(reply)).set_continues(Some(!last))),
                        fds,
                    ),
                    rx,
                ))
            })
            .boxed()
        }

        /// The context is counted as it comes; the answer says what the
        /// spec was.
        #[zlink(return_fds)]
        async fn image_build(
            &self,
            spec: u32,
            context: Option<u32>,
            sections: bool,
            access: Option<u32>,
            #[zlink(fds)] pipes: Vec<OwnedFd>,
        ) -> (Result<Stream, EngineError>, Vec<OwnedFd>) {
            use tokio::io::AsyncReadExt;
            let mut named = velarx_proto::descriptors::Descriptors::new(pipes);
            // (the credentials are a sealed memory file, never a pipe)
            let access_given = named
                .take_opt("the credentials", access)
                .unwrap()
                .map(|fd| {
                    velarx_base::sealed::read_sealed_whole(&std::fs::File::from(fd), 1 << 20)
                        .unwrap()
                });
            let spec_fd = named.take("the spec", spec).unwrap();
            let context_fd = named.take_opt("the context", context).unwrap();
            let mut spec = Vec::new();
            let mut file = tokio::net::unix::pipe::Receiver::from_owned_fd(spec_fd).unwrap();
            file.read_to_end(&mut spec).await.unwrap();
            let spec_text = String::from_utf8(spec.clone()).unwrap();
            let spec: velarx_proto::buildspec::BuildSpec = serde_json::from_slice(&spec).unwrap();
            // (the frames of the context; `end` when its end frame came; the
            // sections of a multipart body: a name, the frames, the empty one)
            let (mut bytes, mut end) = (0u64, false);
            let mut named = Vec::new();
            if let Some(context_fd) = context_fd {
                let mut file = tokio::net::unix::pipe::Receiver::from_owned_fd(context_fd).unwrap();
                let mut head = [0u8; 4];
                let mut section: Option<Vec<u8>> = None;
                let mut name = String::new();
                while file.read_exact(&mut head).await.is_ok() {
                    let n = u32::from_be_bytes(head) as usize;
                    if n == 0 {
                        if sections && section.is_some() {
                            let text = String::from_utf8(section.take().unwrap()).unwrap();
                            if name != "main" {
                                named.push(text);
                            }
                            continue;
                        }
                        end = true;
                        break;
                    }
                    assert!(n <= velarx_proto::build::MAX_CONTEXT_FRAME);
                    let mut buf = vec![0u8; n];
                    file.read_exact(&mut buf).await.unwrap();
                    if sections && section.is_none() {
                        name = String::from_utf8(buf).unwrap();
                        section = Some(Vec::new());
                        continue;
                    }
                    if name == "main" || !sections {
                        bytes += n as u64;
                    }
                    if let Some(s) = section.as_mut() {
                        s.extend_from_slice(&buf);
                    }
                }
            }
            let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
            let line = serde_json::json!({"kind": "output", "stream": "stdout", "text": format!(
                "{bytes} {end} {:?} {:?} {} {} {named:?} {}",
                spec.client,
                spec.tags,
                access_given.is_some(),
                spec_text.contains("hunter2"),
                serde_json::to_string(&serde_json::json!({
                    "quiet": spec.quiet, "layers": spec.layers, "args": spec.build_args,
                    "ulimits": spec.run.ulimits.len(), "platform": spec.platform,
                    "contexts": spec.contexts, "secrets": spec.secrets, "remote": spec.remote,
                    "containerfile": spec.containerfile, "pull": spec.pull,
                    "squash": [spec.squash, spec.squash_all],
                })).unwrap(),
            )});
            std::io::Write::write_all(
                &mut std::fs::File::from(write),
                format!("{line}\n").as_bytes(),
            )
            .unwrap();
            (Ok(Stream { tty: false }), vec![read])
        }

        async fn image_build_answer(
            &self,
            ask: String,
            answer: u32,
            #[zlink(fds)] pipes: Vec<OwnedFd>,
        ) -> Result<Ack, EngineError> {
            let _ = (ask, answer, pipes);
            Ok(Ack {})
        }

        async fn image_tag(
            &self,
            name: String,
            repo: String,
            tag: String,
            docker_hub: bool,
        ) -> Result<Ack, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("image tag {name} {repo} {tag} {docker_hub}"));
            Ok(Ack {})
        }

        async fn image_untag(&self, name: String, names: Vec<String>) -> Result<Ack, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("image untag {name} {names:?}"));
            Ok(Ack {})
        }

        async fn image_remove(
            &self,
            name: String,
            force: bool,
            spare_running: bool,
            noprune: bool,
            ignore: bool,
            manifest_list: bool,
        ) -> Result<ImageRemoved, EngineError> {
            self.calls.lock().unwrap().push(format!(
                "image remove {name} {force} {spare_running} {noprune} {ignore} {manifest_list}"
            ));
            if let Some(e) = refusal(&name) {
                return Err(e);
            }
            Ok(ImageRemoved {
                untagged: vec!["a:1".into()],
                deleted: vec!["abc".into()],
                warnings: Vec::new(),
            })
        }

        async fn version_inspect(&self) -> Result<VersionInspected, EngineError> {
            self.calls.lock().unwrap().push("version inspect".into());
            Ok(VersionInspected {
                version: VersionRecord {
                    version: "6.1".into(),
                    arch: "x86_64".into(),
                    ..Default::default()
                },
            })
        }

        async fn system_inspect(&self) -> Result<SystemInspected, EngineError> {
            self.calls.lock().unwrap().push("system inspect".into());
            Ok(SystemInspected {
                system: SystemRecord {
                    store: StoreRecord {
                        containers: 3,
                        graph_root: "/s".into(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            })
        }

        async fn disk_usage_inspect(&self, store: bool) -> Result<DiskUsageInspected, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("disk usage inspect {store}"));
            let usage = if self.empty_usage {
                DiskUsageRecord::default()
            } else {
                DiskUsageRecord {
                    images_size: 7,
                    ..Default::default()
                }
            };
            Ok(DiskUsageInspected { usage })
        }

        async fn system_prune(
            &self,
            all: bool,
            volumes: bool,
            build: bool,
            filters: Vec<Filter>,
        ) -> Result<SystemPruned, EngineError> {
            self.calls.lock().unwrap().push(format!(
                "system prune {all} {volumes} {build} {:?}",
                filters.iter().map(|f| &f.key).collect::<Vec<_>>()
            ));
            Ok(SystemPruned {
                report: SystemPruneReport {
                    containers: vec!["c1".into()],
                    reclaimed: 5,
                    ..Default::default()
                },
            })
        }

        async fn system_check(&self, spec: CheckSpec) -> Result<SystemChecked, EngineError> {
            self.calls.lock().unwrap().push(format!(
                "system check {} {} {} {:?}",
                spec.quick, spec.repair, spec.repair_lossy, spec.max_age_ms
            ));
            Ok(SystemChecked {
                report: CheckReport::default(),
            })
        }

        async fn registry_login(
            &self,
            host: String,
            access: Option<u32>,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<LoginReply, EngineError> {
            // (the credentials are in the sealed memory file of the call, not
            // in the message)
            let file = std::fs::File::from(fds.into_iter().nth(access.unwrap() as usize).unwrap());
            let bytes = velarx_base::sealed::read_sealed_whole(&file, 1 << 20).unwrap();
            let creds: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let username = creds["creds"]["username"].as_str().unwrap_or_default();
            let password = creds["creds"]["password"].as_str().unwrap_or_default();
            self.calls
                .lock()
                .unwrap()
                .push(format!("registry login {host} {username} {password}"));
            Ok(LoginReply {
                failure: (username == "bad").then(|| "invalid username/password".to_string()),
                unauthorized: username == "bad",
            })
        }

        /// A container that died and a lazy pull that completed (a follow
        /// is answered first without an event).
        #[zlink(more)]
        async fn event_list(
            &self,
            more: bool,
            filters: Vec<Filter>,
            since_ns: Option<i64>,
            until_ns: Option<i64>,
            follow: bool,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<EventListed>, EngineError>> + Unpin
        {
            self.calls.lock().unwrap().push(format!(
                "event list {more} {:?} {since_ns:?} {until_ns:?} {follow}",
                filters.iter().map(|f| &f.key).collect::<Vec<_>>()
            ));
            let event = |action: &str, kind| EventListed {
                event: Some(Event {
                    time_ns: 1_500_000_000,
                    kind,
                    action: action.into(),
                    id: "abc".into(),
                    name: "c1".into(),
                    ..Default::default()
                }),
            };
            let mut replies = Vec::new();
            if follow {
                replies.push(EventListed { event: None });
            }
            replies.push(event("died", EventKind::Container));
            replies.push(event("complete", EventKind::Image));
            replies.push(EventListed { event: None });
            let last = replies.len() - 1;
            futures::stream::iter(
                replies.into_iter().enumerate().map(move |(i, r)| {
                    Ok(zlink::Reply::new(Some(r)).set_continues(Some(i < last)))
                }),
            )
        }

        /// One layer pulled; `nosuch` is not there.
        #[zlink(more)]
        async fn image_pull(
            &self,
            more: bool,
            spec: PullSpec,
            access: Option<u32>,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<Pulled>, EngineError>> + Unpin
        {
            self.calls.lock().unwrap().push(format!(
                "image pull {} {} {} {}",
                spec.source,
                spec.docker_hub,
                access.is_some(),
                fds.len()
            ));
            let pulled = |progress: Option<TransferProgress>| Pulled {
                id: progress.is_none().then(|| "iid".into()),
                images: progress.is_none().then(|| {
                    vec![PulledImage {
                        id: "iid".into(),
                        names: Vec::new(),
                    }]
                }),
                progress,
                stats: None,
                present: Some(false),
            };
            let layer = TransferProgress {
                layer: format!("sha256:{}", "ab".repeat(32)),
                status: TransferStatus::Downloading,
                current_bytes: 1,
                total_bytes: 2,
                ..Default::default()
            };
            let mut replies = Vec::new();
            if spec.source.contains("nosuch") {
                replies.push(Err(EngineError::NoSuchImage {
                    cause: "manifest unknown".into(),
                    message: "{\"errors\":[{\"code\":\"MANIFEST_UNKNOWN\",\"message\":\"manifest unknown\"}]}".into(),
                }));
            } else {
                if more {
                    replies.push(Ok(
                        zlink::Reply::new(Some(pulled(Some(layer)))).set_continues(Some(true))
                    ));
                }
                replies.push(Ok(
                    zlink::Reply::new(Some(pulled(None))).set_continues(Some(false))
                ));
            }
            futures::stream::iter(replies)
        }

        /// Where to, a layer, the manifest pushed.
        #[zlink(more)]
        async fn image_push(
            &self,
            more: bool,
            spec: PushSpec,
            access: Option<u32>,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<Pushed>, EngineError>> + Unpin
        {
            self.calls.lock().unwrap().push(format!(
                "image push {} {:?} {} {}",
                spec.images.join(","),
                spec.destination,
                access.is_some(),
                fds.len()
            ));
            if spec.images[0].contains("nosuch") {
                return futures::stream::iter(vec![Err(EngineError::NoSuchImage {
                    cause: "image not known".into(),
                    message: "nosuch: image not known".into(),
                })]);
            }
            if spec.images[0].contains("refused") {
                return futures::stream::iter(vec![Err(EngineError::Unauthorized {
                    cause: "unauthorized".into(),
                    message: "x509: certificate signed by unknown authority".into(),
                })]);
            }
            let destination = spec.destination.unwrap_or_else(|| spec.images[0].clone());
            let reply = |progress: Option<TransferProgress>, pushed: Option<PushedImage>| Pushed {
                destination: Some(destination.clone()),
                progress,
                pushed,
            };
            let mut replies = Vec::new();
            if more {
                replies.push(Ok(
                    zlink::Reply::new(Some(reply(None, None))).set_continues(Some(true))
                ));
                replies.push(Ok(zlink::Reply::new(Some(reply(
                    Some(TransferProgress {
                        layer: "sha256:1".into(),
                        ..Default::default()
                    }),
                    None,
                )))
                .set_continues(Some(true))));
            }
            let pushed = PushedImage {
                digest: "sha256:d".into(),
                size: 7,
                ..Default::default()
            };
            replies.push(Ok(
                zlink::Reply::new(Some(reply(None, Some(pushed)))).set_continues(Some(false))
            ));
            futures::stream::iter(replies)
        }

        #[zlink(more)]
        async fn metric_descriptor_list(
            &self,
            more: bool,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<MetricDescriptorListed>, EngineError>> + Unpin
        {
            let _ = more;
            let descriptor = MetricDescriptor {
                name: "m".into(),
                ..Default::default()
            };
            futures::stream::iter([Ok(zlink::Reply::new(Some(MetricDescriptorListed {
                descriptor: Some(descriptor),
            }))
            .set_continues(Some(false)))])
        }

        #[zlink(more)]
        async fn pod_metrics_list(
            &self,
            more: bool,
            name: Option<String>,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<PodMetricsListed>, EngineError>> + Unpin
        {
            let _ = more;
            self.calls
                .lock()
                .unwrap()
                .push(format!("pods metrics {name:?}"));
            let pod = PodMetrics {
                name: name.unwrap_or_default(),
                ..Default::default()
            };
            futures::stream::iter([Ok(zlink::Reply::new(Some(PodMetricsListed {
                pod: Some(pod),
            }))
            .set_continues(Some(false)))])
        }

        async fn build_prune(&self) -> Result<BuildPruned, EngineError> {
            self.calls.lock().unwrap().push("build prune".into());
            Ok(BuildPruned {
                ids: vec!["i1".into(), "i2".into()],
                space: 42,
            })
        }

        async fn manifest_exists(&self, name: String) -> Result<Ack, EngineError> {
            if name == "gone" {
                return Err(EngineError::NoSuchImage {
                    cause: String::new(),
                    message: format!("{name}: manifest not found"),
                });
            }
            Ok(Ack {})
        }

        #[allow(clippy::too_many_arguments, unused_variables)]
        async fn manifest_inspect(
            &self,
            name: String,
            tls_verify: bool,
            access: Option<u32>,
            #[zlink(fds)] _fds: Vec<OwnedFd>,
        ) -> Result<ManifestListRecord, EngineError> {
            Ok(ManifestListRecord {
                id: "L1".into(),
                schema_version: 2,
                media_type: "application/vnd.oci.image.index.v1+json".into(),
                manifests: vec![ManifestInstance {
                    media_type: "m".into(),
                    digest: format!("sha256:{name}"),
                    size: 3,
                    platform: Some(ImagePlatform {
                        architecture: "amd64".into(),
                        os: "linux".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            })
        }

        #[allow(clippy::too_many_arguments)]
        async fn manifest_add_images(
            &self,
            name: String,
            images: Vec<String>,
            all: bool,
            instance: InstanceSpec,
            tls_verify: bool,
            access: Option<u32>,
            #[zlink(fds)] _fds: Vec<OwnedFd>,
        ) -> Result<Id, EngineError> {
            self.calls.lock().unwrap().push(format!(
                "manifest add {name} {images:?} all={all} arch={} osv={} ann={:?} tls={tls_verify} access={}",
                instance.architecture,
                instance.os_version,
                instance.annotations,
                access.is_some()
            ));
            if images.iter().any(|i| i.contains("bad")) {
                return Err(EngineError::InvalidArgument {
                    cause: String::new(),
                    message: "no such image".into(),
                });
            }
            Ok(Id { id: "L2".into() })
        }

        async fn manifest_remove_instance(
            &self,
            name: String,
            digest: String,
        ) -> Result<Id, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("manifest remove instance {name} {digest}"));
            if digest.contains("bad") {
                return Err(EngineError::NoSuchImage {
                    cause: String::new(),
                    message: format!("{digest} is not in the list"),
                });
            }
            Ok(Id { id: "L3".into() })
        }

        async fn manifest_annotate(
            &self,
            name: String,
            instance: Option<String>,
            spec: InstanceSpec,
            index_annotations: BTreeMap<String, String>,
            subject: Option<String>,
        ) -> Result<Id, EngineError> {
            self.calls.lock().unwrap().push(format!(
                "manifest annotate {name} {instance:?} arch={} {index_annotations:?} {subject:?}",
                spec.architecture
            ));
            Ok(Id { id: "L4".into() })
        }

        #[allow(unused_variables)]
        async fn manifest_add_artifact(
            &self,
            name: String,
            spec: ManifestArtifactSpec,
            tls_verify: bool,
            access: Option<u32>,
            #[zlink(fds)] pipes: Vec<OwnedFd>,
        ) -> Result<Id, EngineError> {
            let mut named = velarx_proto::descriptors::Descriptors::new(pipes);
            let _ = named.take_opt("the credentials", access).unwrap();
            let contents: Vec<String> = named
                .rest()
                .into_iter()
                .map(|fd| std::io::read_to_string(std::fs::File::from(fd)).unwrap())
                .collect();
            self.calls.lock().unwrap().push(format!(
                "manifest artifact {name} {:?} {contents:?} type={:?} layer={}",
                spec.titles, spec.artifact_type, spec.layer_type
            ));
            Ok(Id {
                id: "sha256:art".into(),
            })
        }

        async fn manifest_remove(&self, name: String) -> Result<ManifestRemoved, EngineError> {
            if name == "gone" {
                return Err(EngineError::NoSuchImage {
                    cause: String::new(),
                    message: format!("{name}: not found"),
                });
            }
            Ok(ManifestRemoved {
                id: "L1".into(),
                names: vec!["localhost/x:latest".into()],
            })
        }

        async fn artifact_inspect(&self, name: String) -> Result<ArtifactInspected, EngineError> {
            Ok(ArtifactInspected {
                artifact: ArtifactRecord {
                    name,
                    digest: "sha256:art".into(),
                    schema_version: 2,
                    media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                    layers: vec![ManifestDescriptor {
                        media_type: "text/plain".into(),
                        digest: "sha256:l".into(),
                        size: 4,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            })
        }

        async fn artifact_remove(&self, name: String) -> Result<Id, EngineError> {
            if name.starts_with("gone") {
                return Err(EngineError::NoSuchObject {
                    cause: String::new(),
                    message: format!("{name}: no such artifact"),
                });
            }
            Ok(Id {
                id: format!("sha256:{name}"),
            })
        }

        async fn image_remote_inspect(
            &self,
            name: String,
            tls_verify: bool,
        ) -> Result<RemoteImage, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("image distribution {name} {tls_verify}"));
            Ok(RemoteImage {
                media_type: "application/vnd.oci.image.index.v1+json".into(),
                digest: name,
                size: 7,
                platforms: vec![
                    ImagePlatform {
                        architecture: "amd64".into(),
                        os: "linux".into(),
                        ..Default::default()
                    },
                    ImagePlatform {
                        architecture: "arm64".into(),
                        os: "linux".into(),
                        variant: "v8".into(),
                        features: vec!["f".into()],
                        ..Default::default()
                    },
                ],
            })
        }

        #[zlink(more)]
        async fn image_prune(
            &self,
            more: bool,
            all: bool,
            filters: Vec<Filter>,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<ImagePruneListed>, EngineError>> + Unpin
        {
            let filters: Vec<String> = filters
                .into_iter()
                .flat_map(|f| f.values.into_iter().map(move |v| format!("{}={v}", f.key)))
                .collect();
            self.calls
                .lock()
                .unwrap()
                .push(format!("image prune {all} {filters:?}"));
            let pruned: Vec<PrunedImage> = if filters.iter().any(|f| f == "label=many") {
                (0..3000)
                    .map(|i| PrunedImage {
                        id: format!("{i:064}"),
                        size: 1,
                    })
                    .collect()
            } else {
                vec![PrunedImage {
                    id: "abc".into(),
                    size: 7,
                }]
            };
            let last = pruned.len() - 1;
            futures::stream::iter(pruned.into_iter().enumerate().map(move |(i, image)| {
                Ok(
                    zlink::Reply::new(Some(ImagePruneListed { image: Some(image) }))
                        .set_continues(Some(more && i < last)),
                )
            }))
        }

        async fn network_create(
            &self,
            spec: NetworkSpec,
            ignore_if_exists: bool,
        ) -> Result<NetworkCreated, EngineError> {
            self.calls.lock().unwrap().push(format!(
                "network create {} {:?} {:?} {:?} {:?} {} {}",
                spec.name,
                spec.subnet,
                spec.gateway6,
                spec.lease.map(|l| (l.start, l.end)),
                spec.options.keys().map(String::as_str).collect::<Vec<_>>(),
                spec.dns_enabled,
                ignore_if_exists
            ));
            Ok(NetworkCreated {
                changed: !ignore_if_exists,
                network: NetworkRecord {
                    id: "nid".into(),
                    name: spec.name,
                    ..Default::default()
                },
            })
        }

        async fn network_remove(
            &self,
            name: String,
            force: bool,
            timeout: Option<u64>,
        ) -> Result<NetworkRemoved, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("network remove {name} {force} {timeout:?}"));
            if name == "isbusy" {
                return Err(EngineError::InvalidState {
                    cause: "network is being used".into(),
                    message: "\"isbusy\" has associated containers with it. Use -f to forcibly delete containers and pods: network is being used".into(),
                });
            }
            if name == "gone" {
                return Err(EngineError::NoSuchNetwork {
                    cause: "network not found".into(),
                    message: "unable to find network with name or ID gone: network not found"
                        .into(),
                });
            }
            Ok(NetworkRemoved {
                name,
                warnings: Vec::new(),
            })
        }

        async fn network_connect(
            &self,
            name: String,
            container: String,
            ip: Option<String>,
            ip6: Option<String>,
            mac: Option<String>,
            aliases: Vec<String>,
        ) -> Result<Ack, EngineError> {
            self.calls.lock().unwrap().push(format!(
                "network connect {name} {container} {ip:?} {ip6:?} {mac:?} {aliases:?}"
            ));
            Ok(Ack {})
        }

        async fn volume_remove(
            &self,
            name: String,
            force: bool,
            timeout: Option<u64>,
        ) -> Result<VolumeRemoved, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("volume remove {name} {force} {timeout:?}"));
            if let Some(e) = refusal(&name) {
                return Err(e);
            }
            Ok(VolumeRemoved {
                warnings: Vec::new(),
            })
        }

        #[zlink(more)]
        async fn volume_list(
            &self,
            more: bool,
            filters: Vec<Filter>,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<VolumeListed>, EngineError>> + Unpin
        {
            self.calls
                .lock()
                .unwrap()
                .push(format!("volume list {}", filters.len()));
            let v = VolumeRecord {
                name: "v".into(),
                ..Default::default()
            };
            let _ = more;
            futures::stream::iter([Ok(zlink::Reply::new(Some(VolumeListed {
                volume: Some(v),
            })))])
        }

        #[allow(
            clippy::too_many_arguments,
            reason = "one parameter for each field of the varlink call"
        )]
        async fn secret_create(
            &self,
            name: String,
            driver: Option<String>,
            driver_opts: std::collections::BTreeMap<String, String>,
            labels: std::collections::BTreeMap<String, String>,
            replace: bool,
            ignore: bool,
            data: u32,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<Id, EngineError> {
            let file = std::fs::File::from(fds.into_iter().nth(data as usize).unwrap());
            let bytes = velarx_base::sealed::read_sealed_whole(&file, 1 << 20).unwrap();
            self.calls.lock().unwrap().push(format!(
                "secret create {name} {} {driver:?} {} {} {replace} {ignore}",
                String::from_utf8_lossy(&bytes),
                driver_opts.len(),
                labels.len()
            ));
            Ok(Id { id: "sid".into() })
        }

        /// The data crosses as the content of a pipe.
        #[zlink(return_fds)]
        async fn secret_inspect(
            &self,
            name: String,
            show_data: bool,
        ) -> (Result<SecretInspected, EngineError>, Vec<OwnedFd>) {
            let secret = SecretRecord {
                id: "sid".into(),
                name,
                driver: "file".into(),
                ..Default::default()
            };
            if !show_data {
                return (Ok(SecretInspected { secret, data: None }), Vec::new());
            }
            let data = b"SHOWN-DATA-6e1f";
            let file = velarx_base::sealed::sealed_memory(data).unwrap();
            (
                Ok(SecretInspected {
                    secret,
                    data: Some(0),
                }),
                vec![file],
            )
        }

        async fn pod_create(
            &self,
            spec: u32,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<Id, EngineError> {
            use tokio::io::AsyncReadExt;
            let mut text = String::new();
            assert_eq!(spec, 0);
            for fd in fds {
                let mut r = tokio::net::unix::pipe::Receiver::from_owned_fd(fd).unwrap();
                r.read_to_string(&mut text).await.unwrap();
            }
            self.calls.lock().unwrap().push({
                let spec: velarx_proto::pod::PodSpec = serde_json::from_str(&text).unwrap();
                format!(
                    "pod create {} {:?} ports={} net={} pid={} ipc={} restart={:?} infra={:?}",
                    spec.name,
                    spec.labels,
                    spec.ports.len(),
                    spec.share_net,
                    spec.share_pid,
                    spec.share_ipc,
                    spec.restart_policy.map(|r| (r.name, r.maximum_retry_count)),
                    spec.infra_image
                )
            });
            Ok(Id { id: "pid".into() })
        }

        async fn pod_run(
            &self,
            name: String,
            op: String,
            timeout: Option<u64>,
            signal: Option<String>,
            verify_image: Vec<String>,
            service: Option<bool>,
        ) -> Result<PodRan, EngineError> {
            self.calls.lock().unwrap().push(format!(
                "pod {op} {name} {timeout:?} {signal:?} {verify_image:?} {service:?}"
            ));
            Ok(match name.as_str() {
                "same" => PodRan {
                    changed: false,
                    id: String::new(),
                    errors: vec![],
                },
                "bad" => PodRan {
                    changed: true,
                    id: "pid".into(),
                    errors: vec!["boom".into()],
                },
                _ => PodRan {
                    changed: true,
                    id: "pid".into(),
                    errors: vec![],
                },
            })
        }

        async fn pod_remove(
            &self,
            name: String,
            force: bool,
            timeout: Option<u64>,
        ) -> Result<PodRemoved, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("pod remove {name} {force} {timeout:?}"));
            if let Some(e) = refusal(&name) {
                return Err(e);
            }
            Ok(PodRemoved {
                id: "pid".into(),
                removed: vec!["c1".into()],
                warnings: Vec::new(),
            })
        }

        async fn container_exists(&self, name: String) -> Result<Ack, EngineError> {
            self.calls.lock().unwrap().push(format!("exists {name}"));
            if let Some(e) = refusal(&name) {
                return Err(e);
            }
            if name == "missing" {
                return Err(EngineError::NoSuchContainer {
                    cause: "no such container".into(),
                    message: "no such container: missing".into(),
                });
            }
            Ok(Ack {})
        }

        async fn container_start(
            &self,
            name: String,
            verify_image: Vec<String>,
            service: Option<bool>,
            run: Option<bool>,
        ) -> Result<Changed, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("start {name} {verify_image:?} {service:?} {run:?}"));
            Ok(Changed {
                changed: name != "running",
            })
        }

        async fn container_stop(
            &self,
            name: String,
            timeout: Option<u64>,
            ignore: bool,
        ) -> Result<Changed, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("stop {name} {timeout:?} {ignore}"));
            if let Some(e) = refusal(&name) {
                return Err(e);
            }
            Ok(Changed {
                changed: name != "stopped",
            })
        }

        async fn container_kill(
            &self,
            name: String,
            signal: Option<String>,
        ) -> Result<Ack, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("kill {name} {signal:?}"));
            Ok(Ack {})
        }

        async fn container_restart(
            &self,
            name: String,
            timeout: Option<u64>,
            verify_image: Vec<String>,
        ) -> Result<Ack, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("restart {name} {timeout:?} {verify_image:?}"));
            Ok(Ack {})
        }

        async fn container_pause(
            &self,
            name: String,
            pause: bool,
            lease: Option<u64>,
        ) -> Result<Ack, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("pause {name} {pause} {lease:?}"));
            Ok(Ack {})
        }

        async fn container_rename(
            &self,
            name: String,
            new_name: String,
        ) -> Result<Ack, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("rename {name} {new_name}"));
            Ok(Ack {})
        }

        async fn container_remove(
            &self,
            name: String,
            force: bool,
            volumes: bool,
            ignore: bool,
            depend: bool,
            timeout: Option<u64>,
        ) -> Result<Removed, EngineError> {
            self.calls.lock().unwrap().push(format!(
                "remove {name} {force} {volumes} {ignore} {depend} {timeout:?}"
            ));
            if let Some(e) = refusal(&name) {
                return Err(e);
            }
            Ok(Removed {
                removed: vec![
                    RemovedContainer {
                        id: "dep".into(),
                        named: "dep".into(),
                    },
                    RemovedContainer {
                        id: "abc".into(),
                        named: name,
                    },
                ],
                warnings: Vec::new(),
            })
        }

        /// A sample of the containers named (`c1` without), `stopped` not
        /// running; two with `stream`.
        #[zlink(more)]
        async fn container_stats(
            &self,
            more: bool,
            names: Vec<String>,
            all: bool,
            size: bool,
            stream: bool,
            interval_ms: Option<u64>,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<StatsListed>, EngineError>> + Unpin
        {
            self.calls.lock().unwrap().push(format!(
                "container stats {more} {names:?} {all} {size} {stream} {interval_ms:?}"
            ));
            let names = if names.is_empty() {
                vec!["c1".to_string()]
            } else {
                names
            };
            let mut replies = Vec::new();
            for n in 1..=if stream { 2 } else { 1 } {
                for name in &names {
                    let running = name != "stopped";
                    replies.push(StatsListed {
                        stats: Some(StatsRecord {
                            id: name.clone(),
                            name: name.clone(),
                            running,
                            time_ns: n * 1_000_000_000,
                            cpu_nano: (n as u64) * 500_000_000 * u64::from(running),
                            mem_usage: 400 * u64::from(running),
                            mem_limit: 1000 * u64::from(running),
                            networks: vec![InterfaceStats {
                                name: "eth0".into(),
                                rx_bytes: 100,
                                ..Default::default()
                            }],
                            ..Default::default()
                        }),
                    });
                }
                replies.push(StatsListed { stats: None });
            }
            let last = replies.len() - 1;
            futures::stream::iter(
                replies.into_iter().enumerate().map(move |(i, r)| {
                    Ok(zlink::Reply::new(Some(r)).set_continues(Some(i < last)))
                }),
            )
        }

        async fn pod_inspect(&self, name: String) -> Result<PodInspected, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("pod inspect {name}"));
            let member = |id: &str| PodMember {
                id: id.into(),
                name: id.into(),
                ..Default::default()
            };
            Ok(PodInspected {
                pod: PodRecord {
                    id: "feedfacecafebeef".into(),
                    name,
                    members: vec![member("infra"), member("stopped")],
                    ..Default::default()
                },
            })
        }

        /// A check that passed.
        async fn container_healthcheck(&self, name: String) -> Result<HealthChecked, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("container healthcheck {name}"));
            Ok(HealthChecked {
                health: Health {
                    status: HealthStatus::Healthy,
                    failing_streak: 0,
                    log: vec![HealthResult {
                        start_ns: 1_000_000_000,
                        end_ns: 2_000_000_000,
                        exit_code: 0,
                        output: "ok".into(),
                    }],
                },
            })
        }

        /// The processes of `c1`; `gone` does not run.
        async fn container_top(
            &self,
            name: String,
            ps_args: Vec<String>,
        ) -> Result<Processes, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("container top {name} {ps_args:?}"));
            if name == "gone" {
                return Err(EngineError::InvalidState {
                    cause: "container state improper".into(),
                    message: "container gone is not running: container state improper".into(),
                });
            }
            Ok(Processes {
                titles: vec!["PID".into()],
                processes: vec![vec!["1".into()]],
            })
        }

        async fn pod_top(
            &self,
            name: String,
            ps_args: Vec<String>,
        ) -> Result<Processes, EngineError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("pod top {name} {ps_args:?}"));
            Ok(Processes {
                titles: vec!["USER".into()],
                processes: Vec::new(),
            })
        }

        #[zlink(more)]
        async fn container_wait(
            &self,
            more: bool,
            name: String,
            conditions: Vec<WaitCondition>,
            interval_ns: i64,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<Waited>, EngineError>> + Unpin
        {
            self.calls
                .lock()
                .unwrap()
                .push(format!("wait {name} {conditions:?} {interval_ns} {more}"));
            let armed = zlink::Reply::new(Some(Waited::default())).set_continues(Some(true));
            // (a wait that nothing ends)
            let hangs = name == "hang";
            let met = Waited {
                status_code: Some(3),
                condition: Some(
                    conditions
                        .first()
                        .copied()
                        .unwrap_or(WaitCondition::Stopped),
                ),
            };
            let met = zlink::Reply::new(Some(met)).set_continues(Some(false));
            let items = if let Some(e) = refusal(&name) {
                vec![Err(e)]
            } else if hangs {
                vec![Ok(armed)]
            } else {
                vec![Ok(armed), Ok(met)]
            };
            let rest = if hangs {
                futures::future::Either::Left(futures::stream::pending())
            } else {
                futures::future::Either::Right(futures::stream::empty())
            };
            futures::StreamExt::chain(futures::stream::iter(items), rest)
        }

        #[zlink(more)]
        async fn container_list(
            &self,
            more: bool,
            filters: Vec<Filter>,
            all: bool,
            size: bool,
            namespace: bool,
            limit: i64,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<ContainerListed>, EngineError>> + Unpin
        {
            *self.seen.lock().unwrap() = Seen {
                all,
                size,
                namespace,
                limit,
                filters: filters.into_iter().map(|f| (f.key, f.values)).collect(),
                ..Seen::default()
            };
            let replies: Vec<Result<zlink::Reply<ContainerListed>, EngineError>> = if self.fail {
                vec![Err(EngineError::Failed {
                    cause: "boom".into(),
                    message: "failed: boom".into(),
                })]
            } else if self.count == 0 {
                vec![Ok(zlink::Reply::new(Some(ContainerListed {
                    container: None,
                })))]
            } else {
                (0..self.count)
                    .map(|i| {
                        let c = ContainerRecord {
                            id: format!("{i:064}"),
                            name: format!("c{i}"),
                            ..Default::default()
                        };
                        Ok(
                            zlink::Reply::new(Some(ContainerListed { container: Some(c) }))
                                .set_continues(Some(more && i + 1 < self.count)),
                        )
                    })
                    .collect()
            };
            futures::stream::iter(replies)
        }

        #[zlink(more)]
        async fn image_list(
            &self,
            more: bool,
            filters: Vec<Filter>,
            all: bool,
            manifest_lists: bool,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<ImageListed>, EngineError>> + Unpin
        {
            *self.seen.lock().unwrap() = Seen {
                libpod: manifest_lists,
                all,
                filters: filters.into_iter().map(|f| (f.key, f.values)).collect(),
                ..Seen::default()
            };
            let replies: Vec<Result<zlink::Reply<ImageListed>, EngineError>> = if self.count == 0 {
                vec![Ok(zlink::Reply::new(Some(ImageListed { image: None })))]
            } else {
                (0..self.count)
                    .map(|i| {
                        let image = ImageRecord {
                            id: format!("{i:064}"),
                            names: vec![format!("localhost/c{i}:1")],
                            size: 7,
                            ..Default::default()
                        };
                        Ok(zlink::Reply::new(Some(ImageListed { image: Some(image) }))
                            .set_continues(Some(more && i + 1 < self.count)))
                    })
                    .collect()
            };
            futures::stream::iter(replies)
        }
    }
}

/// Serve `mock` on `socket` (in the `LocalSet` the test runs in).
fn serve(socket: &Path, mock: Mock) {
    let listener = tokio::net::UnixListener::bind(socket).unwrap();
    tokio::task::spawn_local(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let stream = zlink::tokio::unix::Stream::try_from(stream).unwrap();
            let server = zlink::Server::new(zlink::ReadyListener::new(stream), mock.clone());
            tokio::task::spawn_local(async move {
                let _ = server.run().await;
            });
        }
    });
}

/// The calls in progress at once: now and the most.
#[derive(Default)]
struct Open {
    now: std::sync::atomic::AtomicUsize,
    most: std::sync::atomic::AtomicUsize,
}

/// The refusal of the engine a mock gives to an object named after it.
fn refusal(name: &str) -> Option<EngineError> {
    let (cause, message) = ("c".to_string(), format!("m {name}"));
    Some(match name {
        "ismissing" => EngineError::NoSuchContainer { cause, message },
        "isvolumegone" => EngineError::NoSuchVolume { cause, message },
        "ispodgone" => EngineError::NoSuchPod { cause, message },
        "isimagegone" => EngineError::NoSuchImage { cause, message },
        "isbusy" => EngineError::InvalidState { cause, message },
        "isinvalid" => EngineError::InvalidArgument { cause, message },
        "isconflict" => EngineError::Conflict { cause, message },
        _ => return None,
    })
}

fn mock(count: usize) -> (Mock, Arc<Mutex<Seen>>) {
    let seen = Arc::new(Mutex::new(Seen::default()));
    (
        Mock {
            version: env!("CARGO_PKG_VERSION").into(),
            digest: DIGEST.into(),
            seen: seen.clone(),
            calls: Arc::default(),
            count,
            fail: false,
            slow: std::time::Duration::ZERO,
            empty_usage: false,
            held: Arc::default(),
            sessions: Arc::default(),
            open: Arc::default(),
        },
        seen,
    )
}

async fn get(
    app: &axum::Router,
    method: &str,
    uri: &str,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = res.into_parts();
    let bytes = axum::body::to_bytes(body, 64 << 20).await.unwrap();
    (parts.status, parts.headers, bytes.to_vec())
}

fn json(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body)
        .unwrap_or_else(|e| panic!("{e}: {:?}", String::from_utf8_lossy(body)))
}

#[tokio::test]
async fn the_tcp_listeners_ask_for_the_token() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("token");
    std::fs::write(&file, "0123456789abcdefXYZ\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let token = Arc::new(velarx_proto::bearer::Token::load(&file).unwrap());
    let app =
        velarx_api::serve::with_token(axum::Router::new().fallback(|| async { "served" }), token);
    let ask = |authorization: Option<&'static str>| {
        let app = app.clone();
        async move {
            let mut req = Request::builder().uri("/_ping");
            if let Some(a) = authorization {
                req = req.header("authorization", a);
            }
            let res = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
            (res.status(), res.headers().get("www-authenticate").cloned())
        }
    };
    let (status, challenge) = ask(None).await;
    assert_eq!(status, 401);
    assert_eq!(challenge.unwrap(), "Bearer");
    assert_eq!(ask(Some("Bearer 0123456789abcdefXYz")).await.0, 401);
    assert_eq!(ask(Some("Bearer 0123456789abcdefXYZ")).await.0, 200);
}

#[tokio::test]
async fn ping_goes_to_the_engine_and_answers_as_podman() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            serve(&socket, mock(0).0);
            let app = router(Engine::new(&socket));
            for uri in [
                "/_ping",
                "/libpod/_ping",
                "/v1.41/_ping",
                "/v5.0.0/libpod/_ping",
            ] {
                let (status, headers, body) = get(&app, "GET", uri).await;
                assert_eq!(status, 200, "{uri}");
                assert_eq!(body, b"OK", "{uri}");
                assert_eq!(headers["cache-control"], "no-cache");
                assert_eq!(headers["libpod-api-version"], "5.8.9");
                assert_eq!(headers["api-version"], "1.44");
            }
            let (status, headers, body) = get(&app, "HEAD", "/_ping").await;
            assert_eq!(status, 200);
            assert!(body.is_empty());
            assert_eq!(headers["content-length"], "2");
            let (status, _, _) = get(&app, "POST", "/_ping").await;
            assert_eq!(status, 405);
            let (status, _, body) = get(&app, "GET", "/nothing").await;
            assert_eq!(status, 404);
            assert_eq!(json(&body)["cause"], "page not found");
        })
        .await;
}

#[tokio::test]
async fn the_query_becomes_the_typed_arguments() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, seen) = mock(2);
            serve(&socket, m);
            let app = router(Engine::new(&socket));

            let (status, _, body) = get(
                &app,
                "GET",
                "/libpod/containers/json?all=true&size=1&last=3&limit=9&filters=%7B%22label%22%3A%5B%22a%3Db%22%5D%2C%22status%22%3A%7B%22running%22%3Atrue%7D%7D",
            )
            .await;
            assert_eq!(status, 200);
            let docs = json(&body);
            assert_eq!(docs.as_array().unwrap().len(), 2);
            assert!(body.ends_with(b"]\n"), "a newline as Go writes JSON");
            let mut s = seen.lock().unwrap().clone();
            s.filters.sort();
            assert_eq!(
                s,
                Seen {
                    all: true,
                    size: true,
                    namespace: false,
                    limit: 3,
                    filters: vec![
                        ("label".into(), vec!["a=b".into()]),
                        ("status".into(), vec!["running".into()])
                    ],
                    ..Seen::default()
                }
            );

            // `ps --ns` reaches the engine; Docker's list has no such thing
            get(&app, "GET", "/libpod/containers/json?namespace=true").await;
            assert!(seen.lock().unwrap().namespace);
            get(&app, "GET", "/v1.41/containers/json?namespace=true").await;
            assert!(!seen.lock().unwrap().namespace);

            // Docker's: no `last`, the limit is the limit
            get(&app, "GET", "/v1.41/containers/json?limit=4").await;
            let s = seen.lock().unwrap().clone();
            assert!(!s.libpod && s.limit == 4 && !s.all);

            let (status, _, body) = get(
                &app,
                "GET",
                "/v1.43/images/json?filter=alpine&all=1&shared-size=true",
            )
            .await;
            assert_eq!(status, 200);
            assert_eq!(json(&body).as_array().unwrap().len(), 2);
            let s = seen.lock().unwrap().clone();
            assert!(s.all && !s.libpod);
            assert_eq!(s.filters, vec![("reference".to_string(), vec!["alpine".to_string()])]);
            // Docker's summary of 1.43: the shared size asked for, the
            // virtual size
            let first = &json(&body)[0];
            assert_eq!(
                (&first["Id"], &first["SharedSize"], &first["VirtualSize"]),
                (
                    &serde_json::json!(format!("sha256:{:064}", 0)),
                    &serde_json::json!(0),
                    &serde_json::json!(7)
                )
            );
            let (_, _, body) = get(&app, "GET", "/images/json").await;
            assert_eq!(json(&body)[0]["SharedSize"], -1);
            assert!(json(&body)[0].get("VirtualSize").is_none());

            // libpod's list takes no Docker `filter`, and has the manifest
            // lists
            let (_, _, body) = get(&app, "GET", "/libpod/images/json").await;
            let s = seen.lock().unwrap().clone();
            assert!(s.libpod && s.filters.is_empty());
            assert_eq!(json(&body)[0]["Id"], format!("{:064}", 0));

            // parameters podman's decoder refuses: the 500 of libpod, the 400 of Docker
            let (status, _, body) = get(&app, "GET", "/libpod/containers/json?all=maybe").await;
            assert_eq!(status, 500);
            assert!(json(&body)["cause"].as_str().unwrap().contains("all"));
            let (status, _, _) = get(&app, "GET", "/v1.41/containers/json?all=maybe").await;
            assert_eq!(status, 400);
            let (status, _, body) = get(&app, "GET", "/libpod/containers/json?filters=notjson").await;
            assert_eq!(status, 500);
            assert!(json(&body)["message"].as_str().unwrap().contains("filters"));
        })
        .await;
}

/// A document too large for the reply comes through the pipe, whole, with the
/// length the engine said and the newline of the end.
#[tokio::test]
async fn a_large_document_is_a_pipe_and_arrives_whole() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(5000);
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            let (status, headers, body) = get(&app, "GET", "/libpod/containers/json").await;
            assert_eq!(status, 200);
            let docs = json(&body);
            let docs = docs.as_array().unwrap();
            assert_eq!(docs.len(), 5000);
            // (libpod's list is the engine's reversed: the oldest first)
            assert_eq!(docs[4999]["Names"][0], "c0");
            assert_eq!(docs[0]["Names"][0], "c4999");
            assert_eq!(
                headers["content-length"].to_str().unwrap(),
                body.len().to_string()
            );
            assert!(body.len() > INLINE_MAX);
            let (status, _, body) = get(&app, "GET", "/images/json").await;
            assert_eq!(status, 200);
            assert_eq!(json(&body).as_array().unwrap().len(), 5000);
        })
        .await;
}

#[tokio::test]
async fn the_errors_of_the_engine_are_podmans() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (mut m, _) = mock(0);
            m.fail = true;
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            let (status, _, body) = get(&app, "GET", "/libpod/containers/json").await;
            assert_eq!(status, 500);
            let e = json(&body);
            assert_eq!(e["cause"], "boom");
            assert_eq!(e["message"], "failed: boom");
            assert_eq!(e["response"], 500);
            let (status, _, body) = get(&app, "GET", "/_ping").await;
            assert_eq!(status, 500);
            assert!(json(&body)["message"]
                .as_str()
                .unwrap()
                .contains("told to fail"));
        })
        .await;
}

#[tokio::test]
async fn an_engine_that_is_absent_or_of_another_version_is_a_503() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let app = router(Engine::new(&socket));
            let (status, _, body) = get(&app, "GET", "/_ping").await;
            assert_eq!(status, 503);
            let message = json(&body)["message"].as_str().unwrap().to_string();
            assert!(message.contains("engine.sock"), "{message}");

            let (mut m, _) = mock(0);
            m.version = "0.0.1".into();
            serve(&socket, m);
            let (status, _, body) = get(&app, "GET", "/libpod/images/json").await;
            assert_eq!(status, 503);
            let message = json(&body)["message"].as_str().unwrap().to_string();
            // (asked to start again from the binary installed, it says it is
            // that one: this frontend is the one to restart)
            assert!(
                message.contains("0.0.1") && message.contains("restart this frontend"),
                "{message}"
            );
        })
        .await;
}

/// Many requests at once wait for a connection to the engine rather than
/// failing: no more than MAX_CALLS calls are in progress at once (the engine
/// refuses the connections above a limit of its own).
#[tokio::test]
async fn many_requests_at_once_wait_for_the_engine() {
    use velarx_api::engine::MAX_CALLS;
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (mut m, _) = mock(0);
            m.slow = std::time::Duration::from_millis(20);
            let open = m.open.clone();
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            let answers =
                futures::future::join_all((0..3 * MAX_CALLS).map(|_| get(&app, "GET", "/_ping")))
                    .await;
            assert!(answers.iter().all(|(status, _, _)| *status == 200));
            let most = open.most.load(std::sync::atomic::Ordering::SeqCst);
            assert!(most <= MAX_CALLS && most > 1, "{most} calls at once");
        })
        .await;
}

/// Waits take their connections from a budget of their own: with 100 of them
/// in progress a start and a ping are answered, the waits up to the budget
/// are armed, and the next one is answered 429 at once.
#[tokio::test]
async fn waits_do_not_take_the_connections_of_other_requests() {
    use velarx_api::engine::MAX_WAITS;
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            serve(&socket, m);
            let engine = Engine::new(&socket);
            let mut armed = Vec::new();
            for _ in 0..100 {
                armed.push(engine.container_wait("hang", Vec::new(), 0).await.unwrap());
            }
            assert!(engine.container_start("abc", &[]).await.is_ok());
            engine.ping().await.unwrap();
            for _ in 100..MAX_WAITS {
                armed.push(engine.container_wait("hang", Vec::new(), 0).await.unwrap());
            }
            let refused = engine
                .container_wait("hang", Vec::new(), 0)
                .await
                .err()
                .unwrap();
            assert_eq!(refused.status, 429, "{}", refused.message);
            // the short calls still have their connections
            engine.ping().await.unwrap();
            // a wait that ends gives its connection back
            drop(armed.pop());
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while engine.container_wait("hang", Vec::new(), 0).await.is_err() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the connection of the wait that ended is free again");
        })
        .await;
}

/// A short call that finds every connection of its budget busy waits for one
/// for a while, then is answered 503 rather than waiting for ever.
#[tokio::test]
async fn a_request_without_a_connection_is_answered_503() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (mut m, _) = mock(0);
            m.slow = std::time::Duration::from_millis(600);
            serve(&socket, m);
            let engine = Engine::with_limits(&socket, 2, 2, std::time::Duration::from_millis(100));
            let answers = futures::future::join_all((0..4).map(|_| engine.ping())).await;
            let busy: Vec<_> = answers.iter().filter_map(|a| a.as_ref().err()).collect();
            assert_eq!(answers.iter().filter(|a| a.is_ok()).count(), 2);
            assert_eq!(busy.len(), 2);
            assert!(
                busy.iter().all(|e| e.status == 503),
                "{:?}",
                busy[0].message
            );
        })
        .await;
}

/// The lifecycle routes become the typed calls, and the answers are podman's:
/// 204, 304 for what was already so, the report of libpod's removal.
#[tokio::test]
async fn the_lifecycle_routes_are_typed_calls() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let calls = m.calls.clone();
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            let status = |r: (StatusCode, axum::http::HeaderMap, Vec<u8>)| r.0.as_u16();

            assert_eq!(
                status(get(&app, "GET", "/libpod/containers/abc/exists").await),
                204
            );
            let (st, _, body) = get(&app, "GET", "/libpod/containers/missing/exists").await;
            assert_eq!(st, 404);
            assert_eq!(json(&body)["cause"], "no such container");
            assert_eq!(
                status(get(&app, "GET", "/v1.41/containers/abc/exists").await),
                404
            );

            assert_eq!(
                status(get(&app, "POST", "/v1.41/containers/abc/start").await),
                204
            );
            assert_eq!(
                status(get(&app, "POST", "/libpod/containers/running/start").await),
                304
            );
            assert_eq!(
                status(
                    get(
                        &app,
                        "POST",
                        "/libpod/containers/stopped/stop?timeout=7&ignore=true"
                    )
                    .await
                ),
                304
            );
            assert_eq!(
                status(get(&app, "POST", "/v1.41/containers/abc/stop?t=5").await),
                204
            );
            assert_eq!(
                status(get(&app, "POST", "/v1.41/containers/abc/stop").await),
                204
            );
            assert_eq!(
                status(get(&app, "POST", "/libpod/containers/abc/kill?signal=TERM").await),
                204
            );
            assert_eq!(
                status(get(&app, "POST", "/libpod/containers/abc/kill").await),
                204
            );
            assert_eq!(
                status(get(&app, "POST", "/libpod/containers/abc/restart?timeout=2").await),
                204
            );
            assert_eq!(
                status(get(&app, "POST", "/libpod/containers/abc/pause").await),
                204
            );
            assert_eq!(
                status(get(&app, "POST", "/libpod/containers/abc/unpause").await),
                204
            );
            assert_eq!(
                status(get(&app, "POST", "/libpod/containers/abc/rename?name=new").await),
                204
            );
            let (st, _, body) = get(
                &app,
                "POST",
                "/libpod/containers/abc/wait?condition=stopped&condition=exited",
            )
            .await;
            assert_eq!((st.as_u16(), body.as_slice()), (200, b"3\n".as_slice()));
            let (st, _, body) = get(
                &app,
                "POST",
                // (a negative interval: Go reads it, the wait polls nothing)
                "/libpod/containers/abc/wait?condition=next-exit&interval=-1s",
            )
            .await;
            assert_eq!((st.as_u16(), body.as_slice()), (200, b"3\n".as_slice()));
            // what the frontend cannot map is refused before any call
            for uri in [
                "/v1.41/containers/abc/wait?condition=running",
                "/v1.41/containers/abc/wait?condition=next_exit",
            ] {
                assert_eq!(status(get(&app, "POST", uri).await), 400, "{uri}");
            }
            assert_eq!(
                status(get(&app, "POST", "/libpod/containers/abc/wait?interval=soon").await),
                500
            );
            // Docker's three, its default `not-running`
            for (uri, called) in [
                ("/v1.41/containers/abc/wait", "NotRunning"),
                ("/v1.41/containers/abc/wait?condition=next-exit", "NextExit"),
                ("/v1.41/containers/abc/wait?condition=removed", "Removed"),
            ] {
                let (st, _, body) = get(&app, "POST", uri).await;
                assert_eq!(st, 200, "{uri}");
                assert_eq!(
                    json(&body),
                    serde_json::json!({"StatusCode": 3, "Error": null}),
                    "{uri}"
                );
                let last = calls.lock().unwrap().last().cloned().unwrap();
                assert_eq!(last, format!("wait abc [{called}] 0 true"));
                calls.lock().unwrap().pop();
            }

            // libpod reports every container removed, Docker answers 204
            let (st, _, body) = get(
                &app,
                "DELETE",
                "/libpod/containers/abc?force=true&depend=true&timeout=4&v=1",
            )
            .await;
            assert_eq!(st, 200);
            assert_eq!(
                json(&body),
                serde_json::json!([
                    {"Id": "dep"},
                    {"Id": "abc"}
                ])
            );
            // (Docker's removal gives no time either, nor does `t` or
            // `timeout` change it: the container's own, as podman's)
            assert_eq!(
                status(get(&app, "DELETE", "/v1.41/containers/abc?v=true&depend=true").await),
                204
            );
            assert_eq!(
                status(
                    get(
                        &app,
                        "DELETE",
                        "/v1.41/containers/abc?force=1&t=1&timeout=1"
                    )
                    .await
                ),
                204
            );
            // (libpod without a timeout: the container's own)
            assert_eq!(
                status(get(&app, "DELETE", "/libpod/containers/abc?force=true").await),
                200
            );
            assert_eq!(
                status(get(&app, "DELETE", "/v1.41/containers/abc?link=true").await),
                400
            );
            assert_eq!(
                status(get(&app, "DELETE", "/libpod/containers/abc?force=maybe").await),
                400
            );

            assert_eq!(
                calls.lock().unwrap().clone(),
                [
                    "exists abc",
                    "exists missing",
                    "start abc [] None None",
                    "start running [] None None",
                    "stop stopped Some(7) false",
                    "stop abc Some(5) false",
                    "stop abc None false",
                    "kill abc Some(\"TERM\")",
                    "kill abc None",
                    "restart abc Some(2) []",
                    "pause abc true None",
                    "pause abc false None",
                    "rename abc new",
                    "wait abc [Stopped, Exited] 0 true",
                    "wait abc [NextExit] 0 true",
                    "remove abc true false false true Some(4)",
                    "remove abc false true false false None",
                    "remove abc true false false false None",
                    "remove abc true false false false None",
                ]
            );
        })
        .await;
}

/// The image routes become typed calls, with libpod's and Docker's answers.
#[tokio::test]
async fn the_image_routes_are_typed_calls() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let calls = m.calls.clone();
            serve(&socket, m);
            let app = router(Engine::new(&socket));

            let (st, _, _) = get(&app, "GET", "/libpod/images/quay.io/a/b:1/exists").await;
            assert_eq!(st, 204);
            let (st, _, body) = get(&app, "GET", "/v1.43/images/alpine/json").await;
            assert_eq!(
                (st.as_u16(), json(&body)["Id"].as_str()),
                (200, Some("sha256:alpine"))
            );
            // Docker's of 1.43 still has the configuration of a container
            assert!(json(&body).get("ContainerConfig").is_some());
            let (st, _, _) = get(&app, "POST", "/v1.41/images/alpine/tag?repo=r&tag=").await;
            assert_eq!(st, 201);
            let (st, _, _) = get(&app, "POST", "/libpod/images/alpine/tag").await;
            assert_eq!(st, 400);
            let (st, _, _) = get(&app, "POST", "/libpod/images/alpine/untag").await;
            assert_eq!(st, 201);
            let (st, _, body) = get(&app, "DELETE", "/libpod/images/alpine?force=1").await;
            assert_eq!(st, 200);
            assert_eq!(
                json(&body),
                serde_json::json!({"Deleted": ["abc"], "Untagged": ["a:1"], "Errors": [], "ExitCode": 0})
            );
            let (_, _, body) = get(&app, "DELETE", "/v1.41/images/alpine?noprune=true").await;
            assert_eq!(
                json(&body),
                serde_json::json!([{"Untagged": "a:1"}, {"Deleted": "sha256:abc"}])
            );
            let (_, _, body) = get(&app, "POST", "/libpod/images/prune?all=true").await;
            assert_eq!(json(&body), serde_json::json!([{"Id": "abc", "Err": null, "Size": 7}]));
            let (_, _, body) = get(&app, "POST", "/v1.41/images/prune?filters=%7B%22dangling%22%3A%5B%22false%22%5D%2C%22label%22%3A%5B%22a%22%5D%7D").await;
            assert_eq!(
                json(&body),
                serde_json::json!({"ImagesDeleted": [{"Deleted": "abc"}], "SpaceReclaimed": 7})
            );
            assert_eq!(
                calls.lock().unwrap().clone(),
                [
                    "image exists quay.io/a/b:1",
                    "image inspect alpine",
                    "image tag alpine r latest true",
                    "image untag alpine []",
                    "image remove alpine true false false false false",
                    "image remove alpine false true true false false",
                    "image prune true []",
                    "image prune true [\"label=a\"]",
                ]
            );
            // a prune of thousands, one a reply
            let (_, _, body) = get(&app, "POST", "/libpod/images/prune?filters=%7B%22label%22%3A%5B%22many%22%5D%7D").await;
            assert_eq!(json(&body).as_array().unwrap().len(), 3000);
        })
        .await;
}

/// The pulls and the pushes: velarx-api writes podman's and Docker's lines
/// of the records the engine answers as they come.
#[tokio::test]
async fn the_pulls_and_pushes_are_podmans_lines_of_the_records() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let calls = m.calls.clone();
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            let lines = |body: &[u8]| -> Vec<serde_json::Value> {
                body.split(|b| *b == b'\n')
                    .filter(|l| !l.is_empty())
                    .map(json)
                    .collect()
            };
            let (st, _, body) = get(&app, "POST", "/libpod/images/pull?reference=quay.io/a:1").await;
            assert_eq!(st, 200);
            let blob = format!("sha256:{}", "ab".repeat(32));
            assert_eq!(
                lines(&body),
                [
                    serde_json::json!({"stream": "Trying to pull quay.io/a:1...\n"}),
                    serde_json::json!({"stream": format!("Copying blob {blob}\n")}),
                    serde_json::json!({"stream": "Writing manifest to image destination\n"}),
                    serde_json::json!({"images": ["iid"], "id": "iid"}),
                ]
            );
            let (st, _, body) =
                get(&app, "POST", "/v1.41/images/create?fromImage=quay.io/a&tag=1").await;
            assert_eq!(st, 200);
            assert_eq!(
                lines(&body),
                [
                    serde_json::json!({"status": "Pulling fs layer", "progressDetail": {}, "id": "abababababab"}),
                    serde_json::json!({"status": "Downloading", "progressDetail": {"current": 1, "total": 2}, "id": "abababababab"}),
                    serde_json::json!({"status": "Download complete", "progressDetail": {}, "id": "iid"}),
                ]
            );
            // a pull that fails before its progress is the error of the
            // answer; Docker's has the words of the registry alone
            let (st, _, body) =
                get(&app, "POST", "/libpod/images/pull?reference=quay.io/nosuch").await;
            assert_eq!(st, 404);
            assert!(json(&body)["message"]
                .as_str()
                .unwrap()
                .contains("MANIFEST_UNKNOWN"));
            let (st, _, body) =
                get(&app, "POST", "/v1.41/images/create?fromImage=quay.io/nosuch").await;
            assert_eq!(st, 404);
            assert_eq!(
                json(&body),
                serde_json::json!({"message": "manifest unknown: manifest unknown"})
            );

            let (st, _, body) = get(
                &app,
                "POST",
                "/libpod/images/quay.io%2Fa:1/push?destination=quay.io/b:2",
            )
            .await;
            assert_eq!(st, 200);
            assert_eq!(
                lines(&body),
                [
                    serde_json::json!({"stream": "Pushing quay.io/b:2\n"}),
                    serde_json::json!({"stream": "Writing manifest to image destination\n"}),
                    serde_json::json!({"manifestdigest": "sha256:d"}),
                ]
            );
            let (st, _, body) = get(&app, "POST", "/v1.41/images/quay.io%2Fa/push?tag=1").await;
            assert_eq!(st, 200);
            let docker = lines(&body);
            assert_eq!(
                docker[0]["status"],
                "The push refers to repository [quay.io/a]"
            );
            assert_eq!(
                docker[1]["aux"],
                serde_json::json!({"Tag": "1", "Digest": "sha256:d", "Size": 7})
            );
            // (Docker's push that fails: podman's stream, the status 500; an
            // image that is not there: podman's error document of its lookup)
            let (st, _, body) = get(&app, "POST", "/v1.41/images/quay.io%2Frefused/push").await;
            assert_eq!(st, 500);
            assert_eq!(
                lines(&body),
                [serde_json::json!({
                    "error": "x509: certificate signed by unknown authority",
                    "errorDetail": {"message": "x509: certificate signed by unknown authority"},
                })]
            );
            let (st, _, body) = get(&app, "POST", "/v1.41/images/nosuch/push?tag=t").await;
            assert_eq!(st, 404);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({
                    "cause": "image not known",
                    "message": "failed to find image nosuch:t: nosuch:t: image not known",
                    "response": 404,
                })
            );
            let calls = calls.lock().unwrap().clone();
            for call in [
                "image pull quay.io/a:1 false false 0",
                "image pull quay.io/a:1 true false 0",
                "image push quay.io/a:1 Some(\"quay.io/b:2\") false 0",
            ] {
                assert!(calls.contains(&call.to_string()), "{call}: {calls:?}");
            }
        })
        .await;
}

/// The system routes: the query becomes the arguments, the answers are
/// those of the engine's documents, a login that fails is podman's 500.
#[tokio::test]
async fn the_system_routes_are_typed_calls() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let calls = m.calls.clone();
            serve(&socket, m);
            let app = router(Engine::new(&socket));

            let (st, _, body) = get(&app, "GET", "/version").await;
            let v = json(&body);
            assert_eq!(
                (st.as_u16(), v["Version"].as_str(), v["Arch"].as_str()),
                (200, Some("6.1"), Some("amd64"))
            );
            let (st, _, body) = get(&app, "GET", "/v1.44/info").await;
            assert_eq!((st.as_u16(), json(&body)["Containers"].as_u64()), (200, Some(3)));
            let (st, _, body) = get(&app, "GET", "/libpod/info").await;
            assert_eq!(
                (st.as_u16(), json(&body)["store"]["graphRoot"].as_str()),
                (200, Some("/s"))
            );
            let (st, _, body) = get(&app, "GET", "/v1.52/system/df").await;
            assert_eq!((st.as_u16(), json(&body)["ImageUsage"]["TotalSize"].as_u64()), (200, Some(7)));
            let (_, _, body) = get(&app, "GET", "/libpod/system/df").await;
            assert_eq!(json(&body)["ImagesSize"], 7);
            let (st, _, body) = get(
                &app,
                "POST",
                "/libpod/system/prune?all=true&volumes=1&build=true&filters=%7B%22label%22%3A%5B%22a%22%5D%7D",
            )
            .await;
            assert_eq!(st, 200);
            assert_eq!(json(&body)["ContainerPruneReports"][0]["Id"], "c1");
            assert_eq!(json(&body)["ReclaimedSpace"], 5);
            let (st, _, body) = get(
                &app,
                "POST",
                "/libpod/system/check?quick=true&repair=1&unreferenced_layer_max_age=1m30s",
            )
            .await;
            assert_eq!(st, 200);
            assert_eq!(json(&body)["Errors"], false);
            let (st, _, body) = get(
                &app,
                "POST",
                "/libpod/system/check?unreferenced_layer_max_age=1d",
            )
            .await;
            assert_eq!(st, 400);
            assert!(json(&body)["message"]
                .as_str()
                .unwrap()
                .starts_with("failed to parse unreferenced_layer_max_age parameter \"1d\""));
            let (st, _, body) = get(&app, "GET", "/libpod/metrics/descriptors").await;
            assert_eq!(
                (st.as_u16(), json(&body)[0]["name"].as_str()),
                (200, Some("m"))
            );
            let (_, _, body) = get(&app, "GET", "/libpod/pods/metrics").await;
            assert_eq!(json(&body)[0]["name"], "");
            let (_, _, body) = get(&app, "GET", "/libpod/pods/p1/metrics").await;
            assert_eq!(json(&body)[0]["name"], "p1");
            let (st, _, body) = get(
                &app,
                "GET",
                "/v1.41/distribution/quay.io/a/b:1/json?tlsVerify=false",
            )
            .await;
            assert_eq!(st.as_u16(), 200);
            // (podman's document: OCI's descriptor and platforms, without what is empty)
            assert_eq!(
                json(&body),
                serde_json::json!({
                    "Descriptor": {
                        "mediaType": "application/vnd.oci.image.index.v1+json",
                        "digest": "quay.io/a/b:1",
                        "size": 7
                    },
                    "Platforms": [
                        {"architecture": "amd64", "os": "linux"},
                        {"architecture": "arm64", "os": "linux", "variant": "v8", "features": ["f"]}
                    ]
                })
            );
            assert_eq!(
                calls.lock().unwrap().clone(),
                [
                    "version inspect",
                    "system inspect",
                    "system inspect",
                    "disk usage inspect false",
                    "disk usage inspect false",
                    "system prune true true true [\"label\"]",
                    "system check true true false Some(90000)",
                    "pods metrics None",
                    "pods metrics Some(\"p1\")",
                    "image distribution quay.io/a/b:1 false",
                ]
            );
        })
        .await;
}

/// The system df of an empty store is podman's text: the members of its
/// report in the order of its struct (podman's test-apiv2 compares the
/// body as a string), a sorted map would not do.
#[tokio::test]
async fn the_system_df_of_an_empty_store_is_podman_s_text() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (mut m, _) = mock(0);
            m.empty_usage = true;
            serve(&socket, m);
            let app = router(Engine::new(&socket));

            let (st, _, body) = get(&app, "GET", "/v1.44/system/df").await;
            assert_eq!(
                (
                    st.as_u16(),
                    String::from_utf8_lossy(&body).into_owned()
                ),
                (
                    200,
                    "{\"LayersSize\":0,\"Images\":[],\"Containers\":[],\"Volumes\":[],\"BuildCache\":[]}\n".to_string()
                )
            );
            let (st, _, body) = get(&app, "GET", "/libpod/system/df").await;
            assert_eq!(
                (
                    st.as_u16(),
                    String::from_utf8_lossy(&body).into_owned()
                ),
                (
                    200,
                    "{\"ImagesSize\":0,\"Images\":[],\"Containers\":[],\"Volumes\":[]}\n".to_string()
                )
            );
        })
        .await;
}

/// The events are podman's or Docker's lines of the records, from the
/// times of the query or of the filters.
#[tokio::test]
async fn the_events_are_the_lines_of_the_records() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let calls = m.calls.clone();
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            let lines = |body: &[u8]| -> Vec<serde_json::Value> {
                String::from_utf8_lossy(body).lines().map(|l| json(l.as_bytes())).collect()
            };

            let (st, _, body) = get(
                &app,
                "GET",
                "/v1.41/events?stream=false&since=2&filters=%7B%22event%22%3A%5B%22die%22%5D%2C%22until%22%3A%5B%223%22%5D%7D",
            )
            .await;
            let docker = lines(&body);
            assert_eq!((st.as_u16(), docker.len()), (200, 2), "{docker:?}");
            assert_eq!((docker[0]["Action"].as_str(), docker[0]["status"].as_str()), (Some("die"), Some("die")));
            assert_eq!(docker[0]["time"], 1);
            // (podman's API leaves out the end of a lazy pull)
            let (st, _, body) = get(&app, "GET", "/v4.0.0/libpod/events").await;
            let libpod = lines(&body);
            assert_eq!((st.as_u16(), libpod.len()), (200, 1), "{libpod:?}");
            assert_eq!(libpod[0]["Action"], "died");
            assert_eq!(libpod[0]["Actor"]["Attributes"]["containerExitCode"], "0");
            let (st, _, body) = get(&app, "GET", "/v1.52/events?stream=false").await;
            assert_eq!(st, 200);
            assert!(lines(&body)[0].get("status").is_none());
            let (st, _, body) = get(&app, "GET", "/libpod/events?since=yesterday").await;
            assert_eq!(st, 400);
            assert_eq!(
                json(&body)["message"],
                "failed to parse event filters: invalid since `yesterday`"
            );
            assert_eq!(
                calls.lock().unwrap().clone(),
                [
                    "event list true [\"event\"] Some(2000000000) Some(3000000000) false",
                    "event list true [] None None true",
                    "event list true [] None None false",
                ]
            );
        })
        .await;
}

/// A top is the typed call, with Docker's default arguments of ps and
/// podman's limit of the delay.
#[tokio::test]
async fn a_top_is_the_typed_call() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let calls = m.calls.clone();
            serve(&socket, m);
            let app = router(Engine::new(&socket));

            let (st, _, body) = get(&app, "GET", "/v1.41/containers/c1/top").await;
            assert_eq!(st, 200);
            assert_eq!(
                json(&body),
                serde_json::json!({"Processes": [["1"]], "Titles": ["PID"]})
            );
            let (st, _, _) = get(
                &app,
                "GET",
                "/libpod/containers/c1/top?ps_args=pid&ps_args=args",
            )
            .await;
            assert_eq!(st, 200);
            // (a container that does not run: a failure, not a conflict)
            let (st, _, body) = get(&app, "GET", "/libpod/containers/gone/top").await;
            assert_eq!(st, 500, "{}", String::from_utf8_lossy(&body));
            let (st, _, body) = get(&app, "GET", "/libpod/containers/c1/top?delay=0").await;
            assert_eq!(
                (st.as_u16(), json(&body)["message"].as_str()),
                (400, Some("\"delay\" parameter of value 0 < 1"))
            );
            // a stream: a line now, the next after the delay
            let req = Request::builder()
                .uri("/libpod/containers/c1/top?stream=true&delay=1")
                .body(Body::empty())
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), 200);
            let mut data = res.into_body().into_data_stream();
            let line = futures::StreamExt::next(&mut data).await.unwrap().unwrap();
            assert_eq!(
                &line[..],
                b"{\"Processes\":[[\"1\"]],\"Titles\":[\"PID\"]}\n"
            );
            drop(data);
            let (st, _, body) = get(&app, "GET", "/libpod/containers/c1/healthcheck").await;
            let health = json(&body);
            assert_eq!(
                (st.as_u16(), health["Status"].as_str()),
                (200, Some("healthy"))
            );
            assert_eq!(health["Log"][0]["End"], "1970-01-01T00:00:02Z");
            let (st, _, body) = get(&app, "GET", "/libpod/pods/p1/top?ps_args=user%20pid").await;
            assert_eq!(
                (st.as_u16(), json(&body)["Titles"][0].as_str()),
                (200, Some("USER"))
            );
            assert_eq!(
                calls.lock().unwrap().clone(),
                [
                    "container top c1 [\"-ef\"]",
                    "container top c1 [\"pid\", \"args\"]",
                    "container top gone []",
                    "container top c1 []",
                    "container healthcheck c1",
                    "pod top p1 [\"user\", \"pid\"]",
                ]
            );
        })
        .await;
}

/// The stats are the samples of ContainerStats as podman's reports and
/// Docker's StatsJSON, a line each when they stream.
#[tokio::test]
async fn the_stats_are_the_samples_of_container_stats() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let calls = m.calls.clone();
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            let lines = |body: &[u8]| -> Vec<serde_json::Value> {
                String::from_utf8_lossy(body)
                    .lines()
                    .map(|l| json(l.as_bytes()))
                    .collect()
            };

            let (st, _, body) = get(
                &app,
                "GET",
                "/libpod/containers/stats?stream=false&size=true&containers=c1&containers=c2",
            )
            .await;
            let report = json(&body);
            assert_eq!(st, 200);
            assert!(report["Error"].is_null());
            assert_eq!(report["Stats"][1]["ContainerID"], "c2");
            assert_eq!(report["Stats"][0]["NetInput"], 100);
            // (a report each interval: the mock sends two)
            let (_, _, body) = get(&app, "GET", "/libpod/containers/stats?interval=2").await;
            let reports = lines(&body);
            assert_eq!(reports.len(), 2, "{reports:?}");
            assert_eq!(reports[1]["Stats"][0]["CPUNano"], 1_000_000_000);
            // Docker's: of a second sample, the first is its precpu
            let (st, _, body) = get(&app, "GET", "/v1.41/containers/c1/stats?stream=false").await;
            let docker = json(&body);
            assert_eq!(st, 200);
            assert_eq!(
                docker["precpu_stats"]["cpu_usage"]["total_usage"],
                500_000_000
            );
            assert_eq!(docker["cpu_stats"]["cpu"], 50.0);
            assert_eq!(docker["name"], "/c1");
            let (_, _, body) = get(
                &app,
                "GET",
                "/v1.41/containers/c1/stats?stream=false&one-shot=true",
            )
            .await;
            assert_eq!(json(&body)["precpu_stats"]["cpu_usage"]["total_usage"], 0);
            let (_, _, body) = get(&app, "GET", "/v1.41/containers/c1/stats").await;
            assert_eq!(lines(&body).len(), 2);
            let (st, _, _) = get(
                &app,
                "GET",
                "/v1.41/containers/c1/stats?stream=true&one-shot=true",
            )
            .await;
            assert_eq!(st, 400);
            let (st, _, _) = get(&app, "GET", "/v1.41/containers/stopped/stats?stream=false").await;
            assert_eq!(st, 409);
            // the pods: a row for each container, the infra first
            let (st, _, body) = get(&app, "GET", "/libpod/pods/stats?namesOrIDs=p1").await;
            let rows = json(&body);
            assert_eq!(st, 200);
            assert_eq!(
                (
                    rows[0]["CID"].as_str(),
                    rows[0]["Pod"].as_str(),
                    rows[0]["MemUsage"].as_str()
                ),
                (Some("infra"), Some("feedfacecafe"), Some("400B / 1kB"))
            );
            assert_eq!(rows[1]["MemUsage"], "-- / --");
            let (st, _, _) = get(&app, "GET", "/libpod/pods/stats?namesOrIDs=p1&all=true").await;
            assert_eq!(st, 500);
            assert_eq!(
                calls.lock().unwrap().clone(),
                [
                    "container stats true [\"c1\", \"c2\"] false true false Some(5000)",
                    "container stats true [] false false true Some(2000)",
                    "container stats true [\"c1\"] false false true Some(100)",
                    "container stats true [\"c1\"] false false false Some(100)",
                    "container stats true [\"c1\"] false false true Some(1000)",
                    "container stats true [\"stopped\"] false false true Some(100)",
                    "pod inspect p1",
                    "container stats true [\"infra\", \"stopped\"] true false false None",
                ]
            );
        })
        .await;
}

/// A login is checked by the frontend as podman checks it, and the engine
/// logs in to the registry of the server address.
#[tokio::test]
async fn a_login_is_podmans_answer() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let calls = m.calls.clone();
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            let login = |body: &'static str| {
                let app = app.clone();
                async move {
                    let req = Request::builder()
                        .method("POST")
                        .uri("/v1.41/auth")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap();
                    let res = app.oneshot(req).await.unwrap();
                    let (parts, body) = res.into_parts();
                    let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap();
                    (parts.status.as_u16(), json(&bytes))
                }
            };
            let (st, body) = login(
                r#"{"username":"u","password":"p","serveraddress":"https://index.docker.io/v1/"}"#,
            )
            .await;
            assert_eq!(
                (st, body["Status"].as_str()),
                (200, Some("Login Succeeded"))
            );
            let (st, body) =
                login(r#"{"username":"bad","password":"p","serveraddress":"localhost:5000"}"#)
                    .await;
            assert_eq!(st, 500);
            assert_eq!(
                body["message"],
                "login attempt to localhost:5000 failed with status: 401 Unauthorized"
            );
            let (st, body) = login(r#"{"password":"p","serveraddress":"localhost:5000"}"#).await;
            assert_eq!(st, 500);
            assert!(body["message"]
                .as_str()
                .unwrap()
                .ends_with("cannot prompt for username without stdin"));
            let (st, _) =
                login(r#"{"username":"u","password":"p","serveraddress":"bad host"}"#).await;
            assert_eq!(st, 400);
            assert_eq!(
                calls.lock().unwrap().clone(),
                [
                    "registry login registry-1.docker.io u p",
                    "registry login localhost:5000 bad p"
                ]
            );
        })
        .await;
}

/// What a call carries (registry credentials, the data of a secret) is
/// never written to the logs, whatever the level: a subscriber at trace
/// level sees the calls of a login, a pull with credentials and a secret
/// and not one of their secrets.
#[tokio::test]
async fn the_secrets_of_a_call_are_not_logged_at_trace_level() {
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    // (the global subscriber: the callsites the other tests of this binary
    // reached with none would stay disabled for a thread-local one)
    let sink = Sink::default();
    let writer = sink.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish(),
    )
    .unwrap();
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let calls = m.calls.clone();
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            let post = |uri: &'static str, body: &'static str| {
                let app = app.clone();
                async move {
                    let req = Request::builder()
                        .method("POST")
                        .uri(uri)
                        .body(Body::from(body))
                        .unwrap();
                    app.oneshot(req).await.unwrap().status().as_u16()
                }
            };
            assert_eq!(
                post(
                    "/v1.41/auth",
                    r#"{"username":"u","password":"PW-LOGIN-4f1c","serveraddress":"localhost:5000"}"#
                )
                .await,
                200
            );
            assert_eq!(
                post("/libpod/secrets/create?name=s", "SECRET-DATA-9d2e").await,
                200
            );
            // the data shown is the body's, never the log's
            let (st, _, body) = get(&app, "GET", "/libpod/secrets/s/json?showsecret=true").await;
            assert_eq!(st.as_u16(), 200);
            assert_eq!(json(&body)["SecretData"], "SHOWN-DATA-6e1f");
            let (_, _, body) = get(&app, "GET", "/libpod/secrets/s/json").await;
            assert!(json(&body).get("SecretData").is_none());
            // (Docker's route too, as podman's)
            let (_, _, body) = get(&app, "GET", "/v1.41/secrets/s?showsecret=true").await;
            assert_eq!(json(&body)["SecretData"], "SHOWN-DATA-6e1f");
            let (_, _, body) = get(&app, "GET", "/v1.41/secrets/s").await;
            assert!(json(&body).get("SecretData").is_none());
            let mut conn = velarx_proto::connect::connect_checked(&socket)
                .await
                .unwrap();
            let access = velarx_registry::auth::RegistryAccess {
                creds: Some(velarx_registry::Credentials {
                    username: "u".into(),
                    password: "PW-PULL-77aa".into(),
                    identity_token: Some("IDTOKEN-52cc".into()),
                    registry_token: Some("REGTOKEN-68dd".into()),
                }),
                ..Default::default()
            };
            let spec = PullSpec {
                source: "localhost:5000/a".into(),
                ..Default::default()
            };
            let (at, fds) = access.sealed().unwrap();
            conn.image_pull(spec, at, fds).await.unwrap().unwrap();
            let debug = format!("{access:?}");
            assert!(debug.contains("username") && !debug.contains("PW-PULL"), "{debug}");
            let calls = calls.lock().unwrap().clone();
            assert!(
                calls.contains(&"image pull localhost:5000/a false true 1".to_string()),
                "{calls:?}"
            );
        })
        .await;
    let log = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    assert!(
        log.contains("TRACE") && log.contains("sending call"),
        "the trace logs are not captured: {log}"
    );
    for secret in [
        "PW-LOGIN-4f1c",
        "SECRET-DATA-9d2e",
        "SHOWN-DATA-6e1f",
        "PW-PULL-77aa",
        "IDTOKEN-52cc",
        "REGTOKEN-68dd",
    ] {
        assert!(!log.contains(secret), "{secret} is in the log:\n{log}");
    }
}

/// The network, volume and secret routes decode their bodies into typed
/// calls (the libpod and Docker forms of a create), and answer as podman.
#[tokio::test]
async fn the_network_volume_and_secret_routes_are_typed_calls() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let calls = m.calls.clone();
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            let post = |app: axum::Router, uri: &'static str, body: &'static str| async move {
                let req = Request::builder()
                    .method("POST")
                    .uri(uri)
                    .body(Body::from(body))
                    .unwrap();
                let res = app.oneshot(req).await.unwrap();
                let status = res.status().as_u16();
                let bytes = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
                (status, bytes.to_vec())
            };

            // libpod: the first IPv4 and IPv6 subnet, the lease range, the driver options
            let (st, body) = post(
                app.clone(),
                "/v4.0.0/libpod/networks/create",
                r#"{"name":"n","subnets":[{"subnet":"10.1.0.0/24","gateway":"10.1.0.1","lease_range":{"start_ip":"10.1.0.5","end_ip":"10.1.0.9"}},{"subnet":"fd00::/64","gateway":"fd00::1"}],"options":{"mtu":"1400"}}"#,
            )
            .await;
            assert_eq!(st, 200);
            assert_eq!(json(&body)["name"], "n");
            // Docker: 201 with the id; its IPRange is a CIDR
            let (st, body) = post(
                app.clone(),
                "/v1.41/networks/create",
                r#"{"Name":"d","Driver":"bridge","IPAM":{"Config":[{"Subnet":"10.2.0.0/16","IPRange":"10.2.1.0/30"}]}}"#,
            )
            .await;
            assert_eq!(st, 201);
            assert_eq!(json(&body), serde_json::json!({"Id": "nid", "Warning": ""}));
            // a version before 4 for libpod, a bad subnet (500, as podman's), an unknown option
            let (st, _) = post(app.clone(), "/v3.0.0/libpod/networks/create", "{}").await;
            assert_eq!(st, 400);
            let (st, _) = post(app.clone(), "/libpod/networks/create", r#"{"name":"x","subnets":[{"subnet":"nope"}]}"#).await;
            assert_eq!(st, 500);
            let (st, _) = post(app.clone(), "/libpod/networks/create", r#"{"name":"x","options":{"bogus":"1"}}"#).await;
            assert_eq!(st, 400);
            let (st, _, body) = get(&app, "DELETE", "/libpod/networks/n?force=1&timeout=3").await;
            assert_eq!((st.as_u16(), json(&body)), (200, serde_json::json!([{"Name": "n", "Err": null}])));
            // (podman's libpod route has no `ignore`: a network that is not there is a 404)
            let (st, _, _) = get(&app, "DELETE", "/libpod/networks/gone?ignore=true").await;
            assert_eq!(st, 404);
            assert_eq!(get(&app, "DELETE", "/v1.41/networks/n").await.0, 204);
            let (st, body) = post(
                app.clone(),
                "/libpod/networks/n/connect",
                r#"{"container":"c","static_ips":["10.1.0.7"],"aliases":["a"]}"#,
            )
            .await;
            assert_eq!((st, body.as_slice()), (200, b"OK\n".as_slice()));
            // an address of each family and a MAC address, in either API
            let (st, _) = post(
                app.clone(),
                "/libpod/networks/n6/connect",
                r#"{"container":"c","static_ips":["fd00::7","10.1.0.8"],"static_mac":"0a:00:00:00:00:07"}"#,
            )
            .await;
            assert_eq!(st, 200);
            let (st, _) = post(
                app.clone(),
                "/v1.41/networks/d6/connect",
                r#"{"Container":"c","EndpointConfig":{"IPAMConfig":{"IPv6Address":"fd00::9"},"MacAddress":"0a:00:00:00:00:09"}}"#,
            )
            .await;
            assert_eq!(st, 200);
            // the endpoint fields that podman drops are dropped
            let (st, _) = post(
                app.clone(),
                "/v1.41/networks/d6/connect",
                r#"{"Container":"c","EndpointConfig":{"Links":["x:y"],"DriverOpts":{"a":"b"},"GwPriority":2}}"#,
            )
            .await;
            assert_eq!(st, 200);
            for body in [
                r#"{"container":"c","static_ips":["10.1.0.8","10.1.0.9"]}"#,
                r#"{"container":"c","static_ips":["bogus"]}"#,
            ] {
                let (st, _) = post(app.clone(), "/libpod/networks/n6/connect", body).await;
                assert!(matches!(st, 400 | 501), "{body}: {st}");
            }
            let (st, _) = post(app.clone(), "/libpod/networks/n/connect", "{}").await;
            assert_eq!(st, 400);

            // volumes: Docker's list is an object
            let (_, _, body) = get(&app, "GET", "/v1.41/volumes").await;
            assert_eq!(json(&body)["Volumes"][0]["Name"], "v");
            let (_, _, body) = get(&app, "GET", "/libpod/volumes/json").await;
            assert_eq!(json(&body)[0]["Name"], "v");
            assert_eq!(get(&app, "DELETE", "/libpod/volumes/v?force=1&timeout=9").await.0, 204);
            assert_eq!(get(&app, "DELETE", "/libpod/volumes/v?timeout=x").await.0, 500);

            // secrets: libpod's body is the data, Docker's has it in base64
            let (st, body) = post(app.clone(), "/libpod/secrets/create?name=s&labels=%7B%22a%22%3A%22b%22%7D&replace=true", "hello").await;
            assert_eq!((st, json(&body)), (200, serde_json::json!({"ID": "sid"})));
            let (st, _) = post(app.clone(), "/v1.41/secrets/create", r#"{"Name":"d","Data":"aGk=","Labels":{"x":"y"}}"#).await;
            assert_eq!(st, 200);
            let (st, _) = post(app.clone(), "/v1.41/secrets/create", r#"{"Name":"d"}"#).await;
            assert_eq!(st, 400);
            // Docker's data is checked here: a bad encoding, a secret too
            // large (neither reaches the engine)
            let (st, _) = post(app.clone(), "/v1.41/secrets/create", r#"{"Name":"bad","Data":"!!"}"#).await;
            assert_eq!(st, 400);
            let big: &'static str = Box::leak(
                format!(r#"{{"Name":"big","Data":"{}"}}"#, "QUFB".repeat(512_000 / 3 + 1))
                    .into_boxed_str(),
            );
            let (st, _) = post(app.clone(), "/v1.41/secrets/create", big).await;
            assert_eq!(st, 413);
            // libpod's too: one byte more than a secret
            let lbig: &'static str = Box::leak("z".repeat(512_001).into_boxed_str());
            let (st, _) = post(app.clone(), "/libpod/secrets/create?name=lbig", lbig).await;
            assert_eq!(st, 413);
            let fits: &'static str = Box::leak("z".repeat(512_000).into_boxed_str());
            let (st, _) = post(app.clone(), "/libpod/secrets/create?name=fits", fits).await;
            assert_eq!(st, 200);

            let calls = calls.lock().unwrap().clone();
            assert_eq!(
                calls[0],
                "network create n Some(\"10.1.0.0/24\") Some(\"fd00::1\") Some((\"10.1.0.5\", \"10.1.0.9\")) [\"mtu\"] true false"
            );
            assert_eq!(
                calls[1],
                "network create d Some(\"10.2.0.0/16\") None Some((\"10.2.1.0\", \"10.2.1.3\")) [] true false"
            );
            assert!(calls.iter().any(|c| c.starts_with("secret create fits zzz")));
            for want in [
                "network remove n true None",
                "network remove gone false None",
                "network connect n c Some(\"10.1.0.7\") None None [\"a\"]",
                "network connect n6 c Some(\"10.1.0.8\") Some(\"fd00::7\") Some(\"0a:00:00:00:00:07\") []",
                "network connect d6 c None Some(\"fd00::9\") Some(\"0a:00:00:00:00:09\") []",
                "volume list 0",
                "volume remove v true Some(9)",
                "secret create s hello None 0 1 true false",
                "secret create d hi None 0 1 false false",
            ] {
                assert!(calls.iter().any(|c| c == want), "{want} in {calls:#?}");
            }
            assert!(
                !calls.iter().any(|c| c.starts_with("secret create bad") || c.starts_with("secret create big") || c.starts_with("secret create lbig")),
                "{calls:#?}"
            );
        })
        .await;
}

/// The pod routes: the body of a pod create goes to the
/// engine as text, an operation is a word, the reports are podman's.
#[tokio::test]
async fn the_pod_routes_are_typed_calls() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let calls = m.calls.clone();
            serve(&socket, m);
            let app = router(Engine::new(&socket));

            let req = Request::builder()
                .method("POST")
                .uri("/libpod/pods/create")
                .body(Body::from(
                    r#"{"name":"p","labels":{"a":"b"},"shared_namespaces":["net","pid"],
                    "portmappings":[{"container_port":80,"host_port":8080,"range":2}],
                    "restart_policy":"always","restart_tries":3,"infra_image":"pause"}"#,
                ))
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), 201);
            let body = axum::body::to_bytes(res.into_body(), 1 << 20)
                .await
                .unwrap();
            assert_eq!(json(&body), serde_json::json!({"Id": "pid"}));
            // (a body over the limit does not reach the engine: the API
            // server's 400 for a body over its own)
            let big = format!(
                r#"{{"name":"{}"}}"#,
                "x".repeat(velarx_proto::engine::MAX_POD_SPEC)
            );
            let req = Request::builder()
                .method("POST")
                .uri("/libpod/pods/create")
                .body(Body::from(big))
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), 400);
            let body = axum::body::to_bytes(res.into_body(), 1 << 20)
                .await
                .unwrap();
            assert_eq!(
                json(&body)["message"],
                "read the request body: length limit exceeded"
            );

            // what a pod cannot be is refused here, as the API server does
            let post = |body: &'static str| {
                let app = app.clone();
                async move {
                    let req = Request::builder()
                        .method("POST")
                        .uri("/libpod/pods/create")
                        .body(Body::from(body))
                        .unwrap();
                    app.oneshot(req).await.unwrap().status().as_u16()
                }
            };
            assert_eq!(post(r#"{"netns":{"nsmode":"weird"}}"#).await, 501);
            assert_eq!(post(r#"{"exit_policy":"never"}"#).await, 400);
            assert_eq!(post(r#"{"portmappings":[{"host_port":1}]}"#).await, 400);
            assert_eq!(post(r#"{"name":"#).await, 400);
            assert_eq!(post("[1]").await, 400);

            let (st, _, body) = get(&app, "POST", "/libpod/pods/p/stop?t=4").await;
            assert_eq!(
                (st.as_u16(), json(&body)),
                (200, serde_json::json!({"Errs": null, "Id": "pid"}))
            );
            assert_eq!(get(&app, "POST", "/libpod/pods/same/start").await.0, 304);
            let (st, _, body) = get(&app, "POST", "/libpod/pods/bad/restart").await;
            assert_eq!(
                (st.as_u16(), json(&body)),
                (409, serde_json::json!({"Errs": ["boom"], "Id": "pid"}))
            );
            // (the digests typed go to the engine, once for each)
            assert_eq!(
                get(
                    &app,
                    "POST",
                    "/libpod/pods/p/start?verify_image=sha256:aa&verify_image=sha256:bb"
                )
                .await
                .0,
                200
            );
            assert_eq!(
                get(&app, "POST", "/libpod/pods/p/kill?signal=TERM").await.0,
                200
            );
            let (st, _, body) = get(&app, "DELETE", "/libpod/pods/p?force=true&timeout=2").await;
            assert_eq!(st, 200);
            assert_eq!(
                json(&body),
                serde_json::json!({"Err": null, "Id": "pid", "RemovedCtrs": {"c1": null}})
            );
            // (no time given: the stop timeout of each container)
            assert_eq!(get(&app, "DELETE", "/libpod/pods/p?force=true").await.0, 200);
            assert_eq!(
                get(&app, "DELETE", "/libpod/pods/p?force=true&timeout=0").await.0,
                200
            );
            // (Docker has no pods)
            assert_eq!(get(&app, "GET", "/v1.41/pods/json").await.0, 404);

            assert_eq!(
                calls.lock().unwrap().clone(),
                [
                    "pod create p {\"a\": \"b\"} ports=2 net=true pid=true ipc=false restart=Some((\"always\", 3)) infra=Some(\"pause\")",
                    "pod stop p Some(4) None [] None",
                    "pod start same None None [] None",
                    "pod restart bad None None [] None",
                    "pod start p None None [\"sha256:aa\", \"sha256:bb\"] None",
                    "pod kill p None Some(\"TERM\") [] None",
                    "pod remove p true Some(2)",
                    "pod remove p true None",
                    "pod remove p true Some(0)",
                ]
            );
        })
        .await;
}

/// The arguments of a call are bounded: a few kB of labels pass, 40 kB of
/// them are refused by the frontend with a 413 (zlink would write them in
/// time that grows with the square of their size).
#[tokio::test]
async fn the_arguments_of_a_call_are_bounded() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            serve(&socket, mock(0).0);
            let app = router(Engine::new(&socket));
            let create = |label: String| {
                let app = app.clone();
                async move {
                    let body = format!(r#"{{"Name":"v","Label":{{"k":"{label}"}}}}"#);
                    let req = Request::builder()
                        .method("POST")
                        .uri("/libpod/volumes/create")
                        .body(Body::from(body))
                        .unwrap();
                    app.oneshot(req).await.unwrap().status().as_u16()
                }
            };
            // (the mock has no VolumeCreate: a call that is made is a 500)
            assert_eq!(create("x".repeat(100)).await, 500);
            assert_eq!(create("x".repeat(40_000)).await, 413);
        })
        .await;
}

/// What velarx has no support for, set in the body of a request, is refused
/// naming it (501), not dropped.
#[tokio::test]
async fn the_body_fields_without_support_are_refused_by_name() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            serve(&socket, mock(0).0);
            let app = router(Engine::new(&socket));
            for (method, uri, body, name) in [
                (
                    "POST",
                    "/libpod/networks/n/connect",
                    r#"{"container":"c","options":{"mode":"x"}}"#,
                    "options",
                ),
                (
                    "POST",
                    "/v1.41/networks/n/connect",
                    r#"{"Container":"c","EndpointConfig":{"IPAMConfig":{"LinkLocalIPs":["169.254.1.1"]}}}"#,
                    "LinkLocalIPs",
                ),
                (
                    "POST",
                    "/v1.41/networks/create",
                    r#"{"Name":"x","EnableIPv4":false}"#,
                    "EnableIPv4",
                ),
                (
                    "PUT",
                    "/v5.0.0/libpod/manifests/L1",
                    r#"{"operation":"update","artifact_files":["/etc/hostname"]}"#,
                    "artifact_files",
                ),
                (
                    "POST",
                    "/v3.0.0/libpod/manifests/L1/add",
                    r#"{"images":["a"],"index_annotations":{"a":"b"}}"#,
                    "index_annotations",
                ),
                (
                    "POST",
                    "/v3.0.0/libpod/manifests/L1/add",
                    r#"{"images":["a"],"subject":"s"}"#,
                    "subject",
                ),
            ] {
                let req = Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap();
                let res = app.clone().oneshot(req).await.unwrap();
                let st = res.status().as_u16();
                let b = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
                let message = json(&b)["message"].as_str().unwrap_or_default().to_string();
                assert_eq!(st, 501, "{uri} {body}: {message}");
                assert!(message.contains(name), "{uri} {body}: {message}");
            }
        })
        .await;
}

/// A path no route takes is the "no route" 404; a real mistake of method is
/// a 405.
#[tokio::test]
async fn an_unknown_route_is_a_404_and_a_wrong_method_a_405() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let app = router(Engine::new(&dir.path().join("none.sock")));
            let (st, _, body) = get(&app, "GET", "/libpod/nosuch/export").await;
            assert_eq!(st, 404);
            assert_eq!(json(&body)["cause"], "page not found");
            let (st, _, _) = get(&app, "GET", "/v1.41/containers/abc/nosuch").await;
            assert_eq!(st, 404);
            let (st, _, _) = get(&app, "POST", "/libpod/containers/json").await;
            assert_eq!(st, 405);
            let (st, _, _) = get(&app, "PUT", "/libpod/pods/json").await;
            assert_eq!(st, 405);
        })
        .await;
}

/// The frames of a stream go to the client as they are, or as the raw output
/// of a container with a terminal; a stream that stays open ends for the
/// engine when the client goes away.
#[tokio::test]
async fn a_stream_is_framed_by_the_frontend_and_ends_with_its_client() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let (held, calls) = (m.held.clone(), m.calls.clone());
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            // (the writer of the plain one is closed: the body ends)
            let (st, _, body) = get(&app, "GET", "/v1.41/containers/plain/logs?tail=3&stdout=1&stderr=1").await;
            assert_eq!(st, 200);
            assert_eq!(body, b"\x01\0\0\0\0\0\0\x04out\n\x02\0\0\0\0\0\0\x04err\n");
            let (_, headers, body) = get(&app, "GET", "/v1.41/containers/tty/logs?stdout=1&stderr=1").await;
            assert_eq!(headers["content-type"], "application/vnd.docker.raw-stream");
            assert_eq!(body, b"out\nerr\n");
            // (libpod frames the logs of a container with a terminal too)
            let (_, headers, body) = get(&app, "GET", "/libpod/containers/tty/logs?stdout=1&stderr=1").await;
            assert_eq!(
                headers["content-type"],
                "application/vnd.docker.multiplexed-stream"
            );
            assert_eq!(body, b"\x01\0\0\0\0\0\0\x04out\n\x02\0\0\0\0\0\0\x04err\n");
            // the query is decoded here: the engine gets numbers
            let (st, _, _) = get(
                &app,
                "GET",
                "/libpod/containers/plain/logs?stdout=true&timestamps=true&tail=all&since=1700000000.5&until=2023-11-14T22:13:20Z",
            )
            .await;
            assert_eq!(st, 200);
            // (podman sends Go's zero time for the limit it does not set)
            let (st, _, _) = get(
                &app,
                "GET",
                "/libpod/containers/plain/logs?stderr=1&tail=-1&since=0001-01-01T00%3A00%3A00Z&until=0001-01-01T00%3A00%3A00Z",
            )
            .await;
            assert_eq!(st, 200);
            // (podman's 400s: no stream, a value that does not parse)
            let (st, _, body) = get(&app, "GET", "/libpod/containers/plain/logs").await;
            assert_eq!(st, 400);
            assert_eq!(
                json(&body)["message"],
                "Bad Request: you must choose at least one stream for /libpod/containers/plain/logs"
            );
            let (st, _, body) =
                get(&app, "GET", "/libpod/containers/plain/logs?stdout=1&tail=lots").await;
            assert_eq!(st, 400);
            assert_eq!(json(&body)["cause"], "invalid syntax");
            assert_eq!(
                json(&body)["message"],
                "failed to parse query parameter 'tail': \"lots\": strconv.ParseInt: parsing \"lots\": invalid syntax"
            );
            let (st, _, body) =
                get(&app, "GET", "/libpod/containers/plain/logs?stdout=1&since=yesterday").await;
            assert_eq!(st, 400);
            assert_eq!(json(&body)["cause"], "unable to interpret time value");
            // (a duration and a date are times of podman's; `until=0` is no
            // limit)
            let (st, _, _) = get(
                &app,
                "GET",
                "/libpod/containers/dated/logs?stdout=1&since=5m&until=0",
            )
            .await;
            assert_eq!(st, 200);
            let (st, _, _) =
                get(&app, "GET", "/libpod/containers/day/logs?stdout=1&since=2023-11-14").await;
            assert_eq!(st, 200);
            let calls = calls.lock().unwrap().clone();
            assert!(calls.contains(
                &"logs plain tail=Some(3) since=None until=None follow=false ts=false out=true err=true"
                    .to_string()
            ));
            assert!(calls.contains(
                &"logs plain tail=None since=Some(1700000000500000000) until=Some(1700000000000000000) follow=false ts=true out=true err=false"
                    .to_string()
            ));
            assert!(calls.contains(
                &"logs plain tail=None since=None until=None follow=false ts=false out=false err=true"
                    .to_string()
            ));
            assert!(calls.contains(
                &"logs day tail=None since=Some(1699920000000000000) until=None follow=false ts=false out=true err=false"
                    .to_string()
            ));
            assert!(calls
                .iter()
                .any(|c| c.starts_with("logs dated tail=None since=Some(") && c.contains(" until=None ")));
            assert!(!calls.iter().any(|c| c.contains("lots")));
            // an idle stream: the client reads what there is and goes away
            let req = Request::builder()
                .uri("/libpod/containers/idle/logs?follow=true&stdout=true")
                .body(Body::empty())
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            let mut body = res.into_body().into_data_stream();
            let first = futures::StreamExt::next(&mut body).await.unwrap().unwrap();
            assert!(first.starts_with(b"\x01\0\0\0"));
            let writer = std::fs::File::from(held.lock().unwrap().pop().unwrap());
            drop(body);
            // (the engine's end sees the reader gone: the writer of a pipe
            // whose reader is closed polls POLLERR, which the close wakes;
            // 20 s is an upper bound)
            let mut writer = tokio::task::spawn_blocking(move || {
                use rustix::event::{poll, PollFd, PollFlags, Timespec};
                let until = std::time::Instant::now() + std::time::Duration::from_secs(20);
                loop {
                    let left = until.saturating_duration_since(std::time::Instant::now());
                    let limit = Timespec {
                        tv_sec: left.as_secs() as i64,
                        tv_nsec: left.subsec_nanos() as i64,
                    };
                    let mut fds = [PollFd::new(&writer, PollFlags::empty())];
                    match poll(&mut fds, Some(&limit)) {
                        Err(rustix::io::Errno::INTR) => continue,
                        _ => break,
                    }
                }
                writer
            })
            .await
            .unwrap();
            assert!(
                std::io::Write::write_all(&mut writer, b"x").is_err(),
                "the stream stayed open after its client left"
            );
        })
        .await;
}

/// Without an upgrade the output of a session is the body of the answer;
/// the engine's end sees the client leave.
#[tokio::test]
async fn the_streams_of_an_exec_are_the_body_and_end_with_the_client() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let (sessions, calls) = (m.sessions.clone(), m.calls.clone());
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            // (the engine ends the output: the body ends)
            let req = Request::builder()
                .method("POST")
                .uri("/v1.44/exec/short/start")
                .body(Body::from(r#"{"Detach":false}"#))
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), 200);
            assert_eq!(
                res.headers()["content-type"],
                "application/vnd.docker.multiplexed-stream"
            );
            let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
            assert_eq!(&body[..], b"\x01\0\0\0\0\0\0\x04out\n");
            assert_eq!(
                calls.lock().unwrap().last().unwrap(),
                "exec start short false false 0x0"
            );
            // the size of the terminal and the detach are in the body
            let req = Request::builder()
                .method("POST")
                .uri("/v1.44/exec/short/start")
                .body(Body::from(r#"{"Detach":true,"h":24,"w":80}"#))
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), 200);
            assert_eq!(
                calls.lock().unwrap().last().unwrap(),
                "exec start short false true 24x80"
            );
            // (the engine keeps its end open: the client leaves)
            let req = Request::builder()
                .method("POST")
                .uri("/v1.44/exec/open/start")
                .body(Body::from("{}"))
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            let mut body = res.into_body().into_data_stream();
            let first = futures::StreamExt::next(&mut body).await.unwrap().unwrap();
            assert!(first.starts_with(b"\x01\0\0\0"));
            // (the engine's end is told the client left, without a write)
            let (out, _output) = sessions.lock().unwrap().pop().unwrap();
            drop(body);
            let event = tokio::time::timeout(std::time::Duration::from_secs(5), out.event())
                .await
                .expect("the engine's end is still open");
            assert_eq!(event, velarx_proto::stream::Event::Gone);
        })
        .await;
}

/// podman's body of a modification is decoded by the frontend into typed
/// calls, and the report and its status are made of their results.
#[tokio::test]
async fn a_manifest_modification_is_decoded_and_reported_by_the_frontend() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let calls = m.calls.clone();
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            let send = |method: &'static str, uri: &'static str, ct: &'static str, body: Vec<u8>| {
                let app = app.clone();
                async move {
                    let req = Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("content-type", ct)
                        .body(Body::from(body))
                        .unwrap();
                    let res = app.oneshot(req).await.unwrap();
                    let st = res.status().as_u16();
                    let b = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
                    (
                        st,
                        serde_json::from_slice::<serde_json::Value>(&b).unwrap_or_default(),
                    )
                }
            };
            let put = |body: &str| (body.as_bytes().to_vec(), "application/json");
            // an update: Go's names in any case, an image of the store by its id
            let (b, ct) = put(
                r#"{"Operation":"Update","Images":["containers-storage:abc","docker.io/a"],"Arch":"arm64","OSVersion":"1","annotation":["a=b"],"Username":"u","Password":"p","All":true}"#,
            );
            let (st, report) = send("PUT", "/v5.0.0/libpod/manifests/L1", ct, b).await;
            assert_eq!(st, 200, "{report}");
            assert_eq!(
                report,
                serde_json::json!({"Id": "L2", "images": ["containers-storage:abc", "docker.io/a"]})
            );
            let seen = calls.lock().unwrap().clone();
            assert!(seen.contains(&"image inspect abc".to_string()), "{seen:?}");
            assert!(
                seen.contains(
                    &"manifest add L1 [\"containers-storage:abc\", \"docker.io/a\"] all=true arch=arm64 osv=1 ann={\"a\": \"b\"} tls=true access=true"
                        .to_string()
                ),
                "{seen:?}"
            );
            // the annotations of the index with images: set after them, as
            // podman's add does
            let (b, ct) =
                put(r#"{"operation":"update","images":["docker.io/b"],"IndexAnnotations":{"i":"j"}}"#);
            let (st, report) = send("PUT", "/v5.0.0/libpod/manifests/L1", ct, b).await;
            assert_eq!(st, 200, "{report}");
            assert!(calls
                .lock()
                .unwrap()
                .contains(&"manifest annotate L1 None arch= {\"i\": \"j\"} None".to_string()));
            // both forms of the annotations: 400
            let (b, ct) = put(
                r#"{"operation":"update","images":["x"],"annotation":["a=b"],"annotations":{"c":"d"}}"#,
            );
            let (st, report) = send("PUT", "/v5.0.0/libpod/manifests/L1", ct, b).await;
            assert_eq!(st, 400);
            assert!(report["message"]
                .as_str()
                .unwrap()
                .contains("can not set both Annotation and Annotations"));
            // a change that failed: 400 alone, 409 with one that went
            let (b, ct) = put(r#"{"operation":"update","images":["bad"]}"#);
            let (st, report) = send("PUT", "/v5.0.0/libpod/manifests/L1", ct, b).await;
            assert_eq!(
                (st, &report["errors"][0], report.get("images")),
                (400, &serde_json::json!("no such image"), None)
            );
            let (b, ct) = put(r#"{"operation":"remove","images":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sha256:bad0000000000000000000000000000000000000000000000000000000000000"]}"#);
            let (st, report) = send("PUT", "/v5.0.0/libpod/manifests/L1", ct, b).await;
            assert_eq!(st, 409, "{report}");
            assert_eq!(report["images"], serde_json::json!(["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]));
            // (podman's words for an instance that is not there)
            assert_eq!(
                report["errors"][0],
                serde_json::json!(format!(
                    "no instance matching digest \"{}\" found in manifest list: file does not exist",
                    "sha256:bad0000000000000000000000000000000000000000000000000000000000000"
                ))
            );
            // (podman's refusals: the subject of the index with an instance,
            // the platform of an instance without one)
            for (body, refused) in [
                (
                    r#"{"operation":"annotate","images":["sha256:ok"],"arch":"s390x","indexsubject":"sub"}"#,
                    "setting subject for a manifest list requires no instance digest",
                ),
                (
                    r#"{"operation":"annotate","arch":"s390x"}"#,
                    "setting architecture on an item in a manifest list requires an instance digest",
                ),
            ] {
                let (b, ct) = put(body);
                let (st, report) = send("PUT", "/v5.0.0/libpod/manifests/L1", ct, b).await;
                assert_eq!((st, &report["errors"][0]), (400, &serde_json::json!(refused)));
            }
            let (b, ct) = put(r#"{"operation":"annotate","images":["sha256:ok"],"arch":"s390x"}"#);
            let (st, report) = send("PUT", "/v5.0.0/libpod/manifests/L1", ct, b).await;
            assert_eq!((st, report["Id"].as_str()), (200, Some("L4")));
            let (b, ct) = put(r#"{"operation":"annotate","indexsubject":"sub"}"#);
            let (st, _) = send("PUT", "/v5.0.0/libpod/manifests/L1", ct, b).await;
            assert_eq!(st, 200);
            let seen = calls.lock().unwrap().clone();
            assert!(
                seen.contains(&"manifest annotate L1 Some(\"sha256:ok\") arch=s390x {} None".to_string())
                    && seen.contains(&"manifest annotate L1 None arch= {} Some(\"sub\")".to_string()),
                "{seen:?}"
            );
            // the instances to remove are digests
            let (b, ct) = put(r#"{"operation":"remove","images":["notadigest"]}"#);
            let (st, report) = send("PUT", "/v5.0.0/libpod/manifests/L1", ct, b).await;
            assert_eq!(
                (st, &report["errors"][0]),
                (
                    400,
                    &serde_json::json!(
                        "invalid image digest \"notadigest\": invalid checksum digest format"
                    )
                )
            );
            let (b, ct) = put(r#"{"operation":"frob"}"#);
            let (st, _) = send("PUT", "/v5.0.0/libpod/manifests/L1", ct, b).await;
            assert_eq!(st, 400);
            let (b, ct) = put(r#"{"operation":"update"}"#);
            let (st, report) = send("PUT", "/v5.0.0/libpod/manifests/gone", ct, b).await;
            assert_eq!(st, 404, "{report}");
            // the files of a multipart body cross as descriptors
            let multipart = "--B\r\nContent-Disposition: form-data; name=\"request\"\r\n\r\n{\"operation\":\"update\",\"artifact_type\":\"t/x\",\"artifact_layer_type\":\"text/plain\"}\r\n--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"dir/a.txt\"\r\n\r\nfirst\r\n--B\r\nContent-Disposition: form-data; name=\"g\"\r\n\r\nsecond\r\n--B--\r\n";
            let (st, report) = send(
                "PUT",
                "/v5.0.0/libpod/manifests/L1",
                "multipart/form-data; boundary=B",
                multipart.as_bytes().to_vec(),
            )
            .await;
            assert_eq!(st, 200, "{report}");
            assert_eq!(report["files"], serde_json::json!(["a.txt", "g"]));
            assert!(calls.lock().unwrap().contains(
                &"manifest artifact L1 [\"a.txt\", \"g\"] [\"first\", \"second\"] type=Some(\"t/x\") layer=text/plain"
                    .to_string()
            ));
            // delete: the list, ignoring one that is gone, an instance (3.x)
            let (st, doc) = send("DELETE", "/v5.0.0/libpod/manifests/L1", "", vec![]).await;
            assert_eq!(st, 200);
            assert_eq!(
                doc,
                serde_json::json!({"Deleted": ["L1"], "Untagged": ["localhost/x:latest"],
                                   "Errors": [], "ExitCode": 0})
            );
            let (st, _) = send("DELETE", "/v5.0.0/libpod/manifests/gone", "", vec![]).await;
            assert_eq!(st, 404);
            let (st, doc) =
                send("DELETE", "/v5.0.0/libpod/manifests/gone?ignore=true", "", vec![]).await;
            assert_eq!((st, doc), (200, serde_json::json!({"Errors": [], "ExitCode": 0})));
            let (st, doc) = send(
                "DELETE",
                "/v3.4.0/libpod/manifests/L1?digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "",
                vec![],
            )
            .await;
            assert_eq!((st, doc), (200, serde_json::json!({"Id": "L3"})));
            // inspect: OCI's index
            let (st, doc) = send("GET", "/v5.0.0/libpod/manifests/x/json", "", vec![]).await;
            assert_eq!(st, 200);
            assert_eq!(
                doc["manifests"][0]["platform"],
                serde_json::json!({"architecture": "amd64", "os": "linux"})
            );
            // artifacts: podman's inspect, the removal of several
            let (st, doc) = send("GET", "/v5.0.0/libpod/artifacts/a1/json", "", vec![]).await;
            assert_eq!(
                (st, doc["Name"].clone(), doc["Manifest"]["layers"][0]["size"].clone()),
                (200, serde_json::json!("a1"), serde_json::json!(4))
            );
            let (st, doc) = send(
                "DELETE",
                "/v5.0.0/libpod/artifacts/remove?artifacts=a1&artifacts=gone1&ignore=true",
                "",
                vec![],
            )
            .await;
            assert_eq!(
                (st, doc),
                (200, serde_json::json!({"ArtifactDigests": ["sha256:a1"]}))
            );
            let (st, _) = send(
                "DELETE",
                "/v5.0.0/libpod/artifacts/remove?artifacts=gone1",
                "",
                vec![],
            )
            .await;
            assert_eq!(st, 404);
            let (st, _) = send(
                "DELETE",
                "/v5.0.0/libpod/artifacts/remove?artifacts=a&all=true",
                "",
                vec![],
            )
            .await;
            assert_eq!(st, 400);
        })
        .await;
}

/// The build cache prune answers Docker's document of the engine's record,
/// and refuses what it does not have.
#[tokio::test]
async fn a_build_prune_is_docker_s_document() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let calls = m.calls.clone();
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            let (st, _, body) = get(
                &app,
                "POST",
                "/v1.41/build/prune?keep-storage=0&filters=%7B%7D",
            )
            .await;
            assert_eq!(st, 200);
            assert_eq!(
                json(&body),
                serde_json::json!({"CachesDeleted": ["i1", "i2"], "SpaceReclaimed": 42})
            );
            assert_eq!(
                get(&app, "POST", "/v1.41/build/prune?keep-storage=5")
                    .await
                    .0,
                501
            );
            assert_eq!(calls.lock().unwrap().clone(), ["build prune"]);
        })
        .await;
}

/// The kube routes are not the engine's: they say so, and where they are.
#[tokio::test]
async fn the_kube_routes_say_where_they_are() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            for (method, uri) in [
                ("POST", "/libpod/play/kube"),
                ("DELETE", "/libpod/play/kube"),
                ("POST", "/libpod/kube/apply"),
                ("GET", "/libpod/generate/kube?names=x"),
            ] {
                let req = Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap();
                let res = app.clone().oneshot(req).await.unwrap();
                assert_eq!(res.status(), 501, "{method} {uri}");
                let got = axum::body::to_bytes(res.into_body(), 1 << 16)
                    .await
                    .unwrap();
                assert!(
                    String::from_utf8_lossy(&got).contains("velarx-kube"),
                    "{method} {uri}"
                );
            }
        })
        .await;
}

/// The frontend decodes podman's exec body into the engine's typed spec and
/// shapes the engine's record as podman's inspect document.
#[tokio::test]
async fn an_exec_session_is_decoded_and_shaped_by_the_frontend() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let calls = m.calls.clone();
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            let body = r#"{"Cmd":["sh","-c","true"],"Env":["A=b","C="],"WorkingDir":"/tmp","User":"bin","Tty":true,"AttachStdout":true,"DetachKeys":"ctrl-x","privileged":true}"#;
            let req = Request::builder()
                .method("POST")
                .uri("/v1.44/containers/c1/exec")
                .body(Body::from(body))
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), 201);
            let got = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
            assert_eq!(json(&got), serde_json::json!({"Id": "e1"}));
            let call = calls.lock().unwrap().last().unwrap().clone();
            assert_eq!(
                call,
                "exec create c1 ExecSpec { command: [\"sh\", \"-c\", \"true\"], env: {\"A\": \"b\", \"C\": \"\"}, work_dir: \"/tmp\", user: \"bin\", tty: true, stdin: false, stdout: true, stderr: false, privileged: true, detach_keys: \"ctrl-x\", timeout_ms: None, errors_apart: false }"
            );
            // (podman's 400 for a variable without a value)
            let req = Request::builder()
                .method("POST")
                .uri("/v1.44/containers/c1/exec")
                .body(Body::from(r#"{"Cmd":["env"],"Env":["NOVALUE"]}"#))
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), 400);
            let got = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
            assert_eq!(
                json(&got)["message"],
                "environment variable \"NOVALUE\" badly formed, must be key=value"
            );
            let (st, _, got) = get(&app, "GET", "/v1.44/exec/e1/json").await;
            assert_eq!(st, 200);
            // (podman's order of the members)
            assert!(String::from_utf8_lossy(&got).starts_with(
                r#"{"CanRemove":true,"ContainerID":"c1","DetachKeys":"","ExitCode":3,"ID":"e1","OpenStderr":false,"OpenStdin":false,"OpenStdout":true,"Running":false,"Pid":42,"ProcessConfig":{"#
            ));
            assert_eq!(
                json(&got),
                serde_json::json!({
                    "CanRemove": true, "ContainerID": "c1", "DetachKeys": "", "ExitCode": 3,
                    "ID": "e1", "OpenStderr": false, "OpenStdin": false, "OpenStdout": true,
                    "Running": false, "Pid": 42,
                    "ProcessConfig": {
                        "arguments": ["-c", "exit 3"], "entrypoint": "sh",
                        "privileged": false, "tty": false, "user": "bin"
                    }
                })
            );
            let req = Request::builder()
                .method("POST")
                .uri("/libpod/exec/e1/remove")
                .body(Body::from(r#"{"Force":true}"#))
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), 200);
            assert_eq!(calls.lock().unwrap().last().unwrap(), "exec remove e1 true");
        })
        .await;
}

/// An exec request body over the limit of 1 MiB (the API server takes
/// 16 MiB) does not reach the engine: the API server's 400 for a body over
/// its own limit.
#[tokio::test]
async fn an_exec_body_over_the_limit_is_refused_by_the_frontend() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let calls = m.calls.clone();
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            let big = format!(
                r#"{{"Cmd":["true"],"Env":["X={}"]}}"#,
                "x".repeat(1usize << 20)
            );
            for uri in ["/v1.44/containers/c/exec", "/v1.44/exec/big/start"] {
                let req = Request::builder()
                    .method("POST")
                    .uri(uri)
                    .body(Body::from(big.clone()))
                    .unwrap();
                let res = app.clone().oneshot(req).await.unwrap();
                assert_eq!(res.status(), 400, "{uri}");
                let body = axum::body::to_bytes(res.into_body(), 1 << 20)
                    .await
                    .unwrap();
                assert_eq!(
                    json(&body)["message"],
                    "read the request body: length limit exceeded"
                );
            }
            assert!(
                !calls.lock().unwrap().iter().any(|c| c.starts_with("exec")),
                "{:?}",
                calls.lock().unwrap()
            );
        })
        .await;
}

/// The request of a build is decoded here into the typed spec: the context
/// streams through a pipe, the credentials cross in a pipe of their own (no
/// password in the spec), the parts of a multipart body are descriptors, and
/// what a build does not have is refused by its name.
#[tokio::test]
async fn a_build_streams_its_context_and_sends_its_spec_typed() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            let body = vec![7u8; 3_000_000];
            let auth = base64_url(r#"{"username":"u","password":"hunter2","serveraddress":"r.example"}"#);
            let req = Request::builder()
                .method("POST")
                .uri("/libpod/build?t=a&q=1&nonsense=1&buildargs=%7B%22A%22%3A%22b%22%7D&platform=linux/arm64&ulimits=%5B%22nofile%3D1%3A2%22%5D&dockerfile=sub/Containerfile&pullpolicy=never")
                .header("content-type", "application/x-tar")
                .header("x-registry-auth", auth)
                .body(Body::from(body))
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), 200);
            let out = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
            let out = String::from_utf8(out.to_vec()).unwrap();
            let line: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
            let text = line["stream"].as_str().unwrap();
            // (3 MB of context, its end, libpod, the tags as written, the
            // credentials in their pipe and not in the spec)
            assert!(text.starts_with("3000000 true Libpod [\"a\"] true false []"), "{text}");
            let spec: serde_json::Value =
                serde_json::from_str(text.rsplit_once("[] ").unwrap().1).unwrap();
            assert_eq!(spec["quiet"], true);
            assert_eq!(spec["layers"], false);
            assert_eq!(spec["args"], serde_json::json!([{"name": "A", "value": "b"}]));
            assert_eq!(spec["ulimits"], 1);
            assert_eq!(spec["platform"], "linux/arm64");
            assert_eq!(spec["containerfile"], "sub/Containerfile");
            assert_eq!(spec["pull"], "never");
            // (Docker's client keeps its layers, squashes onto the base)
            let req = Request::builder()
                .method("POST")
                .uri("/v1.41/build?squash=1&remote=https://x/y.tar")
                .body(Body::from("ignored"))
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            let out = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
            let out = String::from_utf8_lossy(&out).to_string();
            // (a remote context: the body is not sent)
            assert!(out.starts_with("{\"stream\":\"0 false Docker"), "{out}");
            assert!(out.contains("\\\"layers\\\":true"), "{out}");
            assert!(out.contains("\\\"squash\\\":[true,false]"), "{out}");
            assert!(out.contains("https://x/y.tar"), "{out}");
            // (a client that goes away half way: no end frame, the engine
            // can tell a cut tar from a whole one)
            let body = futures::stream::iter(vec![
                Ok(bytes::Bytes::from_static(b"12345")),
                Err(std::io::Error::other("gone")),
            ]);
            let req = Request::builder()
                .method("POST")
                .uri("/libpod/build")
                .body(Body::from_stream(body))
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            let out = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
            assert!(
                String::from_utf8_lossy(&out).contains("5 false Libpod"),
                "{out:?}"
            );
            // what a build does not have is refused by its name, before
            // the engine is asked; so is a body that is no tar
            for (uri, ct, status, message) in [
                ("/libpod/build?cppflags=-DX", "application/x-tar", 501, "the build parameter `cppflags` is not supported"),
                ("/libpod/build?dockerfile=Containerfile.in", "application/x-tar", 400, "*.in"),
                ("/libpod/build?platform=test", "application/x-tar", 400, "failed to parse query parameter 'platform'"),
                ("/libpod/build?outputformat=docker", "application/x-tar", 501, "Docker image formats are not supported"),
                ("/libpod/build", "text/plain", 400, "Content-Type: text/plain is not supported"),
                ("/libpod/build?secrets=src%3Dx&remote=https://x/y.tar", "application/x-tar", 400, "a secret without an id"),
                ("/libpod/build?outputs=rel", "application/x-tar", 400, "outputs: rel: an absolute path"),
                ("/libpod/build?sbom-output=rel.json", "application/x-tar", 400, "sbom-output: rel.json: an absolute path"),
                ("/libpod/build?sbom-purl-output=p.json", "application/x-tar", 400, "sbom-purl-output: p.json: an absolute path"),
            ] {
                let req = Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", ct)
                    .body(Body::from("x"))
                    .unwrap();
                let res = app.clone().oneshot(req).await.unwrap();
                assert_eq!(res.status().as_u16(), status, "{uri}");
                let out = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
                assert!(String::from_utf8_lossy(&out).contains(message), "{uri}: {out:?}");
            }
            // a multipart body: the main context is the stream, the named
            // directories are parts of the call
            let multipart = "--B\r\nContent-Disposition: form-data; name=\"MainContext\"\r\n\r\nMAIN\r\n--B\r\nContent-Disposition: form-data; name=\"build-context-extra\"\r\n\r\nEXTRA\r\n--B--\r\n";
            let req = Request::builder()
                .method("POST")
                .uri("/libpod/build?additionalbuildcontexts=img%3Dimage%3Aalpine")
                .header("content-type", "multipart/form-data; boundary=B")
                .body(Body::from(multipart))
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            let out = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
            let out = String::from_utf8_lossy(&out).to_string();
            assert!(out.starts_with("{\"stream\":\"4 true Libpod"), "{out}");
            assert!(out.contains("[\\\"EXTRA\\\"]"), "{out}");
            assert!(
                out.contains("\"contexts\\\":[{\\\"kind\\\":\\\"image\\\",\\\"name\\\":\\\"img\\\",\\\"source\\\":\\\"alpine\\\"}]"),
                "{out}"
            );
        })
        .await;
}

/// The unpadded base64url of `text`.
fn base64_url(text: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in text.as_bytes().chunks(3) {
        let n = chunk.iter().fold(0u32, |n, b| (n << 8) | u32::from(*b)) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// Removal, stop and wait answer as podman 5.8.9 does: its status codes,
/// the parameters it reads on each route, and the shape of its reports.
#[tokio::test]
async fn removals_stops_and_waits_answer_as_podman() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("engine.sock");
            let (m, _) = mock(0);
            let calls = m.calls.clone();
            serve(&socket, m);
            let app = router(Engine::new(&socket));
            let status = |r: (StatusCode, axum::http::HeaderMap, Vec<u8>)| r.0.as_u16();
            let last = || calls.lock().unwrap().last().cloned().unwrap();

            // a container removed: libpod's report has the ids alone
            let (st, _, body) = get(&app, "DELETE", "/v5.0.0/libpod/containers/abc").await;
            assert_eq!(st, 200);
            assert_eq!(json(&body), serde_json::json!([{"Id": "dep"}, {"Id": "abc"}]));
            // a state, a dependent, a conflict: 500 on both routes; a missing one 404
            for route in ["/libpod/containers", "/v1.41/containers"] {
                for (name, want) in [("isbusy", 500), ("isinvalid", 500), ("isconflict", 500), ("ismissing", 404)] {
                    let (st, _, body) = get(&app, "DELETE", &format!("{route}/{name}")).await;
                    assert_eq!(st, want, "{route}/{name}: {}", String::from_utf8_lossy(&body));
                }
            }
            let (_, _, body) = get(&app, "DELETE", "/libpod/containers/isbusy").await;
            assert_eq!(json(&body)["response"], 500);
            // timeout is a uint: -1 and words are a 400 with podman's message, on either route
            for uri in [
                "/libpod/containers/abc?force=true&timeout=-1",
                "/v1.41/containers/abc?timeout=-1",
                "/libpod/containers/abc?timeout=x",
            ] {
                let (st, _, body) = get(&app, "DELETE", uri).await;
                assert_eq!(st, 400, "{uri}");
                let doc = json(&body);
                assert!(
                    doc["message"].as_str().unwrap().starts_with(&format!(
                        "failed to parse parameters for {uri}: schema: error converting value for \"timeout\""
                    )),
                    "{doc}"
                );
                assert_eq!(doc["cause"], doc["message"].as_str().unwrap().split_once(": ").unwrap().1);
            }
            // (an empty one is zero; only libpod passes it on)
            get(&app, "DELETE", "/libpod/containers/abc?timeout=").await;
            assert_eq!(last(), "remove abc false false false false Some(0)");
            get(&app, "DELETE", "/v1.41/containers/abc?timeout=5").await;
            assert_eq!(last(), "remove abc false false false false None");
            // libpod reads `volumes`, Docker `v`
            get(&app, "DELETE", "/libpod/containers/abc?volumes=1&v=1").await;
            assert_eq!(last(), "remove abc false true false false None");
            get(&app, "DELETE", "/v1.41/containers/abc?v=1&volumes=1").await;
            assert_eq!(last(), "remove abc false true false false None");
            get(&app, "DELETE", "/v1.41/containers/abc?v=0&volumes=1").await;
            assert_eq!(last(), "remove abc false false false false None");
            // booleans: strict on libpod, Docker's words on the other routes
            assert_eq!(status(get(&app, "DELETE", "/libpod/containers/abc?force=yes").await), 400);
            assert_eq!(status(get(&app, "DELETE", "/libpod/containers/abc?link=x").await), 400);
            assert_eq!(status(get(&app, "DELETE", "/libpod/containers/abc?link=true").await), 200);
            get(&app, "DELETE", "/v1.41/containers/abc?force=yes&ignore=No").await;
            assert_eq!(last(), "remove abc true false false false None");
            let (st, _, body) = get(&app, "DELETE", "/v1.41/containers/abc?link=maybe").await;
            assert_eq!(st, 400);
            assert_eq!(json(&body)["message"], "link is not supported");

            // stop: `t` is an int and `timeout` a uint on both routes, the route's counts
            for (uri, want) in [
                ("/v1.41/containers/abc/stop?t=-1", "stop abc Some(4294967295) false"),
                ("/v1.41/containers/abc/stop?t=3&timeout=9", "stop abc Some(3) false"),
                ("/v1.41/containers/abc/stop?timeout=9", "stop abc None false"),
                ("/v1.41/containers/abc/stop?t=", "stop abc Some(0) false"),
                ("/libpod/containers/abc/stop?t=-1", "stop abc None false"),
                ("/libpod/containers/abc/stop?timeout=9&t=1", "stop abc Some(9) false"),
                ("/libpod/containers/abc/stop?timeout=", "stop abc Some(0) false"),
                // (the container is looked up first: `ignore` does not hide a missing one)
                ("/libpod/containers/abc/stop?ignore=true", "stop abc None false"),
            ] {
                assert_eq!(status(get(&app, "POST", uri).await), 204, "{uri}");
                assert_eq!(last(), want, "{uri}");
            }
            for uri in [
                "/v1.41/containers/abc/stop?timeout=-1",
                "/libpod/containers/abc/stop?timeout=-1",
                "/libpod/containers/abc/stop?timeout=x",
                "/v1.41/containers/abc/stop?t=x",
                "/libpod/containers/abc/stop?t=x",
                "/libpod/containers/abc/stop?ignore=maybe",
            ] {
                let (st, _, body) = get(&app, "POST", uri).await;
                assert_eq!(st, 400, "{uri}");
                assert!(
                    json(&body)["message"]
                        .as_str()
                        .unwrap()
                        .starts_with(&format!("failed to parse parameters for {uri}: schema: error converting value for")),
                    "{uri}"
                );
            }
            assert_eq!(status(get(&app, "POST", "/v1.41/containers/abc/stop?ignore=maybe").await), 204);
            assert_eq!(status(get(&app, "POST", "/libpod/containers/ismissing/stop?ignore=true").await), 404);
            assert_eq!(status(get(&app, "POST", "/libpod/containers/isbusy/stop").await), 500);

            // wait: a container that is not there; an interval Go cannot read is a 500
            let (st, _, body) = get(&app, "POST", "/v1.41/containers/ismissing/wait").await;
            assert_eq!(st, 404);
            let doc = json(&body);
            assert_eq!((doc["message"].as_str(), doc["cause"].as_str()), (Some("no such container"), Some("no such container")));
            assert_eq!(status(get(&app, "POST", "/libpod/containers/ismissing/wait").await), 404);
            assert_eq!(status(get(&app, "POST", "/libpod/containers/isbusy/wait").await), 500);
            for (interval, message) in [
                ("soon", "time: invalid duration \"soon\""),
                ("", "time: invalid duration \"\""),
                ("5", "time: missing unit in duration \"5\""),
            ] {
                let (st, _, body) = get(&app, "POST", &format!("/libpod/containers/abc/wait?interval={interval}")).await;
                assert_eq!(st, 500);
                assert_eq!(json(&body)["message"], message);
            }
            // (a condition podman cannot read is an exit code of 0 for a container that is there)
            let (st, _, body) = get(&app, "POST", "/libpod/containers/abc/wait?condition=bogus").await;
            assert_eq!((st.as_u16(), body.as_slice()), (200, b"0\n".as_slice()));
            assert_eq!(last(), "exists abc");
            assert_eq!(status(get(&app, "POST", "/libpod/containers/ismissing/wait?condition=bogus").await), 404);
            let (st, _, body) = get(&app, "POST", "/v1.41/containers/abc/wait?condition=running").await;
            assert_eq!(st, 400);
            let doc = json(&body);
            assert_eq!(doc["cause"], "not a valid docker condition");
            assert_eq!(
                doc["message"],
                "failed to parse query parameter 'condition': \"running\": not a valid docker condition"
            );
            // (the last one counts)
            assert_eq!(status(get(&app, "POST", "/v1.41/containers/abc/wait?condition=bogus&condition=removed").await), 200);

            // volumes: a use is a 409 (the engine's state), a refused argument 500, a missing one 404; a number below zero a 500
            for route in ["/libpod/volumes", "/v1.41/volumes"] {
                assert_eq!(status(get(&app, "DELETE", &format!("{route}/isbusy")).await), 409);
                assert_eq!(status(get(&app, "DELETE", &format!("{route}/isinvalid")).await), 500);
                assert_eq!(status(get(&app, "DELETE", &format!("{route}/v?timeout=-1")).await), 500);
                assert_eq!(status(get(&app, "DELETE", &format!("{route}/v?force=maybe&timeout=x")).await), 500);
            }
            assert_eq!(status(get(&app, "DELETE", "/libpod/volumes/isvolumegone").await), 404);
            assert_eq!(status(get(&app, "DELETE", "/libpod/volumes/isvolumegone?force=true").await), 404);
            assert_eq!(status(get(&app, "DELETE", "/v1.41/volumes/isvolumegone").await), 404);
            assert_eq!(status(get(&app, "DELETE", "/v1.41/volumes/isvolumegone?force=true").await), 204);
            // (Docker's force never forces the removal itself)
            get(&app, "DELETE", "/v1.41/volumes/v?force=true").await;
            assert_eq!(last(), "volume remove v false None");
            get(&app, "DELETE", "/libpod/volumes/v?force=true&timeout=4").await;
            assert_eq!(last(), "volume remove v true Some(4)");

            // pods: the parameters are a 400, any failure but a missing pod a 500
            assert_eq!(status(get(&app, "DELETE", "/libpod/pods/p?timeout=-1").await), 400);
            assert_eq!(status(get(&app, "DELETE", "/libpod/pods/p?force=maybe").await), 400);
            assert_eq!(status(get(&app, "DELETE", "/libpod/pods/isbusy").await), 500);
            assert_eq!(status(get(&app, "DELETE", "/libpod/pods/isinvalid").await), 500);
            assert_eq!(status(get(&app, "DELETE", "/libpod/pods/ispodgone").await), 404);

            // networks: libpod reads `force`, a bad one is a 500; Docker's also `timeout` (a 400)
            assert_eq!(status(get(&app, "DELETE", "/libpod/networks/isbusy").await), 500);
            assert_eq!(status(get(&app, "DELETE", "/v1.41/networks/isbusy").await), 500);
            assert_eq!(status(get(&app, "DELETE", "/libpod/networks/n?force=maybe").await), 500);
            assert_eq!(status(get(&app, "DELETE", "/v1.41/networks/n?timeout=-1").await), 400);
            assert_eq!(status(get(&app, "DELETE", "/v1.41/networks/n?force=maybe").await), 204);
            get(&app, "DELETE", "/libpod/networks/n?timeout=3").await;
            assert_eq!(last(), "network remove n false None");
            get(&app, "DELETE", "/v1.41/networks/n?timeout=3&force=1").await;
            assert_eq!(last(), "network remove n true Some(3)");

            // images: a use is a 409, a missing one 404, a refused argument 500
            for uri in ["/libpod/images/", "/v1.41/images/"] {
                assert_eq!(status(get(&app, "DELETE", &format!("{uri}isconflict")).await), 409);
                assert_eq!(status(get(&app, "DELETE", &format!("{uri}isimagegone")).await), 404);
                assert_eq!(status(get(&app, "DELETE", &format!("{uri}isinvalid")).await), 500);
                assert_eq!(status(get(&app, "DELETE", &format!("{uri}x?force=maybe")).await), if uri.contains("libpod") { 400 } else { 200 });
            }
            // (libpod's report leaves out the lists with nothing in them)
            let (st, _, body) = get(&app, "DELETE", "/libpod/images/alpine").await;
            assert_eq!(st, 200);
            assert_eq!(
                json(&body),
                serde_json::json!({"Deleted": ["abc"], "Untagged": ["a:1"], "ExitCode": 0, "Errors": []})
            );
        })
        .await;
}

/// A route that refuses a request before it reads the body (a refused
/// parameter), and a request no route takes, still answer the client that
/// is writing it: the answer is not lost to a reset of the connection.
/// The body is larger than what the sockets hold, and is written while
/// the answer is read.
#[tokio::test]
async fn a_refusal_before_the_body_is_read_reaches_the_writer() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const BODY: usize = 16 << 20;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(velarx_api::serve::serve(
        vec![velarx_api::serve::Listener::Unix(listener)],
        Engine::new(&dir.path().join("engine.sock")),
        velarx_proto::serving::Peers::Any,
        None,
        None,
    ));
    for (target, status) in [
        ("/libpod/build?cppflags=-DX", "501"),
        ("/libpod/nothing", "404"),
    ] {
        let (mut read, mut write) = tokio::net::UnixStream::connect(&socket)
            .await
            .unwrap()
            .into_split();
        let writer = tokio::spawn(async move {
            write
                .write_all(
                    format!(
                        "POST {target} HTTP/1.1\r\nHost: d\r\n\
                         Content-Type: application/x-tar\r\nContent-Length: {BODY}\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await?;
            write.write_all(&vec![0u8; BODY]).await
        });
        let mut answer = Vec::new();
        read.read_buf(&mut answer).await.unwrap();
        assert!(
            answer.starts_with(format!("HTTP/1.1 {status} ").as_bytes()),
            "{target}: {}",
            String::from_utf8_lossy(&answer)
        );
        writer.await.unwrap().unwrap();
    }
    server.abort();
}
