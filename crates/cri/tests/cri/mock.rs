// SPDX-License-Identifier: Apache-2.0
use std::sync::{Arc, Mutex};
use velarx_cri::engine::*;
use velarx_cri::service::Cri;
use velarx_cri::stream::Sessions;
use velarx_proto::engine::{NetworkStatus, RuntimeInfo, StorageUsage, UpdateSpec};
use velarx_proto::request::CreateContainerRequest;
use velarx_proto::workload::{
    ContainerMetrics, ContainerMount, ContainerRecord, ImageRecord, MetricDescriptor, MetricSample,
    MountKind, PodMetrics, PodRecord, PodStatus, Resources, RunState, StatsRecord,
};

/// An error the engine answers, for the calls that are made to fail.
#[derive(Clone)]
pub enum Fail {
    Other(String),
    Unavailable,
    Precondition,
    Deadline,
}

impl Fail {
    fn error(&self) -> EngineError {
        match self {
            Fail::Other(m) => EngineError::Other(m.clone()),
            Fail::Unavailable => EngineError::Unavailable("the engine is gone".into()),
            Fail::Precondition => EngineError::Precondition("not created yet".into()),
            Fail::Deadline => EngineError::DeadlineExceeded("it took too long".into()),
        }
    }
}

#[derive(Default)]
pub struct State {
    /// `exec_sync` fails with this
    pub exec_sync_fails: Option<Fail>,
    /// `image_remove` removes the image, then fails with this
    pub image_remove_fails: Option<Fail>,
    /// `container_runtime_spec` fails with this
    pub spec_fails: Option<Fail>,
    /// `pod_inspect` fails with this
    pub pod_inspect_fails: Option<Fail>,
    /// `image_pull` does not add the image it answers with
    pub pull_unlisted: bool,
    /// What `exec_resize` fails with
    pub resize_fails: Option<Fail>,
    pub pods: Vec<PodRecord>,
    pub containers: Vec<ContainerRecord>,
    pub images: Vec<ImageRecord>,
    pub pod_creates: Vec<PodCreate>,
    pub container_creates: Vec<CreateContainerRequest>,
    pub updates: Vec<(String, UpdateSpec)>,
    pub pod_updates: Vec<(String, Resources)>,
    pub calls: Vec<String>,
    pub pulls: Vec<(String, Option<velarx_registry::auth::RegistryAccess>)>,
    pub exec_exit: i32,
    pub next: u32,
    /// `pod_dial` gives a connection (of 64 bytes of buffer) whose other
    /// end is kept here and never read
    pub dial_stuck: bool,
    pub dial_peers: Vec<tokio::io::DuplexStream>,
    /// What `network_status` answers
    pub network: NetworkStatus,
    pub inodes_used: Option<u64>,
    /// `store_usage` fails
    pub store_usage_fails: bool,
    /// The running containers the engine cannot sample (left out of its
    /// best effort stats)
    pub unsampled: Vec<String>,
    /// `pod_metrics` fails
    pub pod_metrics_fail: bool,
    /// What `pod_checkpoint` was asked: the containers, the directory
    pub pod_checkpoints: Vec<(Vec<String>, String)>,
    /// The manifests written, by directory
    pub manifests: std::collections::HashMap<String, Vec<u8>>,
    /// `container_restore_staged`: the container, the directory, the archive
    pub staged: Vec<(String, String, String)>,
    /// The container whose staging fails
    pub stage_fails: Option<String>,
    /// What the cgroup of every pod has used
    pub pod_usage: Option<velarx_proto::pod::PodUsage>,
    /// The cgroup controllers of the containers
    pub controllers: Vec<String>,
    /// The infra image the engine reports
    pub infra_image: String,
    /// `pod_start` waits for this to be notified, when set
    pub start_gate: Option<Arc<tokio::sync::Notify>>,
    /// `events` keeps its stream open: its sender is kept here
    pub events_held: Option<tokio::sync::mpsc::Sender<EngineEvent>>,
    pub hold_events: bool,
}

#[derive(Default)]
pub struct Mock {
    pub st: Mutex<State>,
    /// Notified when a `pod_start` ended
    pub started: tokio::sync::Notify,
}

impl Mock {
    pub fn cri() -> (Arc<Mock>, Arc<Cri<Mock>>) {
        Self::cri_with(|cri| cri)
    }

    /// [`Mock::cri`] with `set` applied to the CRI before it is shared.
    pub fn cri_with(set: impl FnOnce(Cri<Mock>) -> Cri<Mock>) -> (Arc<Mock>, Arc<Cri<Mock>>) {
        let m = Arc::new(Mock::default());
        let cri = Cri::new(
            m.clone(),
            Arc::new(Sessions::default()),
            "127.0.0.1:1".into(),
        );
        (m, Arc::new(set(cri)))
    }

    /// A pod of the engine that the CRI did not make
    pub fn add_foreign_pod(&self, id: &str) {
        self.st.lock().unwrap().pods.push(PodRecord {
            id: id.to_string(),
            status: PodStatus::Running,
            ..Default::default()
        });
    }

    pub fn calls(&self) -> Vec<String> {
        self.st.lock().unwrap().calls.clone()
    }
}

fn nf<T>(what: &str, id: &str) -> Result<T> {
    Err(EngineError::NotFound(format!("no such {what}: {id}")))
}

impl Engine for Mock {
    async fn version(&self) -> Result<RuntimeInfo> {
        let s = self.st.lock().unwrap();
        Ok(RuntimeInfo {
            name: "velarx".into(),
            version: "9.9".into(),
            api_version: "1.44".into(),
            cgroup_manager: velarx_proto::system::CgroupManager::Cgroupfs,
            oci_runtime: "crun".into(),
            oci_runtimes: vec!["kata".into()],
            handler_support: vec![
                velarx_proto::engine::RuntimeHandlerSupport {
                    name: "crun".into(),
                    recursive_read_only_mounts: true,
                    user_namespaces: true,
                },
                velarx_proto::engine::RuntimeHandlerSupport {
                    name: "kata".into(),
                    recursive_read_only_mounts: true,
                    user_namespaces: false,
                },
            ],
            cgroup_controllers: s.controllers.clone(),
            infra_image: s.infra_image.clone(),
        })
    }

    async fn pod_create(&self, spec: &PodCreate) -> Result<String> {
        let mut s = self.st.lock().unwrap();
        s.next += 1;
        let id = format!("pod{}", s.next);
        s.pod_creates.push(spec.clone());
        s.pods.push(PodRecord {
            id: id.clone(),
            name: spec.name.clone(),
            created_ns: 42,
            host_network: spec.net == NsMode::Host,
            host_ipc: spec.host_ipc,
            host_pid: spec.host_pid,
            spec: velarx_proto::pod::PodSpec {
                labels: spec.labels.clone(),
                hostname: Some(spec.hostname.clone()).filter(|h| !h.is_empty()),
                share_pid: spec.share_pid,
                ..Default::default()
            },
            ips: vec!["10.0.0.2".into()],
            infra_id: format!("{id}-infra"),
            infra_pid: 4242,
            oci_runtime: "crun".into(),
            netns_path: "/proc/4242/ns/net".into(),
            ..Default::default()
        });
        Ok(id)
    }

    async fn pod_start(&self, id: &str) -> Result<()> {
        let gate = self.st.lock().unwrap().start_gate.clone();
        if let Some(gate) = gate {
            gate.notified().await;
        }
        let mut s = self.st.lock().unwrap();
        s.calls.push(format!("pod_start {id}"));
        let done = match s.pods.iter_mut().find(|p| p.id == id) {
            Some(p) => {
                p.status = PodStatus::Running;
                Ok(())
            }
            None => nf("pod", id),
        };
        self.started.notify_one();
        done
    }

    async fn pod_stop(&self, id: &str, timeout: u32) -> Result<()> {
        let mut s = self.st.lock().unwrap();
        s.calls.push(format!("pod_stop {id} {timeout}"));
        match s.pods.iter_mut().find(|p| p.id == id) {
            Some(p) => {
                p.status = PodStatus::Exited;
                Ok(())
            }
            None => nf("pod", id),
        }
    }

    async fn pod_remove(&self, id: &str) -> Result<()> {
        let mut s = self.st.lock().unwrap();
        s.calls.push(format!("pod_remove {id}"));
        let before = s.pods.len();
        s.pods.retain(|p| p.id != id);
        if s.pods.len() == before {
            return nf("pod", id);
        }
        s.containers.retain(|c| c.pod_id != id);
        Ok(())
    }

    async fn pod_inspect(&self, id: &str) -> Result<PodRecord> {
        let s = self.st.lock().unwrap();
        if let Some(f) = &s.pod_inspect_fails {
            return Err(f.error());
        }
        s.pods
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .map_or_else(|| nf("pod", id), Ok)
    }

    async fn pod_list(&self) -> Result<Vec<PodRecord>> {
        Ok(self.st.lock().unwrap().pods.clone())
    }

    async fn container_create(&self, spec: &CreateContainerRequest) -> Result<String> {
        let mut s = self.st.lock().unwrap();
        s.next += 1;
        let id = format!("ctr{}", s.next);
        s.container_creates.push(spec.clone());
        s.containers.push(ContainerRecord {
            id: id.clone(),
            name: spec.name.clone().unwrap_or_default(),
            pod_id: spec.pod.clone().unwrap_or_default(),
            image: spec.image.clone(),
            image_id: "imgid".into(),
            labels: spec.labels.clone(),
            created_ns: 7,
            tty: spec.tty,
            stdin: spec.stdin_open,
            mounts: mounts_of(spec),
            pid: 4243,
            oci_runtime: "crun".into(),
            privileged: spec.privileged,
            process: velarx_proto::workload::ProcessConfig {
                resolved_user: Some(velarx_proto::workload::ProcessUser {
                    uid: 1000,
                    gid: 100,
                    additional_gids: vec![100, 10],
                }),
                ..Default::default()
            },
            ..Default::default()
        });
        Ok(id)
    }

    async fn container_start(&self, id: &str) -> Result<()> {
        let mut s = self.st.lock().unwrap();
        match s.containers.iter_mut().find(|c| c.id == id) {
            Some(c) => {
                c.state = RunState::Running;
                c.started_ns = 8;
                Ok(())
            }
            None => nf("container", id),
        }
    }

    async fn container_stop(&self, id: &str, timeout: u32) -> Result<()> {
        let mut s = self.st.lock().unwrap();
        s.calls.push(format!("container_stop {id} {timeout}"));
        match s.containers.iter_mut().find(|c| c.id == id) {
            Some(c) => {
                c.state = RunState::Exited;
                c.finished_ns = 9;
                c.exit_code = 137;
                Ok(())
            }
            None => nf("container", id),
        }
    }

    async fn container_remove(&self, id: &str) -> Result<()> {
        let mut s = self.st.lock().unwrap();
        let before = s.containers.len();
        s.containers.retain(|c| c.id != id);
        if s.containers.len() == before {
            return nf("container", id);
        }
        Ok(())
    }

    async fn container_inspect(&self, id: &str) -> Result<ContainerRecord> {
        let s = self.st.lock().unwrap();
        s.containers
            .iter()
            .find(|c| c.id == id)
            .cloned()
            .map_or_else(|| nf("container", id), Ok)
    }

    async fn container_runtime_spec(&self, id: &str) -> Result<serde_json::Value> {
        self.container_inspect(id).await?;
        if let Some(f) = &self.st.lock().unwrap().spec_fails {
            return Err(f.error());
        }
        Ok(serde_json::json!({"ociVersion": "1.2.0", "process": {
            "user": {"uid": 1000, "gid": 100, "additionalGids": [100, 10]}, "args": ["sh"],
            "oomScoreAdj": -997}}))
    }

    async fn container_list(&self) -> Result<Vec<ContainerRecord>> {
        let mut s = self.st.lock().unwrap();
        s.calls.push("container_list".into());
        Ok(s.containers.clone())
    }

    async fn pod_update(&self, id: &str, r: &Resources) -> Result<()> {
        let mut s = self.st.lock().unwrap();
        if !s.pods.iter().any(|p| p.id == id) {
            return nf("pod", id);
        }
        s.pod_updates.push((id.into(), r.clone()));
        Ok(())
    }

    async fn container_amend(&self, id: &str, spec: UpdateSpec) -> Result<()> {
        self.st.lock().unwrap().updates.push((id.into(), spec));
        Ok(())
    }

    async fn container_stats(&self, ids: &[String]) -> Result<Vec<StatsRecord>> {
        self.st.lock().unwrap().calls.push("container_stats".into());
        let running: Vec<String>;
        let ids = if ids.is_empty() {
            let s = self.st.lock().unwrap();
            running = s
                .containers
                .iter()
                .filter(|c| c.state == RunState::Running && !s.unsampled.contains(&c.id))
                .map(|c| c.id.clone())
                .collect();
            &running
        } else {
            ids
        };
        Ok(ids
            .iter()
            .map(|id| StatsRecord {
                id: id.clone(),
                cpu_nano: 1000,
                mem_usage: 2048,
                mem_working_set: 1024,
                page_faults: 7,
                rw_bytes: Some(4096),
                rw_inodes: Some(12),
                mem_limit: 4096,
                pids: 3,
                cpu_percent: 50.0,
                mem_anon: 512,
                mem_swap: 100,
                swap_limit: 1000,
                pressure: crate::runtime::pressure(),
                ..Default::default()
            })
            .collect())
    }

    async fn container_checkpoint(&self, _id: &str, _location: &str) -> Result<()> {
        Err(EngineError::Unsupported("checkpoint needs root".into()))
    }

    async fn pod_checkpoint(
        &self,
        containers: &[String],
        output: &str,
        manifest: &[u8],
    ) -> Result<()> {
        let mut s = self.st.lock().unwrap();
        s.pod_checkpoints
            .push((containers.to_vec(), output.to_string()));
        s.manifests.insert(output.to_string(), manifest.to_vec());
        Ok(())
    }

    async fn pod_checkpoint_manifest(&self, path: &str) -> Result<Vec<u8>> {
        match self.st.lock().unwrap().manifests.get(path) {
            Some(m) => Ok(m.clone()),
            None => nf("pod checkpoint", path),
        }
    }

    async fn container_restore_staged(&self, id: &str, path: &str, archive: &str) -> Result<()> {
        let mut s = self.st.lock().unwrap();
        if s.stage_fails.as_deref() == Some(id) {
            return Err(EngineError::Other("the staging fails".into()));
        }
        s.staged
            .push((id.to_string(), path.to_string(), archive.to_string()));
        Ok(())
    }

    async fn container_reopen_log(&self, id: &str) -> Result<()> {
        self.st.lock().unwrap().calls.push(format!("reopen {id}"));
        Ok(())
    }

    async fn exec_sync(&self, id: &str, cmd: &[String], _timeout: u64) -> Result<ExecResult> {
        let s = self.st.lock().unwrap();
        if let Some(f) = &s.exec_sync_fails {
            return Err(f.error());
        }
        if !s.containers.iter().any(|c| c.id == id) {
            return nf("container", id);
        }
        Ok(ExecResult {
            stdout: cmd.join(" ").into_bytes(),
            stderr: b"err".to_vec(),
            exit_code: s.exec_exit,
        })
    }

    async fn exec_open(&self, id: &str, spec: &ExecSpec) -> Result<ExecStream> {
        {
            let s = self.st.lock().unwrap();
            if !s.containers.iter().any(|c| c.id == id) {
                return nf("container", id);
            }
        }
        let (ours, theirs) = tokio::io::duplex(4096);
        let tty = spec.tty;
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut rd, mut wr) = tokio::io::split(theirs);
            let mut buf = [0u8; 256];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut out = Vec::new();
                        if !tty {
                            out.extend_from_slice(&[1, 0, 0, 0]);
                            out.extend_from_slice(&(n as u32).to_be_bytes());
                        }
                        out.extend_from_slice(&buf[..n]);
                        if wr.write_all(&out).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(ExecStream {
            id: "exec1".into(),
            framed: !tty,
            io: Box::new(ours),
        })
    }

    async fn exec_exit_code(&self, _exec_id: &str) -> Result<i32> {
        Ok(self.st.lock().unwrap().exec_exit)
    }

    async fn exec_kill(&self, exec_id: &str) -> Result<()> {
        self.st
            .lock()
            .unwrap()
            .calls
            .push(format!("exec kill {exec_id}"));
        Ok(())
    }

    async fn exec_resize(&self, _exec_id: &str, w: u16, h: u16) -> Result<()> {
        let mut s = self.st.lock().unwrap();
        s.calls.push(format!("resize {w}x{h}"));
        match &s.resize_fails {
            Some(f) => Err(f.error()),
            None => Ok(()),
        }
    }

    async fn attach_open(
        &self,
        id: &str,
        _stdin: bool,
        _stdin_once: bool,
        tty: bool,
    ) -> Result<ExecStream> {
        self.exec_open(
            id,
            &ExecSpec {
                tty,
                ..Default::default()
            },
        )
        .await
    }

    async fn image_list(&self) -> Result<Vec<ImageRecord>> {
        Ok(self.st.lock().unwrap().images.clone())
    }

    async fn image_inspect(&self, id: &str) -> Result<ImageRecord> {
        let s = self.st.lock().unwrap();
        s.images
            .iter()
            .find(|i| {
                i.id.starts_with(id)
                    || i.names
                        .iter()
                        .any(|n| n == id || n.ends_with(&format!("/{id}:latest")))
            })
            .cloned()
            .map_or_else(|| nf("image", id), Ok)
    }

    async fn image_pull(
        &self,
        reference: &str,
        access: Option<&velarx_registry::auth::RegistryAccess>,
    ) -> Result<String> {
        let mut s = self.st.lock().unwrap();
        s.pulls.push((reference.into(), access.cloned()));
        if !s.pull_unlisted {
            s.images.push(ImageRecord {
                id: "sha256img".into(),
                names: vec![format!("docker.io/library/{reference}:latest")],
                digests: vec![format!("docker.io/library/{reference}@sha256:abc")],
                size: 10,
                config: velarx_proto::workload::ImageConfigRecord {
                    user: "1001:2".into(),
                    ..Default::default()
                },
                ..Default::default()
            });
        }
        Ok("sha256img".into())
    }

    async fn image_remove(&self, id: &str) -> Result<()> {
        let mut s = self.st.lock().unwrap();
        s.images.retain(|i| i.id != id);
        match &s.image_remove_fails {
            Some(f) => Err(f.error()),
            None => Ok(()),
        }
    }

    async fn store_usage(&self) -> Result<StorageUsage> {
        self.st.lock().unwrap().calls.push("store_usage".into());
        if self.st.lock().unwrap().store_usage_fails {
            return Err(EngineError::Other("the store cannot be measured".into()));
        }
        Ok(StorageUsage {
            mountpoint: "/store".into(),
            images_bytes: 100,
            containers_bytes: 5,
            inodes_used: self.st.lock().unwrap().inodes_used,
        })
    }

    async fn network_status(&self, network: &str) -> Result<NetworkStatus> {
        let mut s = self.st.lock().unwrap();
        s.calls.push(format!("network_status {network}"));
        Ok(s.network.clone())
    }

    async fn events(&self) -> Result<tokio::sync::mpsc::Receiver<EngineEvent>> {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        {
            // (no event for now, the stream open)
            let mut s = self.st.lock().unwrap();
            if s.hold_events {
                s.events_held = Some(tx);
                return Ok(rx);
            }
        }
        let labels: std::collections::BTreeMap<String, String> =
            [(velarx_cri::meta::KIND.to_string(), "container".to_string())].into();
        for action in ["create", "start", "died", "remove", "attach"] {
            tx.send(EngineEvent {
                object: "container".into(),
                container_id: "ctr1".into(),
                pod_id: String::new(),
                action: action.into(),
                time_ns: 1,
                attributes: labels.clone(),
            })
            .await
            .unwrap();
        }
        // the events of each sandbox of the CRI, and of a pod it did not make
        let pods: Vec<String> = {
            let s = self.st.lock().unwrap();
            s.pods
                .iter()
                .filter(|p| velarx_cri::meta::is_kind(&p.spec.labels, "sandbox"))
                .map(|p| p.id.clone())
                .collect()
        };
        for pod in pods.iter().map(String::as_str).chain(["foreign"]) {
            for action in ["create", "start", "stop", "remove"] {
                tx.send(EngineEvent {
                    object: "pod".into(),
                    container_id: pod.into(),
                    pod_id: String::new(),
                    action: action.into(),
                    time_ns: 2,
                    attributes: Default::default(),
                })
                .await
                .unwrap();
            }
        }
        tx.send(EngineEvent {
            object: "container".into(),
            container_id: "other".into(),
            pod_id: String::new(),
            action: "start".into(),
            time_ns: 1,
            attributes: Default::default(),
        })
        .await
        .unwrap();
        Ok(rx)
    }

    async fn metric_descriptors(&self) -> Result<Vec<MetricDescriptor>> {
        Ok(vec![
            MetricDescriptor {
                name: "container_cpu_usage_seconds_total".into(),
                help: "cpu".into(),
                counter: true,
                labels: vec!["id".into()],
            },
            MetricDescriptor {
                name: "container_memory_rss".into(),
                help: "rss".into(),
                counter: false,
                labels: vec!["id".into()],
            },
        ])
    }

    async fn pod_metrics(&self) -> Result<Vec<PodMetrics>> {
        let mut s = self.st.lock().unwrap();
        s.calls.push("pod_metrics".into());
        if s.pod_metrics_fail {
            return Err(EngineError::Other("the metrics cannot be read".into()));
        }
        Ok(s.pods
            .iter()
            .map(|p| PodMetrics {
                id: p.id.clone(),
                name: String::new(),
                time_ns: 5,
                usage: s.pod_usage.clone(),
                samples: vec![MetricSample {
                    name: "container_memory_rss".into(),
                    labels: vec![p.id.clone()],
                    value: 3.9,
                }],
                containers: s
                    .containers
                    .iter()
                    .filter(|c| c.pod_id == p.id)
                    .map(|c| ContainerMetrics {
                        id: c.id.clone(),
                        name: String::new(),
                        samples: vec![MetricSample {
                            name: "container_cpu_usage_seconds_total".into(),
                            labels: vec![c.id.clone()],
                            value: 2.0,
                        }],
                    })
                    .collect(),
            })
            .collect())
    }

    async fn pod_dial(&self, _id: &str, _port: u16) -> Result<Box<dyn Io>> {
        let mut s = self.st.lock().unwrap();
        if s.dial_stuck {
            let (a, b) = tokio::io::duplex(64);
            s.dial_peers.push(b);
            return Ok(Box::new(a));
        }
        Err(EngineError::Unsupported("no dial".into()))
    }
}

/// The mounts the engine records of a request (the bind mounts and the
/// image mounts), as far as the tests look at them.
pub fn mounts_of(spec: &CreateContainerRequest) -> Vec<ContainerMount> {
    let mut out = Vec::new();
    for m in &spec.bind_mounts {
        let (source, destination) = (m.source.as_str(), m.target.as_str());
        let options = m.options.clone();
        let propagation = options
            .iter()
            .find(|o| ["rshared", "rslave", "rprivate"].contains(&o.as_str()))
            .cloned()
            .unwrap_or_else(|| "rprivate".into());
        out.push(ContainerMount {
            kind: MountKind::Bind,
            source: source.into(),
            destination: destination.into(),
            read_only: options.iter().any(|o| o == "ro"),
            propagation,
            options,
            ..Default::default()
        });
    }
    for m in &spec.image_mounts {
        out.push(ContainerMount {
            kind: MountKind::Image,
            source: m.image.clone(),
            destination: m.target.clone(),
            sub_path: m.subpath.clone().unwrap_or_default(),
            read_only: true,
            ..Default::default()
        });
    }
    out
}
