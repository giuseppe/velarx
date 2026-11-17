// SPDX-License-Identifier: Apache-2.0
//! `runtime.v1.RuntimeService`.

use super::convert::*;
use super::{once, status, Cri, Stream, CRI_API_VERSION, KUBE_RUNTIME_API};
use crate::api::*;
use crate::engine::{Engine, EngineError};
use crate::meta;
use crate::stream::Session;
use std::collections::HashMap;
use tonic::{Request, Response, Status};
use velarx_proto::engine::UpdateSpec;
use velarx_proto::workload::RunState;

/// The containers a `StopPodSandbox` finds running are killed, as
/// containerd does (it stops them with no grace period): the kubelet stops
/// each container with its own grace period first, and a caller with a
/// short deadline (kubeadm reset's `crictl stopp`) gets its answer within it.
const STOP_POD_TIMEOUT: u32 = 0;

/// How the stats of containers are asked of the engine.
#[derive(Clone, Copy)]
enum Each {
    /// By name: an error of one is the answer (`ContainerStats`)
    Named,
    /// Of what runs, as containerd and CRI-O list them: a container that
    /// ended or went away since the list, or that cannot be sampled, is left
    /// out, not the others with it
    BestEffort,
}

/// The CRI event an event of the engine is, by the action the engine
/// reports (`died`, for a container that ended); none for the others.
fn event_type(action: &str, pod_event: bool) -> Option<ContainerEventType> {
    Some(match action {
        "create" => ContainerEventType::ContainerCreatedEvent,
        "start" => ContainerEventType::ContainerStartedEvent,
        "died" if !pod_event => ContainerEventType::ContainerStoppedEvent,
        "stop" if pod_event => ContainerEventType::ContainerStoppedEvent,
        "remove" => ContainerEventType::ContainerDeletedEvent,
        _ => return None,
    })
}

/// The event of the CRI that an event of the engine is, `None` when it is
/// not one (or has no kind the CRI knows); `sandboxes` are the pods the CRI
/// made.  An engine that cannot answer is an error: the event is not dropped.
async fn relayed<E: Engine>(
    engine: &E,
    sandboxes: &mut std::collections::HashSet<String>,
    ev: crate::engine::EngineEvent,
) -> Result<Option<ContainerEventResponse>, Status> {
    use crate::engine::found;
    let pod_event = ev.object == "pod";
    let Some(kind) = event_type(&ev.action, pod_event) else {
        return Ok(None);
    };
    if pod_event {
        // the sandbox is the pod: its events have its id
        let pod = found(engine.pod_inspect(&ev.container_id).await).map_err(status)?;
        match &pod {
            Some(p) if meta::is_kind(&p.spec.labels, "sandbox") => {
                sandboxes.insert(p.id.clone());
            }
            _ if sandboxes.contains(&ev.container_id) => {}
            _ => return Ok(None),
        }
        if kind == ContainerEventType::ContainerDeletedEvent {
            sandboxes.remove(&ev.container_id);
        }
        return Ok(Some(ContainerEventResponse {
            container_id: ev.container_id,
            container_event_type: kind as i32,
            created_at: ev.time_ns,
            pod_sandbox_status: pod.as_ref().map(sandbox_status_of).transpose()?,
            containers_statuses: Vec::new(),
        }));
    }
    if !meta::is_kind(&ev.attributes, "container") {
        return Ok(None);
    }
    let pod = if ev.pod_id.is_empty() {
        None
    } else {
        found(engine.pod_inspect(&ev.pod_id).await).map_err(status)?
    };
    let statuses = found(engine.container_inspect(&ev.container_id).await)
        .map_err(status)?
        .iter()
        .map(container_status_of)
        .collect::<Result<_, _>>()?;
    Ok(Some(ContainerEventResponse {
        container_id: ev.container_id,
        container_event_type: kind as i32,
        created_at: ev.time_ns,
        pod_sandbox_status: pod.as_ref().map(sandbox_status_of).transpose()?,
        containers_statuses: statuses,
    }))
}

/// The network and IPC namespaces of a container are those of its pod: it
/// cannot have the host's where the pod has none, nor namespaces of its own.
/// What it asks for must be what the pod has, else the request is refused
/// (not ignored). (Its user namespace is its pod's, whatever the mappings
/// that the kubelet repeats in its options.)
fn check_namespaces_of_member(
    cfg: &ContainerConfig,
    pod: &velarx_proto::workload::PodRecord,
) -> Result<(), Status> {
    let Some(ns) = cfg
        .linux
        .as_ref()
        .and_then(|l| l.security_context.as_ref())
        .and_then(|s| s.namespace_options.as_ref())
    else {
        return Ok(());
    };
    for (kind, mode, host) in [
        ("network", ns.network, pod.host_network),
        ("IPC", ns.ipc, pod.host_ipc),
    ] {
        match NamespaceMode::try_from(mode) {
            Ok(NamespaceMode::Pod) => {}
            Ok(NamespaceMode::Node) if host => {}
            Ok(NamespaceMode::Node) => {
                return Err(Status::invalid_argument(format!(
                    "the container asks for the host's {kind} namespace and its pod has its own"
                )))
            }
            Ok(NamespaceMode::Container) => {
                return Err(Status::unimplemented(format!(
                    "velarx: a container with a {kind} namespace of its own in a pod is not supported by the engine"
                )))
            }
            _ => {
                return Err(Status::invalid_argument(format!(
                    "the {kind} namespace mode {mode} is not one of a container"
                )))
            }
        }
    }
    Ok(())
}

impl<E: Engine> Cri<E> {
    async fn sandbox_meta(
        &self,
        pod: &str,
    ) -> Result<(velarx_proto::workload::PodRecord, meta::SandboxMeta), Status> {
        let p = self.engine.pod_inspect(pod).await.map_err(status)?;
        if !meta::is_kind(&p.spec.labels, "sandbox") {
            return Err(Status::not_found(format!(
                "{pod} is not a sandbox of the CRI"
            )));
        }
        let (sm, _) = meta::decode(&p.spec.labels)?;
        Ok((p, sm))
    }

    async fn cri_container(
        &self,
        id: &str,
    ) -> Result<velarx_proto::workload::ContainerRecord, Status> {
        let c = self.engine.container_inspect(id).await.map_err(status)?;
        if !meta::is_kind(&c.labels, "container") {
            return Err(Status::not_found(format!(
                "{id} is not a container of the CRI"
            )));
        }
        Ok(c)
    }

    async fn containers(
        &self,
        f: Option<&ContainerFilter>,
    ) -> Result<Vec<velarx_proto::workload::ContainerRecord>, Status> {
        let all = self.engine.container_list().await.map_err(status)?;
        let mut out = Vec::new();
        for c in all
            .into_iter()
            .filter(|c| meta::is_kind(&c.labels, "container"))
        {
            let (_, user): (meta::ContainerMeta, _) = meta::decode(&c.labels)?;
            let keep = f.is_none_or(|f| {
                (f.id.is_empty() || c.id.starts_with(&f.id))
                    && (f.pod_sandbox_id.is_empty() || c.pod_id.starts_with(&f.pod_sandbox_id))
                    && f.state
                        .as_ref()
                        .is_none_or(|s| container_state(&c) as i32 == s.state)
                    && meta::matches_selector(&user, &f.label_selector)
            });
            if keep {
                out.push(c);
            }
        }
        Ok(out)
    }

    async fn sandboxes(
        &self,
        f: Option<&PodSandboxFilter>,
    ) -> Result<Vec<velarx_proto::workload::PodRecord>, Status> {
        let all = self.engine.pod_list().await.map_err(status)?;
        let mut out = Vec::new();
        for p in all
            .into_iter()
            .filter(|p| meta::is_kind(&p.spec.labels, "sandbox"))
        {
            let (_, user): (meta::SandboxMeta, _) = meta::decode(&p.spec.labels)?;
            let keep = f.is_none_or(|f| {
                (f.id.is_empty() || p.id.starts_with(&f.id))
                    && f.state
                        .as_ref()
                        .is_none_or(|s| sandbox_state(p.status.is_running()) as i32 == s.state)
                    && meta::matches_selector(&user, &f.label_selector)
            });
            if keep {
                out.push(p);
            }
        }
        Ok(out)
    }

    async fn stats_of(
        &self,
        list: &[velarx_proto::workload::ContainerRecord],
        each: Each,
    ) -> Result<Vec<ContainerStats>, Status> {
        Ok(self.stats_and_processes(list, each).await?.0)
    }

    /// The stats of the containers of LIST that run, and how many processes
    /// they have in all.
    async fn stats_and_processes(
        &self,
        list: &[velarx_proto::workload::ContainerRecord],
        each: Each,
    ) -> Result<(Vec<ContainerStats>, u64), Status> {
        let running: Vec<String> = list
            .iter()
            .filter(|c| run_state(c) == RunState::Running)
            .map(|c| c.id.clone())
            .collect();
        if running.is_empty() {
            return Ok((Vec::new(), 0));
        }
        let named = match each {
            Each::Named => running.as_slice(),
            Each::BestEffort => &[],
        };
        let stats = self.engine.container_stats(named).await.map_err(status)?;
        let mountpoint = self.engine.store_usage().await.map_err(status)?.mountpoint;
        stats_among(list, &stats, &mountpoint)
    }

    /// The metrics of the pods this frontend made that run.
    async fn pods_metrics(&self) -> Result<Vec<PodSandboxMetrics>, Status> {
        let descriptors = self.engine.metric_descriptors().await.map_err(status)?;
        let ours: std::collections::HashSet<String> = self
            .engine
            .pod_list()
            .await
            .map_err(status)?
            .into_iter()
            .filter(|p| meta::is_kind(&p.spec.labels, "sandbox"))
            .map(|p| p.id)
            .collect();
        Ok(self
            .engine
            .pod_metrics()
            .await
            .map_err(status)?
            .iter()
            .filter(|p| ours.contains(&p.id))
            .map(|p| pod_metrics_of(p, &descriptors))
            .collect())
    }

    /// What the stats of the sandboxes of one request are made of: asked of
    /// the engine once, whatever the number of sandboxes.
    async fn fleet(&self) -> Result<Fleet, Status> {
        let containers: Vec<_> = self
            .engine
            .container_list()
            .await
            .map_err(status)?
            .into_iter()
            .filter(|c| meta::is_kind(&c.labels, "container"))
            .collect();
        // (none runs: nothing to sample)
        let (stats, mountpoint) = if containers.iter().any(|c| run_state(c) == RunState::Running) {
            (
                self.engine.container_stats(&[]).await.map_err(status)?,
                self.engine.store_usage().await.map_err(status)?.mountpoint,
            )
        } else {
            (Vec::new(), String::new())
        };
        Ok(Fleet {
            containers,
            stats,
            mountpoint,
            metrics: self.engine.pod_metrics().await.map_err(status)?,
            descriptors: self.engine.metric_descriptors().await.map_err(status)?,
        })
    }

    /// The stats of the sandboxes `pods`, from one look at the engine.
    async fn pods_stats(
        &self,
        pods: &[velarx_proto::workload::PodRecord],
    ) -> Result<Vec<PodSandboxStats>, Status> {
        if pods.is_empty() {
            return Ok(Vec::new());
        }
        let fleet = self.fleet().await?;
        pods.iter().map(|p| pod_stats(p, &fleet)).collect()
    }
}

/// What [`Cri::fleet`] fetched.
struct Fleet {
    /// The containers of the CRI
    containers: Vec<velarx_proto::workload::ContainerRecord>,
    /// The samples of those that run
    stats: Vec<velarx_proto::workload::StatsRecord>,
    mountpoint: String,
    metrics: Vec<velarx_proto::workload::PodMetrics>,
    descriptors: Vec<velarx_proto::workload::MetricDescriptor>,
}

/// The stats of the containers of LIST that run, from the samples STATS (of
/// more containers, maybe), and how many processes they have in all.
fn stats_among(
    list: &[velarx_proto::workload::ContainerRecord],
    stats: &[velarx_proto::workload::StatsRecord],
    mountpoint: &str,
) -> Result<(Vec<ContainerStats>, u64), Status> {
    let running: std::collections::HashSet<&str> = list
        .iter()
        .filter(|c| run_state(c) == RunState::Running)
        .map(|c| c.id.as_str())
        .collect();
    let stats: Vec<_> = stats
        .iter()
        .filter(|s| running.contains(s.id.as_str()))
        .collect();
    let ts = now_ns();
    let processes = stats.iter().map(|s| s.pids).sum();
    let stats = stats
        .iter()
        .filter_map(|s| {
            list.iter()
                .find(|c| c.id == s.id)
                .map(|c| container_stats_of(c, s, ts, mountpoint))
        })
        .collect::<Result<_, _>>()?;
    Ok((stats, processes))
}

/// The stats of a sandbox: its containers' and its own.
fn pod_stats(
    p: &velarx_proto::workload::PodRecord,
    fleet: &Fleet,
) -> Result<PodSandboxStats, Status> {
    let (sm, user): (meta::SandboxMeta, _) = meta::decode(&p.spec.labels)?;
    let members: Vec<_> = fleet
        .containers
        .iter()
        .filter(|c| c.pod_id == p.id)
        .cloned()
        .collect();
    let (containers, processes) = stats_among(&members, &fleet.stats, &fleet.mountpoint)?;
    let ts = now_ns();
    // the network of the pod is that of its infra container: its interfaces
    // are in the metrics of the pod
    let (all, descriptors) = (&fleet.metrics, &fleet.descriptors);
    let metrics = all.iter().find(|m| m.id == p.id);
    let (network, own) = (
        metrics.and_then(|m| network_usage_of(m, descriptors, ts)),
        metrics.and_then(|m| m.usage.clone()),
    );
    let sum = |pick: &dyn Fn(&ContainerStats) -> Option<u64>| {
        containers.iter().filter_map(pick).sum::<u64>()
    };
    // The cgroup of the pod, when it has one, has the numbers of the pod
    // (its infra container and what the members leave included); else
    // the members' add up.
    let cpu = sum(&|c| {
        c.cpu
            .as_ref()?
            .usage_core_nano_seconds
            .as_ref()
            .map(|v| v.value)
    });
    let cores = sum(&|c| c.cpu.as_ref()?.usage_nano_cores.as_ref().map(|v| v.value));
    let mem = sum(&|c| {
        c.memory
            .as_ref()?
            .working_set_bytes
            .as_ref()
            .map(|v| v.value)
    });
    let rss = sum(&|c| c.memory.as_ref()?.rss_bytes.as_ref().map(|v| v.value));
    let pressure = own.as_ref().map(|u| &u.pressure);
    let memory = match &own {
        Some(u) => MemoryUsage {
            timestamp: ts,
            working_set_bytes: u64v(u.memory_working_set),
            available_bytes: (u.memory_limit > 0)
                .then(|| u64v(u.memory_limit.saturating_sub(u.memory_working_set)))
                .flatten(),
            usage_bytes: u64v(u.memory_usage),
            rss_bytes: u64v(u.memory_rss),
            psi: psi_of(u.pressure.memory.as_ref()),
            ..Default::default()
        },
        None => MemoryUsage {
            timestamp: ts,
            working_set_bytes: u64v(mem),
            usage_bytes: u64v(mem),
            rss_bytes: u64v(rss),
            ..Default::default()
        },
    };
    let cpu = own.as_ref().map_or(cpu, |u| u.cpu_usage_ns);
    Ok(PodSandboxStats {
        attributes: Some(PodSandboxAttributes {
            id: p.id.clone(),
            metadata: Some(PodSandboxMetadata {
                name: sm.name,
                uid: sm.uid,
                namespace: sm.namespace,
                attempt: sm.attempt,
            }),
            labels: user.into_iter().collect(),
            annotations: sm.annotations.into_iter().collect(),
        }),
        linux: Some(LinuxPodSandboxStats {
            cpu: Some(CpuUsage {
                timestamp: ts,
                usage_core_nano_seconds: u64v(cpu),
                usage_nano_cores: u64v(cores),
                psi: psi_of(pressure.and_then(|p| p.cpu.as_ref())),
            }),
            memory: Some(memory),
            network,
            process: Some(ProcessUsage {
                timestamp: ts,
                process_count: u64v(processes),
            }),
            containers,
            io: pressure.and_then(|p| io_usage_of(p, ts)),
        }),
        windows: None,
    })
}

#[tonic::async_trait]
impl<E: Engine> runtime_service_server::RuntimeService for Cri<E> {
    type StreamPodSandboxesStream = Stream<StreamPodSandboxesResponse>;
    type StreamContainersStream = Stream<StreamContainersResponse>;
    type StreamContainerStatsStream = Stream<StreamContainerStatsResponse>;
    type StreamPodSandboxStatsStream = Stream<StreamPodSandboxStatsResponse>;
    type GetContainerEventsStream = Stream<ContainerEventResponse>;
    type StreamPodSandboxMetricsStream = Stream<StreamPodSandboxMetricsResponse>;

    async fn version(
        &self,
        _req: Request<VersionRequest>,
    ) -> Result<Response<VersionResponse>, Status> {
        let v = self.engine.version().await.map_err(status)?;
        Ok(Response::new(VersionResponse {
            version: KUBE_RUNTIME_API.into(),
            runtime_name: v.name,
            runtime_version: v.version,
            runtime_api_version: CRI_API_VERSION.into(),
        }))
    }

    async fn run_pod_sandbox(
        &self,
        req: Request<RunPodSandboxRequest>,
    ) -> Result<Response<RunPodSandboxResponse>, Status> {
        let r = req.get_ref();
        let cfg = r
            .config
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("no sandbox config"))?;
        let (mut spec, _) = pod_create_of(cfg, &r.runtime_handler)?;
        spec.infra_image = self.sandbox_image.clone();
        if spec.net != crate::engine::NsMode::Host {
            spec.network = self.pod_network.clone();
            if spec.network.starts_with("cni:") {
                spec.cni_annotations = cfg
                    .annotations
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                spec.cni_ip_ranges = self.pod_cidr();
            }
        }
        if !r.runtime_handler.is_empty() {
            // the handlers are the runtimes of the engine: its default one by
            // name or the others it is configured with
            let v = self.engine.version().await.map_err(status)?;
            if r.runtime_handler == v.oci_runtime {
                spec.runtime.clear();
            } else if !v.oci_runtimes.contains(&r.runtime_handler) {
                return Err(Status::invalid_argument(format!(
                    "unknown runtime handler {:?}: the engine has {}",
                    r.runtime_handler,
                    std::iter::once(&v.oci_runtime)
                        .chain(&v.oci_runtimes)
                        .map(|n| n.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }
        // The sandbox is made and started, or removed, in a task of its own:
        // a kubelet that gives up (its deadline, a reset stream) drops this
        // handler, and the pod made so far would be left created, in the way
        // of the retry.
        let engine = self.engine.clone();
        let id = tokio::spawn(async move {
            let id = engine.pod_create(&spec).await?;
            if let Err(e) = engine.pod_start(&id).await {
                if let Err(re) = engine.pod_remove(&id).await {
                    tracing::warn!("Cannot remove the sandbox {id} that did not start: {re}");
                }
                return Err(e);
            }
            Ok(id)
        })
        .await
        .map_err(|e| Status::internal(format!("the sandbox was not made: {e}")))?
        .map_err(status)?;
        Ok(Response::new(RunPodSandboxResponse { pod_sandbox_id: id }))
    }

    async fn stop_pod_sandbox(
        &self,
        req: Request<StopPodSandboxRequest>,
    ) -> Result<Response<StopPodSandboxResponse>, Status> {
        match self
            .engine
            .pod_stop(&req.get_ref().pod_sandbox_id, STOP_POD_TIMEOUT)
            .await
        {
            Ok(()) | Err(EngineError::NotFound(_)) => Ok(Response::new(StopPodSandboxResponse {})),
            Err(e) => Err(status(e)),
        }
    }

    async fn remove_pod_sandbox(
        &self,
        req: Request<RemovePodSandboxRequest>,
    ) -> Result<Response<RemovePodSandboxResponse>, Status> {
        match self.engine.pod_remove(&req.get_ref().pod_sandbox_id).await {
            Ok(()) | Err(EngineError::NotFound(_)) => {
                Ok(Response::new(RemovePodSandboxResponse {}))
            }
            Err(e) => Err(status(e)),
        }
    }

    async fn pod_sandbox_status(
        &self,
        req: Request<PodSandboxStatusRequest>,
    ) -> Result<Response<PodSandboxStatusResponse>, Status> {
        let (p, sm) = self.sandbox_meta(&req.get_ref().pod_sandbox_id).await?;
        let mut info = HashMap::new();
        if req.get_ref().verbose {
            let network = self.pod_network.clone();
            info.insert(
                "info".to_string(),
                serde_json::json!({
                    "infra": p.infra_id,
                    "members": p.members.iter().map(|m| &m.id).collect::<Vec<_>>(),
                    "hostname": p.spec.hostname.clone().unwrap_or_default(),
                    "pid": p.infra_pid,
                    "runtimeHandler": sm.runtime_handler,
                    "runtimeType": p.oci_runtime,
                    "netnsPath": p.netns_path,
                    "ips": p.ips,
                    "network": if p.host_network { "host" } else if network.is_empty() { "default" } else { network.as_str() },
                    "logDirectory": sm.log_directory,
                })
                .to_string(),
            );
        }
        let containers_statuses = self
            .containers(Some(&ContainerFilter {
                pod_sandbox_id: p.id.clone(),
                ..Default::default()
            }))
            .await?
            .iter()
            .map(container_status_of)
            .collect::<Result<_, _>>()?;
        Ok(Response::new(PodSandboxStatusResponse {
            status: Some(sandbox_status_of(&p)?),
            info,
            containers_statuses,
            timestamp: now_ns(),
        }))
    }

    async fn list_pod_sandbox(
        &self,
        req: Request<ListPodSandboxRequest>,
    ) -> Result<Response<ListPodSandboxResponse>, Status> {
        let items = self
            .sandboxes(req.get_ref().filter.as_ref())
            .await?
            .iter()
            .map(sandbox_of)
            .collect::<Result<_, _>>()?;
        Ok(Response::new(ListPodSandboxResponse { items }))
    }

    async fn stream_pod_sandboxes(
        &self,
        req: Request<StreamPodSandboxesRequest>,
    ) -> Result<Response<Self::StreamPodSandboxesStream>, Status> {
        let pod_sandboxes = self
            .sandboxes(req.get_ref().filter.as_ref())
            .await?
            .iter()
            .map(sandbox_of)
            .collect::<Result<_, _>>()?;
        Ok(Response::new(once(StreamPodSandboxesResponse {
            pod_sandboxes,
        })))
    }

    async fn create_container(
        &self,
        req: Request<CreateContainerRequest>,
    ) -> Result<Response<CreateContainerResponse>, Status> {
        let r = req.get_ref();
        let cfg = r
            .config
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("no container config"))?;
        let (pod, sm) = self.sandbox_meta(&r.pod_sandbox_id).await?;
        let log_dir = r
            .sandbox_config
            .as_ref()
            .map(|s| s.log_directory.clone())
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| sm.log_directory.clone());
        check_namespaces_of_member(cfg, &pod)?;
        let huge = cfg
            .linux
            .as_ref()
            .and_then(|l| l.resources.as_ref())
            .is_some_and(|r| !r.hugepage_limits.is_empty());
        let hugetlb = huge && self.has_controller("hugetlb").await?;
        let (spec, _) = container_create_of(&pod.id, cfg, &log_dir, &sm.name, &sm, hugetlb)?;
        let id = self.engine.container_create(&spec).await.map_err(status)?;
        Ok(Response::new(CreateContainerResponse { container_id: id }))
    }

    async fn start_container(
        &self,
        req: Request<StartContainerRequest>,
    ) -> Result<Response<StartContainerResponse>, Status> {
        self.engine
            .container_start(&req.get_ref().container_id)
            .await
            .map_err(status)?;
        Ok(Response::new(StartContainerResponse {}))
    }

    async fn stop_container(
        &self,
        req: Request<StopContainerRequest>,
    ) -> Result<Response<StopContainerResponse>, Status> {
        let r = req.get_ref();
        match self
            .engine
            .container_stop(
                &r.container_id,
                u32::try_from(r.timeout.max(0)).unwrap_or(u32::MAX),
            )
            .await
        {
            Ok(()) | Err(EngineError::NotFound(_)) => Ok(Response::new(StopContainerResponse {})),
            Err(e) => Err(status(e)),
        }
    }

    async fn remove_container(
        &self,
        req: Request<RemoveContainerRequest>,
    ) -> Result<Response<RemoveContainerResponse>, Status> {
        match self
            .engine
            .container_remove(&req.get_ref().container_id)
            .await
        {
            Ok(()) | Err(EngineError::NotFound(_)) => Ok(Response::new(RemoveContainerResponse {})),
            Err(e) => Err(status(e)),
        }
    }

    async fn list_containers(
        &self,
        req: Request<ListContainersRequest>,
    ) -> Result<Response<ListContainersResponse>, Status> {
        let containers = self
            .containers(req.get_ref().filter.as_ref())
            .await?
            .iter()
            .map(container_of)
            .collect::<Result<_, _>>()?;
        Ok(Response::new(ListContainersResponse { containers }))
    }

    async fn stream_containers(
        &self,
        req: Request<StreamContainersRequest>,
    ) -> Result<Response<Self::StreamContainersStream>, Status> {
        let containers = self
            .containers(req.get_ref().filter.as_ref())
            .await?
            .iter()
            .map(container_of)
            .collect::<Result<_, _>>()?;
        Ok(Response::new(once(StreamContainersResponse { containers })))
    }

    async fn container_status(
        &self,
        req: Request<ContainerStatusRequest>,
    ) -> Result<Response<ContainerStatusResponse>, Status> {
        let c = self.cri_container(&req.get_ref().container_id).await?;
        let mut cs = container_status_of(&c)?;
        cs.user = container_user_of(c.process.resolved_user.as_ref());
        let mut info = HashMap::new();
        if req.get_ref().verbose {
            // (a container that is not created yet has no configuration)
            let spec = match self.engine.container_runtime_spec(&c.id).await {
                Ok(spec) => Some(spec),
                Err(EngineError::Precondition(_)) => None,
                Err(e) => return Err(status(e)),
            };
            info.insert(
                "info".to_string(),
                serde_json::json!({
                    "sandboxID": c.pod_id,
                    "pid": c.pid,
                    "runtimeType": c.oci_runtime,
                    "privileged": c.privileged,
                    "image": c.image,
                    "imageID": c.image_id,
                    "name": c.name,
                    "state": format!("{:?}", c.state),
                    "runtimeSpec": spec,
                })
                .to_string(),
            );
        }
        Ok(Response::new(ContainerStatusResponse {
            status: Some(cs),
            info,
        }))
    }

    async fn update_container_resources(
        &self,
        req: Request<UpdateContainerResourcesRequest>,
    ) -> Result<Response<UpdateContainerResourcesResponse>, Status> {
        let r = req.get_ref();
        if r.windows.is_some() {
            return Err(Status::invalid_argument("windows resources on linux"));
        }
        let lin = r.linux.clone().unwrap_or_default();
        let resources = resources_of(&lin)?;
        if resources.hugepage_limits.iter().any(|h| h.limit != 0) {
            return Err(Status::unimplemented(
                "velarx: hugepage limits cannot be changed in a running container",
            ));
        }
        if !resources.unified.is_empty() {
            return Err(Status::unimplemented(
                "velarx: unified cgroup settings cannot be changed in a running container",
            ));
        }
        // (the kubelet sends the score of the container's QoS class with every
        // update: the score it has is no change; another one is refused, as
        // the score of its running processes is not set again)
        if resources.oom_score_adj != 0 {
            let spec = self
                .engine
                .container_runtime_spec(&r.container_id)
                .await
                .map_err(status)?;
            let current = spec
                .pointer("/process/oomScoreAdj")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            if resources.oom_score_adj != current {
                return Err(Status::unimplemented(
                    "velarx: oom_score_adj cannot be changed in a running container",
                ));
            }
        }
        // (what the kubelet leaves at zero is not changed)
        let spec = UpdateSpec {
            memory: (resources.memory_limit > 0).then_some(resources.memory_limit),
            memory_swap: (resources.memory_swap > 0).then_some(resources.memory_swap),
            cpu_quota: (resources.cpu_quota != 0).then_some(resources.cpu_quota),
            cpu_period: u64::try_from(resources.cpu_period).ok().filter(|p| *p > 0),
            cpu_shares: u64::try_from(resources.cpu_shares).ok().filter(|s| *s > 0),
            cpuset_cpus: Some(resources.cpuset_cpus).filter(|c| !c.is_empty()),
            cpuset_mems: Some(resources.cpuset_mems).filter(|m| !m.is_empty()),
            ..Default::default()
        };
        self.engine
            .container_amend(&r.container_id, spec)
            .await
            .map_err(status)?;
        Ok(Response::new(UpdateContainerResourcesResponse {}))
    }

    async fn reopen_container_log(
        &self,
        req: Request<ReopenContainerLogRequest>,
    ) -> Result<Response<ReopenContainerLogResponse>, Status> {
        self.engine
            .container_reopen_log(&req.get_ref().container_id)
            .await
            .map_err(status)?;
        Ok(Response::new(ReopenContainerLogResponse {}))
    }

    async fn exec_sync(
        &self,
        req: Request<ExecSyncRequest>,
    ) -> Result<Response<ExecSyncResponse>, Status> {
        let r = req.get_ref();
        if r.cmd.is_empty() {
            return Err(Status::invalid_argument("no command"));
        }
        let out = self
            .engine
            .exec_sync(
                &r.container_id,
                &r.cmd,
                u64::try_from(r.timeout.max(0)).unwrap_or(0),
            )
            .await
            .map_err(status)?;
        Ok(Response::new(ExecSyncResponse {
            stdout: out.stdout,
            stderr: out.stderr,
            exit_code: out.exit_code,
        }))
    }

    async fn exec(&self, req: Request<ExecRequest>) -> Result<Response<ExecResponse>, Status> {
        let r = req.get_ref();
        if r.cmd.is_empty() {
            return Err(Status::invalid_argument("no command"));
        }
        if !r.stdin && !r.stdout && !r.stderr {
            return Err(Status::invalid_argument(
                "one of stdin, stdout, stderr is needed",
            ));
        }
        self.cri_container(&r.container_id).await?;
        let token = self.streams.add(Session::Exec {
            container: r.container_id.clone(),
            spec: crate::engine::ExecSpec {
                cmd: r.cmd.clone(),
                tty: r.tty,
                stdin: r.stdin,
                stdout: r.stdout,
                stderr: r.stderr && !r.tty,
            },
        });
        Ok(Response::new(ExecResponse {
            url: format!("http://{}/exec/{token}", self.stream_addr),
        }))
    }

    async fn attach(
        &self,
        req: Request<AttachRequest>,
    ) -> Result<Response<AttachResponse>, Status> {
        let r = req.get_ref();
        let c = self.cri_container(&r.container_id).await?;
        if r.stdin && !c.stdin {
            return Err(Status::failed_precondition(
                "the container was created without stdin",
            ));
        }
        let (cm, _): (meta::ContainerMeta, _) = meta::decode(&c.labels)?;
        let token = self.streams.add(Session::Attach {
            container: r.container_id.clone(),
            stdin: r.stdin,
            stdin_once: r.stdin && cm.stdin_once,
            tty: r.tty || c.tty,
            stdout: r.stdout,
            stderr: r.stderr,
        });
        Ok(Response::new(AttachResponse {
            url: format!("http://{}/attach/{token}", self.stream_addr),
        }))
    }

    async fn port_forward(
        &self,
        req: Request<PortForwardRequest>,
    ) -> Result<Response<PortForwardResponse>, Status> {
        let r = req.get_ref();
        self.sandbox_meta(&r.pod_sandbox_id).await?;
        // (a port is two channels of one byte on the WebSocket, and a
        // connection each: bounded as the SPDY forwards are)
        if r.port.len() > crate::stream::MAX_FORWARDS {
            return Err(Status::invalid_argument(format!(
                "{} ports: at most {} are forwarded at once",
                r.port.len(),
                crate::stream::MAX_FORWARDS
            )));
        }
        let token = self.streams.add(Session::PortForward {
            pod: r.pod_sandbox_id.clone(),
            ports: r
                .port
                .iter()
                .map(|p| {
                    u16::try_from(*p).ok().filter(|p| *p != 0).ok_or_else(|| {
                        Status::invalid_argument(format!("port {p} is not a TCP port"))
                    })
                })
                .collect::<Result<_, _>>()?,
        });
        Ok(Response::new(PortForwardResponse {
            url: format!("http://{}/portforward/{token}", self.stream_addr),
        }))
    }

    async fn container_stats(
        &self,
        req: Request<ContainerStatsRequest>,
    ) -> Result<Response<ContainerStatsResponse>, Status> {
        let c = self.cri_container(&req.get_ref().container_id).await?;
        let stats = self.stats_of(&[c], Each::Named).await?.into_iter().next();
        stats
            .map(|s| Response::new(ContainerStatsResponse { stats: Some(s) }))
            .ok_or_else(|| Status::failed_precondition("the container does not run: no stats"))
    }

    async fn list_container_stats(
        &self,
        req: Request<ListContainerStatsRequest>,
    ) -> Result<Response<ListContainerStatsResponse>, Status> {
        let f = req.get_ref().filter.clone().unwrap_or_default();
        let filter = ContainerFilter {
            id: f.id,
            pod_sandbox_id: f.pod_sandbox_id,
            label_selector: f.label_selector,
            state: None,
        };
        let list = self.containers(Some(&filter)).await?;
        Ok(Response::new(ListContainerStatsResponse {
            stats: self.stats_of(&list, Each::BestEffort).await?,
        }))
    }

    async fn stream_container_stats(
        &self,
        req: Request<StreamContainerStatsRequest>,
    ) -> Result<Response<Self::StreamContainerStatsStream>, Status> {
        let f = req.get_ref().filter.clone().unwrap_or_default();
        let filter = ContainerFilter {
            id: f.id,
            pod_sandbox_id: f.pod_sandbox_id,
            label_selector: f.label_selector,
            state: None,
        };
        let list = self.containers(Some(&filter)).await?;
        Ok(Response::new(once(StreamContainerStatsResponse {
            container_stats: self.stats_of(&list, Each::BestEffort).await?,
        })))
    }

    async fn pod_sandbox_stats(
        &self,
        req: Request<PodSandboxStatsRequest>,
    ) -> Result<Response<PodSandboxStatsResponse>, Status> {
        let (p, _) = self.sandbox_meta(&req.get_ref().pod_sandbox_id).await?;
        Ok(Response::new(PodSandboxStatsResponse {
            stats: self.pods_stats(&[p]).await?.pop(),
        }))
    }

    async fn list_pod_sandbox_stats(
        &self,
        req: Request<ListPodSandboxStatsRequest>,
    ) -> Result<Response<ListPodSandboxStatsResponse>, Status> {
        let f = req.get_ref().filter.clone().unwrap_or_default();
        let filter = PodSandboxFilter {
            id: f.id,
            state: None,
            label_selector: f.label_selector,
        };
        let pods = self.sandboxes(Some(&filter)).await?;
        let stats = self.pods_stats(&pods).await?;
        Ok(Response::new(ListPodSandboxStatsResponse { stats }))
    }

    async fn stream_pod_sandbox_stats(
        &self,
        req: Request<StreamPodSandboxStatsRequest>,
    ) -> Result<Response<Self::StreamPodSandboxStatsStream>, Status> {
        let f = req.get_ref().filter.clone().unwrap_or_default();
        let filter = PodSandboxFilter {
            id: f.id,
            state: None,
            label_selector: f.label_selector,
        };
        let pods = self.sandboxes(Some(&filter)).await?;
        let stats = self.pods_stats(&pods).await?;
        Ok(Response::new(once(StreamPodSandboxStatsResponse {
            pod_sandbox_stats: stats,
        })))
    }

    async fn update_runtime_config(
        &self,
        req: Request<UpdateRuntimeConfigRequest>,
    ) -> Result<Response<UpdateRuntimeConfigResponse>, Status> {
        let cidr = req
            .get_ref()
            .runtime_config
            .as_ref()
            .and_then(|c| c.network_config.as_ref())
            .map(|n| n.pod_cidr.trim())
            .unwrap_or_default();
        let ranges = pod_cidr_ranges(cidr)?;
        // The subnets only mean something to the plugins of a CNI network
        // (their `ipRanges` capability): the engine's own networks have
        // subnets of their own, and a pod CIDR they do not use is refused.
        if !ranges.is_empty() && !self.pod_network.starts_with("cni:") {
            return Err(Status::failed_precondition(format!(
                "velarx: the pod CIDR {cidr} cannot be used: the pods are on the engine's network, which has subnets of its own (start velarx-cri with --pod-network cni: to give the CNI plugins the range)"
            )));
        }
        *self
            .pod_cidr
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = ranges;
        Ok(Response::new(UpdateRuntimeConfigResponse {}))
    }

    async fn status(
        &self,
        req: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let v = self.engine.version().await;
        let cond = |t: &str, ok: bool, reason: &str, msg: String| RuntimeCondition {
            r#type: t.into(),
            status: ok,
            reason: if ok { String::new() } else { reason.into() },
            message: if ok { String::new() } else { msg },
        };
        let err = v.as_ref().err().map(|e| e.to_string()).unwrap_or_default();
        let ok = v.is_ok();
        let network = self.network_ready().await;
        let mut info = HashMap::new();
        if req.get_ref().verbose {
            if let Ok(v) = &v {
                let mut config = serde_json::json!({
                    "engine": v.version,
                    "api": v.api_version,
                    "ociRuntime": v.oci_runtime,
                    "ociRuntimes": v.oci_runtimes,
                    "cgroupManager": v.cgroup_manager,
                    "podNetwork": self.pod_network,
                    "podCIDR": self.pod_cidr(),
                });
                // (none without --sandbox-image: the engine's infra image is
                // not known here, and an empty name is not one)
                if !self.sandbox_image.is_empty() {
                    config["sandboxImage"] = self.sandbox_image.clone().into();
                }
                info.insert("config".to_string(), config.to_string());
            }
        }
        // the default runtime (its name too) and the others of the engine
        let runtimes: Vec<String> = v
            .as_ref()
            .map(|v| {
                std::iter::once(v.oci_runtime.clone())
                    .chain(v.oci_runtimes.iter().cloned())
                    .filter(|n| !n.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        // the features of each runtime (the unnamed handler is the default
        // runtime); an engine that says nothing of one has none of them
        let handler = |name: &str| {
            let of = if name.is_empty() {
                v.as_ref().map(|v| v.oci_runtime.as_str()).unwrap_or("")
            } else {
                name
            };
            let support = v
                .as_ref()
                .ok()
                .and_then(|v| v.handler_support.iter().find(|h| h.name == of));
            RuntimeHandler {
                name: name.into(),
                features: Some(RuntimeHandlerFeatures {
                    recursive_read_only_mounts: support
                        .is_some_and(|h| h.recursive_read_only_mounts),
                    user_namespaces: support.is_some_and(|h| h.user_namespaces),
                }),
            }
        };
        Ok(Response::new(StatusResponse {
            status: Some(RuntimeStatus {
                conditions: vec![
                    cond("RuntimeReady", ok, "EngineUnavailable", err.clone()),
                    match &network {
                        Err(why) if ok => {
                            cond("NetworkReady", false, "NetworkPluginNotReady", why.clone())
                        }
                        _ => cond("NetworkReady", ok, "EngineUnavailable", err),
                    },
                ],
            }),
            info,
            runtime_handlers: std::iter::once(String::new())
                .chain(runtimes)
                .map(|n| handler(&n))
                .collect(),
            features: Some(RuntimeFeatures {
                supplemental_groups_policy: true,
                user_namespaces_host_network: false,
                mount_options: true,
            }),
        }))
    }

    async fn checkpoint_container(
        &self,
        req: Request<CheckpointContainerRequest>,
    ) -> Result<Response<CheckpointContainerResponse>, Status> {
        let r = req.get_ref();
        if r.location.is_empty() {
            return Err(Status::invalid_argument("no location"));
        }
        self.engine
            .container_checkpoint(&r.container_id, &r.location)
            .await
            .map_err(status)?;
        Ok(Response::new(CheckpointContainerResponse {}))
    }

    async fn checkpoint_pod(
        &self,
        req: Request<CheckpointPodRequest>,
    ) -> Result<Response<CheckpointPodResponse>, Status> {
        let r = req.get_ref();
        if let Some(key) = r.options.keys().min() {
            return Err(Status::invalid_argument(format!(
                "velarx has no checkpoint option {key:?}"
            )));
        }
        if r.output_path.is_empty() {
            return Err(Status::invalid_argument("no output path"));
        }
        if r.container_ids.is_empty() {
            return Err(Status::invalid_argument("no container to checkpoint"));
        }
        let (pod, sm) = self.sandbox_meta(&r.pod_sandbox_id).await?;
        if !pod.status.is_running() {
            return Err(Status::failed_precondition(format!(
                "the sandbox {} is not ready",
                pod.id
            )));
        }
        let mut members = Vec::new();
        for id in &r.container_ids {
            let c = self.cri_container(id).await?;
            if c.pod_id != pod.id {
                return Err(Status::invalid_argument(format!(
                    "the container {} is not in the sandbox {}",
                    c.id, pod.id
                )));
            }
            if run_state(&c) != RunState::Running {
                return Err(Status::failed_precondition(format!(
                    "the container {} is not running",
                    c.id
                )));
            }
            if members
                .iter()
                .any(|m: &velarx_proto::workload::ContainerRecord| m.id == c.id)
            {
                return Err(Status::invalid_argument(format!(
                    "the container {} is more than once in the request",
                    c.id
                )));
            }
            members.push(c);
        }
        let (_, labels): (meta::SandboxMeta, _) = meta::decode(&pod.spec.labels)?;
        let manifest = meta::PodCheckpoint {
            version: meta::POD_CHECKPOINT_VERSION,
            checkpointed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as i64),
            sandbox: sm,
            labels,
            hostname: pod.spec.hostname.clone().unwrap_or_default(),
            host_network: pod.host_network,
            host_ipc: pod.host_ipc,
            host_pid: pod.host_pid,
            shared_pid: pod.spec.share_pid,
            ips: pod.ips.clone(),
            containers: members
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    let (cm, labels): (meta::ContainerMeta, _) = meta::decode(&c.labels)?;
                    Ok::<_, meta::MetaError>(meta::CheckpointedContainer {
                        meta: cm,
                        labels,
                        image_id: c.image_id.clone(),
                        archive: format!("{i}.tar"),
                    })
                })
                .collect::<Result<_, _>>()?,
        };
        let manifest = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| Status::internal(format!("the manifest: {e}")))?;
        let ids: Vec<String> = members.into_iter().map(|c| c.id).collect();
        // The containers are paused while this runs, and resumed when it
        // ends: a task of its own, so that a caller whose deadline passed
        // does not leave the pod frozen.
        let engine = self.engine.clone();
        let output = r.output_path.clone();
        tokio::spawn(async move { engine.pod_checkpoint(&ids, &output, &manifest).await })
            .await
            .map_err(|e| Status::internal(format!("the checkpoint: {e}")))?
            .map_err(status)?;
        Ok(Response::new(CheckpointPodResponse {}))
    }

    async fn restore_pod(
        &self,
        req: Request<RestorePodRequest>,
    ) -> Result<Response<RestorePodResponse>, Status> {
        let r = req.into_inner();
        if let Some(key) = r.options.keys().min() {
            return Err(Status::invalid_argument(format!(
                "velarx has no restore option {key:?}"
            )));
        }
        let config = r
            .config
            .ok_or_else(|| Status::invalid_argument("no sandbox config"))?;
        if r.container_configs.is_empty() {
            return Err(Status::invalid_argument("no container configs"));
        }
        let manifest = self
            .engine
            .pod_checkpoint_manifest(&r.checkpoint_path)
            .await
            .map_err(status)?;
        let saved: meta::PodCheckpoint = serde_json::from_slice(&manifest).map_err(|e| {
            Status::invalid_argument(format!(
                "{} is not a pod checkpoint of velarx: {e}",
                r.checkpoint_path
            ))
        })?;
        if saved.version != meta::POD_CHECKPOINT_VERSION {
            return Err(Status::invalid_argument(format!(
                "{} is a pod checkpoint of version {}, velarx restores version {}",
                r.checkpoint_path,
                saved.version,
                meta::POD_CHECKPOINT_VERSION
            )));
        }
        if saved.sandbox.runtime_handler != r.runtime_handler {
            return Err(Status::invalid_argument(format!(
                "the pod was checkpointed with the runtime handler {:?}, not {:?}",
                saved.sandbox.runtime_handler, r.runtime_handler
            )));
        }
        // each container of the request is one of the checkpoint, by name,
        // and is what was running
        let mut plan = Vec::new();
        for cc in &r.container_configs {
            let name = cc.metadata.as_ref().map(|m| m.name.as_str()).unwrap_or("");
            if name.is_empty() {
                return Err(Status::invalid_argument("a container config has no name"));
            }
            if plan.iter().any(|(n, _, _): &(&str, _, _)| *n == name) {
                return Err(Status::invalid_argument(format!(
                    "the container {name} is more than once in the request"
                )));
            }
            let Some(was) = saved.containers.iter().find(|c| c.meta.name == name) else {
                return Err(Status::invalid_argument(format!(
                    "the checkpoint has no container {name}"
                )));
            };
            let image = cc.image.clone().unwrap_or_default();
            let image = if image.user_specified_image.is_empty() {
                image.image
            } else {
                image.user_specified_image
            };
            for (what, ok) in [
                ("image", image == was.meta.image),
                ("command", cc.command == was.meta.command),
                ("args", cc.args == was.meta.args),
                ("working directory", cc.working_dir == was.meta.working_dir),
                ("environment", env_digest(cc) == was.meta.env_digest),
                ("user", user_of(cc)? == was.meta.user),
            ] {
                if !ok {
                    return Err(Status::invalid_argument(format!(
                        "the {what} of the container {name} is not the one it was checkpointed with"
                    )));
                }
            }
            plan.push((name, cc, was));
        }
        if let Some(missing) = saved
            .containers
            .iter()
            .find(|c| !plan.iter().any(|(n, _, _)| *n == c.meta.name))
        {
            return Err(Status::invalid_argument(format!(
                "the request has no config for the container {} of the checkpoint",
                missing.meta.name
            )));
        }
        let pod = self
            .run_pod_sandbox(Request::new(RunPodSandboxRequest {
                config: Some(config.clone()),
                runtime_handler: r.runtime_handler.clone(),
            }))
            .await?
            .into_inner()
            .pod_sandbox_id;
        let restored = async {
            let mut restored = Vec::new();
            for (name, cc, was) in plan {
                let id = self
                    .create_container(Request::new(CreateContainerRequest {
                        pod_sandbox_id: pod.clone(),
                        config: Some(cc.clone()),
                        sandbox_config: Some(config.clone()),
                    }))
                    .await?
                    .into_inner()
                    .container_id;
                restored.push(RestoredContainer {
                    name: name.to_string(),
                    container_id: id.clone(),
                });
                self.engine
                    .container_restore_staged(&id, &r.checkpoint_path, &was.archive)
                    .await
                    .map_err(status)?;
            }
            Ok::<_, Status>(restored)
        }
        .await;
        match restored {
            Ok(restored_containers) => Ok(Response::new(RestorePodResponse {
                pod_sandbox_id: pod,
                restored_containers,
            })),
            Err(e) => {
                if let Err(gone) = self.engine.pod_remove(&pod).await {
                    tracing::warn!("cannot remove the sandbox {pod} of a failed restore: {gone}");
                }
                Err(e)
            }
        }
    }

    async fn get_container_events(
        &self,
        _req: Request<GetEventsRequest>,
    ) -> Result<Response<Self::GetContainerEventsStream>, Status> {
        let mut rx = self.engine.events().await.map_err(status)?;
        // the sandboxes of the CRI: those there are, and the ones created
        // from now on (an event of the removal comes when the pod is gone)
        let mut sandboxes: std::collections::HashSet<String> = self
            .sandboxes(None)
            .await?
            .into_iter()
            .map(|p| p.id)
            .collect();
        let engine = self.engine.clone();
        let (tx, out) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            // (a kubelet that went away ends the relay at once, and with it
            // the events of the engine)
            loop {
                let ev = tokio::select! {
                    ev = rx.recv() => ev,
                    () = tx.closed() => return,
                };
                let Some(ev) = ev else { return };
                let msg = match relayed(engine.as_ref(), &mut sandboxes, ev).await {
                    Ok(Some(msg)) => msg,
                    Ok(None) => continue,
                    Err(e) => {
                        // the kubelet asks for the events again
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                };
                if tx.send(Ok(msg)).await.is_err() {
                    return;
                }
            }
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(out),
        )))
    }

    async fn list_metric_descriptors(
        &self,
        _req: Request<ListMetricDescriptorsRequest>,
    ) -> Result<Response<ListMetricDescriptorsResponse>, Status> {
        let descriptors = self.engine.metric_descriptors().await.map_err(status)?;
        Ok(Response::new(ListMetricDescriptorsResponse {
            descriptors: descriptors.iter().map(metric_descriptor_of).collect(),
        }))
    }

    async fn list_pod_sandbox_metrics(
        &self,
        _req: Request<ListPodSandboxMetricsRequest>,
    ) -> Result<Response<ListPodSandboxMetricsResponse>, Status> {
        Ok(Response::new(ListPodSandboxMetricsResponse {
            pod_metrics: self.pods_metrics().await?,
        }))
    }

    async fn stream_pod_sandbox_metrics(
        &self,
        _req: Request<StreamPodSandboxMetricsRequest>,
    ) -> Result<Response<Self::StreamPodSandboxMetricsStream>, Status> {
        Ok(Response::new(once(StreamPodSandboxMetricsResponse {
            pod_sandbox_metrics: self.pods_metrics().await?,
        })))
    }

    async fn runtime_config(
        &self,
        _req: Request<RuntimeConfigRequest>,
    ) -> Result<Response<RuntimeConfigResponse>, Status> {
        let v = self.engine.version().await.map_err(status)?;
        let driver = if v.cgroup_manager == velarx_proto::system::CgroupManager::Systemd {
            CgroupDriver::Systemd
        } else {
            CgroupDriver::Cgroupfs
        };
        Ok(Response::new(RuntimeConfigResponse {
            linux: Some(LinuxRuntimeConfiguration {
                cgroup_driver: driver as i32,
            }),
        }))
    }

    async fn update_pod_sandbox_resources(
        &self,
        req: Request<UpdatePodSandboxResourcesRequest>,
    ) -> Result<Response<UpdatePodSandboxResourcesResponse>, Status> {
        let r = req.get_ref();
        let (p, _) = self.sandbox_meta(&r.pod_sandbox_id).await?;
        let Some(lin) = r.resources.as_ref() else {
            return Ok(Response::new(UpdatePodSandboxResourcesResponse {}));
        };
        let resources = sandbox_resources_of(lin, "a pod")?;
        let overhead = match &r.overhead {
            Some(o) => sandbox_resources_of(o, "the overhead of a pod")?,
            None => Default::default(),
        };
        // the limits of the cgroup of the pod are replaced; the OOM score of
        // the sandbox is not applied (docs/CRI.md)
        self.engine
            .pod_update(&p.id, &sandbox_limits(&resources, &overhead))
            .await
            .map_err(status)?;
        Ok(Response::new(UpdatePodSandboxResourcesResponse {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_container_that_ended_is_the_action_the_engine_reports() {
        assert_eq!(
            event_type("died", false),
            Some(ContainerEventType::ContainerStoppedEvent)
        );
        // (Docker's word is not the engine's)
        assert_eq!(event_type("die", false), None);
        assert_eq!(event_type("died", true), None);
        assert_eq!(
            event_type("stop", true),
            Some(ContainerEventType::ContainerStoppedEvent)
        );
        assert_eq!(event_type("stop", false), None);
    }
}
