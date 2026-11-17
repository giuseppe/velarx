// SPDX-License-Identifier: Apache-2.0
use crate::mock::Mock;
use futures::StreamExt;
use tonic::{Code, Request};
use velarx_cri::api::image_service_server::ImageService;
use velarx_cri::api::runtime_service_server::RuntimeService;
use velarx_cri::api::*;
use velarx_proto::workload::Resources;

pub fn sandbox_config() -> PodSandboxConfig {
    PodSandboxConfig {
        metadata: Some(PodSandboxMetadata {
            name: "web".into(),
            uid: "u1".into(),
            namespace: "default".into(),
            attempt: 1,
        }),
        hostname: "h".into(),
        log_directory: "/var/log/pods/x".into(),
        dns_config: Some(DnsConfig {
            servers: vec!["1.1.1.1".into()],
            searches: vec!["a.test".into()],
            options: vec!["ndots:5".into()],
        }),
        port_mappings: vec![
            PortMapping {
                protocol: 1,
                container_port: 53,
                host_port: 5353,
                host_ip: String::new(),
            },
            PortMapping {
                protocol: 0,
                container_port: 80,
                host_port: 0,
                host_ip: String::new(),
            },
        ],
        labels: [("app".to_string(), "web".to_string())].into(),
        annotations: [("note".to_string(), "n".to_string())].into(),
        linux: Some(LinuxPodSandboxConfig {
            cgroup_parent: "kubepods.slice".into(),
            sysctls: [("net.ipv4.ip_forward".to_string(), "1".to_string())].into(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub async fn run_pod(cri: &velarx_cri::service::Cri<Mock>) -> String {
    cri.run_pod_sandbox(Request::new(RunPodSandboxRequest {
        config: Some(sandbox_config()),
        runtime_handler: String::new(),
    }))
    .await
    .unwrap()
    .into_inner()
    .pod_sandbox_id
}

/// A kubelet that gives up on RunPodSandbox (its deadline) does not leave
/// a created pod behind: the sandbox is started whatever became of the call.
#[tokio::test]
async fn a_run_pod_sandbox_that_is_dropped_still_starts_the_pod() {
    let (mock, cri) = Mock::cri();
    let gate = std::sync::Arc::new(tokio::sync::Notify::new());
    mock.st.lock().unwrap().start_gate = Some(gate.clone());
    // the handler is dropped while the engine starts the pod
    let called = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        cri.run_pod_sandbox(Request::new(RunPodSandboxRequest {
            config: Some(sandbox_config()),
            runtime_handler: String::new(),
        })),
    )
    .await;
    assert!(called.is_err(), "the start was gated");
    gate.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(10), mock.started.notified())
        .await
        .expect("the pod is started");
    let st = mock.st.lock().unwrap();
    assert_eq!(st.pods.len(), 1);
    assert_eq!(
        st.pods[0].status,
        velarx_proto::workload::PodStatus::Running
    );
}

pub fn container_config() -> ContainerConfig {
    ContainerConfig {
        metadata: Some(ContainerMetadata {
            name: "main".into(),
            attempt: 0,
        }),
        image: Some(ImageSpec {
            image: "busybox".into(),
            ..Default::default()
        }),
        command: vec!["sleep".into()],
        args: vec!["600".into()],
        envs: vec![KeyValue {
            key: "A".into(),
            value: b"b".to_vec(),
        }],
        labels: [("l".to_string(), "1".to_string())].into(),
        annotations: [("a".to_string(), "2".to_string())].into(),
        log_path: "main/0.log".into(),
        linux: Some(LinuxContainerConfig {
            resources: Some(LinuxContainerResources {
                memory_limit_in_bytes: 1 << 20,
                cpu_quota: 5000,
                cpu_period: 10000,
                ..Default::default()
            }),
            security_context: Some(LinuxContainerSecurityContext {
                run_as_user: Some(Int64Value { value: 1000 }),
                run_as_group: Some(Int64Value { value: 2000 }),
                supplemental_groups: vec![5, 6],
                readonly_rootfs: true,
                no_new_privs: true,
                capabilities: Some(Capability {
                    add_capabilities: vec!["NET_ADMIN".into()],
                    drop_capabilities: vec!["ALL".into()],
                    add_ambient_capabilities: vec![],
                }),
                seccomp: Some(SecurityProfile {
                    profile_type: security_profile::ProfileType::Localhost as i32,
                    localhost_ref: "/profiles/s.json".into(),
                }),
                ..Default::default()
            }),
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn version_and_status() {
    let (_, cri) = Mock::cri();
    let v = cri
        .version(Request::new(VersionRequest::default()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (
            v.runtime_name.as_str(),
            v.runtime_version.as_str(),
            v.runtime_api_version.as_str()
        ),
        ("velarx", "9.9", "v1")
    );
    let s = cri
        .status(Request::new(StatusRequest { verbose: true }))
        .await
        .unwrap()
        .into_inner();
    let conds = s.status.unwrap().conditions;
    assert!(conds.iter().all(|c| c.status));
    assert_eq!(conds.len(), 2);
    let c = cri
        .runtime_config(Request::new(RuntimeConfigRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        c.linux.unwrap().cgroup_driver,
        CgroupDriver::Cgroupfs as i32
    );
    cri.update_runtime_config(Request::new(UpdateRuntimeConfigRequest::default()))
        .await
        .unwrap();
}

#[tokio::test]
async fn sandbox_lifecycle() {
    let (mock, cri) = Mock::cri();
    let id = run_pod(&cri).await;
    {
        let s = mock.st.lock().unwrap();
        let p = &s.pod_creates[0];
        assert_eq!(p.name, "k8s_web_default_u1_1");
        assert_eq!(p.dns_servers, ["1.1.1.1"]);
        assert_eq!(p.cgroup_parent, "kubepods.slice");
        assert_eq!(
            p.ports.len(),
            1,
            "a mapping with no host port is not published"
        );
        assert_eq!(p.ports[0].protocol, "udp");
        assert_eq!(p.sysctls["net.ipv4.ip_forward"], "1");
    }
    let st = cri
        .pod_sandbox_status(Request::new(PodSandboxStatusRequest {
            pod_sandbox_id: id.clone(),
            verbose: false,
        }))
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap();
    assert_eq!(st.state, PodSandboxState::SandboxReady as i32);
    assert_eq!(st.network.unwrap().ip, "10.0.0.2");
    assert_eq!(st.annotations["note"], "n");
    assert_eq!(st.labels["app"], "web");
    assert!(!st.labels.contains_key(velarx_cri::meta::META));
    assert_eq!(st.metadata.unwrap().attempt, 1);

    let list = cri
        .list_pod_sandbox(Request::new(ListPodSandboxRequest::default()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(list.items.len(), 1);
    let none = cri
        .list_pod_sandbox(Request::new(ListPodSandboxRequest {
            filter: Some(PodSandboxFilter {
                label_selector: [("app".to_string(), "other".to_string())].into(),
                ..Default::default()
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(none.items.is_empty());

    cri.stop_pod_sandbox(Request::new(StopPodSandboxRequest {
        pod_sandbox_id: id.clone(),
    }))
    .await
    .unwrap();
    // (what still runs is killed, as containerd does: the kubelet stopped
    // the containers with their grace periods before, and a caller with a
    // short deadline gets its answer)
    assert!(mock
        .st
        .lock()
        .unwrap()
        .calls
        .contains(&format!("pod_stop {id} 0")));
    let list = cri
        .list_pod_sandbox(Request::new(ListPodSandboxRequest {
            filter: Some(PodSandboxFilter {
                state: Some(PodSandboxStateValue {
                    state: PodSandboxState::SandboxNotready as i32,
                }),
                ..Default::default()
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(list.items.len(), 1);
    cri.remove_pod_sandbox(Request::new(RemovePodSandboxRequest {
        pod_sandbox_id: id.clone(),
    }))
    .await
    .unwrap();
    cri.remove_pod_sandbox(Request::new(RemovePodSandboxRequest {
        pod_sandbox_id: id.clone(),
    }))
    .await
    .unwrap();
    cri.stop_pod_sandbox(Request::new(StopPodSandboxRequest { pod_sandbox_id: id }))
        .await
        .unwrap();
}

#[tokio::test]
async fn sandbox_options_and_refusals() {
    let (mock, cri) = Mock::cri();
    let mut cfg = sandbox_config();
    cfg.linux.as_mut().unwrap().security_context = Some(LinuxSandboxSecurityContext {
        namespace_options: Some(NamespaceOption {
            network: NamespaceMode::Node as i32,
            pid: NamespaceMode::Container as i32,
            ipc: NamespaceMode::Pod as i32,
            ..Default::default()
        }),
        ..Default::default()
    });
    cri.run_pod_sandbox(Request::new(RunPodSandboxRequest {
        config: Some(cfg.clone()),
        runtime_handler: "crun".into(),
    }))
    .await
    .unwrap();
    assert_eq!(
        mock.st.lock().unwrap().pod_creates[0].net,
        velarx_cri::engine::NsMode::Host
    );
    // (its ports are the host's: nothing is published)
    assert!(mock.st.lock().unwrap().pod_creates[0].ports.is_empty());

    let e = cri
        .run_pod_sandbox(Request::new(RunPodSandboxRequest {
            config: Some(cfg.clone()),
            runtime_handler: "nope".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
    assert!(e.message().contains("crun, kata"), "{}", e.message());
    // a handler is a runtime of the engine: the default one by its name is the
    // engine's default, the others are asked for by name
    cri.run_pod_sandbox(Request::new(RunPodSandboxRequest {
        config: Some(cfg.clone()),
        runtime_handler: "kata".into(),
    }))
    .await
    .unwrap();
    let creates = mock.st.lock().unwrap().pod_creates.clone();
    assert_eq!(creates.last().unwrap().runtime, "kata");
    assert_eq!(creates[0].runtime, "", "crun is the default");
    let status = cri
        .status(Request::new(StatusRequest { verbose: false }))
        .await
        .unwrap()
        .into_inner();
    let names: Vec<_> = status
        .runtime_handlers
        .iter()
        .map(|h| h.name.as_str())
        .collect();
    assert_eq!(names, ["", "crun", "kata"]);
    // the features are each runtime's own (the unnamed handler is crun)
    let userns: Vec<_> = status
        .runtime_handlers
        .iter()
        .map(|h| h.features.as_ref().unwrap().user_namespaces)
        .collect();
    assert_eq!(userns, [true, true, false]);

    // hostIPC and hostPID are the pod's: the engine is told, the status says so
    let options = cfg
        .linux
        .as_mut()
        .unwrap()
        .security_context
        .as_mut()
        .unwrap()
        .namespace_options
        .as_mut()
        .unwrap();
    options.ipc = NamespaceMode::Node as i32;
    options.pid = NamespaceMode::Node as i32;
    let id = cri
        .run_pod_sandbox(Request::new(RunPodSandboxRequest {
            config: Some(cfg),
            runtime_handler: String::new(),
        }))
        .await
        .unwrap()
        .into_inner()
        .pod_sandbox_id;
    let spec = mock.st.lock().unwrap().pod_creates.last().cloned().unwrap();
    assert!(spec.host_ipc && spec.host_pid && !spec.share_pid);
    let status = cri
        .pod_sandbox_status(Request::new(PodSandboxStatusRequest {
            pod_sandbox_id: id,
            verbose: false,
        }))
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap();
    let ns = status.linux.unwrap().namespaces.unwrap().options.unwrap();
    assert_eq!(ns.ipc, NamespaceMode::Node as i32);
    assert_eq!(ns.pid, NamespaceMode::Node as i32);
}

/// The security context of a sandbox is the infra container's.
#[tokio::test]
async fn the_security_context_of_a_sandbox_goes_to_its_infra_container() {
    let (mock, cri) = Mock::cri();
    let mut cfg = sandbox_config();
    let profile = |t: security_profile::ProfileType, r: &str| SecurityProfile {
        profile_type: t as i32,
        localhost_ref: r.into(),
    };
    cfg.linux.as_mut().unwrap().security_context = Some(LinuxSandboxSecurityContext {
        run_as_user: Some(Int64Value { value: 1000 }),
        run_as_group: Some(Int64Value { value: 2000 }),
        supplemental_groups: vec![3, 4],
        readonly_rootfs: true,
        selinux_options: Some(SeLinuxOption {
            r#type: "container_t".into(),
            level: "s0:c1,c2".into(),
            ..Default::default()
        }),
        seccomp: Some(profile(
            security_profile::ProfileType::Localhost,
            "/var/lib/kubelet/seccomp/p.json",
        )),
        apparmor: Some(profile(security_profile::ProfileType::Unconfined, "")),
        ..Default::default()
    });
    cri.run_pod_sandbox(Request::new(RunPodSandboxRequest {
        config: Some(cfg.clone()),
        runtime_handler: String::new(),
    }))
    .await
    .unwrap();
    let infra = mock.st.lock().unwrap().pod_creates[0].infra.clone();
    assert_eq!(
        (infra.run_as_user, infra.run_as_group),
        (Some(1000), Some(2000))
    );
    assert_eq!(infra.supplemental_groups, [3, 4]);
    assert!(infra.read_only_rootfs && !infra.privileged);
    assert_eq!(
        infra.security_opts,
        [
            "label=type:container_t",
            "label=level:s0:c1,c2",
            "seccomp=/var/lib/kubelet/seccomp/p.json",
            "apparmor=unconfined"
        ]
    );
    assert_eq!(infra.oom_score_adj, None);

    // privileged: no seccomp profile, the files are labelled
    let sc = cfg
        .linux
        .as_mut()
        .unwrap()
        .security_context
        .as_mut()
        .unwrap();
    sc.privileged = true;
    sc.selinux_options = None;
    sc.apparmor = None;
    cri.run_pod_sandbox(Request::new(RunPodSandboxRequest {
        config: Some(cfg.clone()),
        runtime_handler: String::new(),
    }))
    .await
    .unwrap();
    let infra = mock.st.lock().unwrap().pod_creates[1].infra.clone();
    assert!(infra.privileged);
    assert_eq!(infra.security_opts, ["label=files", "seccomp=unconfined"]);

    // the strict policy of the groups is the infra container's anyway
    let sc = cfg
        .linux
        .as_mut()
        .unwrap()
        .security_context
        .as_mut()
        .unwrap();
    sc.supplemental_groups_policy = SupplementalGroupsPolicy::Strict as i32;
    cri.run_pod_sandbox(Request::new(RunPodSandboxRequest {
        config: Some(cfg.clone()),
        runtime_handler: String::new(),
    }))
    .await
    .unwrap();
    // what the engine cannot give is refused
    let sc = cfg
        .linux
        .as_mut()
        .unwrap()
        .security_context
        .as_mut()
        .unwrap();
    sc.supplemental_groups_policy = 0;
    sc.run_as_user = Some(Int64Value { value: -1 });
    let e = cri
        .run_pod_sandbox(Request::new(RunPodSandboxRequest {
            config: Some(cfg),
            runtime_handler: String::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn container_lifecycle() {
    let (mock, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    let id = cri
        .create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: pod.clone(),
            config: Some(container_config()),
            sandbox_config: Some(sandbox_config()),
        }))
        .await
        .unwrap()
        .into_inner()
        .container_id;
    {
        let s = mock.st.lock().unwrap();
        let c = &s.container_creates[0];
        assert_eq!(c.pod.as_deref(), Some(pod.as_str()));
        assert_eq!(c.entrypoint, ["sleep"]);
        assert_eq!(c.command, ["600"]);
        assert!(c.env.contains(&"A=b".to_string()), "{:?}", c.env);
        let log = c.log_config.as_ref().unwrap();
        assert_eq!(
            (log.driver.as_str(), log.config["path"].as_str()),
            ("k8s-file", "/var/log/pods/x/main/0.log")
        );
        assert_eq!(c.user, "1000:2000");
        assert_eq!(c.group_add, ["5", "6"]);
        assert!(c.read_only_rootfs && c.security_opt.no_new_privileges);
        assert_eq!(
            (c.cap_add.clone(), c.cap_drop.clone()),
            (vec!["NET_ADMIN".to_string()], vec!["ALL".to_string()])
        );
        assert_eq!(
            c.security_opt.seccomp_profile.as_deref(),
            Some("/profiles/s.json")
        );
        assert!(!c.security_opt.seccomp_unconfined);
        assert_eq!(c.resources.as_ref().unwrap().memory, Some(1 << 20));
        assert_eq!(c.name.as_deref(), Some("k8s_main_web_default_u1_0"));
        // (the kubelet's cgroups, not the configuration's mode)
        assert_eq!(c.cgroups, velarx_proto::request::CgroupsMode::Enabled);
    }
    let get = |req| cri.container_status(req);
    let s = get(Request::new(ContainerStatusRequest {
        container_id: id.clone(),
        verbose: false,
    }))
    .await
    .unwrap()
    .into_inner()
    .status
    .unwrap();
    assert_eq!(s.state, ContainerState::ContainerCreated as i32);
    assert_eq!(s.log_path, "/var/log/pods/x/main/0.log");
    assert_eq!(s.annotations["a"], "2");
    assert_eq!(s.labels["l"], "1");
    assert_eq!(s.metadata.unwrap().name, "main");

    cri.start_container(Request::new(StartContainerRequest {
        container_id: id.clone(),
    }))
    .await
    .unwrap();
    let list = cri
        .list_containers(Request::new(ListContainersRequest {
            filter: Some(ContainerFilter {
                pod_sandbox_id: pod.clone(),
                state: Some(ContainerStateValue {
                    state: ContainerState::ContainerRunning as i32,
                }),
                ..Default::default()
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(list.containers.len(), 1);
    assert_eq!(list.containers[0].labels["l"], "1");

    cri.update_container_resources(Request::new(UpdateContainerResourcesRequest {
        container_id: id.clone(),
        linux: Some(LinuxContainerResources {
            memory_limit_in_bytes: 5,
            ..Default::default()
        }),
        ..Default::default()
    }))
    .await
    .unwrap();
    assert_eq!(mock.st.lock().unwrap().updates[0].1.memory, Some(5));

    cri.stop_container(Request::new(StopContainerRequest {
        container_id: id.clone(),
        timeout: 30,
    }))
    .await
    .unwrap();
    assert!(mock.calls().contains(&format!("container_stop {id} 30")));
    let s = cri
        .container_status(Request::new(ContainerStatusRequest {
            container_id: id.clone(),
            verbose: false,
        }))
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap();
    assert_eq!(
        (s.state, s.exit_code, s.reason.as_str()),
        (ContainerState::ContainerExited as i32, 137, "Error")
    );

    cri.remove_container(Request::new(RemoveContainerRequest {
        container_id: id.clone(),
    }))
    .await
    .unwrap();
    cri.remove_container(Request::new(RemoveContainerRequest {
        container_id: id.clone(),
    }))
    .await
    .unwrap();
    let e = cri
        .container_status(Request::new(ContainerStatusRequest {
            container_id: id,
            verbose: false,
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::NotFound);
}

#[tokio::test]
async fn oom_killed_reason() {
    let (mock, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    let id = cri
        .create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: pod,
            config: Some(container_config()),
            sandbox_config: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .container_id;
    {
        let mut s = mock.st.lock().unwrap();
        let c = s.containers.iter_mut().find(|c| c.id == id).unwrap();
        c.state = velarx_proto::workload::RunState::Exited;
        c.started_ns = 8;
        c.oom_killed = true;
        c.exit_code = 137;
    }
    let s = cri
        .container_status(Request::new(ContainerStatusRequest {
            container_id: id,
            verbose: false,
        }))
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap();
    assert_eq!(s.reason, "OOMKilled");
}

/// Ambient capabilities and the strict policy of the supplemental groups
/// are the engine's.
#[tokio::test]
async fn ambient_capabilities_and_strict_groups() {
    let (mock, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    let mut cfg = container_config();
    let sc = cfg
        .linux
        .as_mut()
        .unwrap()
        .security_context
        .as_mut()
        .unwrap();
    sc.capabilities.as_mut().unwrap().add_ambient_capabilities = vec!["NET_BIND_SERVICE".into()];
    sc.supplemental_groups_policy = SupplementalGroupsPolicy::Strict as i32;
    sc.supplemental_groups = vec![5000];
    cri.create_container(Request::new(CreateContainerRequest {
        pod_sandbox_id: pod,
        config: Some(cfg),
        sandbox_config: None,
    }))
    .await
    .unwrap();
    let spec = mock.st.lock().unwrap().container_creates[0].clone();
    assert_eq!(spec.cap_ambient, ["NET_BIND_SERVICE"]);
    assert!(spec.groups_strict);
    assert_eq!(spec.group_add, ["5000"]);
    let st = cri
        .status(Request::new(StatusRequest { verbose: false }))
        .await
        .unwrap()
        .into_inner();
    assert!(st.features.unwrap().supplemental_groups_policy);
}

#[tokio::test]
async fn container_refusals() {
    let (_, cri) = Mock::cri();
    let e = cri
        .create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: "nope".into(),
            config: Some(container_config()),
            sandbox_config: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::NotFound);
    let e = cri
        .checkpoint_container(Request::new(CheckpointContainerRequest {
            container_id: "x".into(),
            location: "/tmp/x".into(),
            timeout: 0,
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Unimplemented);
}

#[tokio::test]
async fn exec_sync_and_stats() {
    let (mock, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    let id = cri
        .create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: pod.clone(),
            config: Some(container_config()),
            sandbox_config: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .container_id;
    cri.start_container(Request::new(StartContainerRequest {
        container_id: id.clone(),
    }))
    .await
    .unwrap();
    cri.reopen_container_log(Request::new(ReopenContainerLogRequest {
        container_id: id.clone(),
    }))
    .await
    .unwrap();
    assert!(mock.calls().contains(&format!("reopen {id}")));
    mock.st.lock().unwrap().exec_exit = 3;
    let r = cri
        .exec_sync(Request::new(ExecSyncRequest {
            container_id: id.clone(),
            cmd: vec!["echo".into(), "hi".into()],
            timeout: 5,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (r.stdout.as_slice(), r.stderr.as_slice(), r.exit_code),
        (&b"echo hi"[..], &b"err"[..], 3)
    );

    let s = cri
        .container_stats(Request::new(ContainerStatsRequest {
            container_id: id.clone(),
        }))
        .await
        .unwrap()
        .into_inner()
        .stats
        .unwrap();
    assert_eq!(
        s.cpu
            .as_ref()
            .unwrap()
            .usage_core_nano_seconds
            .as_ref()
            .unwrap()
            .value,
        1000
    );
    assert_eq!(s.cpu.unwrap().usage_nano_cores.unwrap().value, 500_000_000);
    assert_eq!(
        s.memory
            .as_ref()
            .unwrap()
            .available_bytes
            .as_ref()
            .unwrap()
            .value,
        // (the limit less the working set, as the CRI defines it)
        4096 - 1024
    );
    let mem = s.memory.unwrap();
    assert_eq!(mem.working_set_bytes.unwrap().value, 1024);
    assert_eq!(mem.page_faults.unwrap().value, 7);
    let rw = s.writable_layer.unwrap();
    assert_eq!(rw.used_bytes.unwrap().value, 4096);
    assert_eq!(rw.inodes_used.unwrap().value, 12);
    let all = cri
        .list_container_stats(Request::new(ListContainerStatsRequest::default()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(all.stats.len(), 1);
    let p = cri
        .pod_sandbox_stats(Request::new(PodSandboxStatsRequest {
            pod_sandbox_id: pod,
        }))
        .await
        .unwrap()
        .into_inner()
        .stats
        .unwrap();
    assert_eq!(p.linux.unwrap().containers.len(), 1);
}

#[tokio::test]
async fn metrics_of_the_pods_of_the_cri() {
    let (mock, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    let id = cri
        .create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: pod.clone(),
            config: Some(container_config()),
            sandbox_config: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .container_id;
    // (a pod the CRI did not make has no metrics here)
    mock.add_foreign_pod("other");
    let d = cri
        .list_metric_descriptors(Request::new(ListMetricDescriptorsRequest {}))
        .await
        .unwrap()
        .into_inner()
        .descriptors;
    assert_eq!(d.len(), 2);
    assert_eq!(d[0].label_keys, vec!["id".to_string()]);
    let all = cri
        .list_pod_sandbox_metrics(Request::new(ListPodSandboxMetricsRequest {}))
        .await
        .unwrap()
        .into_inner()
        .pod_metrics;
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].pod_sandbox_id, pod);
    let m = &all[0].metrics[0];
    assert_eq!(m.name, "container_memory_rss");
    assert_eq!(m.metric_type, MetricType::Gauge as i32);
    assert_eq!(m.value.as_ref().unwrap().value, 3);
    let c = &all[0].container_metrics[0];
    assert_eq!(c.container_id, id);
    assert_eq!(c.metrics[0].metric_type, MetricType::Counter as i32);
    assert_eq!(c.metrics[0].label_values, vec![id.clone()]);
    assert_eq!(c.metrics[0].value.as_ref().unwrap().value, 2);
}

#[tokio::test]
async fn image_volumes() {
    let (mock, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    let mut c = container_config();
    c.mounts = vec![Mount {
        container_path: "/mnt/image".into(),
        readonly: true,
        image: Some(ImageSpec {
            image: "sha256:abc".into(),
            ..Default::default()
        }),
        image_sub_path: "etc".into(),
        ..Default::default()
    }];
    let id = cri
        .create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: pod.clone(),
            config: Some(c.clone()),
            sandbox_config: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .container_id;
    let spec = mock.st.lock().unwrap().container_creates[0].clone();
    assert_eq!(spec.image_mounts.len(), 1);
    let m = &spec.image_mounts[0];
    assert_eq!(
        (m.image.as_str(), m.target.as_str(), m.subpath.as_deref()),
        ("sha256:abc", "/mnt/image", Some("etc"))
    );
    assert!(spec.volumes.is_empty() && spec.mount.is_empty());
    // the status tells the image of the mount
    let status = cri
        .container_status(Request::new(ContainerStatusRequest {
            container_id: id,
            verbose: false,
        }))
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap();
    let mount = &status.mounts[0];
    assert_eq!(mount.container_path, "/mnt/image");
    assert_eq!(mount.image_sub_path, "etc");
    let image = mount.image.as_ref().unwrap();
    assert_eq!(
        (image.image.as_str(), image.image_ref.as_str()),
        ("sha256:abc", "sha256:abc")
    );
    // an image mount is read-only and has no host path
    c.mounts[0].readonly = false;
    let e = cri
        .create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: pod.clone(),
            config: Some(c.clone()),
            sandbox_config: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
    c.mounts[0].readonly = true;
    c.mounts[0].host_path = "/x".into();
    let e = cri
        .create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: pod,
            config: Some(c),
            sandbox_config: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn stream_urls() {
    let (_, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    let id = cri
        .create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: pod.clone(),
            config: Some(container_config()),
            sandbox_config: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .container_id;
    let e = cri
        .exec(Request::new(ExecRequest {
            container_id: id.clone(),
            cmd: vec!["sh".into()],
            stdout: true,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(e.url.starts_with("http://127.0.0.1:1/exec/"));
    let e = cri
        .exec(Request::new(ExecRequest {
            container_id: id.clone(),
            cmd: vec!["sh".into()],
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
    let a = cri
        .attach(Request::new(AttachRequest {
            container_id: id.clone(),
            stdout: true,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(a.url.contains("/attach/"));
    let e = cri
        .attach(Request::new(AttachRequest {
            container_id: id,
            stdin: true,
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);
    let p = cri
        .port_forward(Request::new(PortForwardRequest {
            pod_sandbox_id: pod,
            port: vec![80],
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(p.url.contains("/portforward/"));
}

#[tokio::test]
async fn events_only_of_the_cri() {
    let (_, cri) = Mock::cri();
    let mut s = cri
        .get_container_events(Request::new(GetEventsRequest {}))
        .await
        .unwrap()
        .into_inner();
    let mut kinds = Vec::new();
    while let Some(ev) = s.next().await {
        kinds.push(ev.unwrap().container_event_type);
    }
    assert_eq!(
        kinds,
        [
            ContainerEventType::ContainerCreatedEvent as i32,
            ContainerEventType::ContainerStartedEvent as i32,
            ContainerEventType::ContainerStoppedEvent as i32,
            ContainerEventType::ContainerDeletedEvent as i32,
        ]
    );
}

/// A kubelet that stops reading the events ends their relay at once, not
/// at the next event: the stream of the engine is given back.
#[tokio::test]
async fn the_events_of_a_kubelet_that_went_away_are_not_relayed() {
    let (mock, cri) = Mock::cri();
    mock.st.lock().unwrap().hold_events = true;
    let s = cri
        .get_container_events(Request::new(GetEventsRequest {}))
        .await
        .unwrap()
        .into_inner();
    drop(s);
    let held = mock.st.lock().unwrap().events_held.take().unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), held.closed())
        .await
        .expect("the relay ended");
}

#[tokio::test]
async fn images() {
    let (mock, cri) = Mock::cri();
    let r = cri
        .pull_image(Request::new(PullImageRequest {
            image: Some(ImageSpec {
                image: "alpine".into(),
                ..Default::default()
            }),
            auth: Some(AuthConfig {
                username: "u".into(),
                password: "p".into(),
                ..Default::default()
            }),
            sandbox_config: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(r.image_ref, "sha256img");
    {
        let s = mock.st.lock().unwrap();
        assert_eq!(s.pulls[0].0, "alpine");
        let creds = s.pulls[0].1.as_ref().unwrap().creds.as_ref().unwrap();
        assert_eq!(
            (creds.username.as_str(), creds.password.as_str()),
            ("u", "p")
        );
    }
    let st = cri
        .image_status(Request::new(ImageStatusRequest {
            image: Some(ImageSpec {
                image: "alpine".into(),
                ..Default::default()
            }),
            verbose: false,
        }))
        .await
        .unwrap()
        .into_inner();
    let img = st.image.unwrap();
    assert_eq!(img.uid.unwrap().value, 1001);
    assert!(img.username.is_empty());
    let none = cri
        .image_status(Request::new(ImageStatusRequest {
            image: Some(ImageSpec {
                image: "nothing".into(),
                ..Default::default()
            }),
            verbose: false,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(none.image.is_none());
    assert_eq!(
        cri.list_images(Request::new(ListImagesRequest::default()))
            .await
            .unwrap()
            .into_inner()
            .images
            .len(),
        1
    );
    let fs = cri
        .image_fs_info(Request::new(ImageFsInfoRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        fs.image_filesystems[0].used_bytes.as_ref().unwrap().value,
        100
    );
    assert_eq!(
        fs.image_filesystems[0].fs_id.as_ref().unwrap().mountpoint,
        "/store"
    );
    cri.remove_image(Request::new(RemoveImageRequest {
        image: Some(ImageSpec {
            image: "alpine".into(),
            ..Default::default()
        }),
    }))
    .await
    .unwrap();
    // removing what is not there is a success
    cri.remove_image(Request::new(RemoveImageRequest {
        image: Some(ImageSpec {
            image: "alpine".into(),
            ..Default::default()
        }),
    }))
    .await
    .unwrap();
    assert!(cri
        .list_images(Request::new(ListImagesRequest::default()))
        .await
        .unwrap()
        .into_inner()
        .images
        .is_empty());
}

#[tokio::test]
async fn defaults_and_validation() {
    let (mock, cri) = Mock::cri();
    let mut cfg = sandbox_config();
    cfg.hostname = String::new();
    cfg.metadata.as_mut().unwrap().name = "A_pod.with/odd name".repeat(5);
    cri.run_pod_sandbox(Request::new(RunPodSandboxRequest {
        config: Some(cfg),
        runtime_handler: String::new(),
    }))
    .await
    .unwrap();
    let h = mock.st.lock().unwrap().pod_creates[0].hostname.clone();
    assert!(
        !h.is_empty() && h.len() <= 63 && !h.contains(['_', '/', ' ', '.']),
        "{h}"
    );

    let pod = run_pod(&cri).await;
    // a security context with no seccomp profile asks for none
    let mut c = container_config();
    c.linux
        .as_mut()
        .unwrap()
        .security_context
        .as_mut()
        .unwrap()
        .seccomp = None;
    cri.create_container(Request::new(CreateContainerRequest {
        pod_sandbox_id: pod.clone(),
        config: Some(c.clone()),
        sandbox_config: None,
    }))
    .await
    .unwrap();
    assert!(
        mock.st.lock().unwrap().container_creates[0]
            .security_opt
            .seccomp_unconfined
    );
    // SELinux options go to the engine; a privileged container asks for its
    // files to be labelled
    let sc = c.linux.as_mut().unwrap().security_context.as_mut().unwrap();
    sc.selinux_options = Some(SeLinuxOption {
        user: "system_u".into(),
        level: "s0:c4,c5".into(),
        ..Default::default()
    });
    sc.privileged = true;
    cri.create_container(Request::new(CreateContainerRequest {
        pod_sandbox_id: pod.clone(),
        config: Some(c.clone()),
        sandbox_config: None,
    }))
    .await
    .unwrap();
    assert_eq!(
        mock.st.lock().unwrap().container_creates[1].security_opts,
        ["label=user:system_u", "label=level:s0:c4,c5", "label=files"]
    );
    assert!(mock.st.lock().unwrap().container_creates[0]
        .security_opts
        .is_empty());
    // a group with no user
    let sc = c.linux.as_mut().unwrap().security_context.as_mut().unwrap();
    sc.run_as_user = None;
    let e = cri
        .create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: pod,
            config: Some(c),
            sandbox_config: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
    // stopping what is gone is a success
    cri.stop_container(Request::new(StopContainerRequest {
        container_id: "gone".into(),
        timeout: 0,
    }))
    .await
    .unwrap();
}

/// What a client asks for and the engine or the pod cannot give is refused
/// with a code and a reason, never ignored.
#[tokio::test]
async fn what_is_asked_and_cannot_be_given_is_refused() {
    let (_, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    let create = |cfg: ContainerConfig| {
        let cri = cri.clone();
        let pod = pod.clone();
        async move {
            cri.create_container(Request::new(CreateContainerRequest {
                pod_sandbox_id: pod,
                config: Some(cfg),
                sandbox_config: None,
            }))
            .await
        }
    };
    // namespaces of a container: its pod's, and the pod here has its own
    let ns = |n: NamespaceOption| {
        let mut cfg = container_config();
        cfg.linux
            .as_mut()
            .unwrap()
            .security_context
            .as_mut()
            .unwrap()
            .namespace_options = Some(n);
        cfg
    };
    use NamespaceMode::*;
    create(ns(NamespaceOption {
        network: Pod as i32,
        ipc: Pod as i32,
        ..Default::default()
    }))
    .await
    .unwrap();
    for (what, o, code) in [
        (
            "the host network in a pod with its own",
            NamespaceOption {
                network: Node as i32,
                ..Default::default()
            },
            Code::InvalidArgument,
        ),
        (
            "the host IPC in a pod with its own",
            NamespaceOption {
                ipc: Node as i32,
                ..Default::default()
            },
            Code::InvalidArgument,
        ),
        (
            "a network namespace of its own",
            NamespaceOption {
                network: Container as i32,
                ..Default::default()
            },
            Code::Unimplemented,
        ),
        (
            "an IPC namespace of its own",
            NamespaceOption {
                ipc: Container as i32,
                ..Default::default()
            },
            Code::Unimplemented,
        ),
        (
            "a target for the network",
            NamespaceOption {
                network: Target as i32,
                ..Default::default()
            },
            Code::InvalidArgument,
        ),
    ] {
        let e = create(ns(o)).await.unwrap_err();
        assert_eq!(e.code(), code, "{what}: {e}");
    }

    // recursive read-only mounts: read-only and private
    let mount = |readonly, propagation: MountPropagation| {
        let mut cfg = container_config();
        cfg.mounts = vec![Mount {
            container_path: "/m".into(),
            host_path: "/h".into(),
            readonly,
            recursive_read_only: true,
            propagation: propagation as i32,
            ..Default::default()
        }];
        cfg
    };
    create(mount(true, MountPropagation::PropagationPrivate))
        .await
        .unwrap();
    for (readonly, p) in [
        (false, MountPropagation::PropagationPrivate),
        (true, MountPropagation::PropagationHostToContainer),
        (true, MountPropagation::PropagationBidirectional),
    ] {
        let e = create(mount(readonly, p)).await.unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument, "{readonly} {p:?}");
    }

    // a port that is not a port is an error, not left out
    for bad in [0, -1, 70000] {
        let e = cri
            .port_forward(Request::new(PortForwardRequest {
                pod_sandbox_id: pod.clone(),
                port: vec![80, bad],
            }))
            .await
            .unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument, "port {bad}");
    }
    // more ports than one session forwards (the channels of the 129th
    // would be those of the first)
    let e = cri
        .port_forward(Request::new(PortForwardRequest {
            pod_sandbox_id: pod.clone(),
            port: (1..=200).collect(),
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
    cri.port_forward(Request::new(PortForwardRequest {
        pod_sandbox_id: pod.clone(),
        port: vec![80, 8080],
    }))
    .await
    .unwrap();

    // an image of a runtime handler is not a separate one
    let e = cri
        .pull_image(Request::new(PullImageRequest {
            image: Some(ImageSpec {
                image: "busybox".into(),
                runtime_handler: "kata".into(),
                ..Default::default()
            }),
            auth: None,
            sandbox_config: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Unimplemented);
}

#[tokio::test]
async fn the_status_and_the_stats_of_a_pod_have_its_containers() {
    let (_, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    let st = cri
        .pod_sandbox_status(Request::new(PodSandboxStatusRequest {
            pod_sandbox_id: pod.clone(),
            verbose: false,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(st.containers_statuses.is_empty());
    let id = cri
        .create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: pod.clone(),
            config: Some(container_config()),
            sandbox_config: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .container_id;
    cri.start_container(Request::new(StartContainerRequest {
        container_id: id.clone(),
    }))
    .await
    .unwrap();
    let st = cri
        .pod_sandbox_status(Request::new(PodSandboxStatusRequest {
            pod_sandbox_id: pod.clone(),
            verbose: false,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(st.containers_statuses.len(), 1);
    assert_eq!(st.containers_statuses[0].id, id);
    let stats = cri
        .pod_sandbox_stats(Request::new(PodSandboxStatsRequest {
            pod_sandbox_id: pod,
        }))
        .await
        .unwrap()
        .into_inner()
        .stats
        .unwrap();
    let linux = stats.linux.unwrap();
    assert_eq!(linux.process.unwrap().process_count.unwrap().value, 3);
    assert_eq!(linux.containers.len(), 1);
}

/// The stats of all the sandboxes of a request are made of one look at the
/// engine (the containers, their samples, the store, the metrics), not one
/// for each sandbox.
#[tokio::test]
async fn the_stats_of_many_pods_ask_the_engine_once() {
    let (mock, cri) = Mock::cri();
    let mut containers = Vec::new();
    for _ in 0..4 {
        let pod = run_pod(&cri).await;
        let id = cri
            .create_container(Request::new(CreateContainerRequest {
                pod_sandbox_id: pod.clone(),
                config: Some(container_config()),
                sandbox_config: None,
            }))
            .await
            .unwrap()
            .into_inner()
            .container_id;
        cri.start_container(Request::new(StartContainerRequest {
            container_id: id.clone(),
        }))
        .await
        .unwrap();
        containers.push((pod, id));
    }
    let before = mock.calls().len();
    let stats = cri
        .list_pod_sandbox_stats(Request::new(ListPodSandboxStatsRequest { filter: None }))
        .await
        .unwrap()
        .into_inner()
        .stats;
    assert_eq!(stats.len(), 4);
    for s in &stats {
        let linux = s.linux.as_ref().unwrap();
        assert_eq!(linux.containers.len(), 1);
        assert_eq!(
            linux
                .process
                .as_ref()
                .unwrap()
                .process_count
                .as_ref()
                .unwrap()
                .value,
            3
        );
    }
    let asked = &mock.calls()[before..];
    for what in [
        "container_list",
        "container_stats",
        "store_usage",
        "pod_metrics",
    ] {
        assert_eq!(
            asked.iter().filter(|c| *c == what).count(),
            1,
            "{what}: {asked:?}"
        );
    }
}

/// The stats of a pod that has a cgroup are that cgroup's, not the sum of
/// its containers.
#[tokio::test]
async fn the_stats_of_a_pod_are_those_of_its_cgroup() {
    let (mock, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    mock.st.lock().unwrap().pod_usage = Some(velarx_proto::pod::PodUsage {
        cpu_usage_ns: 9_000,
        memory_usage: 5_000,
        memory_working_set: 4_000,
        memory_rss: 3_000,
        memory_limit: 10_000,
        pressure: pressure(),
        ..Default::default()
    });
    let stats = cri
        .pod_sandbox_stats(Request::new(PodSandboxStatsRequest {
            pod_sandbox_id: pod,
        }))
        .await
        .unwrap()
        .into_inner()
        .stats
        .unwrap()
        .linux
        .unwrap();
    assert_eq!(
        stats.cpu.unwrap().usage_core_nano_seconds.unwrap().value,
        9_000
    );
    let memory = stats.memory.unwrap();
    assert_eq!(memory.working_set_bytes.unwrap().value, 4_000);
    assert_eq!(memory.usage_bytes.unwrap().value, 5_000);
    assert_eq!(memory.rss_bytes.unwrap().value, 3_000);
    assert_eq!(memory.available_bytes.unwrap().value, 6_000);
    assert_eq!(memory.psi.unwrap().some.unwrap().avg10, 2.5);
    // the IO of the CRI is its pressure, in nanoseconds
    let io = stats.io.unwrap().psi.unwrap();
    assert_eq!(io.full.unwrap().total, 7_000);
}

/// The hugepage limits of a container are the engine's where its cgroups have
/// the hugetlb controller; without it the zero limits the kubelet sends for
/// every size are left out, and a limit is refused.
#[tokio::test]
async fn hugepage_limits_need_the_hugetlb_controller() {
    let create = |cri: std::sync::Arc<velarx_cri::service::Cri<Mock>>, pod: String, limit: u64| async move {
        let mut cfg = container_config();
        cfg.linux = Some(LinuxContainerConfig {
            resources: Some(LinuxContainerResources {
                hugepage_limits: vec![
                    HugepageLimit {
                        page_size: "2MB".into(),
                        limit,
                    },
                    HugepageLimit {
                        page_size: "1GB".into(),
                        limit: 0,
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        });
        cri.create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: pod,
            config: Some(cfg),
            sandbox_config: None,
        }))
        .await
    };
    let (mock, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    let e = create(cri.clone(), pod.clone(), 4 << 20).await.unwrap_err();
    assert_eq!(e.code(), Code::Unimplemented, "{e}");
    assert!(e.message().contains("hugetlb"), "{e}");
    create(cri.clone(), pod.clone(), 0).await.unwrap();
    assert!(mock.st.lock().unwrap().container_creates[0]
        .resources
        .as_ref()
        .is_none_or(|r| r.hugepage_limits.is_empty()));

    let (mock, cri) = Mock::cri();
    mock.st.lock().unwrap().controllers = vec!["memory".into(), "hugetlb".into()];
    let pod = run_pod(&cri).await;
    create(cri.clone(), pod, 4 << 20).await.unwrap();
    let limits = mock.st.lock().unwrap().container_creates[0]
        .resources
        .clone()
        .unwrap()
        .hugepage_limits;
    assert_eq!(limits.len(), 2);
    assert_eq!(
        (limits[0].page_size.as_str(), limits[0].limit),
        ("2MB", 4 << 20)
    );
}

/// The pressure files of a cgroup: memory, and IO with a full line.
pub fn pressure() -> velarx_proto::pod::Pressure {
    use velarx_proto::pod::{Psi, PsiData};
    let psi = |avg10, total_us| Psi {
        some: PsiData {
            avg10,
            total_us,
            ..Default::default()
        },
        full: PsiData {
            total_us,
            ..Default::default()
        },
    };
    velarx_proto::pod::Pressure {
        cpu: None,
        memory: Some(psi(2.5, 1)),
        io: Some(psi(0.0, 7)),
    }
}

/// The file system of the stats is the store's: when the store cannot be
/// measured the stats are an error, not stats of an unnamed file system.
#[tokio::test]
async fn stats_are_an_error_when_the_store_cannot_be_measured() {
    let (mock, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    let id = cri
        .create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: pod,
            config: Some(container_config()),
            sandbox_config: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .container_id;
    cri.start_container(Request::new(StartContainerRequest {
        container_id: id.clone(),
    }))
    .await
    .unwrap();
    mock.st.lock().unwrap().store_usage_fails = true;
    let e = cri
        .container_stats(Request::new(ContainerStatsRequest { container_id: id }))
        .await
        .unwrap_err();
    assert!(e.message().contains("cannot be measured"), "{e}");
}

/// A container the engine cannot sample (it ended since the list, say)
/// is left out of the list of the stats, not the others with it: the
/// lists of containerd and CRI-O are best effort.
#[tokio::test]
async fn a_container_that_cannot_be_sampled_is_left_out_of_the_list() {
    let (mock, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    let mut ids = Vec::new();
    for name in ["a", "b"] {
        let mut config = container_config();
        config.metadata.as_mut().unwrap().name = name.into();
        let id = cri
            .create_container(Request::new(CreateContainerRequest {
                pod_sandbox_id: pod.clone(),
                config: Some(config),
                sandbox_config: None,
            }))
            .await
            .unwrap()
            .into_inner()
            .container_id;
        cri.start_container(Request::new(StartContainerRequest {
            container_id: id.clone(),
        }))
        .await
        .unwrap();
        ids.push(id);
    }
    mock.st.lock().unwrap().unsampled = vec![ids[0].clone()];
    let listed: Vec<String> = cri
        .list_container_stats(Request::new(ListContainerStatsRequest::default()))
        .await
        .unwrap()
        .into_inner()
        .stats
        .into_iter()
        .filter_map(|s| s.attributes.map(|a| a.id))
        .collect();
    assert_eq!(listed, [ids[1].clone()]);
}

#[tokio::test]
async fn the_stats_of_a_pod_are_an_error_when_its_metrics_cannot_be_read() {
    let (mock, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    mock.st.lock().unwrap().pod_metrics_fail = true;
    let e = cri
        .pod_sandbox_stats(Request::new(PodSandboxStatsRequest {
            pod_sandbox_id: pod,
        }))
        .await
        .unwrap_err();
    assert!(e.message().contains("cannot be read"), "{e}");
}

/// The stats of a container: its anonymous memory, its swap and the
/// pressure of its cgroup.
#[tokio::test]
async fn the_stats_of_a_container_have_rss_swap_and_pressure() {
    let (_mock, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    let id = cri
        .create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: pod,
            config: Some(container_config()),
            sandbox_config: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .container_id;
    cri.start_container(Request::new(StartContainerRequest {
        container_id: id.clone(),
    }))
    .await
    .unwrap();
    let stats = cri
        .container_stats(Request::new(ContainerStatsRequest { container_id: id }))
        .await
        .unwrap()
        .into_inner()
        .stats
        .unwrap();
    let memory = stats.memory.unwrap();
    assert_eq!(memory.rss_bytes.unwrap().value, 512);
    assert_eq!(memory.available_bytes.unwrap().value, 4096 - 1024);
    assert!(memory.psi.is_some());
    let swap = stats.swap.unwrap();
    assert_eq!(swap.swap_usage_bytes.unwrap().value, 100);
    assert_eq!(swap.swap_available_bytes.unwrap().value, 900);
    assert!(stats.cpu.unwrap().psi.is_none(), "no cpu.pressure");
    assert_eq!(stats.io.unwrap().psi.unwrap().full.unwrap().total, 7_000);
}

/// The resources of a sandbox, and its overhead, are the limits of the cgroup
/// of the pod, not of its infra container.
#[tokio::test]
async fn the_resources_of_a_sandbox_are_the_limits_of_its_pod() {
    let (mock, cri) = Mock::cri();
    let mut cfg = sandbox_config();
    let linux = cfg.linux.as_mut().unwrap();
    linux.resources = Some(LinuxContainerResources {
        memory_limit_in_bytes: 128 << 20,
        cpu_quota: 50_000,
        cpu_period: 100_000,
        cpu_shares: 512,
        cpuset_cpus: "0-1".into(),
        // (the OOM score is the infra container's at its creation)
        oom_score_adj: -998,
        ..Default::default()
    });
    linux.overhead = Some(LinuxContainerResources {
        memory_limit_in_bytes: 16 << 20,
        // (a period of its own: 10000 of 50000 is a fifth of a CPU)
        cpu_quota: 10_000,
        cpu_period: 50_000,
        cpu_shares: 128,
        ..Default::default()
    });
    let pod = cri
        .run_pod_sandbox(Request::new(RunPodSandboxRequest {
            config: Some(cfg.clone()),
            runtime_handler: String::new(),
        }))
        .await
        .unwrap()
        .into_inner()
        .pod_sandbox_id;
    {
        let s = mock.st.lock().unwrap();
        assert_eq!(s.pod_creates[0].infra.oom_score_adj, Some(-998));
        // asked of the engine as the limits of the pod, none of its infra container
        assert!(s.updates.is_empty());
        let r = &s.pod_creates[0].resources;
        assert_eq!(
            (
                r.memory_limit,
                r.cpu_quota,
                r.cpu_period,
                r.cpu_shares,
                r.oom_score_adj,
                r.cpuset_cpus.as_str()
            ),
            (144 << 20, 70_000, 100_000, 640, 0, "0-1")
        );
    }
    // a sandbox with none: no limits
    run_pod(&cri).await;
    assert_eq!(
        mock.st.lock().unwrap().pod_creates[1].resources,
        Resources::default()
    );
    // an overhead alone limits nothing
    let mut only = sandbox_config();
    only.linux.as_mut().unwrap().overhead = Some(LinuxContainerResources {
        memory_limit_in_bytes: 16 << 20,
        ..Default::default()
    });
    cri.run_pod_sandbox(Request::new(RunPodSandboxRequest {
        config: Some(only),
        runtime_handler: String::new(),
    }))
    .await
    .unwrap();
    assert_eq!(
        mock.st.lock().unwrap().pod_creates[2].resources,
        Resources::default()
    );
    // what cannot be changed in a running container is refused
    let mut bad = cfg.clone();
    bad.linux
        .as_mut()
        .unwrap()
        .resources
        .as_mut()
        .unwrap()
        .unified = [("memory.high".to_string(), "1".to_string())].into();
    let e = cri
        .run_pod_sandbox(Request::new(RunPodSandboxRequest {
            config: Some(bad),
            runtime_handler: String::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Unimplemented);
    // but the kubelet's memory.oom.group of every sandbox
    let mut grouped = cfg.clone();
    let gl = grouped.linux.as_mut().unwrap();
    for r in [&mut gl.resources, &mut gl.overhead] {
        r.as_mut().unwrap().unified = [("memory.oom.group".to_string(), "1".to_string())].into();
    }
    cri.run_pod_sandbox(Request::new(RunPodSandboxRequest {
        config: Some(grouped),
        runtime_handler: String::new(),
    }))
    .await
    .unwrap();
    let id = cri
        .create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: pod,
            config: Some(container_config()),
            sandbox_config: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .container_id;
    let e = cri
        .update_container_resources(Request::new(UpdateContainerResourcesRequest {
            container_id: id.clone(),
            linux: Some(LinuxContainerResources {
                unified: [("memory.high".to_string(), "1".to_string())].into(),
                ..Default::default()
            }),
            windows: None,
            annotations: Default::default(),
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Unimplemented);
    // the score the container has, which the kubelet sends with every update,
    // is no change
    cri.update_container_resources(Request::new(UpdateContainerResourcesRequest {
        container_id: id.clone(),
        linux: Some(LinuxContainerResources {
            oom_score_adj: -997,
            ..Default::default()
        }),
        windows: None,
        annotations: Default::default(),
    }))
    .await
    .unwrap();
    // another OOM score of a running container is not set: refused, not
    // dropped in silence
    let e = cri
        .update_container_resources(Request::new(UpdateContainerResourcesRequest {
            container_id: id,
            linux: Some(LinuxContainerResources {
                oom_score_adj: -500,
                ..Default::default()
            }),
            windows: None,
            annotations: Default::default(),
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Unimplemented);
    assert!(e.message().contains("oom_score_adj"), "{e}");
}

#[tokio::test]
async fn the_events_of_a_sandbox_and_the_update_of_its_resources() {
    let (mock, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    let mut s = cri
        .get_container_events(Request::new(GetEventsRequest {}))
        .await
        .unwrap()
        .into_inner();
    let mut events = Vec::new();
    while let Some(ev) = s.next().await {
        events.push(ev.unwrap());
    }
    // the sandbox of the CRI has its four events (the pod it did not make
    // has none), then the container events of the mock
    let of_pod: Vec<_> = events.iter().filter(|e| e.container_id == pod).collect();
    assert_eq!(of_pod.len(), 4);
    assert_eq!(
        of_pod
            .iter()
            .map(|e| e.container_event_type)
            .collect::<Vec<_>>(),
        [
            ContainerEventType::ContainerCreatedEvent as i32,
            ContainerEventType::ContainerStartedEvent as i32,
            ContainerEventType::ContainerStoppedEvent as i32,
            ContainerEventType::ContainerDeletedEvent as i32,
        ]
    );
    assert_eq!(of_pod[0].pod_sandbox_status.as_ref().unwrap().id, pod);
    assert!(events.iter().all(|e| e.container_id != "foreign"));

    // the update of the resources of a sandbox: the pod's, the overhead added
    cri.update_pod_sandbox_resources(Request::new(UpdatePodSandboxResourcesRequest {
        pod_sandbox_id: pod.clone(),
        overhead: Some(LinuxContainerResources {
            memory_limit_in_bytes: 4 << 20,
            ..Default::default()
        }),
        resources: Some(LinuxContainerResources {
            memory_limit_in_bytes: 64 << 20,
            cpu_shares: 256,
            oom_score_adj: -998,
            ..Default::default()
        }),
    }))
    .await
    .unwrap();
    {
        let s = mock.st.lock().unwrap();
        assert!(s.updates.is_empty(), "not the infra container's");
        assert_eq!(s.pod_updates.len(), 1);
        let (id, r) = &s.pod_updates[0];
        assert_eq!(id, &pod);
        assert_eq!((r.memory_limit, r.cpu_shares), (68 << 20, 256));
    }
    let e = cri
        .update_pod_sandbox_resources(Request::new(UpdatePodSandboxResourcesRequest {
            pod_sandbox_id: "nope".into(),
            overhead: None,
            resources: Some(LinuxContainerResources::default()),
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::NotFound);
}

#[tokio::test]
async fn the_pods_on_a_cni_network() {
    let (mock, cri) = Mock::cri_with(|cri| cri.with_pod_network("cni:k8s"));
    let ready = |cri: &std::sync::Arc<velarx_cri::service::Cri<Mock>>| {
        let cri = cri.clone();
        async move {
            let st = cri
                .status(Request::new(StatusRequest { verbose: false }))
                .await
                .unwrap()
                .into_inner()
                .status
                .unwrap();
            let c = st
                .conditions
                .iter()
                .find(|c| c.r#type == "NetworkReady")
                .unwrap()
                .clone();
            (c.status, c.reason, c.message)
        }
    };
    // not ready, as the plugins say (the kubelet keeps the node not ready)
    mock.st.lock().unwrap().network = velarx_proto::engine::NetworkStatus {
        ready: false,
        message: "no CNI configuration file in /etc/cni/net.d".into(),
    };
    let (ok, reason, message) = ready(&cri).await;
    assert!(!ok);
    assert_eq!(reason, "NetworkPluginNotReady");
    assert!(message.contains("no CNI configuration file"), "{message}");
    mock.st.lock().unwrap().network = velarx_proto::engine::NetworkStatus {
        ready: true,
        message: String::new(),
    };
    assert!(ready(&cri).await.0);
    assert!(mock.calls().iter().any(|c| c == "network_status cni:k8s"));

    // the pods are on the network, unless they are on the host's
    run_pod(&cri).await;
    let mut cfg = sandbox_config();
    cfg.linux = Some(LinuxPodSandboxConfig {
        security_context: Some(LinuxSandboxSecurityContext {
            namespace_options: Some(NamespaceOption {
                network: NamespaceMode::Node as i32,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    });
    cri.run_pod_sandbox(Request::new(RunPodSandboxRequest {
        config: Some(cfg),
        runtime_handler: String::new(),
    }))
    .await
    .unwrap();
    let creates = mock.st.lock().unwrap().pod_creates.clone();
    assert_eq!(creates[0].network, "cni:k8s");
    assert_eq!(creates[1].network, "");

    // the default network of the engine is always ready
    let (plain_mock, plain) = Mock::cri();
    assert!(ready(&plain).await.0);
    assert!(plain_mock.calls().is_empty());
}

#[tokio::test]
async fn the_pod_cidr_and_the_annotations_go_to_the_cni_plugins() {
    let (mock, cri) = Mock::cri_with(|cri| cri.with_pod_network("cni:k8s"));
    let update = |cidr: &str| {
        cri.update_runtime_config(Request::new(UpdateRuntimeConfigRequest {
            runtime_config: Some(RuntimeConfig {
                network_config: Some(NetworkConfig {
                    pod_cidr: cidr.into(),
                }),
            }),
        }))
    };
    for bad in [
        "10.0.0.0",
        "10.0.0.0/33",
        "x/8",
        "10.0.0.0/24,10.1.0.0/24",
        "fd00::/129",
    ] {
        let e = update(bad).await.unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument, "{bad}");
    }
    update("10.244.1.0/24,fd00:1::/64").await.unwrap();

    let mut cfg = sandbox_config();
    cfg.annotations
        .insert("kubernetes.io/egress-bandwidth".into(), "10M".into());
    cri.run_pod_sandbox(Request::new(RunPodSandboxRequest {
        config: Some(cfg),
        runtime_handler: String::new(),
    }))
    .await
    .unwrap();
    // the range of a pod made after the update is the node's; a later update
    // is for the pods after it
    update("").await.unwrap();
    run_pod(&cri).await;
    let creates = mock.st.lock().unwrap().pod_creates.clone();
    assert_eq!(creates[0].cni_ip_ranges, ["10.244.1.0/24", "fd00:1::/64"]);
    assert_eq!(
        creates[0].cni_annotations["kubernetes.io/egress-bandwidth"],
        "10M"
    );
    assert!(creates[1].cni_ip_ranges.is_empty());

    // the engine's own networks have subnets of their own: a range is refused
    let (_, plain) = Mock::cri();
    let e = plain
        .update_runtime_config(Request::new(UpdateRuntimeConfigRequest {
            runtime_config: Some(RuntimeConfig {
                network_config: Some(NetworkConfig {
                    pod_cidr: "10.244.1.0/24".into(),
                }),
            }),
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);
    assert!(e.message().contains("--pod-network cni:"), "{e}");
    plain
        .update_runtime_config(Request::new(UpdateRuntimeConfigRequest::default()))
        .await
        .unwrap();
}

#[tokio::test]
async fn image_fs_info_has_the_inodes() {
    let (mock, cri) = Mock::cri();
    let inodes = |cri: std::sync::Arc<velarx_cri::service::Cri<Mock>>| async move {
        let r = cri
            .image_fs_info(Request::new(ImageFsInfoRequest {}))
            .await
            .unwrap()
            .into_inner();
        (
            r.image_filesystems[0].inodes_used.map(|v| v.value),
            r.container_filesystems[0].inodes_used.map(|v| v.value),
        )
    };
    assert_eq!(inodes(cri.clone()).await, (None, None));
    mock.st.lock().unwrap().inodes_used = Some(1234);
    assert_eq!(inodes(cri).await, (Some(1234), Some(1234)));
}

#[tokio::test]
async fn the_verbose_status_calls_say_what_the_engine_knows() {
    let (_, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    let id = cri
        .create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: pod.clone(),
            config: Some(container_config()),
            sandbox_config: Some(sandbox_config()),
        }))
        .await
        .unwrap()
        .into_inner()
        .container_id;
    let info = |m: std::collections::HashMap<String, String>| -> serde_json::Value {
        serde_json::from_str(&m["info"]).unwrap()
    };

    let st = cri
        .pod_sandbox_status(Request::new(PodSandboxStatusRequest {
            pod_sandbox_id: pod.clone(),
            verbose: true,
        }))
        .await
        .unwrap()
        .into_inner();
    let i = info(st.info);
    assert_eq!(i["pid"], 4242);
    assert_eq!(i["netnsPath"], "/proc/4242/ns/net");
    assert_eq!(i["runtimeType"], "crun");
    assert_eq!(i["ips"], serde_json::json!(["10.0.0.2"]));
    assert_eq!(i["network"], "default");
    let quiet = cri
        .pod_sandbox_status(Request::new(PodSandboxStatusRequest {
            pod_sandbox_id: pod.clone(),
            verbose: false,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(quiet.info.is_empty());

    let st = cri
        .container_status(Request::new(ContainerStatusRequest {
            container_id: id,
            verbose: true,
        }))
        .await
        .unwrap()
        .into_inner();
    let i = info(st.info);
    assert_eq!(i["sandboxID"], pod);
    assert_eq!(i["pid"], 4243);
    assert_eq!(i["runtimeType"], "crun");
    assert_eq!(i["privileged"], false);
    // the OCI configuration, as containerd shows it, and the user of its process
    assert_eq!(
        i["runtimeSpec"]["process"]["args"],
        serde_json::json!(["sh"])
    );
    let user = st.status.unwrap().user.unwrap().linux.unwrap();
    assert_eq!((user.uid, user.gid), (1000, 100));
    assert_eq!(user.supplemental_groups, [100, 10]);
}

#[tokio::test]
async fn the_sandbox_image_is_the_infra_image_of_every_sandbox() {
    // unset: the engine's own infra image
    let (mock, cri) = Mock::cri();
    run_pod(&cri).await;
    assert_eq!(mock.st.lock().unwrap().pod_creates[0].infra_image, "");
    let s = cri
        .status(Request::new(StatusRequest { verbose: true }))
        .await
        .unwrap()
        .into_inner();
    let config: serde_json::Value = serde_json::from_str(&s.info["config"]).unwrap();
    assert!(config.get("sandboxImage").is_none(), "{config}");

    let (mock, cri) = Mock::cri_with(|cri| cri.with_sandbox_image("registry.k8s.io/pause:3.10"));
    run_pod(&cri).await;
    assert_eq!(
        mock.st.lock().unwrap().pod_creates[0].infra_image,
        "registry.k8s.io/pause:3.10"
    );
    // what `crictl info` shows and a kubeadm compares with its pause image
    let s = cri
        .status(Request::new(StatusRequest { verbose: true }))
        .await
        .unwrap()
        .into_inner();
    let config: serde_json::Value = serde_json::from_str(&s.info["config"]).unwrap();
    assert_eq!(config["sandboxImage"], "registry.k8s.io/pause:3.10");
}
