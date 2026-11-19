// SPDX-License-Identifier: Apache-2.0
//! Integration tests for container operations

#[tokio::test]
async fn test_create_container_request_defaults() {
    use velarx_wire::request::CreateContainerRequest;

    let req = CreateContainerRequest::default();

    assert!(req.id.is_none());
    assert!(req.name.is_none());
    assert!(req.command.is_empty());
    assert!(req.entrypoint.is_empty());
    assert!(req.env.is_empty());
    assert!(!req.tty);
    assert!(!req.privileged);
    assert!(!req.read_only_rootfs);
    assert_eq!(req.userns_mode, velarx_wire::request::UsernsChoice::Host);
}

#[tokio::test]
async fn test_resource_limits_serialization() {
    use velarx_wire::request::ResourceLimits;

    let limits = ResourceLimits {
        memory: Some(1024 * 1024 * 512), // 512 MB
        memory_swap: Some(1024 * 1024 * 1024),
        cpu_shares: Some(1024),
        cpu_quota: Some(50000),
        cpu_period: Some(100000),
        cpuset_cpus: Some("0-3".to_string()),
        cpuset_mems: Some("0".to_string()),
        ..Default::default()
    };

    let json = serde_json::to_string(&limits).unwrap();
    let parsed: ResourceLimits = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.memory, limits.memory);
    assert_eq!(parsed.cpu_shares, limits.cpu_shares);
    assert_eq!(parsed.cpuset_cpus, limits.cpuset_cpus);
}

#[test]
fn test_container_error_display() {
    use velarx_core::services::ContainerError;

    let err = ContainerError::NotFound("test-container".to_string());
    assert!(err.to_string().contains("test-container"));

    let err = ContainerError::AlreadyExists("existing".to_string());
    assert!(err.to_string().contains("existing"));

    let err = ContainerError::NotRunning("stopped".to_string());
    assert!(err.to_string().contains("stopped"));
}

#[test]
fn test_port_mapping_serialization() {
    use velarx_wire::request::PortMapping;

    let port = PortMapping {
        container_port: 8080,
        host_port: Some(80),
        host_ip: "0.0.0.0".to_string(),
        protocol: "tcp".to_string(),
    };

    let json = serde_json::to_string(&port).unwrap();
    let parsed: PortMapping = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.container_port, 8080);
    assert_eq!(parsed.host_port, Some(80));
    assert_eq!(parsed.protocol, "tcp");
}

#[test]
fn test_health_check_serialization() {
    use velarx_proto::health::Healthcheck;

    let health = Healthcheck {
        test: vec![
            "CMD".to_string(),
            "curl".to_string(),
            "localhost".to_string(),
        ],
        interval_ns: 30_000_000_000, // 30s in ns
        timeout_ns: 10_000_000_000,
        start_period_ns: 0,
        retries: 3,
        start_interval_ns: 0,
        ..Default::default()
    };

    let json = serde_json::to_string(&health).unwrap();
    let parsed: Healthcheck = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.test.len(), 3);
    assert_eq!(parsed.retries, 3);
}

#[test]
fn test_restart_policy_serialization() {
    use velarx_wire::request::RestartPolicy;

    let policy = RestartPolicy {
        name: "on-failure".to_string(),
        maximum_retry_count: 5,
    };

    let json = serde_json::to_string(&policy).unwrap();
    let parsed: RestartPolicy = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.name, "on-failure");
    assert_eq!(parsed.maximum_retry_count, 5);
}

mod resource_conversion_tests {
    use velarx_wire::request::{ResourceLimits, ThrottleDevice};

    /// Test that ThrottleDevice can be serialized and deserialized
    #[test]
    fn test_throttle_device_serialization() {
        let device = ThrottleDevice {
            path: "/dev/sda".to_string(),
            rate: 1048576, // 1 MB/s
        };

        let json = serde_json::to_string(&device).unwrap();
        let parsed: ThrottleDevice = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.path, "/dev/sda");
        assert_eq!(parsed.rate, 1048576);
    }

    /// Test ResourceLimits with blkio device limits
    #[test]
    fn test_resource_limits_with_blkio_devices() {
        let limits = ResourceLimits {
            memory: Some(1024 * 1024 * 512),
            blkio_device_read_bps: vec![ThrottleDevice {
                path: "/dev/sda".to_string(),
                rate: 1048576,
            }],
            blkio_device_write_bps: vec![ThrottleDevice {
                path: "/dev/sda".to_string(),
                rate: 2097152,
            }],
            blkio_device_read_iops: vec![ThrottleDevice {
                path: "/dev/sda".to_string(),
                rate: 1000,
            }],
            blkio_device_write_iops: vec![ThrottleDevice {
                path: "/dev/sda".to_string(),
                rate: 2000,
            }],
            ..Default::default()
        };

        let json = serde_json::to_string(&limits).unwrap();
        let parsed: ResourceLimits = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.blkio_device_read_bps.len(), 1);
        assert_eq!(parsed.blkio_device_read_bps[0].path, "/dev/sda");
        assert_eq!(parsed.blkio_device_read_bps[0].rate, 1048576);

        assert_eq!(parsed.blkio_device_write_bps.len(), 1);
        assert_eq!(parsed.blkio_device_write_bps[0].rate, 2097152);

        assert_eq!(parsed.blkio_device_read_iops.len(), 1);
        assert_eq!(parsed.blkio_device_read_iops[0].rate, 1000);

        assert_eq!(parsed.blkio_device_write_iops.len(), 1);
        assert_eq!(parsed.blkio_device_write_iops[0].rate, 2000);
    }
}

/// A container service over the database of `e` whose OCI runtime is a
/// program that notes each call in the file `asked` and fails; the image
/// `img` is in the database.  The records `record` makes use that runtime.
struct WithRuntime {
    containers: std::sync::Arc<velarx_core::services::ContainerService>,
    asked: std::path::PathBuf,
    runtime: std::path::PathBuf,
}

impl WithRuntime {
    async fn new(e: &super::common::Env, tmp: &std::path::Path) -> Self {
        use std::sync::Arc;
        use velarx_core::services::{ContainerParts, ContainerService, VolumeService};
        use velarx_db::ImageRecord;

        let asked = tmp.join("asked");
        let runtime = tmp.join("runtime");
        velarx_base::testing::write_script(
            &runtime,
            &format!("echo \"$*\" >> {}\nexit 1", asked.display()),
        );
        let digest = |n: u8| -> velarx_types::digest::Digest {
            format!("sha256:{}", format!("{n:02x}").repeat(32))
                .parse()
                .unwrap()
        };
        e.db.insert_image(&ImageRecord {
            id: "img".into(),
            manifest_digest: digest(1),
            config_digest: digest(2),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: "2024-01-01T00:00:00Z".into(),
            is_lazy: false,
        })
        .await
        .unwrap();
        let volumes = Arc::new(VolumeService::new(e.db.clone(), tmp.join("volumes")).unwrap());
        let userns = Arc::new(velarx_runtime::userns::UserNamespaceManager::new(
            e.db.clone(),
            &Default::default(),
        ));
        let containers = Arc::new(
            ContainerService::new(ContainerParts {
                db: e.db.clone(),
                image_service: Arc::new((*e.service).clone()),
                userns_manager: userns,
                root_dir: tmp.join("root"),
                state_dir: tmp.join("state"),
                cgroup_manager: None,
                network_providers: Default::default(),
                volume_service: volumes,
            })
            .unwrap(),
        );
        Self {
            containers,
            asked,
            runtime,
        }
    }

    fn record(&self, id: &str, state: velarx_db::RecordState) -> velarx_db::ContainerRecord {
        use velarx_runtime::container::ContainerConfig;
        velarx_db::ContainerRecord {
            id: id.into(),
            name: Some(id.into()),
            image_id: "img".into(),
            config: serde_json::to_string(&ContainerConfig {
                id: id.into(),
                image: "img".into(),
                runtime: Some(self.runtime.clone()),
                ..Default::default()
            })
            .unwrap(),
            state,
            pid: None,
            created_at: "2024-01-01T00:00:00Z".into(),
            started_at: None,
            finished_at: None,
            exit_code: None,
        }
    }

    /// How many times the runtime was asked for a state.
    fn states_asked(&self) -> usize {
        std::fs::read_to_string(&self.asked)
            .unwrap_or_default()
            .lines()
            .filter(|line| line.contains(" state "))
            .count()
    }
}

/// Listing and inspecting containers asks the OCI runtime only for a
/// container the record says is alive: a created one is not in the runtime,
/// and a stopped one has nothing to tell.  The runtime here is a program
/// that notes it was run; the running container is the control that shows the
/// test sees an ask.
#[tokio::test]
async fn test_the_runtime_is_asked_only_for_a_container_that_can_be_in_it() {
    use velarx_db::RecordState;

    let e = super::common::env().await;
    let tmp = tempfile::tempdir().unwrap();
    let with = WithRuntime::new(&e, tmp.path()).await;
    let (containers, asked) = (&with.containers, &with.asked);
    let record = |id: &str, state: RecordState| with.record(id, state);
    for (id, state) in [
        ("created", RecordState::Created),
        ("stopped", RecordState::Stopped),
        ("exited", RecordState::Exited),
        ("initialized", RecordState::Initialized),
    ] {
        e.db.insert_container(&record(id, state)).await.unwrap();
    }

    let listed = containers.list(true).await.unwrap();
    assert_eq!(listed.len(), 4);
    for id in ["created", "stopped", "exited", "initialized"] {
        let found = containers.inspect(id).await.unwrap();
        assert_eq!(
            found.state,
            listed.iter().find(|c| c.id == id).unwrap().state
        );
    }
    assert!(
        !asked.exists(),
        "the runtime was asked for containers it cannot have"
    );

    e.db.insert_container(&record("running", RecordState::Running))
        .await
        .unwrap();
    containers.inspect("running").await.unwrap();
    assert!(
        asked.exists(),
        "the runtime is asked for a running container"
    );
}

/// A listing asks the runtime once for each container that runs, and a
/// listing that also needs the state of each (the one a stats sample
/// starts from) has it from that ask, not from another.
#[tokio::test]
async fn test_a_listing_asks_the_runtime_once_for_each_running_container() {
    use velarx_db::RecordState;

    let e = super::common::env().await;
    let tmp = tempfile::tempdir().unwrap();
    let with = WithRuntime::new(&e, tmp.path()).await;
    for n in 0..12 {
        e.db.insert_container(&with.record(&format!("running{n}"), RecordState::Running))
            .await
            .unwrap();
    }
    e.db.insert_container(&with.record("exited", RecordState::Exited))
        .await
        .unwrap();
    let listed = with.containers.list_observed(true).await.unwrap();
    assert_eq!(listed.len(), 13);
    assert_eq!(with.states_asked(), 12);
    let running = with.containers.list_observed(false).await.unwrap();
    assert_eq!(running.len(), 12);
    assert_eq!(with.states_asked(), 24);
}

/// A lock released by its holder is still held while a child that was
/// forked while it was held has not exec'd (the child has a copy of the
/// descriptor, a flock goes with the last copy): other tests of a process
/// fork all the time, so a lock is waited for, never probed, to know it
/// is free.  The pod locks are all taken that way.
#[tokio::test]
async fn a_pod_lock_is_free_once_a_child_forked_while_it_was_held_has_exec_d() {
    use velarx_core::services::{CreateContainerRequest, PodService, PodSpec};

    let e = super::common::env().await;
    let tmp = tempfile::tempdir().unwrap();
    let with = WithRuntime::new(&e, tmp.path()).await;
    let pods = PodService::new(with.containers.clone(), tmp.path().join("pods-root"));
    let id = pods
        .create(PodSpec {
            name: "p".into(),
            no_infra: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let joining = pods
        .prepare_member(&mut CreateContainerRequest {
            pod: Some("p".into()),
            ..Default::default()
        })
        .await
        .unwrap()
        .unwrap();

    // a child forked now stops before its exec until told to go on
    let (ready_r, ready_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let (go_r, go_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let mut cmd = std::process::Command::new("true");
    velarx_sys::spawn::pre_exec(&mut cmd, move |_| {
        let mut byte = [0u8];
        rustix::io::write(&ready_w, &[1])?;
        rustix::io::read(&go_r, &mut byte)?;
        Ok(())
    });
    let spawning = std::thread::spawn(move || cmd.status());
    let mut byte = [0u8];
    rustix::io::read(&ready_r, &mut byte).unwrap();
    drop(joining);

    // released by its holder, held by the copy
    let f = std::fs::File::open(tmp.path().join(format!("pods-root/pods/.{id}.op.lock"))).unwrap();
    assert_eq!(
        rustix::fs::flock(&f, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap_err(),
        rustix::io::Errno::WOULDBLOCK
    );
    // the child execs: the lock is free for whoever waits for it
    rustix::io::write(&go_w, &[1]).unwrap();
    assert!(spawning.join().unwrap().unwrap().success());
    drop(pods.lock_operation(&id).await.unwrap());
}

/// A container made for a pod holds the pod's operation lock (the one a
/// removal of the pod holds all through) from its preparation to its
/// join: a removal comes before it (the pod is gone, the create refused)
/// or after it (the container goes with the pod), never in the middle.
#[tokio::test]
async fn test_a_container_made_for_a_pod_holds_the_operation_lock_of_the_pod() {
    use velarx_core::services::{CreateContainerRequest, PodError, PodService, PodSpec};

    let e = super::common::env().await;
    let tmp = tempfile::tempdir().unwrap();
    let with = WithRuntime::new(&e, tmp.path()).await;
    let pods = PodService::new(with.containers.clone(), tmp.path().join("pods-root"));
    let id = pods
        .create(PodSpec {
            name: "p".into(),
            no_infra: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let request = || CreateContainerRequest {
        pod: Some("p".into()),
        ..Default::default()
    };

    // while it joins, no other operation on the pod runs (the lock is
    // asked for without waiting: a held one says so)
    let joining = pods.prepare_member(&mut request()).await.unwrap().unwrap();
    assert_eq!(joining.id(), id);
    let lock = tmp.path().join(format!("pods-root/pods/.{id}.op.lock"));
    let try_lock = || {
        let f = std::fs::File::open(&lock).unwrap();
        rustix::fs::flock(&f, rustix::fs::FlockOperation::NonBlockingLockExclusive).map(|_| f)
    };
    assert_eq!(try_lock().unwrap_err(), rustix::io::Errno::WOULDBLOCK);
    pods.add_container(joining.id(), "c1").await.unwrap();
    drop(joining);
    // (released: waited for, not probed: a copy of the descriptor that
    // another test of this process forked at that moment holds the lock
    // until the child execs, see the test below)
    drop(pods.lock_operation(&id).await.unwrap());

    // a removal (which holds the lock all through) asked for while a
    // container joins waits for it: the member is there to go with the pod
    let joining = pods.prepare_member(&mut request()).await.unwrap().unwrap();
    let (removed, joined) = tokio::join!(
        async {
            let _op = pods.lock_operation(&id).await.unwrap();
            let members = pods.get(&id).await.unwrap().container_ids;
            pods.remove(&id, true).await.unwrap();
            members
        },
        async {
            let joined = pods.add_container(joining.id(), "c2").await;
            drop(joining);
            joined
        }
    );
    joined.unwrap();
    assert_eq!(removed, ["c1", "c2"]);

    // a removal that came first leaves nothing to join
    let id = pods
        .create(PodSpec {
            name: "p".into(),
            no_infra: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let op = pods.lock_operation(&id).await.unwrap();
    let mut asked = request();
    let (joined, ()) = tokio::join!(pods.prepare_member(&mut asked), async {
        pods.remove(&id, true).await.unwrap();
        drop(op);
    });
    let err = joined.unwrap_err();
    assert!(matches!(err, PodError::NotFound(_)), "{err:?}");
}
