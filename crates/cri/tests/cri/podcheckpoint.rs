// SPDX-License-Identifier: Apache-2.0
//! `CheckpointPod` and `RestorePod`, with a mock engine.

use crate::mock::Mock;
use crate::runtime::{container_config, run_pod, sandbox_config};
use tonic::{Code, Request};
use velarx_cri::api::runtime_service_server::RuntimeService;
use velarx_cri::api::*;
use velarx_cri::service::Cri;

async fn start(cri: &Cri<Mock>, pod: &str, name: &str) -> String {
    let mut cfg = container_config();
    cfg.metadata = Some(ContainerMetadata {
        name: name.into(),
        attempt: 0,
    });
    let id = cri
        .create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: pod.into(),
            config: Some(cfg),
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
    id
}

fn checkpoint_of(pod: &str, ids: &[&str]) -> CheckpointPodRequest {
    CheckpointPodRequest {
        pod_sandbox_id: pod.into(),
        output_path: "/ck/pod1".into(),
        container_ids: ids.iter().map(|i| i.to_string()).collect(),
        options: Default::default(),
    }
}

async fn code(cri: &Cri<Mock>, req: CheckpointPodRequest) -> Code {
    cri.checkpoint_pod(Request::new(req))
        .await
        .unwrap_err()
        .code()
}

#[tokio::test]
async fn a_pod_checkpoint_has_the_containers_and_what_the_pod_was() {
    let (mock, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    let a = start(&cri, &pod, "main").await;
    let b = start(&cri, &pod, "side").await;
    cri.checkpoint_pod(Request::new(checkpoint_of(&pod, &[&a, &b])))
        .await
        .unwrap();
    let s = mock.st.lock().unwrap();
    assert_eq!(
        s.pod_checkpoints,
        [(vec![a.clone(), b.clone()], "/ck/pod1".to_string())]
    );
    let m: serde_json::Value = serde_json::from_slice(&s.manifests["/ck/pod1"]).unwrap();
    assert_eq!(m["version"], 1);
    assert_eq!(m["sandbox"]["name"], "web");
    assert_eq!(m["sandbox"]["namespace"], "default");
    assert_eq!(m["sandbox"]["annotations"]["note"], "n");
    assert_eq!(m["labels"]["app"], "web");
    assert_eq!(m["hostname"], "h");
    assert_eq!(m["ips"][0], "10.0.0.2");
    assert_eq!(m["containers"][0]["meta"]["name"], "main");
    assert_eq!(m["containers"][0]["meta"]["command"][0], "sleep");
    // (the environment by its fingerprint only: its values may be secrets)
    assert!(m["containers"][0]["meta"].get("env").is_none());
    assert!(m["containers"][0]["meta"]["env_digest"]
        .as_str()
        .is_some_and(|d| d.starts_with("sha256:") && d.len() == 71));
    assert_eq!(m["containers"][0]["meta"]["user"], "1000:2000");
    assert_eq!(m["containers"][0]["labels"]["l"], "1");
    assert_eq!(m["containers"][0]["archive"], "0.tar");
    assert_eq!(m["containers"][1]["meta"]["name"], "side");
    assert_eq!(m["containers"][1]["archive"], "1.tar");
}

#[tokio::test]
async fn a_pod_checkpoint_refuses_what_is_not_a_running_pod_of_the_request() {
    let (mock, cri) = Mock::cri();
    let pod = run_pod(&cri).await;
    let other = run_pod(&cri).await;
    let a = start(&cri, &pod, "main").await;
    let theirs = start(&cri, &other, "main").await;
    let idle = cri
        .create_container(Request::new(CreateContainerRequest {
            pod_sandbox_id: pod.clone(),
            config: Some(container_config()),
            sandbox_config: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .container_id;
    assert_eq!(
        code(&cri, checkpoint_of(&pod, &[])).await,
        Code::InvalidArgument
    );
    let mut r = checkpoint_of(&pod, &[&a]);
    r.output_path.clear();
    assert_eq!(code(&cri, r).await, Code::InvalidArgument);
    let mut r = checkpoint_of(&pod, &[&a]);
    r.options.insert("x".into(), "y".into());
    assert_eq!(code(&cri, r).await, Code::InvalidArgument);
    assert_eq!(
        code(&cri, checkpoint_of(&pod, &[&a, &a])).await,
        Code::InvalidArgument
    );
    assert_eq!(
        code(&cri, checkpoint_of(&pod, &[&theirs])).await,
        Code::InvalidArgument
    );
    assert_eq!(
        code(&cri, checkpoint_of(&pod, &[&idle])).await,
        Code::FailedPrecondition
    );
    assert_eq!(
        code(&cri, checkpoint_of(&pod, &["nope"])).await,
        Code::NotFound
    );
    assert_eq!(
        code(&cri, checkpoint_of("nope", &[&a])).await,
        Code::NotFound
    );
    cri.stop_pod_sandbox(Request::new(StopPodSandboxRequest {
        pod_sandbox_id: pod.clone(),
    }))
    .await
    .unwrap();
    assert_eq!(
        code(&cri, checkpoint_of(&pod, &[&a])).await,
        Code::FailedPrecondition
    );
    assert!(mock.st.lock().unwrap().pod_checkpoints.is_empty());
}

/// A pod with two containers, checkpointed, and removed.
async fn checkpointed(cri: &Cri<Mock>) {
    let pod = run_pod(cri).await;
    let a = start(cri, &pod, "main").await;
    let b = start(cri, &pod, "side").await;
    cri.checkpoint_pod(Request::new(checkpoint_of(&pod, &[&a, &b])))
        .await
        .unwrap();
    cri.remove_pod_sandbox(Request::new(RemovePodSandboxRequest {
        pod_sandbox_id: pod,
    }))
    .await
    .unwrap();
}

fn restore_of(names: &[&str]) -> RestorePodRequest {
    let mut config = sandbox_config();
    config.metadata.as_mut().unwrap().uid = "u2".into();
    RestorePodRequest {
        checkpoint_path: "/ck/pod1".into(),
        config: Some(config),
        runtime_handler: String::new(),
        options: Default::default(),
        container_configs: names
            .iter()
            .map(|n| {
                let mut c = container_config();
                c.metadata = Some(ContainerMetadata {
                    name: n.to_string(),
                    attempt: 0,
                });
                c
            })
            .collect(),
    }
}

#[tokio::test]
async fn a_pod_is_restored_in_a_new_sandbox_with_its_containers_created() {
    let (mock, cri) = Mock::cri();
    checkpointed(&cri).await;
    let r = cri
        .restore_pod(Request::new(restore_of(&["side", "main"])))
        .await
        .unwrap()
        .into_inner();
    let s = mock.st.lock().unwrap();
    let pod = s.pods.iter().find(|p| p.id == r.pod_sandbox_id).unwrap();
    assert!(pod.status.is_running());
    assert_eq!(r.restored_containers.len(), 2);
    for (name, archive) in [("main", "0.tar"), ("side", "1.tar")] {
        let id = &r
            .restored_containers
            .iter()
            .find(|c| c.name == name)
            .unwrap()
            .container_id;
        let c = s.containers.iter().find(|c| &c.id == id).unwrap();
        assert_eq!(c.pod_id, pod.id);
        assert_eq!(
            c.state,
            velarx_proto::workload::RunState::Created,
            "not started"
        );
        assert!(s
            .staged
            .contains(&(id.clone(), "/ck/pod1".to_string(), archive.to_string())));
    }
}

async fn restore_code(cri: &Cri<Mock>, req: RestorePodRequest) -> Code {
    cri.restore_pod(Request::new(req)).await.unwrap_err().code()
}

#[tokio::test]
async fn a_restore_refuses_what_is_not_the_checkpoint_and_makes_nothing() {
    let (mock, cri) = Mock::cri();
    checkpointed(&cri).await;
    let before = mock.st.lock().unwrap().pods.len();
    let mut r = restore_of(&["main", "side"]);
    r.checkpoint_path = "/ck/nothere".into();
    assert_eq!(restore_code(&cri, r).await, Code::NotFound);
    assert_eq!(
        restore_code(&cri, restore_of(&[])).await,
        Code::InvalidArgument
    );
    assert_eq!(
        restore_code(&cri, restore_of(&["main"])).await,
        Code::InvalidArgument
    );
    assert_eq!(
        restore_code(&cri, restore_of(&["main", "other"])).await,
        Code::InvalidArgument
    );
    assert_eq!(
        restore_code(&cri, restore_of(&["main", "main"])).await,
        Code::InvalidArgument
    );
    assert_eq!(
        restore_code(&cri, restore_of(&["main", "side", "extra"])).await,
        Code::InvalidArgument
    );
    let mut r = restore_of(&["main", "side"]);
    r.options.insert("x".into(), "y".into());
    assert_eq!(restore_code(&cri, r).await, Code::InvalidArgument);
    let mut r = restore_of(&["main", "side"]);
    r.config = None;
    assert_eq!(restore_code(&cri, r).await, Code::InvalidArgument);
    let mut r = restore_of(&["main", "side"]);
    r.runtime_handler = "other".into();
    assert_eq!(restore_code(&cri, r).await, Code::InvalidArgument);
    // what the process was started with has to be what the request says
    let mut r = restore_of(&["main", "side"]);
    r.container_configs[0].image.as_mut().unwrap().image = "other".into();
    assert_eq!(restore_code(&cri, r).await, Code::InvalidArgument);
    let mut r = restore_of(&["main", "side"]);
    r.container_configs[1].command = vec!["other".into()];
    assert_eq!(restore_code(&cri, r).await, Code::InvalidArgument);
    let mut r = restore_of(&["main", "side"]);
    r.container_configs[1].args = vec![];
    assert_eq!(restore_code(&cri, r).await, Code::InvalidArgument);
    let mut r = restore_of(&["main", "side"]);
    r.container_configs[1].working_dir = "/elsewhere".into();
    assert_eq!(restore_code(&cri, r).await, Code::InvalidArgument);
    // and so do the environment and the credentials of the process
    let mut r = restore_of(&["main", "side"]);
    r.container_configs[0].envs[0].value = b"other".to_vec();
    assert_eq!(restore_code(&cri, r).await, Code::InvalidArgument);
    let mut r = restore_of(&["main", "side"]);
    r.container_configs[0].envs.clear();
    assert_eq!(restore_code(&cri, r).await, Code::InvalidArgument);
    let mut r = restore_of(&["main", "side"]);
    let sc = r.container_configs[1]
        .linux
        .as_mut()
        .unwrap()
        .security_context
        .as_mut()
        .unwrap();
    sc.run_as_user = Some(Int64Value { value: 0 });
    assert_eq!(restore_code(&cri, r).await, Code::InvalidArgument);
    let mut r = restore_of(&["main", "side"]);
    let sc = r.container_configs[1]
        .linux
        .as_mut()
        .unwrap()
        .security_context
        .as_mut()
        .unwrap();
    sc.run_as_group = None;
    assert_eq!(restore_code(&cri, r).await, Code::InvalidArgument);
    // a pod.json of another version (no fingerprint of the environment
    // yet) says so
    let saved = mock.st.lock().unwrap().manifests["/ck/pod1"].clone();
    let mut old: serde_json::Value = serde_json::from_slice(&saved).unwrap();
    old["version"] = 2.into();
    for c in old["containers"].as_array_mut().unwrap() {
        let meta = c["meta"].as_object_mut().unwrap();
        meta.remove("env_digest");
        meta.remove("user");
    }
    mock.st
        .lock()
        .unwrap()
        .manifests
        .insert("/ck/pod1".into(), serde_json::to_vec(&old).unwrap());
    let e = cri
        .restore_pod(Request::new(restore_of(&["main", "side"])))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
    assert!(
        e.message()
            .contains("of version 2, velarx restores version 1"),
        "{}",
        e.message()
    );
    let s = mock.st.lock().unwrap();
    assert_eq!(s.pods.len(), before, "no sandbox was made");
    assert!(s.staged.is_empty());
}

#[tokio::test]
async fn a_restore_that_fails_removes_the_sandbox_and_the_containers() {
    let (mock, cri) = Mock::cri();
    checkpointed(&cri).await;
    // the second container of the restore (the mock numbers its objects: the
    // pod 4, then the containers 5 and 6) fails to stage
    mock.st.lock().unwrap().stage_fails = Some("ctr6".into());
    let e = cri
        .restore_pod(Request::new(restore_of(&["main", "side"])))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Internal, "{e}");
    let s = mock.st.lock().unwrap();
    assert!(s.pods.is_empty(), "{:?}", s.pods);
    assert!(s.containers.is_empty());
}
