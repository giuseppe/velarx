// SPDX-License-Identifier: Apache-2.0
//! What the frontend does with an error of the engine: only the answers that
//! mean "nothing there" are read as nothing, any other reaches the kubelet.
use crate::mock::{Fail, Mock};
use crate::runtime::{container_config, run_pod};
use futures::StreamExt;
use tonic::{Code, Request};
use velarx_cri::api::image_service_server::ImageService;
use velarx_cri::api::runtime_service_server::RuntimeService;
use velarx_cri::api::*;
use velarx_cri::service::Cri;

async fn started(cri: &Cri<Mock>) -> String {
    let pod = run_pod(cri).await;
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
    id
}

fn exec_sync(id: &str) -> Request<ExecSyncRequest> {
    Request::new(ExecSyncRequest {
        container_id: id.into(),
        cmd: vec!["true".into()],
        timeout: 1,
    })
}

/// A failure of the engine that says "exec timed out" is a failure, not the
/// deadline of the call.
#[tokio::test]
async fn an_error_is_not_a_timeout_because_of_its_words() {
    let (mock, cri) = Mock::cri();
    let id = started(&cri).await;
    mock.st.lock().unwrap().exec_sync_fails =
        Some(Fail::Other("exec timed out after 1 seconds".into()));
    let e = cri.exec_sync(exec_sync(&id)).await.unwrap_err();
    assert_eq!(e.code(), Code::Internal);
}

#[tokio::test]
async fn the_deadline_of_an_exec_is_the_deadline_of_the_call() {
    let (mock, cri) = Mock::cri();
    let id = started(&cri).await;
    mock.st.lock().unwrap().exec_sync_fails = Some(Fail::Deadline);
    let e = cri.exec_sync(exec_sync(&id)).await.unwrap_err();
    assert_eq!(e.code(), Code::DeadlineExceeded);
}

fn remove(image: &str) -> Request<RemoveImageRequest> {
    Request::new(RemoveImageRequest {
        image: Some(ImageSpec {
            image: image.into(),
            ..Default::default()
        }),
    })
}

async fn pulled(cri: &Cri<Mock>) {
    cri.pull_image(Request::new(PullImageRequest {
        image: Some(ImageSpec {
            image: "alpine".into(),
            ..Default::default()
        }),
        auth: None,
        sandbox_config: None,
    }))
    .await
    .unwrap();
}

/// The engine failed to remove an image: the kubelet is told, whether or
/// not the image is still there afterwards.
#[tokio::test]
async fn a_failed_remove_of_an_image_reaches_the_kubelet() {
    let (mock, cri) = Mock::cri();
    pulled(&cri).await;
    mock.st.lock().unwrap().image_remove_fails = Some(Fail::Unavailable);
    let e = cri.remove_image(remove("alpine")).await.unwrap_err();
    assert_eq!(e.code(), Code::Unavailable);
}

/// An image that is not there is removed already; asking twice, or at the
/// same time, is not an error.
#[tokio::test]
async fn removing_what_is_gone_is_a_success() {
    let (_, cri) = Mock::cri();
    pulled(&cri).await;
    cri.remove_image(remove("alpine")).await.unwrap();
    cri.remove_image(remove("alpine")).await.unwrap();
}

/// The image the engine makes infra containers with is pinned, whatever it
/// is called: the kubelet's image garbage collection leaves it.
#[tokio::test]
async fn the_infra_image_of_the_engine_is_pinned_by_what_the_engine_says() {
    let (mock, cri) = Mock::cri();
    {
        let mut s = mock.st.lock().unwrap();
        s.infra_image = "registry.example/my/pause:7".into();
        for (id, name) in [("a", "registry.example/my/pause:7"), ("b", "alpine:1")] {
            s.images.push(velarx_proto::workload::ImageRecord {
                id: id.into(),
                names: vec![name.into()],
                ..Default::default()
            });
        }
    }
    let images = cri
        .list_images(Request::new(ListImagesRequest::default()))
        .await
        .unwrap()
        .into_inner()
        .images;
    let pinned = |id: &str| images.iter().find(|i| i.id == id).unwrap().pinned;
    assert!(pinned("a"));
    assert!(!pinned("b"));
}

/// The id the engine answers a pull with is the image of the pull, whether
/// or not a lookup finds it.
#[tokio::test]
async fn a_pull_answers_the_id_of_the_engine() {
    let (mock, cri) = Mock::cri();
    mock.st.lock().unwrap().pull_unlisted = true;
    let r = cri
        .pull_image(Request::new(PullImageRequest {
            image: Some(ImageSpec {
                image: "alpine".into(),
                ..Default::default()
            }),
            auth: None,
            sandbox_config: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(r.image_ref, "sha256img");
}

fn status(id: &str) -> Request<ContainerStatusRequest> {
    Request::new(ContainerStatusRequest {
        container_id: id.into(),
        verbose: false,
    })
}

fn verbose(id: &str) -> Request<ContainerStatusRequest> {
    Request::new(ContainerStatusRequest {
        container_id: id.into(),
        verbose: true,
    })
}

/// The user of a status is the one in the record of the engine: the OCI
/// specification is not fetched for it (it is only for the verbose
/// status), so a specification that cannot be read does not fail it.
#[tokio::test]
async fn the_user_of_a_status_comes_from_the_record_not_from_the_specification() {
    let (mock, cri) = Mock::cri();
    let id = started(&cri).await;
    mock.st.lock().unwrap().spec_fails = Some(Fail::Unavailable);
    let user = cri
        .container_status(status(&id))
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap()
        .user
        .unwrap()
        .linux
        .unwrap();
    assert_eq!((user.uid, user.gid), (1000, 100));
    assert_eq!(user.supplemental_groups, [100, 10]);
}

/// A record with no user (a container made before its specification) has
/// none in its status.
#[tokio::test]
async fn a_record_without_a_user_has_none_in_its_status() {
    let (mock, cri) = Mock::cri();
    let id = started(&cri).await;
    mock.st.lock().unwrap().containers[0].process.resolved_user = None;
    let s = cri
        .container_status(status(&id))
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap();
    assert!(s.user.is_none());
}

#[tokio::test]
async fn container_status_fails_when_the_engine_does() {
    let (mock, cri) = Mock::cri();
    let id = started(&cri).await;
    mock.st.lock().unwrap().spec_fails = Some(Fail::Unavailable);
    let e = cri.container_status(verbose(&id)).await.unwrap_err();
    assert_eq!(e.code(), Code::Unavailable);
}

/// A container that is not created yet has no configuration and no user:
/// its status is still told.
#[tokio::test]
async fn container_status_of_a_container_without_a_configuration() {
    let (mock, cri) = Mock::cri();
    let id = started(&cri).await;
    mock.st.lock().unwrap().spec_fails = Some(Fail::Precondition);
    let s = cri
        .container_status(verbose(&id))
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap();
    assert_eq!(s.id, id);
}

/// The engine cannot tell what a pod is when its event comes: the stream
/// ends with the error, the kubelet asks again, and no event is lost in
/// silence.
#[tokio::test]
async fn an_event_of_a_pod_the_engine_cannot_read_ends_the_stream_with_an_error() {
    let (mock, cri) = Mock::cri();
    {
        let mut s = mock.st.lock().unwrap();
        s.hold_events = true;
        s.pod_inspect_fails = Some(Fail::Unavailable);
    }
    let mut s = cri
        .get_container_events(Request::new(GetEventsRequest {}))
        .await
        .unwrap()
        .into_inner();
    let held = mock.st.lock().unwrap().events_held.take().unwrap();
    held.send(velarx_cri::engine::EngineEvent {
        object: "pod".into(),
        container_id: "pod9".into(),
        pod_id: String::new(),
        action: "create".into(),
        time_ns: 1,
        attributes: Default::default(),
    })
    .await
    .unwrap();
    let first = tokio::time::timeout(std::time::Duration::from_secs(10), s.next())
        .await
        .expect("the relay answered");
    assert_eq!(first.unwrap().unwrap_err().code(), Code::Unavailable);
}

fn broken_labels(meta: Option<&str>, kind: &str) -> std::collections::BTreeMap<String, String> {
    let mut labels: std::collections::BTreeMap<String, String> =
        [(velarx_cri::meta::KIND.to_string(), kind.to_string())].into();
    if let Some(m) = meta {
        labels.insert(velarx_cri::meta::META.into(), m.into());
    }
    labels
}

/// The metadata of a sandbox that cannot be read is an error of the call,
/// not a sandbox with no name, namespace and uid.
#[tokio::test]
async fn a_sandbox_with_broken_metadata_fails_the_call() {
    for meta in [Some("{not json"), Some("{\"attempt\": \"x\"}"), None] {
        let (mock, cri) = Mock::cri();
        mock.st
            .lock()
            .unwrap()
            .pods
            .push(velarx_proto::workload::PodRecord {
                id: "pod9".into(),
                spec: velarx_proto::pod::PodSpec {
                    labels: broken_labels(meta, "sandbox"),
                    ..Default::default()
                },
                ..Default::default()
            });
        let e = cri
            .list_pod_sandbox(Request::new(ListPodSandboxRequest::default()))
            .await
            .unwrap_err();
        assert_eq!(e.code(), Code::Internal, "{meta:?}");
        let e = cri
            .pod_sandbox_status(Request::new(PodSandboxStatusRequest {
                pod_sandbox_id: "pod9".into(),
                verbose: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(e.code(), Code::Internal, "{meta:?}");
    }
}

#[tokio::test]
async fn a_container_with_broken_metadata_fails_the_call() {
    for meta in [Some("{not json"), None] {
        let (mock, cri) = Mock::cri();
        mock.st
            .lock()
            .unwrap()
            .containers
            .push(velarx_proto::workload::ContainerRecord {
                id: "ctr9".into(),
                labels: broken_labels(meta, "container"),
                ..Default::default()
            });
        let e = cri
            .list_containers(Request::new(ListContainersRequest::default()))
            .await
            .unwrap_err();
        assert_eq!(e.code(), Code::Internal, "{meta:?}");
        let e = cri.container_status(status("ctr9")).await.unwrap_err();
        assert_eq!(e.code(), Code::Internal, "{meta:?}");
    }
}

/// An object of the engine that the CRI did not make has no metadata and is
/// not listed, not an error.
#[tokio::test]
async fn an_object_of_another_maker_is_left_out() {
    let (mock, cri) = Mock::cri();
    mock.add_foreign_pod("foreign");
    let l = cri
        .list_pod_sandbox(Request::new(ListPodSandboxRequest::default()))
        .await
        .unwrap()
        .into_inner();
    assert!(l.items.is_empty());
}
