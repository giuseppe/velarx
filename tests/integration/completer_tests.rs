// SPDX-License-Identifier: Apache-2.0
//! Who owns a lazy pull: the engine service of the store makes it and
//! completes it on a task of its own (`ImageService::serve_pulls`); the
//! engine of a command hands every lazy pull, completion and cancel to it
//! (`ImageService::with_hand_off`).  How a command that waits is served, how
//! a pull is resumed and cancelled.  The process found or started on the
//! engine's socket is the end to end tests'; here a recorder stands for it.

use crate::common::*;
use std::sync::{Arc, Mutex};
use velarx_content::pull::staged::PullState;
use velarx_core::services::{ImageService, PullHandOff, PullOptions, PullResult, TransferStats};
use velarx_registry::auth::RegistryAccess;
use velarx_types::ImageResult;

/// The image service of `e` with `pull` as its `[pull]` settings.
fn service_of(e: &Env, pull: velarx_config::PullConfig) -> ImageService {
    ImageService::new(
        e.db.clone(),
        e.store.clone(),
        e.staging.clone(),
        velarx_storage::VerityMode::Off,
    )
    .unwrap()
    .with_pull_config(velarx_config::PullConfig {
        lazy_window_files: 0,
        worker_path: Some(registry_bin().into()),
        ..pull
    })
    .unwrap()
    .with_resolver(client_for(&[&e.host]))
    .with_origin(e.origin.clone())
}

/// The service of `e` as the engine service of the store; with
/// `background` false nothing is completed until a command asks.
fn engine_service(e: &Env, background: bool) -> std::mem::ManuallyDrop<ImageService> {
    let pull = velarx_config::PullConfig {
        lazy_completers: usize::from(background),
        ..Default::default()
    };
    std::mem::ManuallyDrop::new(service_of(e, pull).serve_pulls())
}

/// What the engine of a command asks of "the engine service".
#[derive(Default)]
struct Recorder {
    calls: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl PullHandOff for Recorder {
    async fn pull_lazy(&self, reference: &str, _: &PullOptions) -> ImageResult<PullResult> {
        self.calls.lock().unwrap().push(format!("pull {reference}"));
        Ok(PullResult {
            id: "f".repeat(64),
            stats: TransferStats::default(),
        })
    }
    async fn complete(&self, id: &str, _: &RegistryAccess) -> ImageResult<TransferStats> {
        self.calls.lock().unwrap().push(format!("complete {id}"));
        Ok(TransferStats::default())
    }
    async fn cancel(&self, id: &str, _: bool) -> ImageResult<()> {
        self.calls.lock().unwrap().push(format!("cancel {id}"));
        Ok(())
    }
    fn ensure(&self) -> ImageResult<()> {
        self.calls.lock().unwrap().push("ensure".into());
        Ok(())
    }
}

impl Recorder {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }
}

/// The service of `e` as the engine of a command, `recorder` its engine
/// service.
fn command_engine(e: &Env, recorder: &Arc<Recorder>) -> std::mem::ManuallyDrop<ImageService> {
    std::mem::ManuallyDrop::new(service_of(e, Default::default()).with_hand_off(recorder.clone()))
}

async fn pull_lazily(service: &ImageService, e: &Env) -> velarx_core::services::PullResult {
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    service
        .pull_lazy_with_client(&e.client(), &format!("{}/test:latest", e.host), tx)
        .await
        .unwrap()
}

async fn lazy_env_published() -> Env {
    let e = env().await;
    e.publish(&[&build_chunked(&sample())], &[ZSTD]);
    e
}

/// The engine of a command makes no lazy pull: it hands it to the engine
/// service, and nothing is staged by it.  An eager pull it makes itself.
#[tokio::test]
async fn the_engine_of_a_command_hands_a_lazy_pull_to_the_service() {
    let e = lazy_env_published().await;
    let recorder = Arc::new(Recorder::default());
    let service = command_engine(&e, &recorder);
    let reference = format!("{}/test:latest", e.host);
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let pulled = service
        .pull_with(&reference, true, &PullOptions::default(), tx.clone())
        .await
        .unwrap();
    assert_eq!(pulled.id, "f".repeat(64));
    assert_eq!(recorder.take(), [format!("pull {reference}")]);
    assert!(e.area().pulls().is_empty(), "the command staged a pull");
    // (eager: here)
    let eager = service
        .pull_with_client(&e.client(), &reference, tx)
        .await
        .unwrap();
    assert!(service.get(&eager.id).await.is_ok());
    assert!(recorder.take().is_empty());
}

/// The engine service completes a lazy pull in the background, on a task
/// that holds the lease of the pull, and a command that waits for it gets
/// it from that task.
#[tokio::test]
async fn the_service_completes_a_lazy_pull_in_the_background() {
    let e = lazy_env_published().await;
    let service = engine_service(&e, true);
    let pulled = pull_lazily(&service, &e).await;
    // (its task holds the lease from the pull on)
    assert!(e.area().lease_held(&pulled.id));
    service
        .complete_waiting(&pulled.id, RegistryAccess::default())
        .await
        .unwrap();
    assert!(service.get(&pulled.id).await.is_ok());
    assert!(e.area().pulls().is_empty());
    // the files are in the store, linked (no copy), and none is left staged
    assert!(e.store.contains(&vid(b"hello\n")));
    assert!(e.pooled().is_empty());
}

/// With no background completion (`lazy_completers` 0) a pull waits for
/// its turn, queued, until a command waits for it.
#[tokio::test]
async fn a_queued_pull_goes_on_when_a_command_waits() {
    let e = lazy_env_published().await;
    let service = engine_service(&e, false);
    let pulled = pull_lazily(&service, &e).await;
    let area = e.area();
    // (the task records the state before it waits: the wait for the lease
    // of a pull nobody completes would end at once)
    assert!(area.lease_held(&pulled.id));
    let stats = service
        .complete_waiting(&pulled.id, RegistryAccess::default())
        .await
        .unwrap();
    assert!(stats.duration_ms < 60_000);
    assert!(service.get(&pulled.id).await.is_ok());
}

/// A lease held by another process (`flock`), let go when it has exited:
/// a lock of a descriptor of this process could outlive its drop in a
/// child that another test forks at that moment (until it execs), and the
/// lease would look held after the release.
struct LeaseHolder {
    child: std::process::Child,
}

impl LeaseHolder {
    fn hold(lease: &std::path::Path) -> Self {
        use std::io::BufRead;
        let mut child = std::process::Command::new("flock")
            .args(["--exclusive", "--nonblock"])
            .arg(lease)
            .args(["sh", "-c", "echo held; read -r x; exit 0"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("flock(1)");
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "held", "the lease was not taken");
        Self { child }
    }

    /// Let it go: the holder and its shell have exited when this returns.
    fn release(mut self) {
        drop(self.child.stdin.take());
        assert!(self.child.wait().unwrap().success());
    }
}

/// After a reboot, a kill or a crash the engine service takes over the
/// pulls nobody completes; not a pull that stopped on an error, that waits
/// for credentials, that was cancelled, nor one another process completes.
/// The engine of a command starts the service when there is such a pull.
#[tokio::test]
async fn pulls_nobody_completes_are_resumed() {
    let e = lazy_env_published().await;
    let caller = std::mem::ManuallyDrop::new(service_of(&e, Default::default()));
    let pulled = pull_lazily(&caller, &e).await;
    let area = e.area();
    let recorder = Arc::new(Recorder::default());
    let command = command_engine(&e, &recorder);
    // another process completes it (its lease is held): left alone
    let held = LeaseHolder::hold(&area.image_dir(&pulled.id).join("lease"));
    command.resume_pulls();
    assert!(recorder.take().is_empty());
    let service = engine_service(&e, false);
    service.resume_pulls();
    assert!(!service
        .pulls()
        .await
        .unwrap()
        .iter()
        .any(|p| p.state == velarx_proto::workload::PullState::Running));
    held.release();
    // nobody: the command starts the service, the service takes it
    command.resume_pulls();
    assert_eq!(recorder.take(), ["ensure"]);
    service.resume_pulls();
    assert!(area.lease_held(&pulled.id));
    let stopped = service.cancel_pull(&pulled.id, false).await;
    assert!(stopped.is_ok(), "{stopped:?}");
    let (wait, id) = (area.clone(), pulled.id.clone());
    tokio::task::spawn_blocking(move || wait.wait_for_completer(&id))
        .await
        .unwrap()
        .unwrap();
    // an error that retrying cannot mend, credentials, a cancellation
    let pulled = pull_lazily(&caller, &e).await;
    for state in [
        PullState::Failed {
            reason: "the layer is not what its table says".into(),
        },
        PullState::NeedsCredentials,
        PullState::Cancelled,
    ] {
        area.set_state(&pulled.id, state, None).unwrap();
        command.resume_pulls();
        service.resume_pulls();
        assert!(recorder.take().is_empty());
        assert!(!area.lease_held(&pulled.id));
    }
    // (a cancelled pull nobody completes is gone from the list, and its
    // staging with it)
    assert!(service.pulls().await.unwrap().is_empty());
    let pulled = pull_lazily(&caller, &e).await;
    area.set_state(
        &pulled.id,
        PullState::Failed {
            reason: "blob gone".into(),
        },
        None,
    )
    .unwrap();
    let listed = service.pulls().await.unwrap();
    assert_eq!(
        (listed[0].state.word(), listed[0].error.as_deref()),
        ("failed", Some("blob gone"))
    );
}

/// The engine of a command hands what a waiting command asks, and the
/// cancel of a pull the service completes, to the service.
#[tokio::test]
async fn the_engine_of_a_command_hands_completions_and_cancels_to_the_service() {
    let e = lazy_env_published().await;
    let caller = std::mem::ManuallyDrop::new(service_of(&e, Default::default()));
    let pulled = pull_lazily(&caller, &e).await;
    let recorder = Arc::new(Recorder::default());
    let command = command_engine(&e, &recorder);
    command
        .complete_waiting(&pulled.id, RegistryAccess::default())
        .await
        .unwrap();
    assert_eq!(recorder.take(), [format!("complete {}", pulled.id)]);
    let held = LeaseHolder::hold(&e.area().image_dir(&pulled.id).join("lease"));
    command.cancel_pull(&pulled.id, false).await.unwrap();
    assert_eq!(recorder.take(), [format!("cancel {}", pulled.id)]);
    // (the service cancels it: this engine wrote nothing)
    assert_ne!(
        e.area().state(&pulled.id).unwrap().state,
        PullState::Cancelled
    );
    held.release();
    // nobody completes it: cancelled here, its staging gone at once
    command.cancel_pull(&pulled.id, false).await.unwrap();
    assert!(recorder.take().is_empty());
    assert!(e.area().pulls().is_empty());
}

/// The completion stopped on an error: the command that waits is told why.
#[tokio::test]
async fn a_command_that_waits_is_told_why_the_completion_stopped() {
    let e = lazy_env_published().await;
    // a table that lies about a file: the completion cannot finish
    let service = engine_service(&e, false);
    let pulled = pull_lazily(&service, &e).await;
    let key = e.area().layer_keys().remove(0);
    let path = e.area().layer_dir(&key).join("toc.json");
    let toc = std::fs::read_to_string(&path).unwrap();
    let toc_of =
        |data: &[u8]| velarx_storage::toc_value(&velarx_storage::to_toc(&vid(data)).unwrap());
    let (real, forged) = (toc_of(b"hello\n"), toc_of(b"not hello"));
    std::fs::write(&path, toc.replacen(&real, &forged, 1)).unwrap();
    let err = service
        .complete_waiting(&pulled.id, RegistryAccess::default())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("failed"), "{err}");
    let listed = service.pulls().await.unwrap();
    assert_eq!(listed[0].state.word(), "failed");
    assert!(listed[0].error.is_some());
    assert!(service.get(&pulled.id).await.is_err());
}

/// Cancelling a pull the service completes stops its task: the lease is
/// let go, the state says cancelled, and the staging goes with the next
/// look at the pulls.
#[tokio::test]
async fn cancelling_a_pull_stops_its_completion() {
    let e = lazy_env_published().await;
    let service = engine_service(&e, false);
    let pulled = pull_lazily(&service, &e).await;
    let area = e.area();
    assert!(area.lease_held(&pulled.id));
    service
        .cancel_pull(&format!("{}/test:latest", e.host), false)
        .await
        .unwrap();
    assert_eq!(area.state(&pulled.id).unwrap().state, PullState::Cancelled);
    let (wait, id) = (area.clone(), pulled.id.clone());
    tokio::task::spawn_blocking(move || wait.wait_for_completer(&id))
        .await
        .unwrap()
        .unwrap();
    assert!(service.pulls().await.unwrap().is_empty());
    assert!(area.pulls().is_empty());
}
