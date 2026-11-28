// SPDX-License-Identifier: Apache-2.0
//! The registry fetcher as a process (`velarx-registry`) and the completions
//! and pulls that go to it.

use crate::common::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use velarx_config::PullConfig;
use velarx_db::Database;
use velarx_storage::FileStore;

/// A store on disk with a lazily pulled image from a registry of this process.
struct Setup {
    dir: tempfile::TempDir,
    env: Env,
    layer: velarx_db::LayerKey,
}

async fn setup(delay_ms: u64) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("db.sqlite")).await.unwrap();
    let store = Arc::new(FileStore::new(dir.path().join("storage/objects")).unwrap());
    let (host, reg) = start_registry().await;
    let layer = build_chunked(&sample());
    publish_to(&reg, &[&layer], &[ZSTD]);
    let service = velarx_core::services::ImageService::new(
        db.clone(),
        store.clone(),
        dir.path().join("staging"),
        velarx_storage::VerityMode::Off,
    )
    .unwrap()
    .with_pull_config(PullConfig {
        worker_path: Some(registry_bin().into()),
        ..PullConfig::default()
    })
    .unwrap()
    .with_resolver(client_for(&[&host]));
    // (the fetcher of the environment: its files in a directory of its own,
    // `DIR` is the strict one's, `service_with_strict_origin`)
    let origin = {
        let own = dir.path().join("env");
        std::fs::create_dir_all(&own).unwrap();
        let (spawner, _) = fetcher_spawner_with(
            &own,
            &dir.path().join("staging"),
            &conf_for(&[&host]),
            &velarx_config::Config::default(),
        );
        velarx_content::list::RegistryOrigin::with_shared(spawner, &Default::default())
    };
    let service = service.with_origin(origin.clone());
    let env = Env {
        _tmp: tempfile::tempdir().unwrap(),
        host,
        reg,
        service: std::mem::ManuallyDrop::new(service),
        db,
        store,
        staging: dir.path().join("staging"),
        origin,
    };
    env.pull_lazy().await.unwrap();
    env.reg.delay_ms.store(delay_ms, Ordering::SeqCst);
    let layer = layer.key();
    Setup { dir, env, layer }
}

fn big() -> Vec<u8> {
    sample()
        .into_iter()
        .find_map(|i| match i {
            Item::File {
                name: "usr/big",
                data,
                ..
            } => Some(data),
            _ => None,
        })
        .unwrap()
}

/// The fetcher (`velarx-registry`) as an engine
/// shares it: started by the first connection, held by the connections to
/// it.  The registries configuration is the test's, the fetcher's
/// configuration comes in a read-only file with no name.
fn registry_spawner(
    dir: &Path,
    host: &str,
) -> (Arc<velarx_content::shared::SharedRegistry>, PathBuf) {
    registry_spawner_with(dir, host, true)
}

/// [`registry_spawner`], the registry `insecure` or not in registries.conf.
fn registry_spawner_with(
    dir: &Path,
    host: &str,
    insecure: bool,
) -> (Arc<velarx_content::shared::SharedRegistry>, PathBuf) {
    registry_spawner_for(dir, &[host], insecure)
}

/// [`registry_spawner_with`] for several registries.
pub(crate) fn registry_spawner_for(
    dir: &Path,
    hosts: &[&str],
    insecure: bool,
) -> (Arc<velarx_content::shared::SharedRegistry>, PathBuf) {
    let conf: String = hosts
        .iter()
        .map(|host| format!("[[registry]]\nlocation = \"{host}\"\ninsecure = {insecure}\n"))
        .collect();
    fetcher_spawner(dir, &conf)
}

/// Whether the process of the pidfd `fd` ends within `secs` seconds.  A
/// signal of another test of the process that interrupts the wait does not
/// end it: the bound is an upper one only.
pub(crate) fn pidfd_ended(fd: &std::os::fd::OwnedFd, secs: i64) -> bool {
    let mut ended = [rustix::event::PollFd::new(fd, rustix::event::PollFlags::IN)];
    let wait = rustix::event::Timespec {
        tv_sec: secs,
        tv_nsec: 0,
    };
    loop {
        match rustix::event::poll(&mut ended, Some(&wait)) {
            Err(rustix::io::Errno::INTR) => continue,
            r => break r.unwrap() == 1,
        }
    }
}

/// Wait for the end of the fetcher `pid` (a process of the test, that
/// leaves by itself): an upper bound of 10 s only, the end is told by its
/// pidfd (none: it was reaped already).
pub(crate) fn wait_fetcher(pid: u32) {
    let pid = rustix::process::Pid::from_raw(pid as i32).unwrap();
    let Ok(fd) = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) else {
        return;
    };
    assert!(pidfd_ended(&fd, 10));
}

/// A service with the fetcher as its origin, and a client that does
/// not mark the registry of `s` insecure (nor does the fetcher's
/// registries.conf).
fn service_with_strict_origin(s: &Setup) -> velarx_core::services::ImageService {
    let (spawner, _socket) = registry_spawner_with(s.dir.path(), &s.env.host, false);
    let origin = velarx_content::list::RegistryOrigin::with_shared(spawner, &Default::default());
    velarx_core::services::ImageService::new(
        s.env.db.clone(),
        s.env.store.clone(),
        s.dir.path().join("staging"),
        velarx_storage::VerityMode::Off,
    )
    .unwrap()
    .with_pull_config(PullConfig {
        worker_path: Some(registry_bin().into()),
        ..PullConfig::default()
    })
    .unwrap()
    .with_resolver(client_for(&["127.0.0.1:1"]))
    .with_origin(origin)
}

/// Say how the staged layer was reached by its pull (`tls_verify`,
/// `creds`: what `layer.json` keeps).
fn set_reach(s: &Setup, tls_verify: Option<bool>, creds: Option<bool>) {
    let path = s.env.area().layer_dir(&s.layer).join("layer.json");
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    if let Some(t) = tls_verify {
        v["reach"]["tls_verify"] = t.into();
    }
    if let Some(c) = creds {
        v["reach"]["creds"] = c.into();
    }
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
}

/// A layer pulled with `--tls-verify=false` from a registry that
/// registries.conf does not mark insecure is completed by the registry
/// fetcher on the asker's word: this process opens no connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_layer_pulled_without_tls_verification_goes_to_the_fetcher() {
    let s = setup(0).await;
    set_reach(&s, Some(false), None);
    let service = service_with_strict_origin(&s);
    let image = format!("{}/test:latest", s.env.host);
    let (before, mine) = (
        s.env.reg.ranged.load(Ordering::SeqCst),
        s.env.reg.mine.load(Ordering::SeqCst),
    );
    let stats = service.complete_image(&image).await.unwrap();
    assert!(stats.from("registry").1 >= 2);
    assert!(s.env.reg.ranged.load(Ordering::SeqCst) > before);
    assert_eq!(
        s.env.reg.mine.load(Ordering::SeqCst),
        mine,
        "a request of this process"
    );
    assert!(service.get(&image).await.is_ok());
}

/// A layer pulled with credentials needs them again, and the registry
/// fetcher makes the requests with the ones of the command.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_layer_pulled_with_creds_is_completed_by_the_fetcher() {
    let s = setup(0).await;
    set_reach(&s, Some(false), Some(true));
    let service = service_with_strict_origin(&s);
    let image = format!("{}/test:latest", s.env.host);
    let before = s.env.reg.requests.load(Ordering::SeqCst);
    let err = service.complete_image(&image).await.unwrap_err();
    assert!(err.to_string().contains("--creds"), "{err}");
    assert_eq!(s.env.reg.requests.load(Ordering::SeqCst), before);
    let mine = s.env.reg.mine.load(Ordering::SeqCst);
    let access = velarx_registry::auth::RegistryAccess {
        creds: Some(velarx_registry::Credentials::parse_creds("u:p").unwrap()),
        ..Default::default()
    };
    service.complete_image_with(&image, access).await.unwrap();
    assert_eq!(s.env.reg.mine.load(Ordering::SeqCst), mine);
    assert!(service.get(&image).await.is_ok());
}

/// The completion names where credentials would go: the endpoints of the
/// layers pulled with some, nothing for an image whose layers were pulled
/// without.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_the_scopes_of_a_completion_are_those_of_the_layers_that_need_creds() {
    let s = setup(0).await;
    let service = service_with_strict_origin(&s);
    let image = format!("{}/test:latest", s.env.host);
    assert!(service.credential_scopes(&image).await.unwrap().is_empty());
    set_reach(&s, None, Some(true));
    let scopes = service.credential_scopes(&image).await.unwrap();
    assert_eq!(scopes, [format!("{}/test", s.env.host)]);
}

/// A pull service whose requests to the registry are made by a fetcher
/// process started on demand: the service has the client of the environment
/// and no way to reach the registry otherwise.
fn pull_service_via_fetcher(e: &Env) -> (velarx_core::services::ImageService, PathBuf) {
    let dir = e._tmp.path().to_path_buf();
    let (spawner, _) = registry_spawner(&dir, &e.host);
    let origin = velarx_content::list::RegistryOrigin::with_shared(spawner, &Default::default());
    let service = velarx_core::services::ImageService::new(
        e.db.clone(),
        e.store.clone(),
        e.staging.clone(),
        velarx_storage::VerityMode::Off,
    )
    .unwrap()
    .with_pull_config(PullConfig {
        worker_path: Some(registry_bin().into()),
        ..PullConfig::default()
    })
    .unwrap()
    .with_resolver(client_for(&[&e.host]))
    .with_origin(origin);
    (service, dir)
}

async fn pulled(
    service: &velarx_core::services::ImageService,
    e: &Env,
    lazy: bool,
) -> velarx_core::services::PullResult {
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let image = format!("{}/test:latest", e.host);
    service
        .pull_with(
            &image,
            lazy,
            &velarx_core::services::PullOptions::default(),
            tx,
        )
        .await
        .unwrap()
}

/// A pull gets the manifest, the configuration and every layer, whole or in
/// ranges, from the fetcher: no request is made on a connection of
/// the process that pulls, and the layers pass the checks of the pull.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_pull_gets_everything_from_the_registry_fetcher() {
    for chunked in [false, true] {
        let e = env().await;
        let built = if chunked {
            build_chunked(&sample())
        } else {
            build_gzip(&sample())
        };
        e.publish(&[&built], &[if chunked { ZSTD } else { GZIP }]);
        let (service, _) = pull_service_via_fetcher(&e);
        let result = pulled(&service, &e, false).await;
        assert!(service.get(&result.id).await.is_ok());
        assert!(e.store.contains(&vid(&big())), "chunked: {chunked}");
        assert!(e.store.contains(&vid(b"hello\n")), "chunked: {chunked}");
        assert_eq!(
            e.reg.mine.load(Ordering::SeqCst),
            0,
            "the fetcher makes the requests (chunked: {chunked})"
        );
        assert!(e.reg.requests.load(Ordering::SeqCst) > 0);
        let layer = e.db.get_layer(&built.key()).await.unwrap();
        assert_eq!(layer.status, "ready");
        // (a layer of a table of contents has no diff id of its own)
        assert_eq!(
            layer.diff_id.as_ref(),
            (!built.key().is_toc()).then_some(&built.diff_id)
        );
        let before = e.reg.requests.load(Ordering::SeqCst);
        pulled(&service, &e, false).await;
        assert!(e.reg.requests.load(Ordering::SeqCst) <= before + 1);
    }
}

/// Through the fetcher as in the process: a registry that
/// refuses the ranges gives the blob whole as the transport of the table's
/// ranges, and the layer is the layer of its table; one that
/// answers them with other bytes than the TOC says is refused, and nothing
/// is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_the_fetcher_tells_a_contradiction_from_a_refusal() {
    let built = build_chunked(&sample());
    let e = env().await;
    e.publish(&[&built], &[ZSTD]);
    *e.reg.mode.lock().unwrap() = RangeMode::Refuse;
    let (service, _) = pull_service_via_fetcher(&e);
    let result = pulled(&service, &e, false).await;
    assert_eq!(result.stats.layers.len(), 1);
    assert!(e.db.get_layer(&built.key()).await.is_ok());
    assert!(e.db.get_layer(&built.whole()).await.is_err());

    let e = env().await;
    e.publish(&[&built], &[ZSTD]);
    *e.reg.mode.lock().unwrap() = RangeMode::Lie;
    let (service, _) = pull_service_via_fetcher(&e);
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let err = service
        .pull_with(
            &format!("{}/test:latest", e.host),
            false,
            &velarx_core::services::PullOptions::default(),
            tx,
        )
        .await
        .expect_err("other bytes for the ranges");
    assert!(velarx_content::pull::chunked::refuses(&err), "{err}");
    assert!(e.db.list_layers().await.unwrap().is_empty());
}

/// A lazy pull takes the tables of contents of its layers from the
/// registry fetcher (`Probe`), and nothing of the image on a connection of
/// the process that pulls.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_lazy_pull_gets_its_tables_from_the_registry_fetcher() {
    let e = env().await;
    let zst = build_chunked(&sample());
    e.publish(&[&zst], &[ZSTD]);
    let (service, _) = pull_service_via_fetcher(&e);
    let result = pulled(&service, &e, true).await;
    assert!(service.get(&result.id).await.is_err(), "being pulled");
    assert!(e.db.get_layer(&zst.key()).await.is_err());
    assert!(e.area().layer(&zst.key()).unwrap().is_some());
    assert_eq!(e.reg.mine.load(Ordering::SeqCst), 0);
}

/// The credentials of the request go to the fetcher, which makes
/// the requests: the pulling process opens no connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_pull_with_credentials_of_its_own_uses_the_registry_fetcher() {
    let e = env().await;
    e.publish(&[&build_gzip(&sample())], &[GZIP]);
    let (service, _) = pull_service_via_fetcher(&e);
    let access = velarx_registry::auth::RegistryAccess {
        creds: Some(velarx_registry::auth::Credentials::basic("user", "secret")),
        ..Default::default()
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let options = velarx_core::services::PullOptions {
        access,
        ..Default::default()
    };
    service
        .pull_with(&format!("{}/test:latest", e.host), false, &options, tx)
        .await
        .unwrap();
    assert!(e.reg.requests.load(Ordering::SeqCst) > 0);
    assert_eq!(e.reg.mine.load(Ordering::SeqCst), 0);
}

/// What the fetcher is not told fails the fetch with a reason instead of
/// hanging or serving anything: a call before the scope, a layer it was not
/// told of.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_the_fetcher_refuses_what_it_cannot_serve() {
    use velarx_content::fetcher::fetch::{FetcherError, Urgency};
    use velarx_content::fetcher::fetch_client::CallError;
    let s = setup(0).await;
    let (spawner, _socket) = registry_spawner(s.dir.path(), &s.env.host);
    let origin = velarx_content::list::RegistryOrigin::with_shared(spawner, &Default::default());
    let mut conn = origin.connect().await.unwrap();
    // the error of a call, from its first reply
    async fn refusal(
        r: Result<
            velarx_content::fetcher::fetch_client::Replies<
                '_,
                velarx_content::fetcher::fetch::FetchReply,
            >,
            CallError,
        >,
    ) -> CallError {
        let mut replies = match r {
            Err(e) => return e,
            Ok(r) => r,
        };
        loop {
            match replies.event().await {
                Err(e) => return e,
                Ok(None) => panic!("the call was answered"),
                Ok(Some(_)) => {}
            }
        }
    }
    let e = refusal(
        conn.fetch(
            &s.layer.to_string(),
            &[],
            Urgency::Wait,
            (&[], Vec::new()),
            false,
        )
        .await,
    )
    .await;
    assert!(
        matches!(e, CallError::Fetcher(FetcherError::InvalidArgument { .. })),
        "{e:?}"
    );
    let mut conn = origin.connect().await.unwrap();
    conn.open(velarx_content::fetcher::fetch_client::Scoping {
        source: Some(&format!("{}/test", s.env.host)),
        tls_verify: Some(false),
        ..velarx_content::fetcher::fetch_client::Scoping::bare(std::time::Duration::from_secs(60))
    })
    .await
    .unwrap();
    let e = refusal(
        conn.fetch(
            &s.layer.to_string(),
            &[sha(b"x").to_string()],
            Urgency::Wait,
            (&[], Vec::new()),
            false,
        )
        .await,
    )
    .await;
    assert!(
        matches!(e, CallError::Fetcher(FetcherError::InvalidArgument { .. })),
        "{e:?}"
    );
}

/// The fetcher of a configuration: one process for every connection made
/// to it, which outlives the one that started it while any is open, and
/// leaves when the last one is closed, its socket with it.  An engine holds nothing
/// of its own between its needs: a fetcher its calls are over with
/// leaves while the engine lives, and the next need starts another one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_the_shared_fetcher_lives_as_long_as_its_connections() {
    let base = tempfile::tempdir().unwrap();
    let (engine, socket) = registry_spawner(base.path(), "localhost:1");
    let gone_of = |pid: u32| {
        let ended = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(pid as i32).unwrap(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap();
        move |wait: i64| pidfd_ended(&ended, wait)
    };
    // the calls of the engine: once they are over, nothing holds it (10 s:
    // an upper bound only)
    let origin =
        velarx_content::list::RegistryOrigin::with_shared(engine.clone(), &Default::default());
    origin.connect().await.unwrap().get_info().await.unwrap();
    let first = engine.started().expect("the engine started it");
    tokio::task::spawn_blocking(move || wait_fetcher(first))
        .await
        .unwrap();
    assert!(!socket.exists(), "it took its socket away");
    // connections of three holders (the engine's commands): one process
    // for them all, which leaves with the last of them
    let mut held = Vec::new();
    for _ in 0..3 {
        let mut conn = origin.connect().await.unwrap();
        conn.get_info().await.unwrap();
        held.push(conn);
    }
    let pid = engine.started().expect("the engine started it");
    assert_ne!(pid, first);
    assert!(socket.exists());
    assert_eq!(engine.started(), Some(pid), "no other one was started");
    let gone = gone_of(pid);
    drop(origin);
    drop(engine);
    let last = held.pop().unwrap();
    drop(held);
    assert!(!gone(0), "a connection holds it");
    // the last one goes: it leaves at once (10 s: an upper bound only)
    drop(last);
    let left = tokio::task::spawn_blocking(move || gone(10)).await.unwrap();
    assert!(left, "the fetcher did not leave with its last connection");
    assert!(!socket.exists(), "it took its socket away");
    let (next, _) = registry_spawner(base.path(), "localhost:1");
    let again =
        velarx_content::list::RegistryOrigin::with_shared(next.clone(), &Default::default());
    again.connect().await.unwrap().get_info().await.unwrap();
    assert!(next.started().is_some_and(|p| p != first && p != pid));
}
