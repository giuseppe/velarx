// SPDX-License-Identifier: Apache-2.0
//! The files a fetcher staged reach a store service by the typed interface:
//! the engine verifies each once and hands the file itself over (event
//! `staged` of `org.velarx.StorageFeed`), and the service links it into its
//! store: no byte is written to a place of the service and none is copied by
//! it.  And a service that dies while the files are handed over fails the
//! pull with a typed error, with nothing named in its store.

use std::sync::Arc;
use std::time::Duration;
use velarx_content::layer::writer::{write_layer, Compression};
use velarx_content::pull::Limits;
use velarx_db::Database;
use velarx_graph::conformance::registry::Registry;
use velarx_graph::{
    CheckId, Checked, ContentFeed, DriverErrorKind, FeedLayer, Identities, LayerRef, PullFeed,
    Settled, Settlement, StorageDriver, Verdict,
};
use velarx_storage_client::{Link, Options, VarlinkDriver};
use velarx_storage_server::{Config, Running, Server};
use velarx_types::digest::Algorithm;
use velarx_types::{LayerKey, OciDescriptor};

const SMALL: usize = 40;

fn tar() -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    let mut dir = tar::Header::new_gnu();
    dir.set_entry_type(tar::EntryType::Directory);
    dir.set_mode(0o755);
    dir.set_size(0);
    b.append_data(&mut dir, "d/", &b""[..]).unwrap();
    for i in 0..SMALL {
        let content = format!("file number {i} of the layer, with a content of its own\n");
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o644);
        h.set_size(content.len() as u64);
        b.append_data(&mut h, format!("d/f{i}"), content.as_bytes())
            .unwrap();
    }
    for i in 0..2 {
        let content: Vec<u8> = (0..(1u32 << 20) + 17)
            .map(|n| (n.wrapping_mul(2654435761).wrapping_add(i as u32 * 7919) >> 13) as u8)
            .collect();
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o644);
        h.set_size(content.len() as u64);
        b.append_data(&mut h, format!("d/big{i}"), &content[..])
            .unwrap();
    }
    b.into_inner().unwrap()
}

struct Setup {
    dir: tempfile::TempDir,
    server: Arc<Server>,
    running: Option<Running>,
    socket: std::path::PathBuf,
    graph: std::path::PathBuf,
    driver: Arc<VarlinkDriver>,
    reg: Registry,
    layer: FeedLayer,
}

impl Drop for Setup {
    fn drop(&mut self) {
        // (the runtime of the server is not dropped on a thread of a runtime:
        // the test process ends)
        std::mem::forget(self.running.take());
        std::mem::forget(self.server.clone());
    }
}

fn config(dir: &std::path::Path) -> Config {
    Config {
        root: dir.join("server"),
        timeout: Duration::from_secs(30),
        decision: Duration::from_secs(120),
    }
}

async fn open(socket: std::path::PathBuf, graph: std::path::PathBuf) -> Arc<VarlinkDriver> {
    tokio::task::spawn_blocking(move || {
        VarlinkDriver::open(Options {
            link: Link {
                socket,
                timeout: Duration::from_secs(30),
            },
            graph_root: graph,
        })
    })
    .await
    .unwrap()
    .map(Arc::new)
    .unwrap()
}

async fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::new(config(dir.path())).unwrap();
    let socket = dir.path().join("s.sock");
    let running = server.listen(&socket).unwrap();
    let graph = dir.path().join("graph");
    std::fs::create_dir_all(&graph).unwrap();
    let driver = open(socket.clone(), graph.clone()).await;
    let reg = Registry::start().await;
    let mut blob = Vec::new();
    let w = write_layer(
        &tar()[..],
        Algorithm::Sha256,
        Compression::ZstdChunked,
        &mut blob,
    )
    .unwrap();
    let desc = OciDescriptor {
        media_type: w.media_type.to_string(),
        digest: w.digest,
        size: w.size as i64,
        annotations: w.annotations.into_iter().collect(),
    };
    reg.put(&w.digest.to_string(), blob);
    let layer = FeedLayer {
        key: LayerKey::expected(&desc),
        descriptor: desc,
        diff_id: w.diff_id,
        chain_id: w.diff_id,
        parent: None,
        stored: false,
    };
    Setup {
        dir,
        server,
        running: Some(running),
        socket,
        graph,
        driver,
        reg,
        layer,
    }
}

fn settled() -> Settled {
    Box::new(|_, _| {
        Ok(Settlement {
            identities: Identities::default(),
            verdict: Verdict::sealed(
                &CheckId::fresh(),
                Checked {
                    layer_keys: Vec::new(),
                    merged_id: None,
                    stored_erofs: Default::default(),
                    ours: Default::default(),
                },
            ),
        })
    })
}

async fn feed(s: &Setup, name: &str) -> Arc<dyn PullFeed> {
    let (staged, source) = s
        .reg
        .staged(
            &s.dir.path().join(name),
            std::slice::from_ref(&s.layer.descriptor),
        )
        .await;
    let db = Database::open(s.dir.path().join(format!("db-{name}")))
        .await
        .unwrap();
    Arc::new(
        ContentFeed::new(
            velarx_content::pull::net::Net::Offline,
            source,
            db,
            Limits::from_config(&velarx_config::PullConfig::default()),
        )
        .with_staged(staged),
    )
}

fn status(driver: &VarlinkDriver, name: &str) -> u64 {
    driver
        .status()
        .into_iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("no status line {name}"))
        .1
        .parse()
        .unwrap()
}

/// Every file of the layer reaches the service as a file the engine verified
/// and handed over, and the service has to copy none of them (its store is in
/// the same file system as the engine's staging here: it links the inodes).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pull_hands_every_file_over_and_nothing_is_copied() {
    let s = setup().await;
    let feed = feed(&s, "staging").await;
    let pulled = s
        .driver
        .pull(&feed, std::slice::from_ref(&s.layer), settled())
        .await
        .unwrap();
    let files = pulled.layers[0].files.len() as u64;
    assert!(files > SMALL as u64, "{files} files");
    let driver = s.driver.clone();
    let (handed, copied, copy_events) = tokio::task::spawn_blocking(move || {
        (
            status(&driver, "handed files"),
            status(&driver, "handed bytes copied"),
            status(&driver, "copy events"),
        )
    })
    .await
    .unwrap();
    assert_eq!(handed, files, "each file was handed over");
    assert_eq!(copied, 0, "the service linked every file: no byte copied");
    assert_eq!(copy_events, 0);
    let key = LayerRef {
        key: s.layer.key,
        diff_id: s.layer.diff_id,
        chain_id: s.layer.chain_id,
    };
    assert_eq!(
        s.driver.has_layers(&[key]).await.unwrap(),
        vec![true],
        "the layer is committed"
    );
}

/// The service dies while the files of a pull are on their way to it: the
/// pull fails with the error of a service that is gone, and when the service
/// is started again over its store, the layer is not in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_that_dies_while_the_files_are_handed_over_names_nothing() {
    // (what one pull asks of the registry: the death is at the last request,
    // when the files are fetched and on their way)
    let all = {
        let s = setup().await;
        let feed = feed(&s, "staging").await;
        s.driver
            .pull(&feed, std::slice::from_ref(&s.layer), settled())
            .await
            .unwrap();
        s.reg.requests().len()
    };
    let mut s = setup().await;
    let running = std::sync::Mutex::new(s.running.take());
    let (dead_tx, dead_rx) = std::sync::mpsc::channel::<()>();
    s.reg.at_request(all, move || {
        // (a thread of its own: the runtime of the server is not dropped on a
        // thread of this runtime)
        let running = running.lock().unwrap().take();
        std::thread::spawn(move || {
            drop(running);
            let _ = dead_tx.send(());
        });
    });
    let feed = feed(&s, "staging").await;
    let Err(error) = s
        .driver
        .pull(&feed, std::slice::from_ref(&s.layer), settled())
        .await
    else {
        panic!("the service died: the pull cannot have succeeded");
    };
    dead_rx.recv().unwrap();
    assert!(
        matches!(
            error.kind,
            DriverErrorKind::Unavailable | DriverErrorKind::Io(_)
        ) && error.to_string().contains("start the storage service"),
        "a typed error of a service that is gone: {error:?}"
    );
    // the service again, over its store: nothing was named
    let again = Server::new(config(s.dir.path())).unwrap();
    std::fs::remove_file(&s.socket).ok();
    let running = again.listen(&s.socket).unwrap();
    let driver = open(s.socket.clone(), s.graph.clone()).await;
    let key = LayerRef {
        key: s.layer.key,
        diff_id: s.layer.diff_id,
        chain_id: s.layer.chain_id,
    };
    assert_eq!(driver.has_layers(&[key]).await.unwrap(), vec![false]);
    std::mem::forget((running, again));
}
