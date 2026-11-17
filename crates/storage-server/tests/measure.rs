// SPDX-License-Identifier: Apache-2.0
//! How long it takes to prove a layer of many files by reading it back from
//! the server: the proof of a pull reads each object through `ReadObjects`.
//! Slow: run with `VELARX_SLOW_TESTS=1 cargo test -p velarx-storage-server
//! --test measure -- --nocapture`.

use std::sync::Arc;
use std::time::{Duration, Instant};
use velarx_content::layer::writer::{write_layer, Compression};
use velarx_content::pull::Limits;
use velarx_db::Database;
use velarx_graph::conformance::registry::Registry;
use velarx_graph::{
    prove_by_read_back, CheckId, Checked, ContentFeed, FeedLayer, Identities, PullFeed, Settled,
    Settlement, StorageDriver, Verdict,
};
use velarx_storage_client::{Link, Options, VarlinkDriver};
use velarx_storage_server::{Config, Server};
use velarx_types::digest::Algorithm;
use velarx_types::{LayerKey, OciDescriptor};

fn tar_of(small: usize, big: usize) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    let mut dir = tar::Header::new_gnu();
    dir.set_entry_type(tar::EntryType::Directory);
    dir.set_mode(0o755);
    dir.set_size(0);
    b.append_data(&mut dir, "d/", &b""[..]).unwrap();
    for i in 0..small {
        let content = format!("file number {i} of the layer, with a content of its own\n");
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o644);
        h.set_size(content.len() as u64);
        b.append_data(&mut h, format!("d/f{i}"), content.as_bytes())
            .unwrap();
    }
    for i in 0..big {
        let content: Vec<u8> = (0..(1u32 << 20))
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

async fn measure(small: usize) {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::new(Config {
        root: dir.path().join("server"),
        timeout: Duration::from_secs(120),
        decision: Duration::from_secs(300),
    })
    .unwrap();
    let socket = dir.path().join("s.sock");
    let running = server.listen(&socket).unwrap();
    let graph = dir.path().join("graph");
    std::fs::create_dir_all(&graph).unwrap();
    let driver: Arc<dyn StorageDriver> = {
        let (socket, graph) = (socket.clone(), graph.clone());
        Arc::new(
            tokio::task::spawn_blocking(move || {
                VarlinkDriver::open(Options {
                    link: Link {
                        socket,
                        timeout: Duration::from_secs(120),
                    },
                    graph_root: graph,
                })
            })
            .await
            .unwrap()
            .unwrap(),
        )
    };
    let tar = tar_of(small, 3);
    let reg = Registry::start().await;
    let mut blob = Vec::new();
    let w = write_layer(
        &tar[..],
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
    let (staged, source) = reg
        .staged(
            &dir.path().join("staging"),
            std::slice::from_ref(&layer.descriptor),
        )
        .await;
    let db = Database::open(dir.path().join("db")).await.unwrap();
    let feed: Arc<dyn PullFeed> = Arc::new(
        ContentFeed::new(
            velarx_content::pull::net::Net::Offline,
            source,
            db,
            Limits::from_config(&velarx_config::PullConfig::default()),
        )
        .with_staged(staged),
    );
    let settled: Settled = Box::new(|_| {
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
    });
    let started = Instant::now();
    let pulled = driver.pull(&feed, &[layer], settled).await.unwrap();
    let pull = started.elapsed();
    // the proof again, from the committed layer: one read for each object
    let l = pulled.layers[0].clone();
    let objects = l.done.files.len();
    let d = driver.clone();
    let started = Instant::now();
    tokio::task::spawn_blocking(move || prove_by_read_back(d, &l))
        .await
        .unwrap()
        .unwrap();
    let proof = started.elapsed();
    println!(
        "{small} small files + 3 of 1 MiB: pull with its proof {:.2} s, the proof alone {:.2} s over {objects} objects ({:.0} us each)",
        pull.as_secs_f64(),
        proof.as_secs_f64(),
        proof.as_micros() as f64 / objects as f64
    );
    std::mem::forget((running, server));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_proof_of_a_layer_of_many_files() {
    if std::env::var("VELARX_SLOW_TESTS").is_err() {
        eprintln!("skipped: VELARX_SLOW_TESTS=1 runs it");
        return;
    }
    for small in [5_000, 20_000] {
        measure(small).await;
    }
}
