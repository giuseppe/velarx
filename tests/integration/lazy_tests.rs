// SPDX-License-Identifier: Apache-2.0
//! Lazy pulls: metadata only, in the staging area and not in the store, files
//! on demand through the planner into its pool, and a completion that proves
//! each layer against the diff id and commits it to the store when it is
//! complete, the image with the last.

use crate::common::*;
use std::io::Read;
use std::sync::atomic::Ordering;
use std::time::Duration;
use velarx_content::layer::reproduce::StoredLayer;
use velarx_fuse::LazyFileFetcher;

fn data_of(name: &str) -> Vec<u8> {
    sample()
        .into_iter()
        .find_map(|i| match i {
            Item::File { name: n, data, .. } if n == name => Some(data),
            _ => None,
        })
        .unwrap()
}

fn lazy_requests(e: &Env) -> usize {
    e.reg.requests.load(Ordering::SeqCst)
}

async fn lazy_env() -> (Env, velarx_db::LayerKey, Built) {
    // (the requests are counted: no window fetched behind the reads)
    let e = env_with(velarx_config::PullConfig {
        lazy_window_files: 0,
        ..Default::default()
    })
    .await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    (e, layer.key(), layer)
}

/// The staged layer, as the staging area has it.
fn staged(e: &Env, key: &velarx_db::LayerKey) -> velarx_content::pull::staged::StagedLayer {
    e.area().layer(key).unwrap().expect("the layer is staged")
}

#[tokio::test]
async fn test_lazy_pull_stages_metadata_and_fetches_files_on_demand() {
    let (e, layer_digest, layer) = lazy_env().await;
    let result = e.pull_lazy().await.unwrap();
    assert!(result.stats.from("registry").0 < layer.blob.len() as u64 / 2);
    // The store holds only complete layers and images: nothing of the pull
    // is in it, the pull is in the staging area.
    let err = e.service.get(&result.id).await.unwrap_err();
    assert!(matches!(err, velarx_types::ImageError::Pulling(_)), "{err}");
    assert!(e.service.list().await.unwrap().is_empty());
    assert!(e.db.get_layer(&layer_digest).await.is_err());
    assert!(!e.db.has_layer(&layer_digest).await.unwrap());
    let pulls = e.service.pulls().await.unwrap();
    assert_eq!(pulls.len(), 1);
    assert_eq!(pulls[0].id, result.id);
    assert!(pulls[0].names[0].ends_with("/test:latest"));
    let record = staged(&e, &layer_digest).record();
    assert_eq!(record.status, "lazy");
    assert_eq!(record.diff_id, None);
    // (the tar-split is the completion's)
    assert!(staged(&e, &layer_digest).tarsplit().unwrap().is_empty());
    assert!(!e.store.contains(&vid(b"hello\n")));

    let toc = staged_toc(&staged(&e, &layer_digest));
    assert_eq!(
        toc.get_file_chunks("usr/big").len(),
        100_000usize.div_ceil(16 * 1024)
    );
    assert_eq!(
        toc.find_by_name("etc/link").unwrap().link_name.as_deref(),
        Some("small")
    );

    let before = lazy_requests(&e);
    let path = e
        .service
        .fetch_lazy_file(&vid(b"hello\n"), &layer_digest)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"hello\n");
    assert!(lazy_requests(&e) > before);
    // it is in the staging of its layer, sealed by its name, not in the store
    assert!(path.starts_with(e.area().layer_files(&layer_digest)));
    assert!(!e.store.contains(&vid(b"hello\n")));
    for name in ["usr/big", "usr/holes"] {
        let data = data_of(name);
        let path = e
            .service
            .fetch_lazy_file(&vid(&data), &layer_digest)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), data, "{name}");
    }
    let before = lazy_requests(&e);
    e.service
        .fetch_lazy_file(&vid(b"hello\n"), &layer_digest)
        .await
        .unwrap();
    assert_eq!(lazy_requests(&e), before);
    assert_eq!(e.staged_leftovers(), 0);
    assert!(e.db.get_layer(&layer_digest).await.is_err());
    assert!(e
        .db
        .get_layer_file_refs(&layer_digest)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn test_unknown_files_and_complete_layers_are_not_fetched() {
    let (e, layer_digest, _) = lazy_env().await;
    e.pull_lazy().await.unwrap();
    assert!(e
        .service
        .fetch_lazy_file(&vid(b"not in the layer"), &layer_digest)
        .await
        .is_err());
    assert!(e
        .service
        .fetch_lazy_file("sha256:short", &layer_digest)
        .await
        .is_err());
    assert!(e
        .service
        .fetch_lazy_file(
            &vid(b"hello\n"),
            &velarx_db::LayerKey::Whole(sha(b"no such layer")),
        )
        .await
        .is_err());
}

#[tokio::test]
async fn test_completion_proves_the_layer_and_commits_it() {
    let (e, layer_digest, layer) = lazy_env().await;
    let result = e.pull_lazy().await.unwrap();
    e.service
        .fetch_lazy_file(&vid(b"hello\n"), &layer_digest)
        .await
        .unwrap();
    let image_ref = format!("{}/test:latest", e.host);
    let stats = e.service.complete_image(&image_ref).await.unwrap();
    assert!(stats.from("registry").1 >= 2);
    assert!(e.service.get(&result.id).await.is_ok());
    assert_eq!(e.db.get_layer(&layer_digest).await.unwrap().status, "ready");
    for name in ["usr/big", "usr/holes"] {
        assert!(e.store.contains(&vid(&data_of(name))));
    }
    // The staging area has nothing left of it: the files were linked (the
    // same inodes), the pull and its layer are in the store.
    assert!(e.pooled().is_empty(), "{:?}", e.pooled());
    assert!(e.area().pulls().is_empty());
    assert!(e.area().layer_keys().is_empty());
    assert!(e.service.pulls().await.unwrap().is_empty());
    // The EROFS image of the layer is the store's.
    let erofs = velarx_fuse::composefs::layer_image_path(e.store.root(), &layer_digest.file_stem());
    assert!(erofs.is_file());
    // The tar-split rebuilds the stream of the diff id.
    let stored = StoredLayer::load_expecting(
        &e.db,
        &layer_digest,
        Some(layer.diff_id.alg()),
        Some(&layer.diff_id),
    )
    .await
    .unwrap();
    let mut tar = Vec::new();
    stored
        .verified_stream(e.store.clone())
        .unwrap()
        .read_to_end(&mut tar)
        .unwrap();
    assert_eq!(sha(&tar), layer.diff_id);
    let again = e.service.complete_image(&image_ref).await.unwrap();
    assert_eq!(again.from("registry").1, 0);
    assert_eq!(e.staged_leftovers(), 0);
}

/// The chunks of the blob were changed after the lazy pull.
#[tokio::test]
async fn test_completion_refuses_a_blob_that_changed() {
    let (e, layer_digest, layer) = lazy_env().await;
    e.pull_lazy().await.unwrap();
    {
        let mut blobs = e.reg.blobs.lock().unwrap();
        let blob = blobs.get_mut(&sha(&layer.blob).to_string()).unwrap();
        for b in blob.iter_mut().skip(1000).take(64) {
            *b ^= 0x55;
        }
    }
    let image_ref = format!("{}/test:latest", e.host);
    assert!(e.service.complete_image(&image_ref).await.is_err());
    // nothing was committed: the layer is staged, the image is being pulled
    assert!(e.db.get_layer(&layer_digest).await.is_err());
    assert!(matches!(
        e.service.get(&image_ref).await,
        Err(velarx_types::ImageError::Pulling(_))
    ));
    assert!(e.area().layer(&layer_digest).unwrap().is_some());
    assert_eq!(e.staged_leftovers(), 0);
}

/// A layer of a table of contents is verified by that table and claims no
/// diff id: a configuration that names another one does not stop the
/// completion, and the stream of the layer is what tells when it is read
/// back against that diff id.
#[tokio::test]
async fn test_a_toc_layer_claims_no_diff_id_and_its_stream_is_checked_when_read() {
    let (e, layer_digest, layer) = lazy_env().await;
    let result = e.pull_lazy().await.unwrap();
    let (right, wrong) = (layer.diff_id.to_string(), sha(b"another layer"));
    let json = e.area().image_dir(&result.id).join("pull.json");
    let text = std::fs::read_to_string(&json).unwrap();
    assert!(text.contains(&right));
    std::fs::write(&json, text.replace(&right, &wrong.to_string())).unwrap();
    let image_ref = format!("{}/test:latest", e.host);
    e.service.complete_image(&image_ref).await.unwrap();
    assert_eq!(e.db.get_layer(&layer_digest).await.unwrap().diff_id, None);
    let stored = StoredLayer::load_expecting(&e.db, &layer_digest, Some(wrong.alg()), Some(&wrong))
        .await
        .unwrap();
    let mut tar = Vec::new();
    let read = stored
        .verified_stream(e.store.clone())
        .unwrap()
        .read_to_end(&mut tar);
    assert_eq!(
        read.unwrap_err().kind(),
        std::io::ErrorKind::InvalidData,
        "the stream is not the diff id of the configuration"
    );
}

#[tokio::test]
async fn test_a_toc_that_lies_about_a_file_is_caught_when_the_file_is_fetched() {
    // a layer of its own: the TOC of a layer digest is parsed once for the
    // process, and the one changed here is not that of the other tests
    let e = env().await;
    let mut items = sample();
    items.push(Item::File {
        name: "etc/lie",
        data: b"a layer of this test".to_vec(),
        chunk: 4096,
    });
    let layer = build_chunked(&items);
    e.publish(&[&layer], &[ZSTD]);
    let layer_digest = layer.key();
    e.pull_lazy().await.unwrap();
    let mut toc = staged_toc(&staged(&e, &layer_digest));
    // (no sha256: nothing checks the file before its fs-verity digest)
    let lie = vid(b"something else");
    for entry in toc.entries.iter_mut().filter(|e| e.name == "etc/small") {
        entry.fsverity = velarx_storage::to_toc(&lie);
        entry.digest = None;
        entry.chunk_digest = None;
    }
    restage_toc(&e, &layer_digest, &toc);
    assert!(e
        .service
        .fetch_lazy_file(&lie, &layer_digest)
        .await
        .is_err());
    assert!(!e.store.contains(&lie));
    assert!(!e.store.contains(&vid(b"hello\n")));
    assert_eq!(e.staged_leftovers(), 0);
}

/// A table of contents without the fs-verity digest of every file is refused,
/// naming the layer and the file: it is not pulled lazily, nor whole.
#[tokio::test]
async fn test_a_lazy_pull_of_a_table_without_file_digests_is_refused() {
    let e = env().await;
    let plain = build_chunked_plain(&sample());
    e.publish(&[&plain], &[ZSTD]);
    let before = e.stored().await;
    let refused = e.pull_lazy().await.unwrap_err().to_string();
    assert!(refused.contains(&sha(&plain.blob).to_string()), "{refused}");
    assert!(refused.contains("no fs-verity digest for `"), "{refused}");
    assert_eq!(e.stored().await, before);
    assert!(e.area().pulls().is_empty());
    assert_eq!(e.staged_leftovers(), 0);
}

/// A lazy pull of an image with a layer that has no table of contents is
/// refused, naming the layer and why, before anything of it exists: no layer
/// is pulled whole instead.
#[tokio::test]
async fn test_a_lazy_pull_of_an_image_with_a_layer_without_a_table_is_refused() {
    let e = env().await;
    let first = build_gzip(&sample());
    let second = build_chunked(&sample()[..2]);
    e.publish(&[&first, &second], &[GZIP, ZSTD]);
    let refused = e.pull_lazy().await;
    let Err(velarx_types::ImageError::NotLazy { image, layers }) = refused else {
        panic!("{refused:?}");
    };
    assert!(image.ends_with("/test:latest"), "{image}");
    assert_eq!(layers.len(), 1, "{layers:?}");
    assert_eq!(
        (
            layers[0].index,
            layers[0].reason.word(),
            layers[0].media_type.as_str()
        ),
        (0, "no_toc", GZIP)
    );
    assert_eq!(
        layers[0].digest,
        Digest::of(velarx_types::digest::Algorithm::Sha256, &first.blob).to_string()
    );
    assert!(e.db.get_layer(&first.key()).await.is_err());
    assert!(e.db.get_layer(&second.key()).await.is_err());
    assert!(e.area().pulls().is_empty());
    assert!(e.area().layer(&second.key()).unwrap().is_none());
    assert_eq!(e.staged_leftovers(), 0);
    assert!(!e.store.contains(&vid(&data_of("usr/big"))));
}

#[tokio::test]
async fn test_a_full_pull_completes_a_lazy_image_and_a_lazy_pull_of_a_full_one_does_nothing() {
    let (e, layer_digest, _) = lazy_env().await;
    let lazy = e.pull_lazy().await.unwrap();
    let full = e.pull().await.unwrap();
    assert_eq!(lazy.id, full.id);
    assert!(e.service.get(&full.id).await.is_ok());
    assert!(e.area().pulls().is_empty());
    assert_eq!(e.db.get_layer(&layer_digest).await.unwrap().status, "ready");
    let before = lazy_requests(&e);
    e.pull_lazy().await.unwrap();
    assert_eq!(lazy_requests(&e), before, "no blob is requested");
    assert!(e.service.get(&full.id).await.is_ok());
    assert!(e.area().pulls().is_empty());
}

#[tokio::test]
async fn test_concurrent_requests_for_a_file_download_it_once() {
    let (e, layer_digest, _) = lazy_env().await;
    e.pull_lazy().await.unwrap();
    let wanted = vid(&data_of("usr/big"));
    let before = e.reg.ranged.load(Ordering::SeqCst);
    let results = futures::future::join_all(
        (0..8).map(|_| e.service.fetch_lazy_file(&wanted, &layer_digest)),
    )
    .await;
    assert!(results.iter().all(|r| r.is_ok()));
    let used = e.reg.ranged.load(Ordering::SeqCst) - before;
    assert!(used >= 1);
    let single = {
        let (e2, d2, _) = lazy_env().await;
        e2.pull_lazy().await.unwrap();
        let b = e2.reg.ranged.load(Ordering::SeqCst);
        e2.service.fetch_lazy_file(&wanted, &d2).await.unwrap();
        e2.reg.ranged.load(Ordering::SeqCst) - b
    };
    assert_eq!(used, single);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_the_fuse_fetcher_interface() {
    let (e, layer_digest, _) = lazy_env().await;
    e.pull_lazy().await.unwrap();
    let fetcher: &dyn LazyFileFetcher = &*e.service;
    let file = vid(b"hello\n");
    let layer = layer_digest.to_string();
    // A FUSE thread is a plain thread.
    let path = std::thread::scope(|s| {
        s.spawn(|| fetcher.fetch_file_blocking(&file, &layer, Some(Duration::from_secs(10))))
            .join()
            .unwrap()
    })
    .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), b"hello\n");
    assert!(fetcher
        .fetch_file_blocking(
            &vid(b"nothing"),
            &layer_digest.to_string(),
            Some(Duration::from_secs(10)),
        )
        .is_err());
}

/// Complete files in the staging of the (one) staged layer: the contents
/// of these files of the sample, as a container's fetches leave them.
fn stage(e: &Env, names: &[&str]) {
    let area = e.area();
    area.create().unwrap();
    let pool = velarx_storage::FileStore::new(area.layer_files(&area.layer_keys()[0]))
        .unwrap()
        .with_verity(velarx_storage::VerityMode::On);
    for name in names {
        pool.put(velarx_types::digest::Algorithm::Sha256, &data_of(name))
            .unwrap();
    }
}

const ALL: [&str; 3] = ["etc/small", "usr/big", "usr/holes"];

fn linked(e: &Env) -> Vec<&'static str> {
    ALL.into_iter()
        .filter(|n| e.store.contains(&vid(&data_of(n))))
        .collect()
}

/// What the completion finds missing is retrieved into the pool; the files
/// the pool had are not fetched again.  The layer is committed with the
/// link of the same files.
#[tokio::test]
async fn test_completion_retrieves_what_the_pool_lacks() {
    let (e, layer_digest, _) = lazy_env().await;
    let result = e.pull_lazy().await.unwrap();
    stage(&e, &["usr/big"]);
    let before = e.reg.ranged.load(Ordering::SeqCst);
    let image_ref = format!("{}/test:latest", e.host);
    e.service.complete_image(&image_ref).await.unwrap();
    assert!(e.reg.ranged.load(Ordering::SeqCst) > before);
    assert!(e.service.get(&result.id).await.is_ok());
    assert_eq!(e.db.get_layer(&layer_digest).await.unwrap().status, "ready");
    assert_eq!(linked(&e), ALL);
    // (what was retrieved was in the pool, linked into the store: no copy)
    assert!(e.pooled().is_empty());
    assert_eq!(e.staged_leftovers(), 0);
    assert_eq!(
        e.service
            .complete_image(&image_ref)
            .await
            .unwrap()
            .from("registry")
            .1,
        0
    );
}

/// A retrieval that fails: nothing was linked, whatever the pool had, and
/// the image is still being pulled.
#[tokio::test]
async fn test_a_failed_retrieval_links_nothing() {
    let (e, layer_digest, layer) = lazy_env().await;
    let result = e.pull_lazy().await.unwrap();
    let toc = staged_toc(&staged(&e, &layer_digest));
    // the registry serves a damaged usr/holes: the one file that is missing
    let at = toc
        .entries
        .iter()
        .find(|t| t.name == "usr/holes")
        .unwrap()
        .offset as usize;
    {
        let mut blobs = e.reg.blobs.lock().unwrap();
        let blob = blobs.get_mut(&sha(&layer.blob).to_string()).unwrap();
        for b in blob.iter_mut().skip(at + 8).take(16) {
            *b ^= 0x55;
        }
    }
    stage(&e, &["etc/small", "usr/big"]);
    let image_ref = format!("{}/test:latest", e.host);
    assert!(e.service.complete_image(&image_ref).await.is_err());
    assert_eq!(linked(&e), Vec::<&str>::new(), "nothing is linked");
    assert!(e.service.get(&result.id).await.is_err());
    assert!(e.db.get_layer(&layer_digest).await.is_err());
    assert_eq!(e.staged_leftovers(), 0);
    assert_eq!(e.pooled().len(), 2);
}

/// A crash in the middle of a download leaves no committed partial layer,
/// and the next completion resumes from the pool.
#[tokio::test]
async fn test_a_completion_that_is_interrupted_is_resumed_from_the_pool() {
    let (e, layer_digest, layer) = lazy_env().await;
    let result = e.pull_lazy().await.unwrap();
    let image_ref = format!("{}/test:latest", e.host);
    // the blob is damaged after the first file: the first completion stops
    // with the files it could fetch in the pool
    let damaged = {
        let mut blobs = e.reg.blobs.lock().unwrap();
        let blob = blobs.get_mut(&sha(&layer.blob).to_string()).unwrap();
        let saved = blob.clone();
        for b in blob.iter_mut().skip(1000).take(64) {
            *b ^= 0x55;
        }
        saved
    };
    assert!(e.service.complete_image(&image_ref).await.is_err());
    assert!(e.db.get_layer(&layer_digest).await.is_err());
    assert!(e.service.get(&result.id).await.is_err());
    {
        let mut blobs = e.reg.blobs.lock().unwrap();
        *blobs.get_mut(&sha(&layer.blob).to_string()).unwrap() = damaged;
    }
    e.service.complete_image(&image_ref).await.unwrap();
    assert!(e.service.get(&result.id).await.is_ok());
    assert_eq!(linked(&e), ALL);
}

/// A complete pool commits without a request for a file: the only request
/// is for the tar-split, which the completion fetches.
#[tokio::test]
async fn test_a_complete_pool_is_committed_as_it_is() {
    let (e, layer_digest, _) = lazy_env().await;
    let result = e.pull_lazy().await.unwrap();
    stage(&e, &ALL);
    let before = lazy_requests(&e);
    let image_ref = format!("{}/test:latest", e.host);
    e.service.complete_image(&image_ref).await.unwrap();
    assert_eq!(lazy_requests(&e), before + 1, "only the tar-split");
    assert!(e.service.get(&result.id).await.is_ok());
    assert_eq!(e.db.get_layer(&layer_digest).await.unwrap().status, "ready");
    assert_eq!(linked(&e), ALL);
    assert!(e.pooled().is_empty());
}

#[tokio::test]
async fn test_two_completions_of_one_image_commit_once() {
    let (e, layer_digest, _) = lazy_env().await;
    let result = e.pull_lazy().await.unwrap();
    stage(&e, &["usr/big"]);
    let image_ref = format!("{}/test:latest", e.host);
    let (a, b) = tokio::join!(
        e.service.complete_image(&image_ref),
        e.service.complete_image(&image_ref)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(linked(&e), ALL);
    assert!(e.service.get(&result.id).await.is_ok());
    assert_eq!(e.db.list_images().await.unwrap().len(), 1);
    assert_eq!(e.db.layer_digests().await.unwrap(), vec![layer_digest]);
}

/// Two images that share a lazy layer: the layer is committed once, by
/// whichever completes first, and the other image takes it.
#[tokio::test]
async fn test_concurrent_pulls_of_the_same_layer_commit_it_once() {
    let (e, digests, [first, second]) = two_images(&[0, 1], &[1, 0]).await;
    assert_ne!(first.id, second.id);
    // (same layers, other manifests)
    let (first_ref, second_ref) = (
        format!("{}/test:first", e.host),
        format!("{}/test:second", e.host),
    );
    let (a, b) = tokio::join!(
        e.service.complete_image(&first_ref),
        e.service.complete_image(&second_ref)
    );
    a.unwrap();
    b.unwrap();
    let mut keys = e.db.layer_digests().await.unwrap();
    keys.sort();
    let mut want = digests.to_vec();
    want.sort();
    assert_eq!(keys, want);
    assert!(e.service.get(&first.id).await.is_ok());
    assert!(e.service.get(&second.id).await.is_ok());
    assert!(e.pooled().is_empty());
    assert!(e.area().layer_keys().is_empty());
}

/// A file two layers of an image share is staged once, in the staging of
/// the layer it was read from: the second here, not the first, which the
/// completion fetches it into.  The completion commits it from there.
#[tokio::test]
async fn test_a_shared_file_staged_in_the_second_layer_is_committed() {
    let (e, [_, second], [first, _]) = two_images(&[0, 1], &[1]).await;
    e.service
        .fetch_lazy_file(&vid(b"hello\n"), &second)
        .await
        .unwrap();
    e.service
        .complete_image(&format!("{}/test:first", e.host))
        .await
        .unwrap();
    assert!(e.service.get(&first.id).await.is_ok());
}

/// A pooled file that is not what its name says is not linked, and the
/// proof does not fetch it behind the link: the commit fails and the image
/// is still being pulled.
#[tokio::test]
async fn test_a_pooled_file_the_link_refuses_leaves_the_image_pulling() {
    let (e, layer_digest, _) = lazy_env().await;
    let result = e.pull_lazy().await.unwrap();
    stage(&e, &["etc/small", "usr/holes"]);
    let files =
        velarx_storage::FileStore::new(e.area().layer_files(&e.area().layer_keys()[0])).unwrap();
    let path = files.local_path(&vid(&data_of("usr/big"))).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"not usr/big").unwrap();
    let before = lazy_requests(&e);
    let image_ref = format!("{}/test:latest", e.host);
    let err = e.service.complete_image(&image_ref).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("not the fs-verity digest it is known by"),
        "{err}"
    );
    assert_eq!(lazy_requests(&e), before + 1, "only the tar-split");
    assert!(e.service.get(&result.id).await.is_err());
    assert!(e.db.get_layer(&layer_digest).await.is_err());
    assert!(!e.store.contains(&vid(&data_of("usr/big"))));
    // the name that lied is gone from the pool: the next try fetches the
    // file and commits (it does not meet the same file for ever)
    assert!(!path.exists());
    e.service.complete_image(&image_ref).await.unwrap();
    assert!(e.service.get(&result.id).await.is_ok());
    assert_eq!(linked(&e), ALL);
}

/// `[storage] sync`: the files of a layer are written to the disk once they
/// are complete and sealed, before they leave the staging area (one
/// `syncfs`, and one for their names before the rows), never while they are
/// fetched into the pool; without it, never.
#[tokio::test]
async fn test_a_completion_syncs_the_files_only_as_storage_sync_says() {
    for sync in [
        velarx_base::sync::SyncMode::Syncfs,
        velarx_base::sync::SyncMode::None,
    ] {
        let (e, layer_digest, _) = lazy_env().await;
        let result = e.pull_lazy().await.unwrap();
        let store = std::sync::Arc::new(
            velarx_storage::FileStore::new(e.store.root())
                .unwrap()
                .with_sync(sync),
        );
        let service = std::mem::ManuallyDrop::new(
            velarx_core::services::ImageService::new(
                e.db.clone(),
                store.clone(),
                e.staging.clone(),
                velarx_storage::VerityMode::Off,
            )
            .unwrap()
            // (as the environment's: in this process, no window)
            .with_pull_config(velarx_config::PullConfig {
                lazy_window_files: 0,
                worker_path: Some(registry_bin().into()),
                ..Default::default()
            })
            .unwrap()
            .with_resolver(e.client())
            .with_origin(e.origin.clone()),
        );
        // a fetch into the pool: a file in progress is never synced
        service
            .fetch_lazy_file(&vid(b"hello\n"), &layer_digest)
            .await
            .unwrap();
        assert_eq!(store.barriers(), 0, "{sync:?}: a fetch into the pool");
        let image_ref = format!("{}/test:latest", e.host);
        service.complete_image(&image_ref).await.unwrap();
        assert!(service.get(&result.id).await.is_ok());
        let want = match sync {
            velarx_base::sync::SyncMode::Syncfs => 2,
            velarx_base::sync::SyncMode::None => 0,
        };
        assert_eq!(store.barriers(), want, "{sync:?}: the commit of the layer");
    }
}

/// Pull `test:<tag>` lazily.
async fn pull_lazy_tag(e: &Env, tag: &str) -> velarx_core::services::PullResult {
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    e.service
        .pull_lazy_with_client(&e.client(), &format!("{}/test:{tag}", e.host), tx)
        .await
        .unwrap()
}

/// Two images, `first` of the layers `a` and `second` of the layers `b`
/// (indexes of `layers`), pulled lazily.
async fn two_images(
    a: &[usize],
    b: &[usize],
) -> (
    Env,
    [velarx_db::LayerKey; 2],
    [velarx_core::services::PullResult; 2],
) {
    let e = env_with(velarx_config::PullConfig {
        lazy_window_files: 0,
        ..Default::default()
    })
    .await;
    let layers = [build_chunked(&sample()), build_chunked(&sample()[..2])];
    for (tag, which) in [("first", a), ("second", b)] {
        let list: Vec<&Built> = which.iter().map(|&i| &layers[i]).collect();
        publish_arch(&e.reg, &list, &vec![ZSTD; list.len()], "amd64", tag);
    }
    let digests = [layers[0].key(), layers[1].key()];
    let results = [
        pull_lazy_tag(&e, "first").await,
        pull_lazy_tag(&e, "second").await,
    ];
    (e, digests, results)
}

/// Another image completed every lazy layer of this one: the next
/// completion commits it without a fetch.
#[tokio::test]
async fn test_an_image_whose_lazy_layers_another_image_committed_is_committed() {
    let (e, _, [first, second]) = two_images(&[0, 1], &[0]).await;
    assert_ne!(first.id, second.id);
    e.service
        .complete_image(&format!("{}/test:first", e.host))
        .await
        .unwrap();
    assert!(e.service.get(&first.id).await.is_ok());
    assert!(
        e.service.get(&second.id).await.is_err(),
        "nothing looked at it yet: it is still a pull"
    );
    let before = lazy_requests(&e);
    e.service
        .complete_image(&format!("{}/test:second", e.host))
        .await
        .unwrap();
    assert!(e.service.get(&second.id).await.is_ok());
    assert_eq!(lazy_requests(&e), before, "nothing was fetched");
    assert_eq!(e.staged_leftovers(), 0);
    assert!(e.area().pulls().is_empty());
}

/// An image with a layer another image committed and one of its own: the
/// completion fetches only the second, and the image is committed.
#[tokio::test]
async fn test_an_image_with_one_shared_and_one_own_lazy_layer_is_completed() {
    let (e, digests, [_, second]) = two_images(&[0], &[0, 1]).await;
    e.service
        .complete_image(&format!("{}/test:first", e.host))
        .await
        .unwrap();
    assert_eq!(e.db.get_layer(&digests[0]).await.unwrap().status, "ready");
    assert!(e.db.get_layer(&digests[1]).await.is_err());
    assert!(e.service.get(&second.id).await.is_err());
    e.service
        .complete_image(&format!("{}/test:second", e.host))
        .await
        .unwrap();
    assert!(e.service.get(&second.id).await.is_ok());
    assert_eq!(e.db.get_layer(&digests[1]).await.unwrap().status, "ready");
    assert_eq!(e.staged_leftovers(), 0);
}

/// A layer of the store that is not what the configuration says is refused:
/// the image stays a pull and the call says so.
#[tokio::test]
async fn test_a_stored_layer_with_another_diff_id_is_refused_by_the_commit() {
    let (e, digests, [_, second]) = two_images(&[0, 1], &[0]).await;
    e.service
        .complete_image(&format!("{}/test:first", e.host))
        .await
        .unwrap();
    let (digest, wrong) = (digests[0].to_string(), sha(b"another"));
    e.db.conn()
        .call(move |c| {
            c.execute(
                "UPDATE layers SET diff_id = ?2 WHERE id = ?1",
                [digest, wrong.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let err = e
        .service
        .complete_image(&format!("{}/test:second", e.host))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("diff id"), "{err}");
    assert!(e.service.get(&second.id).await.is_err());
}

// Lazy layers pulled with what only the pulling command had: the completion
// reaches the registry the way the pull did, and asks again for what is not
// stored.

use velarx_core::services::{ImageService, PullOptions};
use velarx_registry::auth::RegistryAccess;
use velarx_registry::certs::RawCerts;

/// A service on the database and the store of `e` that trusts no registry
/// (registries.conf has no insecure host): what it reaches over TLS is
/// verified unless a pull says otherwise.
fn strict_service(e: &Env) -> std::mem::ManuallyDrop<ImageService> {
    std::mem::ManuallyDrop::new(
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
            ..Default::default()
        })
        .unwrap()
        .with_resolver(client_conf(""))
        .with_origin({
            // (its own fetcher, which trusts no registry either, on the
            // staging of `e`)
            let dir = e._tmp.path().join("strict");
            std::fs::create_dir_all(&dir).unwrap();
            let (spawner, _) =
                fetcher_spawner_with(&dir, &e.staging, "", &velarx_config::Config::default());
            velarx_content::list::RegistryOrigin::with_shared(spawner, &Default::default())
        }),
    )
}

async fn pull_lazy_with(
    service: &ImageService,
    reference: &str,
    options: &PullOptions,
) -> velarx_types::ImageResult<velarx_core::services::PullResult> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    service.pull_with(reference, true, options, tx).await
}

/// A lazy image behind an HTTPS front with a self-signed certificate.
async fn https_env() -> (Env, TlsFront, velarx_db::LayerKey, String) {
    let (e, digest, _) = lazy_env().await;
    let front = tls_front(&e.host);
    let reference = format!("{}/test:latest", front.host);
    (e, front, digest, reference)
}

/// All the text the database holds, to look for what must not be there.
async fn database_text(e: &Env) -> String {
    e.db.conn()
        .call(|c| {
            let tables: Vec<String> = c
                .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")?
                .query_map([], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            let mut text = String::new();
            for t in tables {
                let columns: Vec<String> = c
                    .prepare(&format!("PRAGMA table_info('{t}')"))?
                    .query_map([], |r| r.get(1))?
                    .collect::<Result<_, _>>()?;
                let mut stmt = c.prepare(&format!("SELECT * FROM \"{t}\""))?;
                let mut rows = stmt.query([])?;
                while let Some(row) = rows.next()? {
                    for i in 0..columns.len() {
                        match row.get_ref(i)? {
                            rusqlite::types::ValueRef::Text(b)
                            | rusqlite::types::ValueRef::Blob(b) => {
                                text += &String::from_utf8_lossy(b);
                            }
                            other => text += &format!("{other:?}"),
                        }
                        text.push('|');
                    }
                    text.push('\n');
                }
            }
            Ok(text)
        })
        .await
        .unwrap()
}

/// All the text of the staging area, to look for what must not be there.
fn staging_text(e: &Env) -> String {
    fn walk(dir: &std::path::Path, text: &mut String) {
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, text);
            } else if let Ok(bytes) = std::fs::read(&path) {
                *text += &String::from_utf8_lossy(&bytes);
            }
        }
    }
    let mut text = String::new();
    walk(e.area().root(), &mut text);
    text
}

/// Change what `layer.json` of the staged layer says.
fn edit_layer(e: &Env, key: &velarx_db::LayerKey, edit: impl FnOnce(&mut serde_json::Value)) {
    let path = e.area().layer_dir(key).join("layer.json");
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    edit(&mut v);
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
}

/// `--tls-verify=false` at the pull: the completion of its layers does not
/// verify either, for that registry; the staged layer says so and the
/// registry has nothing else to say about it.
#[tokio::test]
async fn test_a_layer_pulled_without_tls_verification_is_completed_the_same_way() {
    let (e, _front, digest, reference) = https_env().await;
    let service = strict_service(&e);
    let options = PullOptions {
        tls_verify: false,
        ..Default::default()
    };
    let pulled = pull_lazy_with(&service, &reference, &options)
        .await
        .unwrap();
    let reach = staged(&e, &digest).meta.reach;
    assert!(!reach.tls_verify && !reach.creds && !reach.certs);
    service.complete_image(&reference).await.unwrap();
    assert!(service.get(&pulled.id).await.is_ok());
    assert_eq!(e.db.get_layer(&digest).await.unwrap().status, "ready");
}

/// A layer that is not marked as pulled without verification is verified:
/// the certificate is refused and the image stays lazy.
#[tokio::test]
async fn test_a_layer_pulled_with_verification_is_verified_by_its_completion() {
    let (e, _front, digest, reference) = https_env().await;
    let service = strict_service(&e);
    let options = PullOptions {
        tls_verify: false,
        ..Default::default()
    };
    let pulled = pull_lazy_with(&service, &reference, &options)
        .await
        .unwrap();
    edit_layer(&e, &digest, |v| v["reach"]["tls_verify"] = true.into());
    // (the completion of another process: the list of fetchers the pull
    // opened is not at hand)
    let service = strict_service(&e);
    let err = service.complete_image(&reference).await.unwrap_err();
    let text = err.to_string().to_lowercase();
    assert!(
        text.contains("certificate") || text.contains("tls") || text.contains("ssl"),
        "{text}"
    );
    assert!(service.get(&pulled.id).await.is_err());
    assert!(e.db.get_layer(&digest).await.is_err());
}

/// `--tls-verify=false` is for the registry the row names: in one
/// completion, a layer of registry A pulled without verification does not
/// turn it off for a layer of registry B whose row says to verify.
#[tokio::test]
async fn test_tls_verification_off_for_one_registry_is_not_off_for_another() {
    let e = env_with(velarx_config::PullConfig {
        lazy_window_files: 0,
        ..Default::default()
    })
    .await;
    // (B's layer has a file of its own, which only B can give)
    let own = Item::File {
        name: "opt/only-on-b",
        data: b"only on registry B\n".repeat(100),
        chunk: 4096,
    };
    let layers = [build_chunked(&sample()), build_chunked(&[own])];
    e.publish(&[&layers[0], &layers[1]], &[ZSTD, ZSTD]);
    let (a, b) = (tls_front(&e.host), tls_front(&e.host));
    let reference = format!("{}/test:latest", a.host);
    let service = strict_service(&e);
    let options = PullOptions {
        tls_verify: false,
        ..Default::default()
    };
    let pulled = pull_lazy_with(&service, &reference, &options)
        .await
        .unwrap();
    let on_b = layers[1].key();
    let registry_b = staged(&e, &on_b)
        .meta
        .registry_ref
        .unwrap()
        .replace(&a.host, &b.host);
    let set_b = |tls_verify: bool| {
        edit_layer(&e, &on_b, |v| {
            v["registry_ref"] = registry_b.clone().into();
            v["reach"]["tls_verify"] = tls_verify.into();
        })
    };
    set_b(true);
    let service = strict_service(&e);
    let err = service.complete_image(&reference).await.unwrap_err();
    let text = err.to_string().to_lowercase();
    assert!(
        text.contains("certificate") || text.contains("tls") || text.contains("ssl"),
        "{text}"
    );
    assert!(service.get(&pulled.id).await.is_err());
    assert!(e.area().layer(&on_b).unwrap().is_some());

    // (B answers: it was the verification that refused it)
    set_b(false);
    service.complete_image(&reference).await.unwrap();
    assert!(service.get(&pulled.id).await.is_ok());
}

/// `--creds` at the pull: the secret is nowhere in the database, the row
/// says only that credentials were used; the completion without them fails
/// naming the registry and the flag, and with them it works.
#[tokio::test]
async fn test_a_layer_pulled_with_creds_needs_them_again() {
    let (e, digest, _) = lazy_env().await;
    let service = strict_service(&e);
    let secret = "s3cr3t-pa55word-of-the-test";
    let creds = velarx_registry::Credentials::parse_creds(&format!("alice:{secret}")).unwrap();
    let access = RegistryAccess {
        creds: Some(creds),
        ..Default::default()
    };
    // (plain HTTP, which a client of this service accepts with --tls-verify=false)
    let reference = format!("{}/test:latest", e.host);
    let options = PullOptions {
        tls_verify: false,
        access: access.clone(),
        ..Default::default()
    };
    let pulled = pull_lazy_with(&service, &reference, &options)
        .await
        .unwrap();
    let reach = staged(&e, &digest).meta.reach;
    assert!(reach.creds && !reach.certs && !reach.tls_verify);
    let text = database_text(&e).await + &staging_text(&e);
    assert!(
        !text.contains(secret) && !text.contains("alice"),
        "a secret is stored"
    );
    let before = lazy_requests(&e);

    let err = service.complete_image(&reference).await.unwrap_err();
    // (a refusal of the access: the completer of the pull waits for the
    // credentials, `needs-credentials`, it does not fail the pull)
    assert!(
        matches!(err, velarx_types::ImageError::Unauthorized(_)),
        "{err:?}"
    );
    let text = err.to_string();
    assert!(text.contains(&e.host) && text.contains("--creds"), "{text}");
    assert!(text.contains("image complete"), "{text}");
    assert_eq!(lazy_requests(&e), before, "no request without them");
    assert!(service.get(&pulled.id).await.is_err());

    service
        .complete_image_with(&reference, access)
        .await
        .unwrap();
    assert!(service.get(&pulled.id).await.is_ok());
    assert!(!(database_text(&e).await + &staging_text(&e)).contains(secret));
}

/// `--cert-dir` at the pull: the registry is verified with the certificate
/// the command brought, which is not stored; the completion needs it again.
#[tokio::test]
async fn test_a_layer_pulled_with_a_cert_dir_needs_it_again() {
    let (e, front, digest, reference) = https_env().await;
    let service = strict_service(&e);
    let access = RegistryAccess {
        certs: Some(RawCerts {
            ca: vec![front.ca.clone()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let options = PullOptions {
        access: access.clone(),
        ..Default::default()
    };
    let pulled = pull_lazy_with(&service, &reference, &options)
        .await
        .unwrap();
    let reach = staged(&e, &digest).meta.reach;
    assert!(reach.certs && reach.tls_verify && !reach.creds);
    let pem = front.ca.lines().nth(1).unwrap().to_string();
    assert!(
        !(database_text(&e).await + &staging_text(&e)).contains(&pem),
        "a certificate is stored"
    );

    let err = service.complete_image(&reference).await.unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains(&front.host) && text.contains("--cert-dir"),
        "{text}"
    );
    assert!(service.get(&pulled.id).await.is_err());

    service
        .complete_image_with(&reference, access)
        .await
        .unwrap();
    assert!(service.get(&pulled.id).await.is_ok());
}

/// What a command brings to the fetcher: with TLS verification
/// off for a registry that registries.conf does not mark insecure the
/// fetcher sends only the credentials of the call, so the stored ones for
/// the registry go with it; nothing is added in the other cases or when the
/// command has credentials for every registry.
#[test]
fn test_the_stored_credentials_go_with_a_request_without_tls_verification() {
    use velarx_content::pull::access::{access_for, with_stored};
    use velarx_registry::auth::{Credentials, RegistryAccess};
    let dir = tempfile::tempdir().unwrap();
    let auth = dir.path().join("auth.json");
    let basic = |p: &str| {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(format!("u:{p}"))
    };
    std::fs::write(
        &auth,
        format!(
            r#"{{"auths": {{"strict.example": {{"auth": "{}"}}}}}}"#,
            basic("stored")
        ),
    )
    .unwrap();
    let stored = velarx_registry::AuthConfig::load_file(&auth);
    let none = RegistryAccess::default();
    // the stored credentials of the registry are added, and only its own
    let access = with_stored(&stored, "strict.example/a/b", &none).unwrap();
    assert_eq!(
        access.auths.get("strict.example"),
        Some(&Credentials::basic("u", "stored"))
    );
    assert!(with_stored(&stored, "other.example/a/b", &none)
        .unwrap()
        .is_empty());
    // what the command brought for the registry comes first
    let brought = RegistryAccess {
        auths: [(
            "strict.example".to_string(),
            Credentials::basic("me", "mine"),
        )]
        .into(),
        ..Default::default()
    };
    let access = with_stored(&stored, "strict.example/a/b", &brought).unwrap();
    assert_eq!(
        access.auths.get("strict.example"),
        Some(&Credentials::basic("me", "mine"))
    );
    // the other cases add nothing: verified, insecure, `--creds`
    let client = velarx_registry::target::Resolver::with_config(
        velarx_registry::target::TransportConfig {
            registries: velarx_registry::config::RegistriesConfig::parse(
                "[[registry]]\nlocation = \"loose.example\"\ninsecure = true\n",
            )
            .unwrap(),
            certs_dirs: vec![],
            tls_verify: true,
        },
        velarx_registry::AuthConfig::load_file(&auth),
    );
    assert!(access_for(&client, "strict.example/a/b", true, &none)
        .unwrap()
        .is_empty());
    assert!(access_for(&client, "loose.example/a/b", false, &none)
        .unwrap()
        .is_empty());
    let creds = RegistryAccess {
        creds: Some(Credentials::basic("me", "mine")),
        ..Default::default()
    };
    assert!(access_for(&client, "strict.example/a/b", false, &creds)
        .unwrap()
        .auths
        .is_empty());
}

/// A miss of a file that a fetch of a lower urgency (the completion's
/// batch, a read-ahead) has in flight is asked for on its own at once: it
/// does not wait for that batch.  The registry answers a blob request only
/// when a second one came (the rendezvous): the batch alone would wait for
/// the rendezvous to give up.
#[tokio::test(flavor = "multi_thread")]
async fn test_a_miss_does_not_wait_for_the_batch_it_falls_into() {
    use velarx_content::fetcher::fetch::Urgency;
    let (e, layer, _) = lazy_env().await;
    e.pull_lazy().await.unwrap();
    let file = vid(&data_of("usr/big"));
    e.reg.rendezvous.store(2, Ordering::SeqCst);
    let batch = {
        let (service, file) = (e.service.clone(), file.clone());
        tokio::spawn(async move {
            service
                .stage_lazy(&layer, vec![file], Urgency::Background)
                .await
        })
    };
    // (the batch is in flight once its request arrived)
    let mut arrived = e.reg.arrived.subscribe();
    arrived.wait_for(|n| *n >= 1).await.unwrap();
    e.service.fetch_lazy_file(&file, &layer).await.unwrap();
    batch.await.unwrap().unwrap();
    assert!(
        !e.reg.apart.load(Ordering::SeqCst),
        "the miss waited for the batch it fell into"
    );
    assert!(e.pooled().contains(&file));
}

/// The image servers of a pull ask the engine service of the store
/// (`org.velarx.ImageFetch`, one socket for every pull): with the token of
/// the pull of their image and for its own layers only; the misses of one
/// file, from any number of connections at once, are one fetch, which puts
/// the file in the staging.
#[tokio::test(flavor = "multi_thread")]
async fn test_the_misses_of_a_pull_are_one_fetch_through_the_engine() {
    use velarx_content::imagefetch::Client;
    use velarx_core::image_fetch::{Proxy, ProxyEndpoint};
    let (e, layer, _) = lazy_env().await;
    let id = e.pull_lazy().await.unwrap().id;
    let token = e.area().token(&id).unwrap();
    let services = tempfile::tempdir().unwrap();
    let endpoint = ProxyEndpoint::new((*e.service).clone(), tokio::runtime::Handle::current());
    let _proxy = Proxy::start(services.path(), endpoint).unwrap();
    // a second engine cannot serve the same store
    let again = ProxyEndpoint::new((*e.service).clone(), tokio::runtime::Handle::current());
    assert!(Proxy::start(services.path(), again).is_err());
    let socket = velarx_content::imagefetch::socket(services.path());
    let (file, key) = (vid(&data_of("usr/big")), layer.to_string());
    let deadline = || Some(std::time::Instant::now() + Duration::from_secs(60));
    let before = lazy_requests(&e);
    let answers = tokio::task::spawn_blocking({
        let (socket, token, file, key) = (socket.clone(), token.clone(), file.clone(), key.clone());
        let id = id.clone();
        move || {
            let threads: Vec<_> = (0..4)
                .map(|_| {
                    let client = Client::new(socket.clone(), id.clone(), token.clone());
                    let (file, key) = (file.clone(), key.clone());
                    std::thread::spawn(move || client.miss(&key, &file, deadline()).unwrap())
                })
                .collect();
            threads
                .into_iter()
                .map(|t| t.join().unwrap())
                .collect::<Vec<_>>()
        }
    })
    .await
    .unwrap();
    assert_eq!(answers, vec![(); 4]);
    assert!(e.pooled().contains(&file));
    let one = lazy_requests(&e) - before;
    assert!(one > 0);
    tokio::task::spawn_blocking({
        let (socket, token, file, key) = (socket.clone(), token.clone(), file.clone(), key.clone());
        let id = id.clone();
        move || {
            Client::new(socket, id, token)
                .miss(&key, &file, deadline())
                .unwrap()
        }
    })
    .await
    .unwrap();
    assert_eq!(lazy_requests(&e) - before, one);
    let refused = tokio::task::spawn_blocking(move || {
        let other = "sha256:".to_string() + &"2".repeat(64);
        // (a well-formed digest that is no file of the layer)
        let stranger = vid(b"a file the layer does not have");
        let not_a_file = Client::new(socket.clone(), id.clone(), token.clone())
            .miss(&key, &stranger, deadline())
            .unwrap_err()
            .to_string();
        assert!(not_a_file.contains("InvalidArgument"), "{not_a_file}");
        (
            Client::new(socket.clone(), id.clone(), "0".repeat(32))
                .miss(&key, &file, deadline())
                .unwrap_err()
                .to_string(),
            Client::new(socket.clone(), id.clone(), token.clone())
                .miss(&other, &file, deadline())
                .unwrap_err()
                .to_string(),
            Client::new(socket, "e".repeat(64), token)
                .miss(&key, &file, deadline())
                .unwrap_err()
                .to_string(),
        )
    })
    .await
    .unwrap();
    assert!(refused.0.contains("Refused"), "{}", refused.0);
    assert!(
        refused.1.contains("not a layer of the pull"),
        "{}",
        refused.1
    );
    // (the token of one image is not that of another's)
    assert!(refused.2.contains("Refused"), "{}", refused.2);
}

/// A cancelled pull leaves nothing in the staging area: its layers and the
/// files its containers or its completer fetched into the pool go with it
/// (no file is left that no pull wants, which `system check` reports).
#[tokio::test]
async fn test_a_cancelled_pull_leaves_no_file_in_the_pool() {
    let (e, layer_digest, _) = lazy_env().await;
    e.pull_lazy().await.unwrap();
    e.service
        .fetch_lazy_file(&vid(b"hello\n"), &layer_digest)
        .await
        .unwrap();
    assert_eq!(e.pooled().len(), 1);
    let image_ref = format!("{}/test:latest", e.host);
    e.service.cancel_pull(&image_ref, false).await.unwrap();
    assert!(e.service.pulls().await.unwrap().is_empty());
    assert!(e.pooled().is_empty(), "{:?}", e.pooled());
    assert!(e.area().layer_keys().is_empty());
    // (and nothing of it went to the store)
    assert!(!e.store.contains(&vid(b"hello\n")));
}

/// Two engines (two processes, each with its own funnel; here two services
/// on one store) and one layer: the second waits for the lease of the layer
/// that the first holds while it stages, then finds what it staged and asks
/// no fetcher for it.  The wait is the kernel's: the lock is given when the
/// holder lets go, nothing polls.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_an_engine_waits_for_the_lease_of_a_layer_and_fetches_nothing_again() {
    let (e, layer_digest, _) = lazy_env().await;
    e.pull_lazy().await.unwrap();
    let other = strict_service(&e);
    // the first engine stages the layer: it holds its lease
    let lease = e.area().lease_layer(&layer_digest).unwrap();
    let file = vid(&data_of("usr/big"));
    let waiting = {
        let (other, file) = ((*other).clone(), file.clone());
        tokio::spawn(async move { other.fetch_lazy_file(&file, &layer_digest).await })
    };
    // (whatever the order: the second has not fetched before the lease goes)
    let before = lazy_requests(&e);
    stage(&e, &["usr/big"]);
    drop(lease);
    let path = waiting.await.unwrap().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), data_of("usr/big"));
    assert!(path.starts_with(e.area().layer_files(&layer_digest)));
    assert_eq!(
        lazy_requests(&e),
        before,
        "the staged file was fetched again"
    );
}

/// One file of a layer that does not match its table of contents fails
/// alone: the file asked for with it, in the same request, is staged.
#[tokio::test]
async fn test_a_bad_file_does_not_fail_the_file_fetched_with_it() {
    let e = env().await;
    // (bytes that do not compress: a byte changed in the middle of a frame is
    // still a frame, of other bytes)
    let noise = |seed: u32| -> Vec<u8> {
        let mut x = seed;
        (0..100_000)
            .map(|_| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (x >> 24) as u8
            })
            .collect()
    };
    let (good, bad) = (noise(1), noise(2));
    let items = vec![
        Item::File {
            name: "a",
            data: good.clone(),
            chunk: 8192,
        },
        Item::File {
            name: "b",
            data: bad.clone(),
            chunk: 8192,
        },
    ];
    let mut layer = build_chunked(&items);
    let original = frame(&bad[..8192]);
    let at = layer
        .blob
        .windows(original.len())
        .position(|w| w == original)
        .unwrap();
    layer.blob[at + original.len() / 2] ^= 0xff;
    e.publish(&[&layer], &[ZSTD]);
    e.pull_lazy().await.unwrap();
    // (the window brings `b` with `a`)
    e.service
        .fetch_lazy_file(&vid(&good), &layer.key())
        .await
        .unwrap();
    assert!(e
        .service
        .fetch_lazy_file(&vid(&bad), &layer.key())
        .await
        .is_err());
}
