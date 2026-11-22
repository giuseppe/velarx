// SPDX-License-Identifier: Apache-2.0
//! Fetchers other than the registry fetcher: what they stage is verified like
//! what the registry fetcher stages, a fetcher that is not there is skipped,
//! one that stages wrong bytes is fallen back from.  The fetchers here are
//! processes' stand-ins on unix sockets, serving the interface of
//! `interfaces/org.velarx.Fetcher.varlink`.

use crate::common::*;
use std::sync::atomic::Ordering;

use std::time::{Duration, Instant};

fn chunk_map(items: &[Item]) -> std::collections::HashMap<String, Vec<u8>> {
    let mut map = std::collections::HashMap::new();
    for i in items {
        if let Item::File { data, chunk, .. } = i {
            for c in data.chunks(*chunk) {
                if !c.iter().all(|&b| b == 0) {
                    map.insert(sha(c).to_string(), c.to_vec());
                }
            }
        }
    }
    map
}

fn sample_big() -> Vec<u8> {
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

#[tokio::test]
async fn test_chunks_come_from_a_source() {
    let source = fake_source().await;
    *source.items.lock().unwrap() = chunk_map(&sample());
    let e = env_with_sources(&[&source.socket]).await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    let result = e.pull().await.unwrap();
    assert!(source.fetched.load(Ordering::SeqCst) > 0);
    assert!(result.stats.from("source0").0 > 0);
    assert_eq!(e.reg.ranged.load(Ordering::SeqCst), 1);
    assert_eq!(e.db.get_layer(&layer.key()).await.unwrap().status, "ready");
    assert!(e.store.contains(&vid(b"hello\n")));
}

#[tokio::test]
async fn test_wrong_chunks_from_a_source_fail_the_pull_naming_it() {
    let source = fake_source().await;
    let mut map = chunk_map(&sample());
    // Same size, other bytes: every chunk (which files are fetched from the
    // source is not the map's order).
    map.values_mut()
        .for_each(|v| v.iter_mut().for_each(|x| *x ^= 1));
    *source.items.lock().unwrap() = map;
    let e = env_with_sources(&[&source.socket]).await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    let err = e.pull().await.unwrap_err();
    assert!(
        matches!(&err, velarx_types::ImageError::Transfer { party, failure, .. }
            if party == "source0" && failure.class == velarx_proto::transfer::FailureClass::Invalid),
        "{err}"
    );
    assert!(!e.store.contains(&vid(&sample_big())));
}

#[tokio::test]
async fn test_a_chain_without_sources_asks_nobody() {
    let source = fake_source().await;
    *source.items.lock().unwrap() = chunk_map(&sample());
    let e = env().await;
    e.publish(&[&build_chunked(&sample())], &[ZSTD]);
    let result = e.pull().await.unwrap();
    assert_eq!(source.has_calls.load(Ordering::SeqCst), 0);
    assert_eq!(result.stats.from("source0").0, 0);
}

/// `[pull] sources` is used as written: a list without `registry` never
/// asks the registry, so a tag cannot be pulled; with it, the order given is
/// the order asked, `registry` first or not.
#[tokio::test]
async fn test_the_registry_is_a_source_only_when_it_is_listed() {
    let source = fake_source().await;
    *source.items.lock().unwrap() = chunk_map(&sample());
    let pull = |list: &[&str]| velarx_config::PullConfig {
        sources: list.iter().map(|n| n.to_string()).collect(),
        ..Default::default()
    };
    let e = env_sources(
        pull(&["source0"]),
        velarx_config::PushConfig::default(),
        chain_of(&[&source.socket]),
    )
    .await;
    e.publish(&[&build_chunked(&sample())], &[ZSTD]);
    let err = e.pull().await.unwrap_err();
    assert!(
        err.to_string()
            .contains("`registry` is not one of the sources")
            && err.to_string().contains("a tag needs the registry"),
        "{err}"
    );
    assert_eq!(e.reg.ranged.load(Ordering::SeqCst), 0);
    let e = env_sources(
        pull(&["registry", "source0"]),
        velarx_config::PushConfig::default(),
        chain_of(&[&source.socket]),
    )
    .await;
    e.publish(&[&build_chunked(&sample())], &[ZSTD]);
    e.pull().await.unwrap();
    assert!(e.reg.ranged.load(Ordering::SeqCst) > 0);
    assert_eq!(
        e.db.get_layer(&build_chunked(&sample()).key())
            .await
            .unwrap()
            .status,
        "ready"
    );
}

#[tokio::test]
async fn test_a_source_that_is_not_there_costs_nothing() {
    let gone = std::path::Path::new("/nonexistent/dir/source.sock");
    let e = env_with_sources(&[gone]).await;
    e.publish(&[&build_chunked(&sample())], &[ZSTD]);
    let started = Instant::now();
    let result = e.pull().await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(result.stats.from("source0").0, 0);
}

#[tokio::test]
async fn test_a_lazy_file_comes_from_a_source() {
    let source = fake_source().await;
    *source.items.lock().unwrap() = chunk_map(&sample());
    let e = env_with_sources(&[&source.socket]).await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    e.pull_lazy().await.unwrap();
    let before = e.reg.ranged.load(Ordering::SeqCst);
    let big = sample_big();
    let path = e
        .service
        .fetch_lazy_file(&vid(&big), &layer.key())
        .await
        .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), big);
    assert_eq!(
        e.reg.ranged.load(Ordering::SeqCst),
        before,
        "no range request"
    );
    assert!(source.fetched.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn test_a_lazy_file_with_wrong_bytes_fails_naming_the_source() {
    let source = fake_source().await;
    let mut map = chunk_map(&sample());
    map.values_mut()
        .for_each(|v| v.iter_mut().for_each(|x| *x ^= 1));
    *source.items.lock().unwrap() = map;
    let e = env_with_sources(&[&source.socket]).await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    e.pull_lazy().await.unwrap();
    let before = e.reg.ranged.load(Ordering::SeqCst);
    let big = sample_big();
    let err = e
        .service
        .fetch_lazy_file(&vid(&big), &layer.key())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, velarx_types::ImageError::Transfer { party, failure, .. }
            if party == "source0" && failure.class == velarx_proto::transfer::FailureClass::Invalid),
        "{err}"
    );
    assert_eq!(e.reg.ranged.load(Ordering::SeqCst), before);
}

#[tokio::test]
async fn test_the_first_source_with_a_chunk_gives_it() {
    // the first has the chunks of one file, the second all of them: each
    // file comes from the first that has all of its chunks
    let (first, second) = (fake_source().await, fake_source().await);
    let all = chunk_map(&sample());
    let big: Vec<Item> = sample()
        .into_iter()
        .filter(|i| {
            matches!(
                i,
                Item::File {
                    name: "usr/big",
                    ..
                }
            )
        })
        .collect();
    let half = chunk_map(&big);
    *first.items.lock().unwrap() = half.clone();
    *second.items.lock().unwrap() = all.clone();
    let e = env_with_sources(&[&first.socket, &second.socket]).await;
    e.publish(&[&build_chunked(&sample())], &[ZSTD]);
    e.pull().await.unwrap();
    assert_eq!(first.fetched.load(Ordering::SeqCst), half.len());
    assert_eq!(
        second.fetched.load(Ordering::SeqCst),
        all.len() - half.len()
    );
    assert_eq!(e.reg.ranged.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_a_wrong_layer_from_a_source_is_dropped_for_the_registry() {
    let source = fake_source().await;
    let layer = build_gzip(&sample());
    // Right size and digest asked for, other bytes; then the right bytes cut short.
    let mut bad = layer.blob.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0xff;
    source
        .items
        .lock()
        .unwrap()
        .insert(sha(&layer.blob).to_string(), bad);
    let e = env_with_sources(&[&source.socket]).await;
    e.publish(&[&layer], &[GZIP]);
    let result = e.pull().await.unwrap();
    assert_eq!(
        e.reg.hits.lock().unwrap().get(&sha(&layer.blob)).copied(),
        Some(1),
        "the registry gave it"
    );
    assert_eq!(result.stats.from("source0").0, 0);
    assert!(e.store.contains(&vid(&sample_big())));
    let truncated = layer.blob[..layer.blob.len() / 2].to_vec();
    source
        .items
        .lock()
        .unwrap()
        .insert(sha(&layer.blob).to_string(), truncated);
    let e = env_with_sources(&[&source.socket]).await;
    e.publish(&[&layer], &[GZIP]);
    e.pull().await.unwrap();
    assert!(e.store.contains(&vid(&sample_big())));
}

#[tokio::test]
async fn test_completing_a_lazy_image_from_a_source_leaves_the_objects_in_the_store() {
    let source = fake_source().await;
    *source.items.lock().unwrap() = chunk_map(&sample());
    let e = env_with_sources(&[&source.socket]).await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    let result = e.pull_lazy().await.unwrap();
    let ranged = e.reg.ranged.load(Ordering::SeqCst);
    let stats = e.service.complete_image(&result.id).await.unwrap();
    assert!(stats.from("source0").0 > 0, "{stats:?}");
    assert_eq!(
        e.reg.ranged.load(Ordering::SeqCst),
        ranged,
        "the registry was not asked"
    );
    // Another process (a fetcher of its own) finds the objects without any fetch.
    let requests = e.reg.requests.load(Ordering::SeqCst);
    let asked = source.fetched.load(Ordering::SeqCst);
    let path = e
        .service
        .fetch_lazy_file(
            &vid(&sample_big()),
            &stored_key(&e.db, &sha(&layer.blob)).await,
        )
        .await
        .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), sample_big());
    assert_eq!(e.reg.requests.load(Ordering::SeqCst), requests);
    assert_eq!(source.fetched.load(Ordering::SeqCst), asked);
}

/// A file the store gets while a lazy image is completed is taken as one it
/// had: the completion commits the layer all the same.
#[tokio::test]
async fn test_a_file_the_store_gets_during_a_completion_is_taken() {
    for meanwhile in [false, true] {
        let source = fake_source().await;
        *source.items.lock().unwrap() = chunk_map(&sample());
        let e = env_with_sources(&[&source.socket]).await;
        let layer = build_chunked(&sample());
        e.publish(&[&layer], &[ZSTD]);
        let result = e.pull_lazy().await.unwrap();
        if meanwhile {
            let store = e.store.clone();
            *source.on_first.lock().unwrap() = Some(Box::new(move || {
                store
                    .put(velarx_types::digest::Algorithm::Sha256, &sample_big())
                    .unwrap();
            }));
        }
        e.service.complete_image(&result.id).await.unwrap();
        assert!(source.fetched.load(Ordering::SeqCst) > 0);
        let key = stored_key(&e.db, &sha(&layer.blob)).await;
        assert_eq!(
            e.db.get_layer(&key).await.unwrap().status,
            "ready",
            "meanwhile {meanwhile}"
        );
        assert!(e.store.contains(&vid(&sample_big())));
    }
}

/// A pull with a directory configured as a source, in this process: no daemon,
/// no socket.
mod dir_source {
    use super::*;
    use velarx_config::Config;

    fn chain_for(dir: &std::path::Path) -> Fetchers {
        let config: Config = toml::from_str(&format!(
            "[[sources.external]]\nname = \"cache\"\ndir = \"{}\"\n[pull]\nsources = [\"cache\", \"registry\"]\n",
            dir.display()
        ))
        .unwrap();
        config.validate().unwrap();
        Fetchers(config.sources.external)
    }

    async fn env_for(dir: &std::path::Path) -> Env {
        env_sources(
            velarx_config::PullConfig::default(),
            velarx_config::PushConfig::default(),
            chain_for(dir),
        )
        .await
    }

    fn fill(dir: &std::path::Path, chunks: &std::collections::HashMap<String, Vec<u8>>) {
        for (d, data) in chunks {
            std::fs::write(dir.join(d.trim_start_matches("sha256:")), data).unwrap();
        }
    }

    #[tokio::test]
    async fn test_chunks_come_from_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        fill(dir.path(), &chunk_map(&sample()));
        let e = env_for(dir.path()).await;
        let layer = build_chunked(&sample());
        e.publish(&[&layer], &[ZSTD]);
        let result = e.pull().await.unwrap();
        assert!(result.stats.from("cache").0 > 0);
        assert_eq!(e.reg.ranged.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_wrong_files_fail_the_pull_and_missing_ones_fall_back_to_the_registry() {
        let dir = tempfile::tempdir().unwrap();
        let mut map = chunk_map(&sample());
        map.values_mut()
            .for_each(|v| v.iter_mut().for_each(|x| *x ^= 1));
        fill(dir.path(), &map);
        let e = env_for(dir.path()).await;
        e.publish(&[&build_chunked(&sample())], &[ZSTD]);
        let err = e.pull().await.unwrap_err();
        assert!(
            matches!(&err, velarx_types::ImageError::Transfer { failure, .. }
                if failure.class == velarx_proto::transfer::FailureClass::Invalid),
            "{err}"
        );
        assert!(!e.store.contains(&vid(&sample_big())));
        // A directory that is not there, or holds a directory by the name.
        let e = env_for(std::path::Path::new("/nonexistent/cache")).await;
        e.publish(&[&build_chunked(&sample())], &[ZSTD]);
        e.pull().await.unwrap();
        let odd = tempfile::tempdir().unwrap();
        for d in chunk_map(&sample()).keys() {
            std::fs::create_dir(odd.path().join(d.trim_start_matches("sha256:"))).unwrap();
        }
        let e = env_for(odd.path()).await;
        e.publish(&[&build_chunked(&sample())], &[ZSTD]);
        assert_eq!(e.pull().await.unwrap().stats.from("source0").0, 0);
    }

    /// A lazy image is completed from the files of a directory.
    #[tokio::test]
    async fn test_a_layer_is_completed_from_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        fill(dir.path(), &chunk_map(&sample()));
        let e = env_for(dir.path()).await;
        let layer = build_chunked(&sample());
        e.publish(&[&layer], &[ZSTD]);
        let result = e.pull_lazy().await.unwrap();
        let stats = e.service.complete_image(&result.id).await.unwrap();
        assert!(stats.from("cache").0 > 0, "{stats:?}");
        let key = stored_key(&e.db, &sha(&layer.blob)).await;
        assert_eq!(e.db.get_layer(&key).await.unwrap().status, "ready");
    }
}

/// The whole files of `items`, by digest.
fn file_map(items: &[Item]) -> std::collections::HashMap<String, Vec<u8>> {
    items
        .iter()
        .filter_map(|i| match i {
            Item::File { data, .. } if !data.is_empty() => Some((vid(data), data.clone())),
            _ => None,
        })
        .collect()
}

/// The index of a layer a node pulled: its TOC and tar-split.
async fn index_of(layer: &Built) -> Vec<u8> {
    let a = env().await;
    a.publish(&[layer], &[GZIP]);
    a.pull().await.unwrap();
    let digest = sha(&layer.blob);
    let toc =
        a.db.get_layer_toc_z(&stored_key(&a.db, &digest).await)
            .await
            .unwrap()
            .unwrap();
    let tarsplit =
        a.db.get_layer_tarsplit(&stored_key(&a.db, &digest).await)
            .await
            .unwrap()
            .unwrap();
    velarx_content::pull::index::encode_compressed(&toc, &tarsplit).unwrap()
}

/// A gzip layer from its index and its files, from the sources, checked
/// against its diff id: the registry is not asked for the blob.
#[tokio::test]
async fn test_a_gzip_layer_comes_from_its_index_and_its_files() {
    let layer = build_gzip(&sample());
    let source = fake_source().await;
    let mut items = file_map(&sample());
    items.insert(
        format!("index:{}", sha(&layer.blob)),
        index_of(&layer).await,
    );
    *source.items.lock().unwrap() = items;
    let e = env_with_sources(&[&source.socket]).await;
    e.publish(&[&layer], &[GZIP]);
    e.pull().await.unwrap();
    assert_eq!(
        e.reg
            .hits
            .lock()
            .unwrap()
            .get(&sha(&layer.blob))
            .copied()
            .unwrap_or(0),
        0,
        "the registry was not asked for the layer"
    );
    let rec = e.db.get_layer(&layer.key()).await.unwrap();
    assert_eq!(rec.status, "ready");
    assert_eq!(rec.diff_id.as_ref(), Some(&layer.diff_id));
    assert!(e.store.contains(&vid(&sample_big())));
    assert!(e
        .db
        .get_layer_tarsplit(&layer.key())
        .await
        .unwrap()
        .is_some());
}

/// An index that lies (the tar-split of another layer), or whose files the
/// sources do not have: the layer comes from the registry, right.
#[tokio::test]
async fn test_a_lying_or_incomplete_index_falls_back_to_the_registry() {
    let layer = build_gzip(&sample());
    let other = build_gzip(&sample()[..3]);
    let right = index_of(&layer).await;
    let wrong = index_of(&other).await;
    // the TOC of the layer with the tar-split of the other
    let (toc, _) = velarx_content::pull::index::decode(&right, 32 << 20).unwrap();
    let (_, other_ts) = velarx_content::pull::index::decode(&wrong, 32 << 20).unwrap();
    let lying = index_of_toc(&toc, &other_ts);
    for (index, files) in [(lying, file_map(&sample())), (right, Default::default())] {
        let source = fake_source().await;
        let mut items: std::collections::HashMap<String, Vec<u8>> = files;
        items.insert(format!("index:{}", sha(&layer.blob)), index);
        *source.items.lock().unwrap() = items;
        let e = env_with_sources(&[&source.socket]).await;
        e.publish(&[&layer], &[GZIP]);
        e.pull().await.unwrap();
        assert_eq!(
            e.reg.hits.lock().unwrap().get(&sha(&layer.blob)).copied(),
            Some(1),
            "the registry gave it"
        );
        let rec = e.db.get_layer(&layer.key()).await.unwrap();
        assert_eq!(rec.diff_id.as_ref(), Some(&layer.diff_id));
        assert!(e.store.contains(&vid(&sample_big())));
    }
}

/// A layer made of what the peers have for a diff id is stored by the blob
/// its descriptor names, a blob never hashed: an image whose configuration
/// lies (another layer's files for the diff id of the blob of a third)
/// does not keep a later pull of that blob from proving it.  The pull of
/// the blob does not ask the peers again, hashes the blob, and its layer
/// takes the place of the one the peers made.
#[tokio::test]
async fn test_a_layer_of_the_peers_gives_way_to_its_blob_hashed() {
    let layer = build_gzip(&sample());
    let other = build_gzip(&sample()[..3]);
    let source = fake_source().await;
    let mut items = file_map(&sample());
    // the index of the other layer, for the blob of the first
    items.insert(
        format!("index:{}", sha(&layer.blob)),
        index_of(&other).await,
    );
    *source.items.lock().unwrap() = items;
    let e = env_with_sources(&[&source.socket]).await;
    let lie = Built {
        blob: layer.blob.clone(),
        diff_id: other.diff_id,
        annotations: Default::default(),
    };
    e.publish(&[&lie], &[GZIP]);
    let lied = e.pull().await.unwrap();
    let rec = e.db.get_layer(&layer.whole()).await.unwrap();
    assert_eq!(rec.diff_id.as_ref(), Some(&other.diff_id));
    assert_eq!(e.reg.hits.lock().unwrap().get(&sha(&layer.blob)), None);

    // (the peers have the right index now: the blob is pulled all the same)
    let right = index_of(&layer).await;
    source
        .items
        .lock()
        .unwrap()
        .insert(format!("index:{}", sha(&layer.blob)), right);
    e.publish(&[&layer], &[GZIP]);
    let pulled = e.pull().await.unwrap();
    assert_ne!(pulled.id, lied.id);
    assert_eq!(
        e.reg.hits.lock().unwrap().get(&sha(&layer.blob)).copied(),
        Some(1),
        "the blob was pulled and hashed"
    );
    let rec = e.db.get_layer(&layer.whole()).await.unwrap();
    assert_eq!(rec.diff_id.as_ref(), Some(&layer.diff_id));
    let files: std::collections::BTreeSet<String> =
        e.db.get_layer_file_refs(&layer.whole())
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.file_digest)
            .collect();
    assert!(files.contains(&vid(&sample_big())), "the files of the blob");
}

/// The archive of a shared checkpoint from a source that lies: a piece
/// with other bytes, a reference with another key, a piece missing.  Each
/// fails the fetch; nothing is taken that is not checked.
#[tokio::test]
async fn test_a_shared_checkpoint_from_a_source_that_lies_is_refused() {
    use velarx_core::services::checkpoint::{fetch, Reference, SharedCheckpoints, PIECE};
    let dir = tempfile::tempdir().unwrap();
    let shared = SharedCheckpoints::new(dir.path()).unwrap();
    let archive: Vec<u8> = (0..PIECE + 100).map(|i| (i % 253) as u8).collect();
    let path = dir.path().join("cp.tar");
    std::fs::write(&path, &archive).unwrap();
    let (reference, digests) = shared.share(&path).unwrap();
    let items: std::collections::HashMap<String, Vec<u8>> = digests
        .iter()
        .map(|d| {
            let (mut file, _) = shared.open(d).unwrap();
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut file, &mut bytes).unwrap();
            (d.clone(), bytes)
        })
        .collect();

    let source = fake_source().await;
    *source.items.lock().unwrap() = items.clone();
    let e = env_with_sources(&[&source.socket]).await;
    let dest = dir.path().join("ok.tar");
    fetch(&*e.service, &reference, &dest).await.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), archive);

    let mut bad = items.clone();
    bad.get_mut(&digests[1]).unwrap()[0] ^= 1;
    let source = fake_source().await;
    *source.items.lock().unwrap() = bad;
    let e = env_with_sources(&[&source.socket]).await;
    let e = fetch(&*e.service, &reference, &dir.path().join("a.tar"))
        .await
        .unwrap_err();
    assert!(e.contains("pieces"), "{e}");

    // another key: the manifest does not decrypt, nothing is fetched
    let other = reference.to_string();
    let other = format!("{}{}", &other[..other.len() - 64], "00".repeat(32));
    let other = Reference::parse(&other).unwrap();
    let source = fake_source().await;
    *source.items.lock().unwrap() = items.clone();
    let e = env_with_sources(&[&source.socket]).await;
    let e = fetch(&*e.service, &other, &dir.path().join("b.tar"))
        .await
        .unwrap_err();
    assert!(e.contains("decrypt"), "{e}");
    assert!(
        source.fetched.load(Ordering::SeqCst) <= 1,
        "only the manifest"
    );

    let mut bad = items;
    bad.remove(&digests[2]);
    let source = fake_source().await;
    *source.items.lock().unwrap() = bad;
    let e = env_with_sources(&[&source.socket]).await;
    assert!(fetch(&*e.service, &reference, &dir.path().join("d.tar"))
        .await
        .is_err());
}

/// An index that names more than its layer: files the layer does not use,
/// or more bytes than a layer of its size may hold.  What it made this
/// node fetch is not kept, and too much is not asked at all.
#[tokio::test]
async fn test_what_an_index_adds_is_not_kept_nor_asked() {
    let layer = build_gzip(&sample());
    let (mut toc, ts) =
        velarx_content::pull::index::decode(&index_of(&layer).await, 32 << 20).unwrap();
    // a file the tar-split never uses
    let junk = b"junk the peer wants stored".to_vec();
    let mut entry = toc
        .entries
        .iter()
        .find(|e| e.entry_type == velarx_storage::TocEntryType::Reg && e.size > 0)
        .unwrap()
        .clone();
    entry.name = "junk".into();
    entry.digest = Some(sha(&junk).to_string());
    entry.fsverity = velarx_storage::to_toc(&vid(&junk));
    entry.size = junk.len() as u64;
    toc.entries.push(entry.clone());
    let padded = index_of_toc(&toc, &ts);
    let source = fake_source().await;
    let mut items = file_map(&sample());
    items.insert(vid(&junk), junk.clone());
    items.insert(format!("index:{}", sha(&layer.blob)), padded);
    *source.items.lock().unwrap() = items;
    let e = env_with_sources(&[&source.socket]).await;
    e.publish(&[&layer], &[GZIP]);
    e.pull().await.unwrap();
    let rec = e.db.get_layer(&layer.key()).await.unwrap();
    assert_eq!(rec.diff_id.as_ref(), Some(&layer.diff_id));
    assert!(e.store.contains(&vid(&sample_big())));
    assert!(!e.store.contains(&vid(&junk)), "the junk was kept");
    assert_eq!(e.staged_leftovers(), 0);

    // a file of 1 TiB for a layer of a few KiB: nothing is asked
    let (mut toc, ts) =
        velarx_content::pull::index::decode(&index_of(&layer).await, 32 << 20).unwrap();
    entry.name = "huge".into();
    entry.digest = Some(sha(b"huge").to_string());
    entry.fsverity = velarx_storage::to_toc(&vid(b"huge"));
    entry.size = 1 << 40;
    toc.entries.push(entry);
    let huge = index_of_toc(&toc, &ts);
    let source = fake_source().await;
    let mut items = file_map(&sample());
    items.insert(format!("index:{}", sha(&layer.blob)), huge);
    *source.items.lock().unwrap() = items;
    let e = env_with_sources(&[&source.socket]).await;
    e.publish(&[&layer], &[GZIP]);
    e.pull().await.unwrap();
    assert_eq!(source.fetched.load(Ordering::SeqCst), 1, "only the index");
    assert_eq!(
        e.reg.hits.lock().unwrap().get(&sha(&layer.blob)).copied(),
        Some(1),
        "the registry gave it"
    );
}

/// The files a read-only store has that a pull names (a zstd:chunked TOC, or
/// the index a source gives for a gzip layer) are copied into the store to
/// be used, and the layer they make is complete.
#[tokio::test]
async fn test_a_pull_uses_the_files_of_a_read_only_store() {
    let dir = tempfile::tempdir().unwrap();
    let ro = velarx_storage::FileStore::new(dir.path().join("ro-objects")).unwrap();
    for (_, data) in file_map(&sample()) {
        ro.put(velarx_types::digest::Algorithm::Sha256, &data)
            .unwrap();
    }
    let chunked = build_chunked(&sample());
    let gzip = build_gzip(&sample());
    let source = fake_source().await;
    let index = index_of(&gzip).await;
    source
        .items
        .lock()
        .unwrap()
        .insert(format!("index:{}", sha(&gzip.blob)), index);
    for (layer, media, chain) in [
        (&chunked, ZSTD, Fetchers::default()),
        (&gzip, GZIP, chain_of(&[&source.socket])),
    ] {
        let e = env_sources_over(
            velarx_config::PullConfig::default(),
            velarx_config::PushConfig::default(),
            chain,
            Some(dir.path().join("ro-objects")),
        )
        .await;
        e.publish(&[layer], &[media]);
        e.pull().await.unwrap();
        let record =
            e.db.get_layer(&stored_key(&e.db, &sha(&layer.blob)).await)
                .await
                .unwrap();
        assert_eq!(record.status, "ready", "{media}");
        if media == GZIP {
            assert_eq!(record.diff_id.as_ref(), Some(&layer.diff_id));
        }
        assert!(e.store.contains_local(&vid(&sample_big())), "{media}");
    }
}

/// A pull with credentials asks the source that asks other nodes, as any
/// other pull, and takes the files from it.
#[tokio::test]
async fn test_a_pull_with_credentials_asks_the_peer_source() {
    use velarx_registry::auth::{Credentials, RegistryAccess};
    let layer = build_chunked(&sample());
    let source = fake_source().await;
    *source.items.lock().unwrap() = chunk_map(&sample());
    let e = env_with_sources(&[&source.socket]).await;
    e.publish(&[&layer], &[ZSTD]);
    let client = e.client().with_access(&RegistryAccess {
        creds: Some(Credentials::basic("alice", "secret")),
        ..Default::default()
    });
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let result = e
        .service
        .pull_with_client(&client, &format!("{}/test:latest", e.host), tx)
        .await
        .unwrap();
    assert!(source.has_calls.load(Ordering::SeqCst) > 0);
    assert!(source.fetched.load(Ordering::SeqCst) > 0);
    assert!(result.stats.from("source0").0 > 0);
    assert!(e.store.contains(&vid(&sample_big())));
}

/// A store of version 1, with the two tables of what could be given to
/// peers, loses them when it is opened, and pulls as any other.
#[tokio::test]
async fn test_a_store_with_the_old_tables_opens_and_pulls() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    let old = velarx_db::Database::open(&path).await.unwrap();
    old.conn()
        .call(|c| {
            Ok(c.execute_batch(
                "CREATE TABLE shared_layers (layer_id TEXT PRIMARY KEY, proven INTEGER);
                 CREATE TABLE shared_images (image_id TEXT, repository TEXT, tag TEXT);
                 INSERT INTO shared_layers VALUES ('l', 1);
                 INSERT INTO shared_images VALUES ('i', '', '');
                 PRAGMA user_version = 1;",
            )?)
        })
        .await
        .unwrap();
    old.close().await.unwrap();
    let db = velarx_db::Database::open(&path).await.unwrap();
    let e = env_on(
        db,
        velarx_config::PullConfig::default(),
        velarx_config::PushConfig::default(),
        Fetchers::default(),
        None,
    )
    .await;
    e.publish(&[&build_chunked(&sample())], &[ZSTD]);
    e.pull().await.unwrap();
    let tables: i64 =
        e.db.conn()
            .call(|c| {
                Ok(c.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name LIKE 'shared_%'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
    assert_eq!(tables, 0);
    assert!(e.store.contains(&vid(&sample_big())));
}

/// The index of the table of contents `toc` and the tar-split `ts`.
fn index_of_toc(toc: &velarx_storage::Toc, ts: &[u8]) -> Vec<u8> {
    let toc_z = zstd::encode_all(&serde_json::to_vec(toc).unwrap()[..], 3).unwrap();
    velarx_content::pull::index::encode_compressed(&toc_z, ts).unwrap()
}
