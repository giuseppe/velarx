// SPDX-License-Identifier: Apache-2.0
//! Fetchers before the registry fetcher: what they stage is verified like
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
            sharing(),
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
        a.db.get_layer(&stored_key(&a.db, &digest).await)
            .await
            .unwrap()
            .toc
            .unwrap();
    let tarsplit =
        a.db.get_layer_tarsplit(&stored_key(&a.db, &digest).await)
            .await
            .unwrap()
            .unwrap();
    velarx_content::pull::index::encode(toc.as_bytes(), &tarsplit).unwrap()
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
    let lying = velarx_content::pull::index::encode(
        serde_json::to_string(&toc).unwrap().as_bytes(),
        &other_ts,
    )
    .unwrap();
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

/// A pull with credentials may be of a private image: its sources are not
/// asked (they would learn its digests) and its layers are not shareable;
/// a pull without is, and the snapshot of the daemon tells only what is
/// shareable.
#[tokio::test]
async fn test_what_may_be_private_is_neither_asked_nor_told() {
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
    e.service
        .pull_with_client(&client, &format!("{}/test:latest", e.host), tx)
        .await
        .unwrap();
    assert_eq!(
        source.has_calls.load(Ordering::SeqCst),
        0,
        "a source was asked"
    );
    let digest = sha(&layer.blob);
    assert!(!e
        .db
        .is_layer_shareable(&stored_key(&e.db, &digest).await)
        .await
        .unwrap());
    assert!(!e.db.is_content_shareable(&vid(b"hello\n")).await.unwrap());
    let snapshot = velarx_core::store_service::Announcement::from_database(&e.db, true)
        .await
        .unwrap();
    assert!(snapshot.layers.is_empty() && snapshot.images.is_empty());

    let e = env_with_sources(&[&source.socket]).await;
    e.publish(&[&layer], &[ZSTD]);
    e.pull().await.unwrap();
    assert!(e
        .db
        .is_layer_shareable(&stored_key(&e.db, &digest).await)
        .await
        .unwrap());
    assert!(e.db.is_content_shareable(&vid(b"hello\n")).await.unwrap());
    let snapshot = velarx_core::store_service::Announcement::from_database(&e.db, true)
        .await
        .unwrap();
    assert_eq!(snapshot.layers, layer.announced_names());
    assert_eq!(snapshot.images.len(), 1);

    // a local name of the image, and an image no pull recorded (a commit
    // that changes the configuration only has the layers of the image)
    let image = snapshot.images[0].clone();
    assert_eq!(image.tags, vec![format!("{}/test:latest", e.host)]);
    e.db.insert_image_tag(&velarx_db::ImageTag {
        repository: "localhost/secret-project".into(),
        tag: "v2".into(),
        image_id: image.id.clone(),
    })
    .await
    .unwrap();
    let id = image.id.clone();
    e.db.conn()
        .call(move |c| {
            c.execute(
                "INSERT INTO images (id, manifest_digest, config_digest, manifest, config, created_at)
                 SELECT 'committed0000', 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', config_digest, manifest, config, created_at
                 FROM images WHERE id = ?1",
                [&id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    e.db.insert_image_tag(&velarx_db::ImageTag {
        repository: "localhost/committed".into(),
        tag: "latest".into(),
        image_id: "committed0000".into(),
    })
    .await
    .unwrap();
    let snapshot = velarx_core::store_service::Announcement::from_database(&e.db, true)
        .await
        .unwrap();
    assert_eq!(snapshot.images.len(), 1);
    assert_eq!(snapshot.images[0].id, image.id);
    assert_eq!(snapshot.images[0].tags, image.tags);
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
    let padded =
        velarx_content::pull::index::encode(serde_json::to_string(&toc).unwrap().as_bytes(), &ts)
            .unwrap();
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
    let huge =
        velarx_content::pull::index::encode(serde_json::to_string(&toc).unwrap().as_bytes(), &ts)
            .unwrap();
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

/// A public image that names the digest and diff id of a private layer
/// the store has (they leak through inspect, SBOMs, logs) does not make it
/// shareable, whatever its repository says: only what a pull fetched and
/// checked is.
#[tokio::test]
async fn test_a_public_image_does_not_make_a_private_layer_shareable() {
    use velarx_registry::auth::{Credentials, RegistryAccess};
    let e = env_sharing().await;
    let private = build_gzip(&sample());
    let public = build_gzip(&sample()[..2]);
    e.publish(&[&private], &[GZIP]);
    let creds = e.client().with_access(&RegistryAccess {
        creds: Some(Credentials::basic("alice", "secret")),
        ..Default::default()
    });
    let pull = |client: velarx_registry::target::Resolver, image: String| {
        let service = e.service.clone();
        async move {
            let (tx, mut rx) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            service.pull_with_client(&client, &image, tx).await
        }
    };
    pull(creds, format!("{}/test:latest", e.host))
        .await
        .unwrap();
    let (p, q) = (sha(&private.blob), sha(&public.blob));
    assert!(!e
        .db
        .is_layer_shareable(&stored_key(&e.db, &p).await)
        .await
        .unwrap());

    // a public image of the private layer and another: the registry even
    // answers for the private one
    publish_arch(&e.reg, &[&private, &public], &[GZIP, GZIP], "amd64", "pub1");
    pull(e.client(), format!("{}/test:pub1", e.host))
        .await
        .unwrap();
    assert!(
        e.db.is_layer_shareable(&stored_key(&e.db, &q).await)
            .await
            .unwrap(),
        "the layer it fetched"
    );
    assert!(
        !e.db
            .is_layer_shareable(&stored_key(&e.db, &p).await)
            .await
            .unwrap(),
        "the private layer"
    );
    assert!(!e
        .db
        .is_content_shareable(&vid(&sample_big()))
        .await
        .unwrap());
}

/// A layer made from an index is not shareable: its blob was never seen.
/// A peer offers a fake gzip layer (a digest of its own) with the diff id,
/// TOC and tar-split of a private layer of the victim; the victim's public
/// pull rebuilds it from its private files: neither the layer nor those
/// files become shareable.
#[tokio::test]
async fn test_a_layer_rebuilt_from_an_index_is_not_shareable() {
    use velarx_registry::auth::{Credentials, RegistryAccess};
    let private = build_gzip(&sample());
    let source = fake_source().await;
    let e = env_with_sources(&[&source.socket]).await;
    // the victim's private image
    e.publish(&[&private], &[GZIP]);
    let creds = e.client().with_access(&RegistryAccess {
        creds: Some(Credentials::basic("alice", "secret")),
        ..Default::default()
    });
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    e.service
        .pull_with_client(&creds, &format!("{}/test:latest", e.host), tx)
        .await
        .unwrap();
    // the fake layer: other bytes, the private layer's diff id; its index
    // is the private layer's, offered by the peer
    let fake = Built {
        blob: b"not the layer".to_vec(),
        diff_id: private.diff_id,
        annotations: Default::default(),
    };
    let x = sha(&fake.blob);
    let index = index_of(&private).await;
    source
        .items
        .lock()
        .unwrap()
        .insert(format!("index:{x}"), index);
    publish_arch(&e.reg, &[&fake], &[GZIP], "amd64", "evil");
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    e.service
        .pull_with_client(&e.client(), &format!("{}/test:evil", e.host), tx)
        .await
        .unwrap();
    assert_eq!(
        e.reg.hits.lock().unwrap().get(&x).copied().unwrap_or(0),
        0,
        "the layer came from the index"
    );
    assert_eq!(
        e.db.get_layer(&stored_key(&e.db, &x).await)
            .await
            .unwrap()
            .diff_id
            .as_ref(),
        Some(&private.diff_id)
    );
    assert!(!e
        .db
        .is_layer_shareable(&stored_key(&e.db, &x).await)
        .await
        .unwrap());
    assert!(!e
        .db
        .is_content_shareable(&vid(&sample_big()))
        .await
        .unwrap());
}

/// Nothing is shared unless the configuration says so: an anonymous pull
/// of a registry it does not list is private.
#[tokio::test]
async fn test_nothing_is_shared_by_default() {
    let e = env().await;
    let layer = build_gzip(&sample());
    e.publish(&[&layer], &[GZIP]);
    e.pull().await.unwrap();
    assert!(!e.db.is_layer_shareable(&layer.key()).await.unwrap());
    let e = env_sharing().await;
    e.publish(&[&layer], &[GZIP]);
    e.pull().await.unwrap();
    assert!(e.db.is_layer_shareable(&layer.key()).await.unwrap());
}

/// A client certificate is a credential: what is pulled with one may be
/// private.
#[tokio::test]
async fn test_a_client_certificate_is_a_credential() {
    use velarx_registry::auth::RegistryAccess;
    use velarx_registry::certs::RawCerts;
    let e = env().await;
    let layer = build_gzip(&sample());
    e.publish(&[&layer], &[GZIP]);
    let target = e
        .client()
        .target(&velarx_types::ImageReference::parse(&format!("{}/test:latest", e.host)).unwrap())
        .unwrap();
    assert!(!e.client().has_credentials(&target));
    // a client certificate of its own, self-signed
    let key = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let mut name = openssl::x509::X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "client").unwrap();
    let name = name.build();
    let mut b = openssl::x509::X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    b.sign(&key, openssl::hash::MessageDigest::sha256())
        .unwrap();
    let cert = b.build();
    let with_cert = e.client().with_access(&RegistryAccess {
        certs: Some(RawCerts {
            ca: vec![],
            cert: Some(String::from_utf8(cert.to_pem().unwrap()).unwrap()),
            key: Some(String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap()),
        }),
        ..Default::default()
    });
    let target = with_cert
        .target(&velarx_types::ImageReference::parse(&format!("{}/test:latest", e.host)).unwrap());
    assert!(with_cert.has_credentials(&target.unwrap()));
}

/// A zstd:chunked layer made of files the store had before its pull (of a
/// private image) is not given, though its pull was public: they may be
/// private files a public image names.  Fetched whole, or from the
/// sources, it is.
#[tokio::test]
async fn test_a_layer_of_files_the_store_had_is_not_shareable() {
    use velarx_registry::auth::{Credentials, RegistryAccess};
    let e = env_sharing().await;
    let private = build_gzip(&sample());
    e.publish(&[&private], &[GZIP]);
    let creds = e.client().with_access(&RegistryAccess {
        creds: Some(Credentials::basic("alice", "secret")),
        ..Default::default()
    });
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    e.service
        .pull_with_client(&creds, &format!("{}/test:latest", e.host), tx)
        .await
        .unwrap();
    // a public zstd:chunked layer of the same files
    let chunked = build_chunked(&sample());
    publish_arch(&e.reg, &[&chunked], &[ZSTD], "amd64", "chunked");
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    e.service
        .pull_with_client(&e.client(), &format!("{}/test:chunked", e.host), tx)
        .await
        .unwrap();
    let c = sha(&chunked.blob);
    assert_eq!(
        e.db.get_layer(&stored_key(&e.db, &c).await)
            .await
            .unwrap()
            .status,
        "ready"
    );
    assert!(!e
        .db
        .is_layer_shareable(&stored_key(&e.db, &c).await)
        .await
        .unwrap());
    assert!(!e
        .db
        .is_content_shareable(&vid(&sample_big()))
        .await
        .unwrap());

    let e = env_sharing().await;
    e.publish(&[&chunked], &[ZSTD]);
    e.pull().await.unwrap();
    assert!(e
        .db
        .is_layer_shareable(&stored_key(&e.db, &c).await)
        .await
        .unwrap());
    assert!(e
        .db
        .is_content_shareable(&vid(&sample_big()))
        .await
        .unwrap());
}

/// What the store service tells the peers this node has: the layers and
/// the images it may give.
async fn told(e: &Env) -> Vec<String> {
    let a = velarx_core::store_service::Announcement::from_database(&e.db, true)
        .await
        .unwrap();
    a.content.into_iter().chain(a.layers).collect()
}

/// Files a read-only store has (a private image's) that a public pull
/// names (a zstd:chunked TOC, or an index a peer crafted) are copied to be
/// used, but never announced nor given, and the layer they make is not
/// proven.
#[tokio::test]
async fn test_the_files_of_a_read_only_store_are_not_given() {
    let dir = tempfile::tempdir().unwrap();
    let ro = velarx_storage::FileStore::new(dir.path().join("ro-objects")).unwrap();
    for (_, data) in file_map(&sample()) {
        ro.put(velarx_types::digest::Algorithm::Sha256, &data)
            .unwrap();
    }
    let private: Vec<String> = file_map(&sample()).into_keys().collect();

    // a public zstd:chunked image of those files
    let e = env_sources_over(
        sharing(),
        velarx_config::PushConfig::default(),
        Fetchers::default(),
        Some(dir.path().join("ro-objects")),
    )
    .await;
    let chunked = build_chunked(&sample());
    e.publish(&[&chunked], &[ZSTD]);
    e.pull().await.unwrap();
    let c = sha(&chunked.blob);
    assert_eq!(
        e.db.get_layer(&stored_key(&e.db, &c).await)
            .await
            .unwrap()
            .status,
        "ready"
    );
    assert!(!e
        .db
        .is_layer_shareable(&stored_key(&e.db, &c).await)
        .await
        .unwrap());
    let all = told(&e).await;
    for d in &private {
        assert!(!all.contains(d), "{d} was announced");
        assert!(!e.db.is_content_shareable(d).await.unwrap());
    }
    assert!(!all.contains(&c.to_string()));

    // a gzip layer whose index a peer crafted to name them
    let layer = build_gzip(&sample());
    let source = fake_source().await;
    let index = index_of(&layer).await;
    source
        .items
        .lock()
        .unwrap()
        .insert(format!("index:{}", sha(&layer.blob)), index);
    let e = env_sources_over(
        sharing(),
        velarx_config::PushConfig::default(),
        chain_of(&[&source.socket]),
        Some(dir.path().join("ro-objects")),
    )
    .await;
    e.publish(&[&layer], &[GZIP]);
    e.pull().await.unwrap();
    let g = sha(&layer.blob);
    assert!(!e
        .db
        .is_layer_shareable(&stored_key(&e.db, &g).await)
        .await
        .unwrap());
    let all = told(&e).await;
    for d in &private {
        assert!(!all.contains(d), "{d} was announced");
        assert!(!e.db.is_content_shareable(d).await.unwrap());
    }
}

/// A file a public zstd:chunked TOC names whose content is one chunk of a
/// private file of the store is assembled from that chunk, but neither
/// told nor given while the pull runs nor after it: the TOC proves only
/// that its author knows the chunk's digest.
#[tokio::test]
async fn test_a_file_made_of_a_private_chunk_is_not_given() {
    use velarx_registry::auth::{Credentials, RegistryAccess};
    let e = env_sharing().await;
    // a private zstd:chunked image: the store has the chunks of usr/big
    let private = build_chunked(&sample());
    e.publish(&[&private], &[ZSTD]);
    let creds = e.client().with_access(&RegistryAccess {
        creds: Some(Credentials::basic("alice", "secret")),
        ..Default::default()
    });
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    e.service
        .pull_with_client(&creds, &format!("{}/test:latest", e.host), tx)
        .await
        .unwrap();

    // a public one of a file equal to the first chunk of usr/big
    let chunk = sample_big()[..16 * 1024].to_vec();
    let d = sha(&chunk);
    let public = build_chunked(&[Item::File {
        name: "usr/guess",
        data: chunk.clone(),
        chunk: 16 * 1024,
    }]);
    publish_arch(&e.reg, &[&public], &[ZSTD], "amd64", "chunked");
    let (tx, mut prx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while prx.recv().await.is_some() {} });
    e.service
        .pull_with_client(&e.client(), &format!("{}/test:chunked", e.host), tx)
        .await
        .unwrap();
    let p = sha(&public.blob);
    assert_eq!(
        e.db.get_layer(&stored_key(&e.db, &p).await)
            .await
            .unwrap()
            .status,
        "ready"
    );
    let all = told(&e).await;
    assert!(!all.contains(&p.to_string()));
    assert!(!e
        .db
        .is_layer_shareable(&stored_key(&e.db, &p).await)
        .await
        .unwrap());
    for d in [d.to_string(), vid(&chunk)] {
        assert!(!all.contains(&d), "the file of a private chunk was told");
        assert!(!e.db.is_content_shareable(&d).await.unwrap());
    }
}

/// A private pull (nothing is shared by default) asks the user's own
/// sources, not the peers: asking a peer tells what is pulled.  A pull
/// that may be shared asks both.
#[tokio::test]
async fn test_a_private_pull_asks_the_local_sources_not_the_peers() {
    let (local, peer) = (fake_source().await, fake_source().await);
    *local.items.lock().unwrap() = chunk_map(&sample());
    *peer.items.lock().unwrap() = chunk_map(&sample());
    let chain = chain_trusted(&[(&peer.socket, true), (&local.socket, false)]);
    let e = env_sources(
        velarx_config::PullConfig::default(),
        velarx_config::PushConfig::default(),
        chain.clone(),
    )
    .await;
    e.publish(&[&build_chunked(&sample())], &[ZSTD]);
    let result = e.pull().await.unwrap();
    assert_eq!(peer.has_calls.load(Ordering::SeqCst), 0);
    assert!(local.fetched.load(Ordering::SeqCst) > 0);
    assert!(result.stats.from("source1").0 > 0);
    assert!(e.store.contains(&vid(&sample_big())));

    // shared: the peer first
    let (local, peer) = (fake_source().await, fake_source().await);
    *local.items.lock().unwrap() = chunk_map(&sample());
    *peer.items.lock().unwrap() = chunk_map(&sample());
    let e = env_sources(
        sharing(),
        velarx_config::PushConfig::default(),
        chain_trusted(&[(&peer.socket, true), (&local.socket, false)]),
    )
    .await;
    e.publish(&[&build_chunked(&sample())], &[ZSTD]);
    e.pull().await.unwrap();
    assert!(peer.fetched.load(Ordering::SeqCst) > 0);
    assert_eq!(local.fetched.load(Ordering::SeqCst), 0);
}

/// The files of a lazily pulled private layer are not asked of the peers
/// either, only of the user's own sources.
#[tokio::test]
async fn test_a_lazy_file_of_a_private_pull_is_not_asked_of_the_peers() {
    let (local, peer) = (fake_source().await, fake_source().await);
    *local.items.lock().unwrap() = chunk_map(&sample());
    *peer.items.lock().unwrap() = chunk_map(&sample());
    let e = env_sources(
        velarx_config::PullConfig::default(),
        velarx_config::PushConfig::default(),
        chain_trusted(&[(&peer.socket, true), (&local.socket, false)]),
    )
    .await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    e.pull_lazy().await.unwrap();
    let big = sample_big();
    let path = e
        .service
        .fetch_lazy_file(&vid(&big), &layer.key())
        .await
        .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), big);
    assert_eq!(peer.has_calls.load(Ordering::SeqCst), 0);
    assert_eq!(peer.fetched.load(Ordering::SeqCst), 0);
    assert!(local.fetched.load(Ordering::SeqCst) > 0);
}

/// What a local source gives is the user's, like what the store has: a
/// public image naming it gets it, but neither the files nor the layer are
/// told or given (a public TOC may name a private file of a cache), while
/// the pull runs or after it.
#[tokio::test]
async fn test_what_a_local_source_gives_is_not_given() {
    let private: Vec<String> = file_map(&sample()).into_keys().collect();
    {
        let local = fake_source().await;
        let layer = build_chunked(&sample());
        *local.items.lock().unwrap() = chunk_map(&sample());
        let e = env_sources(
            sharing(),
            velarx_config::PushConfig::default(),
            chain_trusted(&[(&local.socket, false)]),
        )
        .await;
        e.publish(&[&layer], &[ZSTD]);
        let result = e.pull().await.unwrap();
        assert!(local.fetched.load(Ordering::SeqCst) > 0);
        assert!(result.stats.from("source0").0 > 0);
        let l = sha(&layer.blob);
        assert_eq!(
            e.db.get_layer(&stored_key(&e.db, &l).await)
                .await
                .unwrap()
                .status,
            "ready"
        );
        assert!(!e
            .db
            .is_layer_shareable(&stored_key(&e.db, &l).await)
            .await
            .unwrap(),);
        let all = told(&e).await;
        assert!(!all.contains(&l.to_string()));
        for d in &private {
            assert!(!all.contains(d), "{d} was told");
            assert!(!e.db.is_content_shareable(d).await.unwrap());
        }
    }
}
