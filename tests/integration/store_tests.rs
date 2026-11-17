// SPDX-License-Identifier: Apache-2.0
//! The store after pulls: concurrent pulls, leftovers and the check that
//! finds them.

use crate::common::*;

fn layer() -> Built {
    build_gzip(&sample())
}

fn hits(e: &Env, digest: &Digest) -> usize {
    e.reg.hits.lock().unwrap().get(digest).copied().unwrap_or(0)
}

#[tokio::test]
async fn test_concurrent_pulls_of_one_image_download_it_once() {
    let e = env().await;
    let l = layer();
    e.publish(&[&l], &[GZIP]);
    e.reg
        .delay_ms
        .store(100, std::sync::atomic::Ordering::SeqCst);
    let (a, b, c) = tokio::join!(e.pull(), e.pull(), e.pull());
    let (a, b, c) = (a.unwrap(), b.unwrap(), c.unwrap());
    assert_eq!(a.id, b.id);
    assert_eq!(a.id, c.id);
    assert_eq!(hits(&e, &sha(&l.blob)), 1);
    // The ones that waited found everything stored.
    let cached = [&a, &b, &c]
        .iter()
        .filter(|r| r.stats.layers_cached == 1)
        .count();
    assert_eq!(cached, 2);
    assert_eq!(e.db.list_images().await.unwrap().len(), 1);
    assert_eq!(e.staged_leftovers(), 0);
}

/// An image whose id (a prefix of its digest, as ids were made) is taken by
/// another manifest is still pulled, and both are found.
#[tokio::test]
async fn an_id_taken_by_another_manifest_does_not_block_a_pull() {
    let e = env().await;
    let l = layer();
    e.publish(&[&l], &[GZIP]);
    let first = e.pull().await.unwrap();
    let image = e.db.get_image(&first.id).await.unwrap();
    let bare = image.manifest_digest.hex();
    let bare = bare.as_str();
    assert_eq!(first.id, bare, "a new image has the whole digest as id");
    e.service.remove(&first.id, true).await.unwrap();

    let squatter = velarx_db::ImageRecord {
        id: bare[..12].to_string(),
        manifest_digest: sha(b"squatter"),
        config_digest: sha(b"squatter-config"),
        manifest: "{}".into(),
        config: "{}".into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        is_lazy: false,
    };
    e.db.insert_image(&squatter).await.unwrap();

    let again = e.pull().await.unwrap();
    assert_eq!(again.id, bare);
    assert_eq!(e.db.list_images().await.unwrap().len(), 2);
    // the short id is the one that holds it; a longer prefix is the image's
    assert_eq!(e.service.get(&bare[..12]).await.unwrap().id, bare[..12]);
    assert_eq!(e.service.get(&bare[..20]).await.unwrap().id, bare);
    assert_eq!(e.service.get(bare).await.unwrap().id, bare);
    // a prefix both have designates none, as with podman
    assert!(matches!(
        e.service.get(&bare[..8]).await,
        Err(velarx_types::ImageError::NotFound(_))
    ));
    e.service.remove(&again.id, true).await.unwrap();
    assert!(e.service.get(&bare[..12]).await.is_ok());
}

#[tokio::test]
async fn test_images_with_a_layer_in_common_fetch_it_once() {
    let e = env().await;
    let shared = layer();
    let own = build_gzip(&[Item::Dir("own/")]);
    publish_arch(&e.reg, &[&shared], &[GZIP], "amd64", "latest");
    publish_arch(&e.reg, &[&shared, &own], &[GZIP, GZIP], "amd64", "other");
    e.reg
        .delay_ms
        .store(100, std::sync::atomic::Ordering::SeqCst);
    let first = e.pull();
    let second = async {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        e.service
            .pull_with_client(&e.client(), &format!("{}/test:other", e.host), tx)
            .await
    };
    let (a, b) = tokio::join!(first, second);
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_ne!(a.id, b.id);
    assert_eq!(hits(&e, &sha(&shared.blob)), 1);
    assert_eq!(hits(&e, &sha(&own.blob)), 1);
    assert_eq!(e.db.list_images().await.unwrap().len(), 2);
}

/// An image of a layer that only a read-only store has is pulled into
/// this store, with the files of that layer of its own.
#[tokio::test]
async fn test_a_layer_of_a_read_only_store_is_pulled_again() {
    let dir = tempfile::tempdir().unwrap();
    let ro_path = dir.path().join("ro.sqlite");
    let shared = layer();
    let own = build_gzip(&[Item::Dir("own/")]);
    let ro_env = env_on(
        velarx_db::Database::open(&ro_path).await.unwrap(),
        velarx_config::PullConfig::default(),
        velarx_config::PushConfig::default(),
        Fetchers::default(),
        None,
    )
    .await;
    ro_env.publish(&[&shared], &[GZIP]);
    ro_env.pull().await.unwrap();
    let ro_objects = ro_env._tmp.path().join("objects");
    // (a store is read-only once its owner has flushed its WAL)
    ro_env.db.checkpoint().await.unwrap();

    let ro = velarx_db::Database::open_read_only(&ro_path).await.unwrap();
    let main = velarx_db::Database::open_in_memory()
        .await
        .unwrap()
        .with_additional(vec![ro]);
    let e = env_on(
        main,
        velarx_config::PullConfig::default(),
        velarx_config::PushConfig::default(),
        Fetchers::default(),
        Some(ro_objects),
    )
    .await;
    e.publish(&[&shared, &own], &[GZIP, GZIP]);
    let pulled = e.pull().await.unwrap();
    let layers = e.db.get_image_layers(&pulled.id).await.unwrap();
    assert_eq!(layers.len(), 2);
    assert!(e.db.get_own_layer(&shared.key()).await.is_ok());
    for item in sample() {
        if let Item::File { data, .. } = item {
            if !data.is_empty() {
                let d = vid(&data);
                assert!(e.store.contains_local(&d), "{d} is not in this store");
            }
        }
    }
}

#[tokio::test]
async fn test_a_failed_pull_does_not_hold_its_layers() {
    let e = env().await;
    let l = layer();
    e.publish(&[&l], &[GZIP]);
    // The first pull fails (the blob is corrupt) and releases the layer.
    let good = e
        .reg
        .blobs
        .lock()
        .unwrap()
        .get(&sha(&l.blob).to_string())
        .cloned()
        .unwrap();
    e.reg
        .blobs
        .lock()
        .unwrap()
        .insert(sha(&l.blob).to_string(), b"corrupt".to_vec());
    assert!(e.pull().await.is_err());
    e.reg
        .blobs
        .lock()
        .unwrap()
        .insert(sha(&l.blob).to_string(), good);
    e.pull().await.unwrap();
}

fn record(id: &str, manifest: &str, config: &str) -> velarx_db::ImageRecord {
    velarx_db::ImageRecord {
        id: id.to_string(),
        manifest_digest: format!("sha256:{manifest}").parse().unwrap(),
        config_digest: format!("sha256:{config}").parse().unwrap(),
        manifest: "{}".into(),
        config: "{}".into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        is_lazy: false,
    }
}

/// podman's lookup of an image: a full id is an id; else a name, then an id
/// (the whole one first) or the unique prefix of one; a prefix of several
/// designates none.  Observed with podman 5.8.
#[tokio::test]
async fn an_image_is_found_by_name_or_id_as_podman_does() {
    use velarx_types::ImageError;
    let e = env().await;
    let h = |c: char, n: usize| c.to_string().repeat(n);
    let (a, b, c) = (
        format!("ab{}", h('1', 62)),
        format!("ab{}", h('2', 62)),
        format!("cd{}", h('3', 62)),
    );
    // the first 12 digits of c are the whole id of another image
    let short = c[..12].to_string();
    for r in [
        record(&a, &a, &h('5', 64)),
        record(&b, &b, &h('6', 64)),
        record(&c, &c, &h('7', 64)),
        record(&short, &h('4', 64), &h('8', 64)),
    ] {
        e.db.insert_image(&r).await.unwrap();
    }
    let id = |r: &str| {
        let r = r.to_string();
        let service = e.service.clone();
        async move { service.get(&r).await.map(|i| i.id) }
    };
    assert_eq!(id(&a).await.unwrap(), a);
    assert_eq!(id(&format!("sha256:{a}")).await.unwrap(), a);
    assert_eq!(id("ab1").await.unwrap(), a);
    assert_eq!(id("ab2").await.unwrap(), b);
    // a prefix of several images is none of them
    for p in ["a", "ab", "c", "cd33"] {
        assert!(matches!(id(p).await, Err(ImageError::NotFound(_))), "{p}");
    }
    // the whole id wins over the longer ids it starts
    assert_eq!(id(&short).await.unwrap(), short);
    assert_eq!(id(&c[..13]).await.unwrap(), c);
    // the config digest is an id too (podman's)
    assert_eq!(id(&h('6', 20)).await.unwrap(), b);
    // sha256: wants the whole digest
    let short = id("sha256:ab1").await.unwrap_err();
    assert_eq!(
        short.to_string(),
        "sha256:ab1: invalid format: no 64-byte hexadecimal value"
    );
    assert!(matches!(short, ImageError::Invalid(_)));
    // capitals are no id, and no repository
    let upper = id(&a.to_uppercase()).await.unwrap_err();
    assert_eq!(
        upper.to_string(),
        format!(
            "parsing reference \"{}\": repository name must be lowercase",
            a.to_uppercase()
        )
    );
    assert!(matches!(
        id(&format!("sha256:{}", a.to_uppercase())).await,
        Err(ImageError::Invalid(_))
    ));
    // a 65th digit is nothing
    assert!(matches!(
        id(&format!("{a}0")).await,
        Err(ImageError::NotFound(_))
    ));
    // a name wins over an id prefix
    e.db.insert_image_tag(&velarx_db::ImageTag {
        repository: "localhost/ab1".into(),
        tag: "latest".into(),
        image_id: b.clone(),
    })
    .await
    .unwrap();
    assert_eq!(id("ab1").await.unwrap(), b);
    assert_eq!(id(&a).await.unwrap(), a, "(a full id is never a name)");
}

/// podman stores one image per configuration: a second manifest of it (a
/// load of a saved archive, a pull from another registry) becomes the
/// image's default one (c/image storage_dest.go commitWithOptions sets
/// ImageDigestBigDataKey on the image of that id).  Its id designates the
/// record stored last, not an error and not the first.
#[tokio::test]
async fn the_id_of_a_configuration_stored_twice_is_its_last_manifest() {
    let e = env().await;
    let h = |c: char| c.to_string().repeat(64);
    let config = h('9');
    let (first, second) = (h('a'), h('b'));
    e.db.insert_image(&record(&first, &first, &config))
        .await
        .unwrap();
    e.db.insert_image(&velarx_db::ImageRecord {
        created_at: "2026-01-02T00:00:00Z".into(),
        ..record(&second, &second, &config)
    })
    .await
    .unwrap();
    for r in [
        config.clone(),
        format!("sha256:{config}"),
        config[..12].into(),
    ] {
        assert_eq!(e.service.get(&r).await.unwrap().id, second, "{r}");
    }
}
