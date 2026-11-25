// SPDX-License-Identifier: Apache-2.0
//! Pulls against an in-process registry that serves synthetic layers
//! (zstd:chunked, gzip) with range requests, to check the pull engine end to
//! end: digests, the diff id binding, fallbacks and hostile responses.

use crate::common::*;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use velarx_config::PullConfig;

#[tokio::test]
async fn test_chunked_layer_is_pulled_by_ranges_and_bound_to_the_diff_id() {
    let e = env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    let result = e.pull().await.unwrap();
    assert!(e.reg.ranged.load(Ordering::SeqCst) > 0, "no range request");
    assert_eq!(result.stats.layers.len(), 1);

    let rec = e.db.get_layer(&layer.key()).await.unwrap();
    assert_eq!(rec.status, "ready");
    // (a layer of a table of contents is verified by its table: no diff id
    // until a recreation of its stream checks one)
    assert_eq!(rec.diff_id, None);
    let toc = stored_toc(&e.db, &layer.key()).await;
    assert_eq!(
        names(&toc),
        [
            "etc",
            "etc/small",
            "etc/copy",
            "etc/empty",
            "usr/big",
            "usr/holes",
            "etc/link"
        ]
    );
    // The tar-split is kept: it gives back the stream of the diff id.
    let stored = velarx_content::layer::reproduce::StoredLayer::load_expecting(
        &e.db,
        &layer.key(),
        None,
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
    let small = vid(b"hello\n");
    assert_eq!(
        std::fs::read(e.store.local_path(&small).unwrap()).unwrap(),
        b"hello\n"
    );
    let holes = toc.find_by_name("usr/holes").unwrap();
    let content = std::fs::read(e.store.local_path(&holes.verity().unwrap()).unwrap()).unwrap();
    assert_eq!(content.len(), 16384);
    assert!(content[4096..12288].iter().all(|&b| b == 0));
    assert_eq!(e.staged_leftovers(), 0);
    // Chunk locations are recorded for later pulls: the replay hashed each
    // chunk of the staged files at the offsets the verified table gives
    // (the fetcher's check of a chunk proves nothing to the engine).
    for (data, offset) in [(vec![1u8; 4096], 0), (vec![2u8; 4096], 12288)] {
        let at =
            e.db.get_chunk_location(&sha(&data))
                .await
                .unwrap()
                .expect("the place of a chunk the replay checked");
        assert_eq!((at.offset, at.size), (offset, 4096));
    }
}

/// The fs-verity digests a TOC gives are kept in the stored TOC, eager or
/// lazy, and a file whose content does not have its digest fails the pull.
#[tokio::test]
async fn test_the_fs_verity_digests_of_the_toc_are_kept_and_checked() {
    let layer = build_chunked_verity(&sample(), &|_, d| Some(toc_verity(d)));
    for lazy in [false, true] {
        let e = env().await;
        e.publish(&[&layer], &[ZSTD]);
        if lazy {
            e.pull_lazy().await.unwrap();
        } else {
            e.pull().await.unwrap();
        }
        // (a lazy pull's layer is staged, not in the store)
        let toc = match lazy {
            true => staged_toc(&e.area().layer(&layer.key()).unwrap().unwrap()),
            false => stored_toc(&e.db, &layer.key()).await,
        };
        let regs: Vec<_> = toc
            .entries
            .iter()
            .filter(|e| e.entry_type == velarx_storage::TocEntryType::Reg && e.size > 0)
            .collect();
        assert_eq!(regs.len(), 4);
        for r in regs {
            let v = r
                .verity()
                .unwrap_or_else(|| panic!("{} has no fs-verity digest", r.name));
            if !lazy {
                assert!(e.store.contains(&v), "{}", r.name);
            }
        }
    }
    let wrong = build_chunked_verity(&sample(), &|name, d| {
        Some(toc_verity(if name == "usr/big" { b"other" } else { d }))
    });
    let e = env().await;
    e.publish(&[&wrong], &[ZSTD]);
    let err = e.pull().await.unwrap_err().to_string();
    assert!(
        err.contains("usr/big") && err.contains("fs-verity"),
        "{err}"
    );
    assert!(e.db.list_images().await.unwrap().is_empty());
}

/// An image whose manifest states the digest of its merged EROFS is
/// recorded only if the one its layers make has it; a lazy one is completed
/// only then.
#[tokio::test]
async fn test_the_merged_erofs_must_be_the_one_the_manifest_states() {
    const KEY: &str = "composefs.merged.erofs.v1.fsverity-sha256-12";
    let layer = build_chunked_verity(&sample(), &|_, d| Some(toc_verity(d)));
    let e = env().await;
    publish_annotated(
        &e.reg,
        &[&layer],
        &[ZSTD],
        "amd64",
        "latest",
        serde_json::json!({ KEY: "ab".repeat(32) }),
    );
    let err = e.pull().await.unwrap_err().to_string();
    assert!(err.contains(KEY), "{err}");
    assert!(e.db.list_images().await.unwrap().is_empty());
    let lazy = e.pull_lazy().await.unwrap();
    let err = e
        .service
        .complete_image(&lazy.id)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains(KEY), "{err}");
    assert!(e.service.get(&lazy.id).await.is_err(), "still being pulled");
    let bad = serde_json::json!({ KEY: "not a digest" });
    let e = env().await;
    publish_annotated(&e.reg, &[&layer], &[ZSTD], "amd64", "latest", bad);
    assert!(e.pull().await.is_err());
}

/// The annotation of a layer descriptor with the digests of the EROFS image of
/// its layer (podman's `composefs-verity` branch).
const LAYER_KEY: &str = "io.containers.composefs.digest";

/// `layer` with this value for the annotation.
fn annotated_layer(layer: &Built, value: &str) -> Built {
    let mut l = Built {
        blob: layer.blob.clone(),
        diff_id: layer.diff_id,
        annotations: layer.annotations.clone(),
    };
    l.annotations.insert(LAYER_KEY.into(), value.into());
    l
}

/// The digest of the EROFS image velarx makes of `layer`.
async fn erofs_of(layer: &Built) -> String {
    let e = env().await;
    e.publish(&[layer], &[ZSTD]);
    e.pull().await.unwrap();
    e.db.get_layer(&layer.key()).await.unwrap().erofs.unwrap()
}

/// A list of digests the manifest states for a layer that has the one of the
/// EROFS image velarx makes of it is right (one of a list is enough); a list
/// that has none of ours is another writer's: the pull works (eager or lazy)
/// and holds the layer to its record, and under `composefs_digests =
/// "require"` it fails with nothing stored; none is fine.
#[tokio::test]
async fn test_the_layer_erofs_digest_the_manifest_states_is_checked() {
    let layer = build_chunked_verity(&sample(), &|_, d| Some(toc_verity(d)));
    let ours = erofs_of(&layer).await;
    let other = "ab".repeat(32);
    for lazy in [false, true] {
        for value in [
            ours.clone(),
            format!("sha256:{other},{ours}"),
            format!("{ours}, sha256:{other}"),
        ] {
            let e = env().await;
            e.publish(&[&annotated_layer(&layer, &value)], &[ZSTD]);
            let image = if lazy {
                e.pull_lazy().await
            } else {
                e.pull().await
            }
            .unwrap_or_else(|err| panic!("{value}: {err}"));
            let manifest = match lazy {
                true => e.area().pull(&image.id).unwrap().unwrap().manifest,
                false => e.service.get(&image.id).await.unwrap().manifest,
            };
            assert!(manifest.contains(&value));
            // the completion commits the layers with the images made at the
            // pull: the same digests
            if lazy {
                e.service.complete_image(&image.id).await.unwrap();
                assert!(e
                    .service
                    .get(&image.id)
                    .await
                    .unwrap()
                    .manifest
                    .contains(&value));
            }
        }
        for value in [
            format!("sha256:{other}"),
            format!("sha256:{other},sha256:{}", "cd".repeat(32)),
            ours.to_uppercase(),
            ours.strip_prefix("sha256:").unwrap().to_string(),
            format!("sha512:{},,", "ab".repeat(64)),
            "sha256:zz".to_string(),
            String::new(),
        ] {
            let e = env().await;
            e.publish(&[&annotated_layer(&layer, &value)], &[ZSTD]);
            let image = if lazy {
                e.pull_lazy().await
            } else {
                e.pull().await
            }
            .unwrap_or_else(|err| panic!("{value}: {err}"));
            if lazy {
                e.service.complete_image(&image.id).await.unwrap();
            }
            assert_eq!(
                e.db.get_layer(&layer.key()).await.unwrap().erofs,
                Some(ours.clone()),
                "{value}"
            );
            let e = env_built(
                velarx_db::Database::open_in_memory().await.unwrap(),
                PullConfig::default(),
                velarx_config::PushConfig::default(),
                Fetchers::default(),
                None,
                |service| service.with_composefs_digests(velarx_config::ComposefsDigests::Require),
            )
            .await;
            e.publish(&[&annotated_layer(&layer, &value)], &[ZSTD]);
            let err = if lazy {
                e.pull_lazy().await
            } else {
                e.pull().await
            }
            .unwrap_err();
            assert!(
                matches!(err, velarx_types::ImageError::ComposefsDigest(_)),
                "{value}: {err}"
            );
            let msg = err.to_string();
            assert!(
                msg.contains(LAYER_KEY) && msg.contains(&sha(&layer.blob).to_string()),
                "{msg}"
            );
            assert!(e.db.list_images().await.unwrap().is_empty());
            let left = velarx_fuse::composefs::layer_image_path(
                e.store.root(),
                &sha(&layer.blob).to_string(),
            );
            assert!(!left.exists(), "{}", left.display());
            // (nor is any file of the layer named in the store)
            assert!(!e.store.contains(&vid(b"hello\n")), "{value}");
        }
    }
}

/// `[storage] composefs_digests = "require"`: every layer of a pulled image
/// states a digest.
#[tokio::test]
async fn test_composefs_digests_require_refuses_an_image_that_states_none() {
    let layer = build_chunked_verity(&sample(), &|_, d| Some(toc_verity(d)));
    let ours = erofs_of(&layer).await;
    for lazy in [false, true] {
        let require = || async {
            env_built(
                velarx_db::Database::open_in_memory().await.unwrap(),
                PullConfig::default(),
                velarx_config::PushConfig::default(),
                Fetchers::default(),
                None,
                |service| service.with_composefs_digests(velarx_config::ComposefsDigests::Require),
            )
            .await
        };
        let e = require().await;
        e.publish(&[&layer], &[ZSTD]);
        let err = if lazy {
            e.pull_lazy().await
        } else {
            e.pull().await
        }
        .unwrap_err();
        assert!(
            matches!(err, velarx_types::ImageError::ComposefsDigest(_)),
            "{err}"
        );
        assert!(err.to_string().contains("composefs_digests"), "{err}");
        assert!(e.db.list_images().await.unwrap().is_empty());
        let e = require().await;
        e.publish(&[&annotated_layer(&layer, &ours.clone())], &[ZSTD]);
        if lazy {
            e.pull_lazy().await
        } else {
            e.pull().await
        }
        .unwrap();
        let e = require().await;
        e.publish(
            &[&annotated_layer(
                &layer,
                &format!("sha256:{}", "ab".repeat(32)),
            )],
            &[ZSTD],
        );
        assert!(if lazy {
            e.pull_lazy().await
        } else {
            e.pull().await
        }
        .is_err());
    }
}

/// `require` that is newer than a stored image: the pull of an image the
/// store has already is refused too when its layers state no digest.
#[tokio::test]
async fn test_composefs_digests_require_applies_to_an_image_already_stored() {
    let layer = build_chunked_verity(&sample(), &|_, d| Some(toc_verity(d)));
    let mut e = env().await;
    e.publish(&[&layer], &[ZSTD]);
    e.pull().await.unwrap();
    let service = (*e.service)
        .clone()
        .with_composefs_digests(velarx_config::ComposefsDigests::Require);
    e.service = std::mem::ManuallyDrop::new(service);
    let err = e.pull().await.unwrap_err();
    assert!(
        matches!(err, velarx_types::ImageError::ComposefsDigest(_)),
        "{err}"
    );
}

/// The digests a start gives the monitor: the stored image of a pull, its
/// layers, and what `start_digests` says of it.
async fn stored_image(e: &Env, id: &str) -> (velarx_db::ImageRecord, Vec<velarx_db::LayerRecord>) {
    let image = e.service.get(id).await.unwrap();
    let layers = e.db.get_image_layers(&image.id).await.unwrap();
    (image, layers)
}

/// A start takes the list of each layer from the manifest as stored, not
/// from the record of the layer: a list is given whole, and a record the
/// manifest does not state is refused where the digests are enforced (the
/// list is another writer's, and the layer is held to its record, where they
/// are not).
#[tokio::test]
async fn test_a_start_takes_the_digests_from_the_stored_manifest() {
    let layer = build_chunked_verity(&sample(), &|_, d| Some(toc_verity(d)));
    let ours = erofs_of(&layer).await;
    let other = format!("sha256:{}", "ab".repeat(32));
    let list = format!("{other},{ours}");
    let e = env().await;
    e.publish(&[&annotated_layer(&layer, &list)], &[ZSTD]);
    let id = e.pull().await.unwrap().id;
    let (image, layers) = stored_image(&e, &id).await;
    for container in [false, true] {
        let enforcing = e.service.enforcing(container);
        let lists = e.service.start_digests(&image, &layers, enforcing).unwrap();
        assert_eq!(lists, [vec![other.clone(), ours.clone()]]);
    }
    // the record of the layer is not among the digests the manifest states
    e.db.set_layer_erofs(&layers[0].key, &other.replace("ab", "cd"), "[[],[]]")
        .await
        .unwrap();
    let (image, layers) = stored_image(&e, &id).await;
    let enforcing = e.service.enforcing(false);
    let lists = e.service.start_digests(&image, &layers, enforcing).unwrap();
    assert_eq!(lists, [vec![other.replace("ab", "cd")]]);
    let enforcing = e.service.enforcing(true);
    let err = e
        .service
        .start_digests(&image, &layers, enforcing)
        .unwrap_err();
    assert!(
        matches!(err, velarx_types::ImageError::ComposefsDigest(_)),
        "{err}"
    );
    assert!(
        err.to_string().contains("layer 1 of 1") && err.to_string().contains("verity=enforce"),
        "{err}"
    );
}

/// A manifest that was edited in the database after the pull is not the one
/// its id names: no start takes digests from it.
#[tokio::test]
async fn test_a_manifest_edited_after_the_pull_is_refused_at_the_start() {
    let layer = build_chunked_verity(&sample(), &|_, d| Some(toc_verity(d)));
    let ours = erofs_of(&layer).await;
    let e = env().await;
    e.publish(&[&annotated_layer(&layer, &ours)], &[ZSTD]);
    let id = e.pull().await.unwrap().id;
    let (mut image, layers) = stored_image(&e, &id).await;
    let enforcing = e.service.enforcing(true);
    e.service.start_digests(&image, &layers, enforcing).unwrap();
    // the digest the manifest states is changed to the one of another
    // image, and the layer record with it
    image.manifest = image
        .manifest
        .replace(&ours, &format!("sha256:{}", "ab".repeat(32)));
    let enforcing = e.service.enforcing(false);
    let err = e
        .service
        .start_digests(&image, &layers, enforcing)
        .unwrap_err();
    assert!(
        err.to_string().contains("is not the one its id names")
            && err.to_string().contains("pull the image again"),
        "{err}"
    );
}

/// An image without annotations (pulled before `require` was on, or made by
/// another writer) runs by default and is refused when the container asks
/// for `verity=enforce` or the node requires the digests.
#[tokio::test]
async fn test_an_image_without_annotations_is_refused_when_enforced() {
    let layer = build_chunked_verity(&sample(), &|_, d| Some(toc_verity(d)));
    let ours = erofs_of(&layer).await;
    let e = env().await;
    e.publish(&[&layer], &[ZSTD]);
    let id = e.pull().await.unwrap().id;
    let (image, layers) = stored_image(&e, &id).await;
    let enforcing = e.service.enforcing(false);
    let lists = e.service.start_digests(&image, &layers, enforcing).unwrap();
    assert_eq!(lists, vec![vec![ours]]);
    let enforcing = e.service.enforcing(true);
    let err = e
        .service
        .start_digests(&image, &layers, enforcing)
        .unwrap_err();
    assert!(
        matches!(err, velarx_types::ImageError::ComposefsDigest(_))
            && err.to_string().contains("layer 1 of 1")
            && err.to_string().contains("--security-opt verity=enforce"),
        "{err}"
    );
    let require = (*e.service)
        .clone()
        .with_composefs_digests(velarx_config::ComposefsDigests::Require);
    for container in [false, true] {
        let err = require
            .start_digests(&image, &layers, require.enforcing(container))
            .unwrap_err();
        assert!(err.to_string().contains("composefs_digests"), "{err}");
    }
}

/// A sparse file keeps its holes in the store, whatever the layer: the
/// zeros chunks of zstd:chunked are not written, nor are the blocks of
/// zeros of a stream.  A file of zeros chunks only is made whole too.
#[tokio::test]
async fn test_sparse_files_keep_their_holes() {
    use std::os::unix::fs::MetadataExt;
    let mut data = vec![1u8; 4096];
    data.extend(vec![0u8; 1 << 20]);
    data.extend(vec![2u8; 4096]);
    data.extend(vec![0u8; 1 << 20]);
    let zeros = vec![0u8; 1 << 20];
    let items = || {
        vec![
            Item::File {
                name: "usr/sparse",
                data: data.clone(),
                chunk: 4096,
            },
            Item::File {
                name: "usr/zeros",
                data: zeros.clone(),
                chunk: 4096,
            },
        ]
    };
    for (layer, media) in [
        (build_chunked(&items()), ZSTD),
        (build_gzip(&items()), GZIP),
    ] {
        let e = env().await;
        e.publish(&[&layer], &[media]);
        e.pull().await.unwrap();
        for content in [&data, &zeros] {
            let path = e.store.get_path(&vid(content)).unwrap();
            assert_eq!(&std::fs::read(&path).unwrap(), content);
            let blocks = std::fs::metadata(&path).unwrap().blocks();
            assert!(blocks <= 64, "{media}: {blocks} blocks of 512 bytes");
        }
    }
}

/// A layer whose TOC gives only the sha256 of its files (containers/storage
/// writes them so) is refused, eagerly and lazily, naming the layer and the file, and nothing of the image is stored, the layers above it either.
#[tokio::test]
async fn test_a_toc_without_fs_verity_digests_is_refused() {
    let base = build_chunked_plain(&sample());
    let top = build_chunked(&[
        Item::Dir("opt/"),
        Item::File {
            name: "opt/top",
            data: b"built on top\n".to_vec(),
            chunk: 4096,
        },
    ]);
    let e = env().await;
    e.publish(&[&base, &top], &[ZSTD, ZSTD]);
    let before = e.stored().await;
    for refused in [e.pull().await, e.pull_lazy().await] {
        let refused = refused.unwrap_err().to_string();
        assert!(refused.contains(&sha(&base.blob).to_string()), "{refused}");
        assert!(refused.contains("no fs-verity digest for `"), "{refused}");
        assert_eq!(e.stored().await, before);
    }
}

/// The layers pulled whole (gzip) are deduplicated against the store like
/// those of a table of contents: the files an image's layer shares with a
/// stored one are not fetched, and the report of the pull says so.
#[tokio::test]
async fn test_a_layer_pulled_whole_reuses_the_files_of_the_store() {
    let e = env().await;
    let big = sample()
        .into_iter()
        .find_map(|i| match i {
            Item::File {
                name: "usr/big",
                data,
                ..
            } => Some(data),
            _ => None,
        })
        .unwrap();
    let first = build_gzip(&sample());
    e.publish(&[&first], &[GZIP]);
    let one = e.pull().await.unwrap();
    // (the two names of "hello" are one file)
    assert_eq!(
        (
            one.stats.from("registry").1,
            one.stats.from("store").1,
            one.stats.layers[0].fetched_files
        ),
        (3, 1, 3),
        "{:?}",
        one.stats
    );
    let second = build_gzip(&[
        Item::Dir("usr/"),
        Item::File {
            name: "usr/big",
            data: big.clone(),
            chunk: 4096,
        },
        Item::File {
            name: "usr/own",
            data: b"only in the second\n".to_vec(),
            chunk: 4096,
        },
        Item::File {
            name: "usr/hello",
            data: b"hello\n".to_vec(),
            chunk: 4096,
        },
    ]);
    e.publish(&[&second], &[GZIP]);
    let two = e.pull().await.unwrap();
    assert_eq!(
        (
            two.stats.from("registry").1,
            two.stats.from("store").1,
            two.stats.layers[0].fetched_files,
            two.stats.layers[0].deduplicated_files
        ),
        // (the files the store has are told by the kernel's measure of the
        // staged file, which the replay takes before it reads it: where the
        // file system has no fs-verity nothing says the store has one
        // before the commit, which finds the name there)
        if two.stats.from("store").1 == 0 {
            (3, 0, 3, 0)
        } else {
            (1, 2, 1, 2)
        },
        "{:?}",
        two.stats
    );
    // the bytes of a stream cross the wire all the same
    assert!(two.stats.from("registry").0 > 0 && two.stats.from("store").0 == 0);
    for data in [&big[..], b"only in the second\n", b"hello\n"] {
        assert!(e.store.contains(&vid(data)));
    }
    assert_eq!(e.staged_leftovers(), 0);
}

#[tokio::test]
async fn test_second_pull_fetches_nothing() {
    let e = env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    e.pull().await.unwrap();
    let before = e.reg.requests.load(Ordering::SeqCst);
    let again = e.pull().await.unwrap();
    assert_eq!(e.reg.requests.load(Ordering::SeqCst), before);
    assert_eq!(again.stats.layers_cached, 1);
}

/// A chained driver (the conformance suite's double of a snapshot driver: it
/// holds layers by chain id and refuses a layer whose parent it does not
/// hold) pulls through the engine: the engine gives it the whole list of the
/// image, in order, with the OCI chain ids, the parents and the layers it has
/// marked `stored`, and asks `has_layers` per position.  An image on the same
/// base fetches only its own layer; the base again on top of the stack is
/// another chain, fetched for that place only.
#[tokio::test]
async fn test_a_chained_driver_gets_the_whole_stack_from_the_engine() {
    use velarx_graph::conformance::Chained;
    let held: Arc<std::sync::OnceLock<Arc<Chained>>> = Arc::default();
    let e = {
        let held = held.clone();
        env_built(
            velarx_db::Database::open_in_memory().await.unwrap(),
            PullConfig::default(),
            velarx_config::PushConfig::default(),
            Fetchers::default(),
            None,
            move |s| {
                let chained = Chained::of(s.storage().clone());
                let _ = held.set(chained.clone());
                s.with_storage_driver(chained)
            },
        )
        .await
    };
    let chained = held.get().unwrap().clone();
    let base = build_chunked(&sample());
    let top = build_chunked(&[Item::File {
        name: "top",
        data: b"top\n".to_vec(),
        chunk: 4096,
    }]);
    let blob = |b: &Built| {
        velarx_types::digest::Digest::of(velarx_types::digest::Algorithm::Sha256, &b.blob)
    };
    let hits = |b: &Built| {
        e.reg
            .hits
            .lock()
            .unwrap()
            .get(&blob(b))
            .copied()
            .unwrap_or(0)
    };
    let pull = |tag: &'static str| {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let (service, client, name) = (&e.service, e.client(), format!("{}/test:{tag}", e.host));
        async move { service.pull_with_client(&client, &name, tx).await }
    };
    e.publish(&[&base], &[ZSTD]);
    pull("latest").await.unwrap();
    let one = velarx_types::chain_ids(&[base.diff_id]);
    assert!(
        chained.holds(&one[0]),
        "the base is held under its chain id"
    );

    publish_arch(&e.reg, &[&base, &top], &[ZSTD, ZSTD], "amd64", "two");
    let (base_hits, top_hits) = (hits(&base), hits(&top));
    pull("two").await.expect("the top's parent is in the list");
    let two = velarx_types::chain_ids(&[base.diff_id, top.diff_id]);
    assert!(chained.holds(&two[1]));
    assert_eq!(hits(&base), base_hits, "the stored base is not fetched");
    assert!(hits(&top) > top_hits, "the top is fetched");

    // base, top, base: the third layer is the base's content on another
    // stack, not held: fetched for that place, and nothing else
    publish_arch(
        &e.reg,
        &[&base, &top, &base],
        &[ZSTD, ZSTD, ZSTD],
        "amd64",
        "three",
    );
    let (base_hits, top_hits) = (hits(&base), hits(&top));
    pull("three")
        .await
        .expect("a layer at another place is pulled");
    let three = velarx_types::chain_ids(&[base.diff_id, top.diff_id, base.diff_id]);
    assert!(chained.holds(&three[2]), "the third place is its own chain");
    assert_ne!(three[2], three[0]);
    assert!(
        hits(&base) > base_hits,
        "the base is fetched for its new place"
    );
    assert_eq!(hits(&top), top_hits, "the stored top is not fetched");
    let (base_hits, top_hits) = (hits(&base), hits(&top));
    pull("three").await.unwrap();
    assert_eq!((hits(&base), hits(&top)), (base_hits, top_hits));
}

/// The instance an index names is not asked of the registry when the store
/// has the manifest.
#[tokio::test]
async fn test_the_instance_of_an_index_the_store_has_is_not_asked_for() {
    let e = env().await;
    let layer = build_chunked(&sample());
    let digest = publish_arch(
        &e.reg,
        &[&layer],
        &[ZSTD],
        velarx_registry::target::host_arch(),
        "*",
    );
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": digest, "size": 1,
            "platform": {"architecture": velarx_registry::target::host_arch(), "os": "linux"},
        }],
    });
    e.reg
        .blobs
        .lock()
        .unwrap()
        .insert("manifest:latest".into(), index.to_string().into_bytes());
    let asked = || -> Vec<String> {
        let log = e.reg.log.lock().unwrap();
        log.iter()
            .filter_map(|l| l.strip_prefix("GET-MANIFEST ").map(str::to_string))
            .collect()
    };
    let first = e.pull().await.unwrap();
    assert_eq!(asked(), ["latest".to_string(), digest.to_string()]);
    let again = e.pull().await.unwrap();
    assert_eq!(again.id, first.id);
    assert_eq!(
        &asked()[2..],
        ["latest".to_string()],
        "the second pull asks for the index only"
    );
}

#[tokio::test]
async fn test_registry_that_ignores_ranges() {
    let e = env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    *e.reg.mode.lock().unwrap() = RangeMode::Ignore;
    e.pull().await.unwrap();
    assert!(e.store.contains(&vid(b"hello\n")));
}

#[tokio::test]
async fn test_registry_that_refuses_multiple_ranges() {
    let e = env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    *e.reg.mode.lock().unwrap() = RangeMode::SingleOnly;
    e.pull().await.unwrap();
    assert!(e.store.contains(&vid(b"hello\n")));
}

/// The bytes the `Range` header asks for.
fn asked(range: &str) -> u64 {
    parse_ranges(range, usize::MAX)
        .unwrap()
        .iter()
        .map(|(a, b)| (b - a + 1) as u64)
        .sum()
}

/// A range answer cut short: the retry asks only for what did not arrive.
#[tokio::test]
async fn test_a_cut_answer_is_resumed() {
    let e = env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    // the metadata first, untouched; then the first answer for the files
    e.pull_lazy().await.unwrap();
    e.reg.range_log.lock().unwrap().clear();
    e.reg.cut.store(1, Ordering::SeqCst);
    e.pull().await.unwrap();
    assert!(e.store.contains(&vid(b"hello\n")));
    let log = e.reg.range_log.lock().unwrap().clone();
    assert!(log.len() >= 2, "{log:?}");
    assert!(asked(&log[1]) < asked(&log[0]), "{log:?}");
}

/// Answers cut short every time: the retries go on while chunks arrive, and
/// stop after a few that bring none instead of asking forever: the pull of
/// the lazy image it joins fails, and the image stays a pull.
#[tokio::test]
async fn test_answers_that_bring_nothing_end_the_pull() {
    let e = env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    e.pull_lazy().await.unwrap();
    e.reg.range_log.lock().unwrap().clear();
    e.reg.cut.store(usize::MAX, Ordering::SeqCst);
    let ended = tokio::time::timeout(std::time::Duration::from_secs(30), e.pull())
        .await
        .expect("the pull must end");
    assert!(ended.is_err());
    let asked = e.reg.range_log.lock().unwrap().len();
    assert!(asked < 10, "{asked} range requests");
}

/// The TOC of a layer stored lazily is not fetched again by a pull (the
/// tar-split, which the lazy pull did without, is).
#[tokio::test]
async fn test_the_metadata_of_a_lazy_layer_is_not_fetched_again() {
    let e = env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    e.pull_lazy().await.unwrap();
    let position: Vec<usize> = layer.annotations
        ["io.github.containers.zstd-chunked.manifest-position"]
        .split(':')
        .map(|n| n.parse().unwrap())
        .collect();
    let toc = position[0]..position[0] + position[1];
    e.reg.range_log.lock().unwrap().clear();
    e.pull().await.unwrap();
    let rec = e.db.get_layer(&layer.key()).await.unwrap();
    assert_eq!(rec.status, "ready");
    for r in e.reg.range_log.lock().unwrap().iter() {
        for (a, b) in parse_ranges(r, usize::MAX).unwrap() {
            assert!(
                b < toc.start || a >= toc.end,
                "{r} reaches the TOC at {toc:?}"
            );
        }
    }
}

#[tokio::test]
async fn test_gzip_layer_is_streamed() {
    let e = env().await;
    let layer = build_gzip(&sample());
    e.publish(&[&layer], &[GZIP]);
    let result = e.pull().await.unwrap();
    assert_eq!(e.reg.ranged.load(Ordering::SeqCst), 0);
    assert_eq!(result.stats.from("registry").0, layer.blob.len() as u64);
    let toc = stored_toc(&e.db, &layer.key()).await;
    assert_eq!(
        toc.find_by_name("etc/link").unwrap().link_name.as_deref(),
        Some("small")
    );
    assert!(e.store.contains(&vid(b"hello\n")));
    assert!(!e.store.contains(&vid(b"")), "an empty file is no object");

    let stored = velarx_content::layer::reproduce::StoredLayer::load(&e.db, &layer.key())
        .await
        .unwrap();
    let mut tar = Vec::new();
    stored
        .verified_stream(e.store.clone())
        .unwrap()
        .read_to_end(&mut tar)
        .unwrap();
    assert_eq!(sha(&tar), layer.diff_id);
}

#[tokio::test]
async fn test_wrong_diff_id_is_refused_and_nothing_is_recorded() {
    // (a layer of a table of contents is verified by its table, and no
    // diff id is claimed for it before a recreation of its stream checks
    // one: only a layer of its blob is held to the diff id at the pull)
    for chunked in [false] {
        let e = env().await;
        let mut layer = if chunked {
            build_chunked(&sample())
        } else {
            build_gzip(&sample())
        };
        layer.diff_id = sha(b"another layer");
        let manifest = publish_to(&e.reg, &[&layer], &[if chunked { ZSTD } else { GZIP }]);
        assert!(e.pull().await.is_err());
        // (nor is the pull of the manifest recorded)
        assert!(e.db.pulled_image(&manifest).await.unwrap().is_empty());
        assert!(e.db.get_layer(&layer.key()).await.is_err());
        assert!(
            !e.store.contains(&vid(b"hello\n")),
            "staged content became visible"
        );
        assert_eq!(e.staged_leftovers(), 0);
        assert!(e.db.list_images().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn test_tampered_chunk_is_refused() {
    let e = env().await;
    let items = vec![Item::File {
        name: "f",
        data: (0..50_000u32).map(|i| (i % 253) as u8).collect(),
        chunk: 8192,
    }];
    let mut layer = build_chunked(&items);
    let victim = frame(&vec![9u8; 8192]);
    let original = frame(&(0..8192u32).map(|i| (i % 253) as u8).collect::<Vec<_>>());
    let at = layer
        .blob
        .windows(original.len())
        .position(|w| w == original)
        .unwrap();
    layer.blob.splice(at..at + original.len(), victim);
    e.publish(&[&layer], &[ZSTD]);
    assert!(e.pull().await.is_err());
    assert!(!e.store.contains(&vid(&vec![9u8; 8192])));
    assert_eq!(e.staged_leftovers(), 0);
}

#[tokio::test]
async fn test_path_traversal_in_a_layer_is_refused() {
    let e = env().await;
    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(1);
    h.set_mode(0o644);
    // append_data refuses "..": write the name by hand.
    h.as_old_mut().name[..8].copy_from_slice(b"../evil\0");
    h.set_cksum();
    b.append(&h, &b"x"[..]).unwrap();
    let tar = b.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar).unwrap();
    let layer = Built {
        diff_id: sha(&tar),
        blob: gz.finish().unwrap(),
        annotations: HashMap::new(),
    };
    e.publish(&[&layer], &[GZIP]);
    assert!(e.pull().await.is_err());
    assert!(!e.store.contains(&vid(b"x")));
}

#[tokio::test]
async fn test_decompression_bomb_is_bounded() {
    // 40 MiB of zeros in a file, with a bound of 32 times the blob (at
    // least 1 MiB): the registry fetcher's workers refuse it
    let e = env_with(PullConfig {
        max_inflate_ratio: 32,
        inflate_floor_mib: 1,
        ..PullConfig::default()
    })
    .await;
    let bomb = vec![0u8; 40 << 20];
    let layer = build_gzip(&[Item::File {
        name: "z",
        data: bomb,
        chunk: 1,
    }]);
    e.publish(&[&layer], &[GZIP]);
    let err = e.pull().await.expect_err("the bomb must be refused");
    assert!(err.to_string().contains("larger than"), "{err}");
    assert!(err.to_string().contains("max_inflate_ratio"), "{err}");
    assert!(!e.store.contains(&vid(&vec![0u8; 40 << 20])));
}

#[tokio::test]
async fn test_registry_that_lies_about_ranges_cannot_corrupt_the_image() {
    let e = env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    *e.reg.mode.lock().unwrap() = RangeMode::Lie;
    // The chunks are not what the TOC says: the registry's answer to the
    // ranges contradicts the descriptor, and the pull is refused (as
    // podman does), not taken whole; nothing is recorded.
    let err = e.pull().await.expect_err("other bytes for the ranges");
    assert!(velarx_content::pull::chunked::refuses(&err), "{err}");
    assert!(e.db.list_layers().await.unwrap().is_empty());
    assert_eq!(e.staged_leftovers(), 0);
}

#[tokio::test]
async fn test_hostile_manifests_are_refused() {
    let e = env().await;
    let layer = build_gzip(&sample());
    e.publish(&[&layer], &[GZIP]);
    let good = e.reg.blobs.lock().unwrap()["manifest:latest"].clone();
    let good = String::from_utf8(good).unwrap();
    let digest = sha(&layer.blob);

    let bad = good.replace(&digest.to_string(), "sha256:../../../../etc/passwd");
    e.reg
        .blobs
        .lock()
        .unwrap()
        .insert("manifest:latest".into(), bad.into_bytes());
    assert!(e.pull().await.is_err());

    // More layers than diff ids.
    let value: serde_json::Value = serde_json::from_str(&good).unwrap();
    let mut extra = value.clone();
    let l = extra["layers"][0].clone();
    extra["layers"].as_array_mut().unwrap().push(l);
    e.reg
        .blobs
        .lock()
        .unwrap()
        .insert("manifest:latest".into(), extra.to_string().into_bytes());
    assert!(e.pull().await.is_err());

    let mut huge = good.clone().into_bytes();
    huge.extend(vec![b' '; 5 << 20]);
    e.reg
        .blobs
        .lock()
        .unwrap()
        .insert("manifest:latest".into(), huge);
    assert!(e.pull().await.is_err());
    assert!(e.db.list_images().await.unwrap().is_empty());
    assert_eq!(e.staged_leftovers(), 0);
}

#[tokio::test]
async fn test_blob_with_the_wrong_digest_is_refused() {
    let e = env().await;
    let layer = build_gzip(&sample());
    e.publish(&[&layer], &[GZIP]);
    let other = build_gzip(&[Item::File {
        name: "x",
        data: b"evil".to_vec(),
        chunk: 1,
    }]);
    e.reg
        .blobs
        .lock()
        .unwrap()
        .insert(sha(&layer.blob).to_string(), other.blob.clone());
    assert!(e.pull().await.is_err());
    assert!(!e.store.contains(&vid(b"evil")));
    assert!(e.db.list_images().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_signature_policy_is_enforced_before_any_request() {
    let policy_dir = tempfile::tempdir().unwrap();
    for (policy, allowed) in [
        (r#"{"default":[{"type":"insecureAcceptAnything"}]}"#, true),
        (r#"{"default":[{"type":"reject"}]}"#, false),
        // Signatures cannot be verified: failing closed.
        (
            r#"{"default":[{"type":"signedBy","keyType":"GPGKeys","keyPath":"/k"}]}"#,
            false,
        ),
    ] {
        let path = policy_dir.path().join("policy.json");
        std::fs::write(&path, policy).unwrap();
        let e = env_with(PullConfig {
            policy_path: Some(path),
            ..PullConfig::default()
        })
        .await;
        e.publish(&[&build_gzip(&sample())], &[GZIP]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let image = format!("{}/test:latest", e.host);
        let result = e.service.pull_with_client(&e.client(), &image, tx).await;
        assert_eq!(result.is_ok(), allowed, "{policy}");
        if !allowed {
            assert_eq!(e.reg.requests.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn test_an_image_can_use_a_layer_twice() {
    let e = env().await;
    let (host_b, b) = start_registry().await;
    e.trust(&[&host_b]);
    let layer = build_gzip(&sample());
    e.publish(&[&layer, &layer], &[GZIP, GZIP]);
    let result = e.pull().await.unwrap();
    let layers = e.db.get_image_layers(&result.id).await.unwrap();
    assert_eq!(layers.len(), 2);
    assert_eq!(layers[0].key, layers[1].key);
    assert_eq!(result.stats.layers.len(), 2);
    assert_eq!(
        e.reg.requests.load(Ordering::SeqCst),
        2,
        "the layer and the configuration"
    );
    let push = e
        .service
        .push_with_client(
            &client_for(&[&e.host, &host_b]),
            &format!("{}/test:latest", e.host),
            &velarx_core::services::PushOptions {
                destination: Some(format!("{host_b}/twice:latest")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!((push.blobs_uploaded, push.blobs_existing), (2, 1));
    assert_eq!(b.logged("PUT-MANIFEST"), 1);
}

/// A layer whose TOC does not have the digest its manifest annotation
/// says is never trusted, and not pulled whole instead: the descriptor
/// vouches for bytes the registry does not give, as podman refuses it.
/// Nothing of the image is recorded, lazy or not.
#[tokio::test]
async fn test_a_toc_without_its_announced_digest_is_not_trusted() {
    let forged = || {
        let mut layer = build_chunked(&sample());
        layer.annotations.insert(
            "io.github.containers.zstd-chunked.manifest-checksum".into(),
            sha(b"not the TOC").to_string(),
        );
        layer
    };
    for lazy in [true, false] {
        let e = env().await;
        let layer = forged();
        e.publish(&[&layer], &[ZSTD]);
        let err = match lazy {
            true => e.pull_lazy().await,
            false => e.pull().await,
        }
        .unwrap_err()
        .to_string();
        assert!(
            err.contains(&sha(b"not the TOC").to_string()) && err.contains("digest mismatch"),
            "{err}"
        );
        assert!(!e.store.contains(&vid(b"hello\n")), "pulled whole");
        assert!(e.db.list_images().await.unwrap().is_empty());
        assert!(e.db.list_layers().await.unwrap().is_empty());
        assert_eq!(e.staged_leftovers(), 0);
    }
}

/// A pull onto a file system that fills up fails with the error of the file
/// system, whichever way the layer comes, and what it wrote goes with it: no
/// name in the staging directory, nothing in the store or the database.
/// The file system is a small tmpfs of a user and mount namespace, in which
/// the test runs again.
#[test]
fn test_a_pull_that_fills_the_file_system_leaves_nothing() {
    const IN_NAMESPACE: &str = "VELARX_TEST_SMALL_FS";
    if std::env::var_os(IN_NAMESPACE).is_none() {
        // (the mount point is a directory of this process, removed when it
        // drops: the tmpfs goes with the namespace, the directory would not)
        let mount_point = tempfile::tempdir().unwrap();
        let script = r#"mount -t tmpfs -o size=4m tmpfs "$2" && TMPDIR=$2 VELARX_TEST_SMALL_FS=1 "$0" --exact "$1" --nocapture"#;
        let out = std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount", "sh", "-c", script])
            .arg(std::env::current_exe().unwrap())
            .arg("pull_tests::test_a_pull_that_fills_the_file_system_leaves_nothing")
            .arg(mount_point.path())
            .output();
        match out {
            Ok(out) if out.status.success() => {}
            Ok(out) if String::from_utf8_lossy(&out.stderr).contains("unshare failed") => {
                eprintln!("no user namespace here: the test is skipped");
            }
            Ok(out) => panic!(
                "{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
            Err(e) => eprintln!("no unshare here ({e}): the test is skipped"),
        }
        return;
    }
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let big: Vec<u8> = (0..16usize << 20).map(|i| (i * 31 % 251) as u8).collect();
        let items = vec![Item::File {
            name: "big",
            data: big.clone(),
            chunk: 64 * 1024,
        }];
        for chunked in [true, false] {
            let e = env().await;
            let layer = if chunked {
                build_chunked(&items)
            } else {
                build_gzip(&items)
            };
            e.publish(&[&layer], &[if chunked { ZSTD } else { GZIP }]);
            let err = e.pull().await.expect_err("the pull must fail");
            let text = err.to_string().to_lowercase();
            assert!(text.contains("no space left"), "{err}");
            assert!(e.db.get_layer(&layer.key()).await.is_err());
            assert_eq!(e.staged_leftovers(), 0);
            assert!(e.db.list_images().await.unwrap().is_empty());
            assert!(!e.store.contains(&vid(&big)));
        }
    });
}

mod docker_formats {
    use super::*;
    use velarx_types::ImageError;

    const DOCKER_LAYER: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
    const FOREIGN_LAYER: &str = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip";
    const SCHEMA2: &str = "application/vnd.docker.distribution.manifest.v2+json";
    const CONFIG: &str = "application/vnd.docker.container.image.v1+json";
    const LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";

    /// What a pull of an image in a Docker format Velarx does not read must
    /// do: the error names the media type, and no layer was asked for.
    async fn refused(e: &Env, layer: &Built, lazy: bool, media_type: &str) {
        let err = if lazy {
            e.pull_lazy().await
        } else {
            e.pull().await
        }
        .expect_err("this Docker image must be refused");
        assert!(matches!(err, ImageError::DockerFormat(_)), "{err}");
        let message = err.to_string();
        assert!(message.contains(media_type), "{message}");
        assert!(
            message.contains("only OCI and Docker schema 2 images"),
            "{message}"
        );
        assert_eq!(
            e.reg
                .hits
                .lock()
                .unwrap()
                .get(&sha(&layer.blob))
                .copied()
                .unwrap_or(0),
            0,
            "a layer was downloaded"
        );
        assert!(e.db.list_images().await.unwrap().is_empty());
        assert_eq!(e.staged_leftovers(), 0);
    }

    /// The image published as `test:latest` with the media types of
    /// `replace` (OCI to Docker) in its manifest, as the registry serves it.
    fn docker_manifest(e: &Env, replace: &[(&str, &str)]) -> Vec<u8> {
        let mut blobs = e.reg.blobs.lock().unwrap();
        let mut body = String::from_utf8(blobs["manifest:latest"].clone()).unwrap();
        for (from, to) in replace {
            body = body.replace(from, to);
        }
        blobs.insert(
            format!("manifest:{}", sha(body.as_bytes())),
            body.clone().into_bytes(),
        );
        blobs.insert("manifest:latest".into(), body.clone().into_bytes());
        body.into_bytes()
    }

    #[tokio::test]
    async fn test_a_layer_of_a_docker_type_is_pulled() {
        // the gzip layer and the uncompressed one (containers/image reads both)
        let plain = || {
            let tar = tar_of(&sample());
            Built {
                diff_id: sha(&tar),
                blob: tar,
                annotations: Default::default(),
            }
        };
        let cases = [
            (false, build_gzip(&sample()), DOCKER_LAYER),
            (true, build_gzip(&sample()), DOCKER_LAYER),
            (
                false,
                plain(),
                "application/vnd.docker.image.rootfs.diff.tar",
            ),
            (
                true,
                plain(),
                "application/vnd.docker.image.rootfs.diff.tar",
            ),
        ];
        for (lazy, layer, media_type) in cases {
            let e = env().await;
            e.publish(&[&layer], &[media_type]);
            let result = if lazy {
                e.pull_lazy().await
            } else {
                e.pull().await
            };
            // (a lazy pull of a layer without a table of contents is refused)
            if lazy && media_type != ZSTD {
                assert!(
                    matches!(result, Err(velarx_types::ImageError::NotLazy { .. })),
                    "{result:?}"
                );
                continue;
            }
            let result = result.unwrap();
            assert_eq!(result.stats.layers.len(), 1);
            let rec = e.db.get_layer(&layer.key()).await.unwrap();
            assert_eq!(rec.diff_id.as_ref(), Some(&layer.diff_id));
            if !lazy {
                assert!(e.store.contains(&vid(b"hello\n")));
            }
        }
    }

    #[tokio::test]
    async fn test_a_schema_2_manifest_is_kept_as_the_registry_served_it() {
        for lazy in [false, true] {
            let e = env().await;
            let layer = build_gzip(&sample());
            e.publish(&[&layer], &[GZIP]);
            let served = docker_manifest(
                &e,
                &[
                    ("application/vnd.oci.image.manifest.v1+json", SCHEMA2),
                    ("application/vnd.oci.image.config.v1+json", CONFIG),
                    (GZIP, DOCKER_LAYER),
                ],
            );
            let result = if lazy {
                e.pull_lazy().await
            } else {
                e.pull().await
            };
            // (a lazy pull of a layer without a table of contents is refused)
            if lazy {
                assert!(
                    matches!(result, Err(velarx_types::ImageError::NotLazy { .. })),
                    "{result:?}"
                );
                continue;
            }
            let result = result.unwrap();
            let image = e.service.get(&result.id).await.unwrap();
            // the bytes and the digest are the registry's: no conversion
            assert_eq!(image.manifest.as_bytes(), &served[..]);
            assert_eq!(image.manifest_digest, sha(&served));
            let by_digest = format!("{}/test@{}", e.host, sha(&served));
            let (tx, mut rx) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            let again = e
                .service
                .pull_with_client(&e.client(), &by_digest, tx)
                .await
                .unwrap();
            assert_eq!(again.id, result.id);
        }
    }

    /// A pull by `repository@digest` names the image so: it is not
    /// dangling (a prune keeps it), found by that name and by no other
    /// repository, and the name goes with `untag`.
    #[tokio::test]
    async fn test_a_pull_by_digest_names_the_image() {
        let e = env().await;
        let layer = build_gzip(&sample());
        e.publish(&[&layer], &[GZIP]);
        let served = docker_manifest(
            &e,
            &[
                ("application/vnd.oci.image.manifest.v1+json", SCHEMA2),
                ("application/vnd.oci.image.config.v1+json", CONFIG),
                (GZIP, DOCKER_LAYER),
            ],
        );
        let digest = sha(&served);
        let name = format!("{}/test", e.host);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let result = e
            .service
            .pull_with_client(&e.client(), &format!("{name}@{digest}"), tx)
            .await
            .unwrap();
        assert_eq!(
            e.db.get_digest_names_for_image(&result.id).await.unwrap(),
            [(name.clone(), digest)]
        );
        assert!(e
            .db
            .get_tags_for_image(&result.id)
            .await
            .unwrap()
            .is_empty());
        assert!(e.db.image_is_named(&result.id).await.unwrap());
        assert_eq!(
            e.service.get(&format!("{name}@{digest}")).await.unwrap().id,
            result.id
        );
        // the image never came from another repository
        let other = format!("{}/other@{digest}", e.host);
        assert!(matches!(
            e.service.get(&other).await,
            Err(ImageError::NotFound(_))
        ));
        let deleted: Vec<String> = e
            .service
            .prune(false, &[])
            .await
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert!(deleted.is_empty(), "{deleted:?}");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        e.service
            .pull_with_client(&e.client(), &format!("{name}@{digest}"), tx)
            .await
            .unwrap();
        assert_eq!(
            e.db.get_digest_names_for_image(&result.id)
                .await
                .unwrap()
                .len(),
            1
        );
        let removed = e
            .service
            .untag(&result.id, &[format!("{name}@{digest}")])
            .await
            .unwrap();
        assert_eq!(removed, [format!("{name}@{digest}")]);
        assert!(!e.db.image_is_named(&result.id).await.unwrap());
        let deleted: Vec<String> = e
            .service
            .prune(false, &[])
            .await
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(deleted, [result.id]);
    }

    /// What Velarx writes is OCI: a pushed image that was pulled as Docker
    /// schema 2 has an OCI manifest and OCI layer types.
    #[tokio::test]
    async fn test_a_pushed_docker_image_is_written_as_oci() {
        let e = env().await;
        let (host_b, b) = start_registry().await;
        e.trust(&[&host_b]);
        let layer = build_gzip(&sample());
        e.publish(&[&layer], &[GZIP]);
        docker_manifest(
            &e,
            &[
                ("application/vnd.oci.image.manifest.v1+json", SCHEMA2),
                ("application/vnd.oci.image.config.v1+json", CONFIG),
                (GZIP, DOCKER_LAYER),
            ],
        );
        e.pull().await.unwrap();
        let pushed = e
            .service
            .push_with_client(
                &client_for(&[&e.host, &host_b]),
                &format!("{}/test:latest", e.host),
                &velarx_core::services::PushOptions {
                    destination: Some(format!("{host_b}/out:latest")),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            pushed.media_type,
            "application/vnd.oci.image.manifest.v1+json"
        );
        let body = String::from_utf8(b.blobs.lock().unwrap()["manifest:latest"].clone()).unwrap();
        assert!(!body.contains("vnd.docker."), "{body}");
        assert!(body.contains(GZIP), "{body}");
    }

    #[tokio::test]
    async fn test_a_manifest_list_of_docker_manifests_is_resolved() {
        let e = env().await;
        let layer = build_gzip(&sample());
        let digest = publish_arch(&e.reg, &[&layer], &[GZIP], "amd64", "*");
        let instance = {
            let mut blobs = e.reg.blobs.lock().unwrap();
            let key = format!("manifest:{digest}");
            let body = String::from_utf8(blobs[&key].clone())
                .unwrap()
                .replace("application/vnd.oci.image.manifest.v1+json", SCHEMA2)
                .replace("application/vnd.oci.image.config.v1+json", CONFIG)
                .replace(GZIP, DOCKER_LAYER)
                .into_bytes();
            blobs.insert(key.clone(), body.clone());
            body
        };
        let list = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": LIST,
            "manifests": [{
                "mediaType": SCHEMA2,
                "digest": sha(&instance), "size": instance.len(),
                "platform": {"architecture": velarx_registry::target::host_arch(), "os": "linux"},
            }],
        });
        e.reg
            .blobs
            .lock()
            .unwrap()
            .insert(format!("manifest:{}", sha(&instance)), instance.clone());
        e.reg
            .blobs
            .lock()
            .unwrap()
            .insert("manifest:latest".into(), list.to_string().into_bytes());
        let result = e.pull().await.unwrap();
        let image = e.service.get(&result.id).await.unwrap();
        assert_eq!(image.manifest.as_bytes(), &instance[..]);
        assert_eq!(image.manifest_digest, sha(&instance));
    }

    #[tokio::test]
    async fn test_a_foreign_layer_is_refused() {
        for lazy in [false, true] {
            let e = env().await;
            let layer = build_gzip(&sample());
            e.publish(&[&layer], &[FOREIGN_LAYER]);
            refused(&e, &layer, lazy, FOREIGN_LAYER).await;
        }
    }

    #[tokio::test]
    async fn test_a_schema_1_manifest_is_refused() {
        let e = env().await;
        let layer = build_gzip(&sample());
        e.publish(&[&layer], &[GZIP]);
        e.reg.blobs.lock().unwrap().insert(
            "manifest:latest".into(),
            br#"{"schemaVersion":1,"name":"test","tag":"latest","fsLayers":[],"history":[]}"#
                .to_vec(),
        );
        refused(&e, &layer, false, "schema 1").await;
    }

    #[tokio::test]
    async fn test_a_manifest_list_of_schema_1_manifests_is_refused() {
        let e = env().await;
        let layer = build_gzip(&sample());
        let digest = publish_arch(&e.reg, &[&layer], &[GZIP], "amd64", "*");
        let list = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": LIST,
            "manifests": [{
                "mediaType": "application/vnd.docker.distribution.manifest.v1+json",
                "digest": digest, "size": 1,
                "platform": {"architecture": velarx_registry::target::host_arch(), "os": "linux"},
            }],
        });
        e.reg
            .blobs
            .lock()
            .unwrap()
            .insert("manifest:latest".into(), list.to_string().into_bytes());
        refused(
            &e,
            &layer,
            false,
            "application/vnd.docker.distribution.manifest.v1+json",
        )
        .await;
    }
}

/// A layer is never fetched when the manifest announces more bytes than a
/// layer may inflate to: the registry is not asked for anything, and the
/// refusal names the limit.
#[tokio::test]
async fn test_a_layer_announced_larger_than_the_limit_is_refused_unrequested() {
    let e = env().await;
    let layer = build_gzip(&sample());
    e.publish(&[&layer], &[GZIP]);
    let good = e.reg.blobs.lock().unwrap()["manifest:latest"].clone();
    let mut value: serde_json::Value = serde_json::from_slice(&good).unwrap();
    // (the default limit of a layer is 32 GiB)
    value["layers"][0]["size"] = serde_json::json!(100u64 << 30);
    e.reg
        .blobs
        .lock()
        .unwrap()
        .insert("manifest:latest".into(), value.to_string().into_bytes());
    let err = e.pull().await.unwrap_err().to_string();
    assert!(err.contains("max_layer_gib"), "{err}");
    assert!(
        !e.reg.hits.lock().unwrap().contains_key(&sha(&layer.blob)),
        "the layer was asked for"
    );
    assert!(e.db.list_images().await.unwrap().is_empty());
    assert_eq!(e.staged_leftovers(), 0);
}

/// A blob shorter than its descriptor says is refused for its size, not as
/// a "digest mismatch" between two equal digests.
#[tokio::test]
async fn test_a_layer_shorter_than_its_descriptor_is_refused_for_its_size() {
    let e = env().await;
    let layer = build_gzip(&sample());
    e.publish(&[&layer], &[GZIP]);
    let good = e.reg.blobs.lock().unwrap()["manifest:latest"].clone();
    let mut value: serde_json::Value = serde_json::from_slice(&good).unwrap();
    value["layers"][0]["size"] = serde_json::json!(layer.blob.len() + 100);
    e.reg
        .blobs
        .lock()
        .unwrap()
        .insert("manifest:latest".into(), value.to_string().into_bytes());
    let err = e.pull().await.unwrap_err().to_string();
    assert!(err.contains("its descriptor says"), "{err}");
    assert!(e.db.list_images().await.unwrap().is_empty());
    assert_eq!(e.staged_leftovers(), 0);
}

/// The timeout of a read restarts with every byte: a server that sends
/// one now and then is given up by the minimum speed.
#[tokio::test]
async fn test_a_server_that_sends_a_byte_now_and_then_is_given_up() {
    // (the default is 1 KiB per second over 120 seconds; the fetcher has the
    // `[pull]` of the engine)
    let e = env_with(PullConfig {
        min_speed_kib: 1,
        min_speed_secs: 1,
        ..PullConfig::default()
    })
    .await;
    e.publish(&[&build_gzip(&sample())], &[GZIP]);
    e.reg.trickle_ms.store(250, Ordering::SeqCst);
    let client = e.client();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let image = format!("{}/test:latest", e.host);
    let err = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        e.service.pull_with_client(&client, &image, tx),
    )
    .await
    .expect("the pull went on with a server that sends a byte every 250 ms")
    .unwrap_err()
    .to_string();
    assert!(err.contains("min_speed_kib"), "{err}");
    assert!(e.db.list_images().await.unwrap().is_empty());
    assert_eq!(e.staged_leftovers(), 0);
}

/// The engine works through `dyn StorageDriver`: what a pull made is read
/// back, checked, planned and served through the trait alone, and a layer
/// is read back as the stream of its diff id.
#[tokio::test]
async fn test_a_pulled_image_is_used_through_the_storage_driver() {
    use velarx_core::storage_driver::{
        Keep, MountRequest, Purpose, StorageDriver, VerityAsk, Writable,
    };
    // (the plan of an image mount, which makes no mount)
    let plan_of = |driver: &dyn StorageDriver,
                   image: &velarx_db::ImageRecord,
                   layers: &[velarx_db::LayerRecord]| {
        let container = Writable::new("plan", "/velarx-test/plan");
        driver.image_volume_create(&MountRequest {
            container: &container,
            purpose: Purpose::Volume { index: 0 },
            image,
            layers,
            mapping: None,
            translate: None,
            idmap_mount: false,
            label: None,
            verity: VerityAsk::Off,
            volatile: false,
        })
    };
    let layer = build_chunked_verity(&sample(), &|_, d| Some(toc_verity(d)));
    let e = env().await;
    e.publish(&[&layer], &[ZSTD]);
    let id = e.pull().await.unwrap().id;
    let (image, layers) = stored_image(&e, &id).await;
    let driver: &dyn StorageDriver = e.service.storage().as_ref();
    assert_eq!(driver.name(), "composefs");
    assert!(layers[0].erofs.is_some() && layers[0].owners.is_some());
    for full in [false, true] {
        let with_toc = e.db.get_image_layers(&image.id).await.unwrap();
        assert!(driver
            .check(&image, &with_toc, full)
            .await
            .unwrap()
            .is_empty());
    }
    // the plan is O(layers): the layer records have no table of contents
    let velarx_fuse::plan::RootfsPlan::MountFd(plan) =
        plan_of(driver, &image, &layers).unwrap().plan
    else {
        panic!("the plan of composefs is a mount of the driver");
    };
    assert_eq!(plan.fd_index, 0);
    let erofs = velarx_fuse::composefs::layer_image_path(
        e.service.file_store().root(),
        &layers[0].key.file_stem(),
    );
    assert!(erofs.is_file());
    let view = driver.image_view(&image.id, &layers).unwrap();
    assert!(view.resolve("etc/small").is_some());
    let stored = velarx_core::storage_driver::objects::open_layer_expecting(
        driver.name(),
        &e.db,
        &layers[0].key,
        &layer.diff_id,
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
    assert!(driver.capabilities().serve_content);
    // what the store has is kept by a collection, and the rest is removed
    let kept = driver
        .collect(&Keep {
            layers: vec![layers[0].key],
            images: vec![image.id.clone()],
            ..Keep::default()
        })
        .unwrap();
    assert!(kept.errors.is_empty() && kept.bytes_freed == 0);
    assert!(erofs.is_file());
    let usage = driver.usage().unwrap();
    let content = velarx_core::storage_driver::objects::content_usage(e.service.file_store());
    assert!(content.0 > 0 && usage.artifacts.0 >= 2);
    let gone = driver.collect(&Keep::default()).unwrap();
    assert!(gone.errors.is_empty() && gone.bytes_freed > 0);
    assert!(!erofs.exists());
    let err = plan_of(driver, &image, &layers).unwrap_err();
    assert!(err
        .to_string()
        .ends_with("`velarx system check --repair` makes it again"));
    // (and `check` finds it, with the fix that makes it again)
    let with_toc = e.db.get_image_layers(&image.id).await.unwrap();
    let problems = driver.check(&image, &with_toc, false).await.unwrap();
    assert!(problems
        .iter()
        .any(|p| p.kind == velarx_core::storage_driver::ProblemKind::ArtifactMissing && p.repair));
}

/// An eager pull of a layer with a table of contents from a registry
/// reached by confined workers goes through the registry fetcher:
/// the table comes by `Probe`, the files by `Fetch` into the staging
/// directory of the layer, from where the engine takes them and replays the
/// layer against its diff id.  The fetcher checked the chunks; the engine
/// records the places of those its replay checked again, and nothing stays
/// in the staging.
#[tokio::test]
async fn test_an_eager_pull_of_a_table_of_contents_goes_through_the_fetcher() {
    let e = env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    e.pull().await.unwrap();
    assert!(e.reg.ranged.load(Ordering::SeqCst) > 0, "no range request");
    let rec = e.db.get_layer(&layer.key()).await.unwrap();
    assert_eq!(rec.diff_id, None, "verified by its table");
    assert!(e.store.contains(&vid(b"hello\n")));
    assert!(e
        .db
        .get_chunk_location(&sha(&vec![1u8; 4096]))
        .await
        .unwrap()
        .is_some());
    assert_eq!(e.staged_leftovers(), 0);

    // a registry that gives other bytes for the ranges: the fetcher's check
    // of a chunk fails it, and the pull is refused, nothing recorded
    let e = env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    *e.reg.mode.lock().unwrap() = RangeMode::Lie;
    let err = e.pull().await.expect_err("other bytes for the ranges");
    assert!(velarx_content::pull::chunked::refuses(&err), "{err}");
    assert!(e.db.list_layers().await.unwrap().is_empty());
    assert_eq!(e.staged_leftovers(), 0);
}

/// A pull on a store without fs-verity (the test store is in a file system
/// with none): the engine copies and hashes the files a fetcher hands over
/// (those it keeps in memory) as it takes them in, which is the one read of
/// each; the commit reads once the file the fetcher named, and copies none
/// (the name is a link of the inode the fetcher wrote).
#[tokio::test]
async fn test_a_pull_without_verity_reads_each_file_once_and_copies_none() {
    let e = env().await;
    let mut items = sample();
    items.push(Item::File {
        name: "usr/huge",
        data: vec![9u8; 300_000],
        chunk: 64 * 1024,
    });
    let layer = build_chunked(&items);
    e.publish(&[&layer], &[ZSTD]);
    e.pull().await.unwrap();
    assert!(e.store.contains(&vid(b"hello\n")));
    assert!(e.store.contains(&vid(&[9u8; 300_000])));
    assert_eq!(e.store.copied(), 0, "no byte copied by the commit");
    assert_eq!(
        e.store.hashed(),
        300_000,
        "the commit read the file that was not handed over"
    );
}

/// Two engines of one store (two commands, each the engine of its own
/// process) pull the same image at the same time: the files of its layer
/// are fetched once.  The engines share nothing in memory: the one that
/// comes second waits for the lease of the layer (`staging/meta/<stem>`)
/// that the first holds while it stages, and then finds the files in the
/// store.  Range requests: a probe each (as a lazy pull makes one), the
/// files once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_two_engines_pulling_one_image_fetch_its_layer_once() {
    let layer = build_chunked(&sample());
    // what one probe asks: a lazy pull is the probe and nothing else
    let probe = {
        let e = env().await;
        e.publish(&[&layer], &[ZSTD]);
        e.pull_lazy().await.unwrap();
        e.reg.ranged.load(Ordering::SeqCst)
    };
    // what one pull asks
    let alone = {
        let e = env().await;
        e.publish(&[&layer], &[ZSTD]);
        e.pull().await.unwrap();
        e.reg.ranged.load(Ordering::SeqCst)
    };
    assert!(
        alone > probe,
        "a pull fetches files: {alone} ranges, {probe} to probe"
    );
    let e = env().await;
    e.publish(&[&layer], &[ZSTD]);
    let second = std::mem::ManuallyDrop::new(
        velarx_core::services::ImageService::new(
            e.db.clone(),
            e.store.clone(),
            e.staging.clone(),
            velarx_storage::VerityMode::Off,
        )
        .unwrap()
        .with_pull_config(PullConfig {
            worker_path: Some(registry_bin().into()),
            ..Default::default()
        })
        .unwrap()
        .with_resolver(e.client())
        .with_origin(e.origin.clone()),
    );
    // (both are in flight before either is answered)
    e.reg.rendezvous.store(2, Ordering::SeqCst);
    let image = format!("{}/test:latest", e.host);
    let pull = |service: velarx_core::services::ImageService, client| {
        let image = image.clone();
        tokio::spawn(async move {
            let (tx, mut rx) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            service.pull_with_client(&client, &image, tx).await
        })
    };
    let a = pull((*e.service).clone(), e.client());
    let b = pull((*second).clone(), e.client());
    let (a, b) = (a.await.unwrap().unwrap(), b.await.unwrap().unwrap());
    assert_eq!(a.id, b.id);
    assert!(
        !e.reg.apart.load(Ordering::SeqCst),
        "the pulls did not meet"
    );
    let both = e.reg.ranged.load(Ordering::SeqCst);
    assert!(
        both <= alone + probe,
        "the files were fetched twice: {both} ranges, one pull asks {alone}, a probe {probe}"
    );
    assert!(e.store.contains(&vid(b"hello\n")));
    assert_eq!(e.staged_leftovers(), 0);
}

/// The bytes the `Range` headers of `log` ask for (`bytes=a-b,c-d`).
fn asked_bytes(log: &[String]) -> u64 {
    log.iter()
        .flat_map(|r| r.trim_start_matches("bytes=").split(','))
        .filter_map(|r| {
            let (a, b) = r.trim().split_once('-')?;
            Some(b.parse::<u64>().ok()? - a.parse::<u64>().ok()? + 1)
        })
        .sum()
}

/// A file that two layers of one pull have is fetched once: the layer that
/// plans it second waits for the fetch of the first, and both layers are
/// committed with it.
#[tokio::test]
async fn test_a_file_of_two_layers_of_a_pull_is_fetched_once() {
    let e = env().await;
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let big: Vec<u8> = (0..256 * 1024)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    let layer = |name: &'static str| {
        build_chunked(&[Item::File {
            name,
            data: big.clone(),
            chunk: 16 * 1024,
        }])
    };
    let (a, b) = (layer("usr/a"), layer("usr/b"));
    e.publish(&[&a, &b], &[ZSTD, ZSTD]);
    e.pull().await.unwrap();
    let asked = asked_bytes(&e.reg.range_log.lock().unwrap());
    assert!(
        asked < big.len() as u64 * 3 / 2,
        "the file of both layers was fetched twice: {asked} bytes"
    );
    assert!(e.store.contains(&vid(&big)));
    assert_eq!(e.staged_leftovers(), 0);
}

/// A file of an updated image that differs from a file of the store in a few
/// bytes is made of the chunks the store holds: the registry fetcher is
/// given them (the reuse hints of `Fetch`) and asks the registry only for
/// the chunk that changed, and the file is the updated one.
#[tokio::test]
async fn test_an_updated_file_takes_the_chunks_the_store_has() {
    let e = env().await;
    // (bytes zstd cannot make smaller: the chunks are as big in the blob)
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let big: Vec<u8> = (0..256 * 1024)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    let first = build_chunked(&[Item::File {
        name: "usr/big",
        data: big.clone(),
        chunk: 16 * 1024,
    }]);
    e.publish(&[&first], &[ZSTD]);
    e.pull().await.unwrap();

    let mut edited = big.clone();
    edited[100_000..100_016].copy_from_slice(&[0xee; 16]);
    let second = build_chunked(&[Item::File {
        name: "usr/big",
        data: edited.clone(),
        chunk: 16 * 1024,
    }]);
    publish_arch(&e.reg, &[&second], &[ZSTD], "amd64", "updated");
    let from = e.reg.range_log.lock().unwrap().len();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    e.service
        .pull_with_client(&e.client(), &format!("{}/test:updated", e.host), tx)
        .await
        .unwrap();
    let asked = asked_bytes(&e.reg.range_log.lock().unwrap()[from..]);
    assert!(
        asked < edited.len() as u64 / 4,
        "the chunks the store holds were asked for again: {asked} bytes"
    );
    let path = e.store.local_path(&vid(&edited)).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), edited);
    assert_eq!(e.staged_leftovers(), 0);
}

/// A layer with a table of contents records the places of the chunks of
/// all of its files, those the store had from a gzip pull of the same files
/// too: the node serves their chunks to its peers.
#[tokio::test]
async fn test_the_files_the_store_had_record_their_chunk_places() {
    let e = env().await;
    let noise = |mut x: u64| -> Vec<u8> {
        (0..64 * 1024)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    };
    let (had, new) = (noise(0x9e37_79b9_7f4a_7c15), noise(0x2545_f491_4f6c_dd1d));
    let items = |with_new: bool| {
        let mut items = vec![
            Item::Dir("usr/"),
            Item::File {
                name: "usr/had",
                data: had.clone(),
                chunk: 16 * 1024,
            },
        ];
        if with_new {
            items.push(Item::File {
                name: "usr/new",
                data: new.clone(),
                chunk: 16 * 1024,
            });
        }
        items
    };
    e.publish(&[&build_gzip(&items(false))], &[GZIP]);
    e.pull().await.unwrap();
    e.publish(&[&build_chunked(&items(true))], &[ZSTD]);
    e.pull().await.unwrap();
    let place = |data: &[u8]| {
        let chunk = Digest::of(Algorithm::Sha256, &data[16 * 1024..32 * 1024]);
        let db = e.db.clone();
        async move { db.get_chunk_location(&chunk).await.unwrap() }
    };
    assert_eq!(place(&new).await.unwrap().file_digest, vid(&new));
    assert_eq!(place(&had).await.unwrap().file_digest, vid(&had));
}

/// A barrier of the store that fails fails the pull, whichever of the two
/// it is: nothing is recorded for names and images that did not reach the
/// disk, and nothing stays staged.
#[tokio::test]
async fn test_a_failed_barrier_fails_the_pull_and_records_nothing() {
    for failing in [1, 2] {
        let e = env().await;
        let layer = build_gzip(&sample());
        e.publish(&[&layer], &[GZIP]);
        e.store.fail_barrier(failing);
        let err = e.pull().await.expect_err("the barrier failed");
        assert!(
            err.to_string().contains("cannot commit the pulled files"),
            "barrier {failing}: {err}"
        );
        assert!(e.db.get_layer(&layer.key()).await.is_err(), "{failing}");
        assert!(e.db.list_images().await.unwrap().is_empty(), "{failing}");
        assert_eq!(e.staged_leftovers(), 0);
    }
}

/// The content of a layer is hashed once on a store with no fs-verity: a
/// layer pulled whole is read by the replay, which copies each file as it
/// reads it, and the commit links the copies (the commit reads nothing); a
/// layer of a table has its files handed over, which the engine copies and
/// hashes as it takes them in (the commit reads nothing).
#[tokio::test]
async fn test_the_files_of_a_layer_are_read_once_on_a_store_without_fs_verity() {
    let e = env().await;
    let layer = build_gzip(&sample());
    e.publish(&[&layer], &[GZIP]);
    e.pull().await.unwrap();
    assert_eq!(e.store.hashed(), 0, "a layer pulled whole");
    assert!(e.store.contains(&vid(b"hello\n")));

    let e = env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    e.pull().await.unwrap();
    assert_eq!(
        e.store.hashed(),
        0,
        "a layer of a table, whose files are in memory"
    );
    assert!(e.store.contains(&vid(b"hello\n")));
}

/// A layer of a table of contents is held to its table, not to a diff id: one
/// whose configuration claims another diff id is accepted and recorded with
/// none, and the layer is not claimed to have the stream the configuration
/// names.
#[tokio::test]
async fn test_a_layer_of_a_table_with_another_diff_id_is_recorded_with_none() {
    let e = env().await;
    let mut layer = build_chunked(&sample());
    layer.diff_id = sha(b"another layer");
    e.publish(&[&layer], &[ZSTD]);
    e.pull().await.unwrap();
    let rec = e.db.get_layer(&layer.key()).await.unwrap();
    assert_eq!(rec.status, "ready");
    assert_eq!(rec.diff_id, None);
    assert!(e.store.contains(&vid(b"hello\n")));
}

/// An eager pull makes its files, the images of its layers and the names
/// durable with one barrier of the staging and one of the store, whatever the
/// number of layers: the images have none of their own.
#[tokio::test]
async fn test_an_eager_pull_has_two_barriers_of_the_store() {
    let e = env().await;
    let first = build_chunked(&sample());
    let second = build_gzip(&[Item::File {
        name: "usr/own",
        data: b"only in the second\n".to_vec(),
        chunk: 4096,
    }]);
    e.publish(&[&first, &second], &[ZSTD, GZIP]);
    e.pull().await.unwrap();
    assert_eq!(e.store.barriers(), 2, "the barriers of the pull");
}

/// `n` layers of one small file each, all different.
fn tiny_layers(n: usize, build: fn(&[Item]) -> Built) -> Vec<Built> {
    (0..n)
        .map(|i| {
            build(&[Item::File {
                name: "f",
                data: i.to_le_bytes().to_vec(),
                chunk: 4096,
            }])
        })
        .collect()
}

/// The overlay of a container takes 500 layers, the data-only layers of the
/// store among them: an image the overlay could never mount is refused
/// before anything of it is fetched, with the image and the limit named.
#[tokio::test]
async fn test_an_image_the_overlay_cannot_take_is_refused_before_anything_is_fetched() {
    let e = env().await;
    // (the objects of the store are the one data-only layer of the overlay)
    let layers = tiny_layers(500, build_gzip);
    let refs: Vec<&Built> = layers.iter().collect();
    e.publish(&refs, &vec![GZIP; refs.len()]);
    let refused = e.pull().await.unwrap_err();
    let velarx_types::ImageError::TooManyLayers {
        image,
        layers,
        limit,
        overlay,
        stores,
        lazy,
    } = &refused
    else {
        panic!("{refused:?}")
    };
    assert_eq!(
        (image.as_str(), *layers, *limit, *overlay, *stores, *lazy),
        (
            format!("{}/test:latest", e.host).as_str(),
            500,
            499,
            500,
            1,
            false
        )
    );
    let said = refused.to_string();
    assert!(
        said.contains(image.as_str()) && said.contains("499"),
        "{said}"
    );
    assert!(e.db.list_layers().await.unwrap().is_empty());
    assert_eq!(e.staged_leftovers(), 0);
}

/// The most the overlay takes is a pull: one layer of the 500 is the store's
/// objects.  A lazy image has a data-only layer for the files fetched for each
/// of its layers: half of what is left, 249, is a lazy pull, one more is
/// refused before anything of it is fetched.
#[tokio::test]
async fn test_the_most_layers_the_overlay_takes_are_pulled() {
    let layers = tiny_layers(499, build_gzip);
    let refs: Vec<&Built> = layers.iter().collect();
    let e = env().await;
    e.publish(&refs, &vec![GZIP; refs.len()]);
    let pulled = e.pull().await.unwrap();
    assert_eq!(e.db.get_image_layers(&pulled.id).await.unwrap().len(), 499);

    let lazy = tiny_layers(250, build_chunked);
    let refs: Vec<&Built> = lazy.iter().collect();
    let e = env().await;
    e.publish(&refs, &vec![ZSTD; refs.len()]);
    let refused = e.pull_lazy().await.unwrap_err();
    assert!(
        matches!(
            refused,
            velarx_types::ImageError::TooManyLayers {
                layers: 250,
                limit: 249,
                overlay: 500,
                stores: 1,
                lazy: true,
                ..
            }
        ),
        "{refused:?}"
    );
    assert!(refused.to_string().contains("without --lazy"), "{refused}");
    assert!(e.db.list_layers().await.unwrap().is_empty());
    assert_eq!(e.staged_leftovers(), 0);
    let refs: Vec<&Built> = lazy[..249].iter().collect();
    let e = env().await;
    e.publish(&refs, &vec![ZSTD; refs.len()]);
    let pulled = e.pull_lazy().await.unwrap();
    // (a lazy pull, staged: the image is the store's once it is complete)
    assert!(e.service.get(&pulled.id).await.is_err(), "being pulled");
    e.service.complete_image(&pulled.id).await.unwrap();
    assert_eq!(e.db.get_image_layers(&pulled.id).await.unwrap().len(), 249);
}

/// A mount holds descriptors for the layers of the image: a hard limit of
/// open files below what they need (3 for each layer and the engine's own) is
/// refused before anything is fetched, with the image, the need and the hard
/// limit named; one that has the need pulls it.
#[test]
fn test_a_hard_limit_of_open_files_below_the_need_is_refused_before_anything_is_fetched() {
    velarx_base::testing::in_child(|| {
        let limit = |n: u64| {
            rustix::process::setrlimit(
                rustix::process::Resource::Nofile,
                rustix::process::Rlimit {
                    current: Some(n),
                    maximum: Some(n),
                },
            )
            .unwrap()
        };
        let layers = tiny_layers(499, build_gzip);
        let refs: Vec<&Built> = layers.iter().collect();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let e = env().await;
            e.publish(&refs, &vec![GZIP; refs.len()]);
            let need = velarx_base::hardening::open_files_needed(499);
            assert_eq!(need, 3 * 499 + 64);
            limit(need - 1);
            let refused = e.pull().await.unwrap_err();
            let velarx_types::ImageError::NoOpenFiles {
                image,
                layers,
                needed,
                hard,
            } = &refused
            else {
                panic!("{refused:?}")
            };
            assert_eq!(
                (image.as_str(), *layers, *needed, *hard),
                (
                    format!("{}/test:latest", e.host).as_str(),
                    499,
                    need,
                    need - 1
                )
            );
            let said = refused.to_string();
            assert!(
                said.contains(image.as_str()) && said.contains("1560"),
                "{said}"
            );
            assert!(e.db.list_layers().await.unwrap().is_empty());
            assert_eq!(e.staged_leftovers(), 0);
        });
    });
}

/// `files` files of `size` bytes each that do not compress, in chunks of
/// 64 KiB.
fn incompressible_files(files: usize, size: usize) -> Vec<Item> {
    let names = ["f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7"];
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    names[..files]
        .iter()
        .map(|name| Item::File {
            name,
            data: (0..size)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    (state >> 24) as u8
                })
                .collect(),
            chunk: 64 * 1024,
        })
        .collect()
}

/// The files of `items` are in the store.
fn assert_stored(e: &Env, items: &[Item]) {
    for item in items {
        if let Item::File { data, .. } = item {
            assert!(e.store.contains(&vid(data)));
        }
    }
}

/// A registry that cannot give the ranges of a blob (it answers them with
/// the whole blob, or refuses them) is read once: the blob goes into a file
/// with no name, which every request for a part of it is served from, and
/// which is let go with the layer.  A pull reads the blob once; so does a
/// lazy one, and so does the completion that follows it.
#[tokio::test]
async fn test_a_registry_that_cannot_give_ranges_is_read_once() {
    let items = incompressible_files(8, 1 << 20);
    let layer = build_chunked(&items);
    let blob = layer.blob.len() as u64;
    for mode in [RangeMode::Ignore, RangeMode::Refuse] {
        for lazy in [true, false] {
            let e = env().await;
            e.publish(&[&layer], &[ZSTD]);
            *e.reg.mode.lock().unwrap() = mode;
            let served = || e.reg.served.load(Ordering::SeqCst);
            // (and what the registry had queued of the answer a worker that
            // finds it is no range dropped unread)
            let within = |bytes: u64, what: &str| {
                assert!(bytes < blob + (2 << 20), "{what}: {bytes} of {blob}");
            };
            if lazy {
                e.pull_lazy().await.unwrap();
                within(served(), "a lazy pull");
                let before = served();
                e.service
                    .complete_image(&format!("{}/test:latest", e.host))
                    .await
                    .unwrap();
                within(served() - before, "its completion");
            } else {
                e.pull().await.unwrap();
                within(served(), "a pull");
            }
            assert_stored(&e, &items);
            assert_eq!(e.staged_leftovers(), 0);
        }
    }
}

/// A registry that has ranges is asked for what is needed only.
#[tokio::test]
async fn test_a_registry_with_ranges_is_not_read_whole() {
    let items = incompressible_files(8, 1 << 20);
    let layer = build_chunked(&items);
    let e = env().await;
    e.publish(&[&layer], &[ZSTD]);
    e.pull().await.unwrap();
    assert_stored(&e, &items);
    let served = e.reg.served.load(Ordering::SeqCst);
    assert!(
        served < layer.blob.len() as u64 + (1 << 20),
        "{served} bytes for a blob of {}",
        layer.blob.len()
    );
    assert!(e.reg.ranged.load(Ordering::SeqCst) > 0, "no range request");
}

/// A registry that sends more than the blob has, or less, fails the pull and
/// leaves nothing: no file, nothing in the store.
#[tokio::test]
async fn test_a_whole_blob_of_the_wrong_size() {
    let items = incompressible_files(2, 1 << 20);
    let layer = build_chunked(&items);
    let digest = sha(&layer.blob).to_string();
    for tamper in [Tamper::Append(64 << 20), Tamper::Cut] {
        let e = env().await;
        e.publish(&[&layer], &[ZSTD]);
        *e.reg.mode.lock().unwrap() = RangeMode::Ignore;
        *e.reg.tamper.lock().unwrap() = Some((digest.clone(), tamper));
        assert!(e.pull().await.is_err());
        assert_eq!(e.staged_leftovers(), 0);
        assert!(!e.store.contains(&vid(match &items[0] {
            Item::File { data, .. } => data,
            _ => unreachable!(),
        })));
        assert!(e.db.list_layers().await.unwrap().is_empty());
    }
}

/// A whole blob that is not the one of the descriptor is refused as it is
/// written, whatever its size.
#[tokio::test]
async fn test_a_whole_blob_that_is_not_the_one_asked_for() {
    let items = incompressible_files(2, 1 << 20);
    let layer = build_chunked(&items);
    let digest = sha(&layer.blob).to_string();
    let e = env().await;
    e.publish(&[&layer], &[ZSTD]);
    *e.reg.mode.lock().unwrap() = RangeMode::Ignore;
    *e.reg.tamper.lock().unwrap() = Some((digest, Tamper::Flip));
    let err = e.pull().await.unwrap_err();
    assert!(err.to_string().contains("sha256"), "{err}");
    assert_eq!(e.staged_leftovers(), 0);
}
