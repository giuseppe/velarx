// SPDX-License-Identifier: Apache-2.0
//! One view of a zstd:chunked layer: a layer whose descriptor has the
//! zstd:chunked labels is the layer of the TOC they name, pulled through
//! it; when that cannot be done it is pulled whole and is the layer of its
//! blob.  Neither ever stands for the other, and a diff id is recorded only
//! once the layer was verified against it.

use crate::common::*;
use std::sync::atomic::Ordering;
use velarx_core::services::{CheckService, PushOptions};
use velarx_db::LayerKey;
use velarx_proto::system::CheckSpec;

const LABELS: [&str; 3] = [
    "io.github.containers.zstd-chunked.manifest-checksum",
    "io.github.containers.zstd-chunked.manifest-position",
    "io.github.containers.zstd-chunked.tarsplit-position",
];

/// Pull `reference` (a tag of the registry of `e`), lazily or not.
async fn pull_tag(
    e: &Env,
    tag: &str,
    lazy: bool,
) -> Result<velarx_core::services::PullResult, velarx_types::ImageError> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let image = format!("{}/test:{tag}", e.host);
    match lazy {
        true => {
            e.service
                .pull_lazy_with_client(&e.client(), &image, tx)
                .await
        }
        false => e.service.pull_with_client(&e.client(), &image, tx).await,
    }
}

/// The layers an image records, or a pull in progress names.
async fn keys_of(e: &Env, id: &str) -> Vec<LayerKey> {
    if let Some(pull) = e.area().pull(id).unwrap() {
        return pull
            .layers
            .iter()
            .map(|k| LayerKey::parse(k).unwrap())
            .collect();
    }
    e.db.get_image_layers(id)
        .await
        .unwrap()
        .into_iter()
        .map(|l| l.key)
        .collect()
}

/// The digests of the files the layer `key` holds.
async fn files_of(e: &Env, key: &LayerKey) -> std::collections::BTreeSet<String> {
    e.db.get_layer_file_refs(key)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.file_digest)
        .collect()
}

async fn file_rows(e: &Env) -> usize {
    e.db.conn()
        .call(|c| Ok(c.query_row("SELECT count(*) FROM files", [], |r| r.get::<_, i64>(0))?))
        .await
        .unwrap() as usize
}

/// A lazily pulled chunked layer is the layer of its TOC, with no diff id
/// until its completion proves it; the completion keeps it the layer of the
/// TOC.  Nothing is recorded as the layer of the blob, which was never
/// checked.
#[tokio::test]
async fn test_a_lazy_chunked_layer_is_its_toc_until_and_after_its_completion() {
    let e = env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    let toc = layer.key();
    assert!(toc.is_toc());
    let pulled = e.pull_lazy().await.unwrap();
    assert_eq!(keys_of(&e, &pulled.id).await, std::slice::from_ref(&toc));
    // (staged: the store has no layer of it)
    assert!(e.db.get_layer(&toc).await.is_err());
    let record = e
        .area()
        .layer(&toc)
        .unwrap()
        .unwrap()
        .record(false)
        .unwrap();
    assert_eq!(record.status, "lazy");
    assert_eq!(record.diff_id, None, "a claim is recorded as proven");
    assert_eq!(record.blob, Some(sha(&layer.blob)));
    assert!(e.db.get_layer(&layer.whole()).await.is_err());

    e.service.complete_image(&pulled.id).await.unwrap();
    let record = e.db.get_layer(&toc).await.unwrap();
    assert_eq!(record.status, "ready");
    // (verified by its table of contents: no diff id claimed)
    assert_eq!(record.diff_id.as_ref(), None);
    assert_eq!(keys_of(&e, &pulled.id).await, [toc]);
    assert!(e.db.get_layer(&layer.whole()).await.is_err());
    let e = env().await;
    e.publish(&[&layer], &[ZSTD]);
    let eager = e.pull().await.unwrap();
    assert_eq!(keys_of(&e, &eager.id).await, [layer.key()]);
}

/// A registry that serves no range: the chunked layer is pulled whole and is
/// the layer of its blob, its diff id proven; its TOC is not used, nor
/// recorded, lazily or not.
#[tokio::test]
async fn test_a_chunked_layer_that_cannot_be_ranged_is_the_layer_of_its_blob() {
    for lazy in [false, true] {
        let e = env().await;
        let layer = build_chunked(&sample());
        e.publish(&[&layer], &[ZSTD]);
        *e.reg.mode.lock().unwrap() = RangeMode::Refuse;
        let pulled = pull_tag(&e, "latest", lazy).await;
        // (a lazy pull of a layer that cannot be lazy is refused)
        if lazy {
            assert!(
                matches!(pulled, Err(velarx_types::ImageError::NotLazy { .. })),
                "{pulled:?}"
            );
            continue;
        }
        let pulled = pulled.unwrap();
        assert_eq!(keys_of(&e, &pulled.id).await, [layer.whole()]);
        let record = e.db.get_layer(&layer.whole()).await.unwrap();
        assert_eq!(record.status, "ready");
        assert_eq!(record.diff_id.as_ref(), Some(&layer.diff_id));
        assert!(e.db.get_layer(&layer.key()).await.is_err());
        assert!(e.service.get(&pulled.id).await.is_ok());
    }
}

/// The TOC route needs the tar-split: a descriptor with the labels of the
/// TOC and none of the tar-split is pulled whole, the layer of its blob.
#[tokio::test]
async fn test_a_chunked_layer_without_its_tar_split_is_the_layer_of_its_blob() {
    let e = env().await;
    let mut layer = build_chunked(&sample());
    layer.annotations.remove(LABELS[2]);
    e.publish(&[&layer], &[ZSTD]);
    let refused = e.pull_lazy().await;
    assert!(
        matches!(refused, Err(velarx_types::ImageError::NotLazy { .. })),
        "{refused:?}"
    );
    let pulled = e.pull().await.unwrap();
    assert_eq!(keys_of(&e, &pulled.id).await, [layer.whole()]);
    let record = e.db.get_layer(&layer.whole()).await.unwrap();
    assert_eq!(record.diff_id.as_ref(), Some(&layer.diff_id));
}

/// The layer of a TOC never stands for a layer of a blob: a gzip image
/// whose configuration has the same diff id pulls its own layer, which
/// shares the files of the store; and a lazy pull of a chunked descriptor
/// whose blob the store has whole does not take that layer for the one of
/// its TOC.
#[tokio::test]
async fn test_the_layer_of_a_toc_and_the_layer_of_a_blob_are_never_one_for_the_other() {
    let e = env().await;
    let tar = tar_of(&sample());
    let chunked = build_written(
        &tar,
        velarx_content::layer::writer::Compression::ZstdChunked,
    );
    let gzip = build_written(&tar, velarx_content::layer::writer::Compression::Gzip);
    assert_eq!(chunked.diff_id, gzip.diff_id);
    assert!(chunked.key().is_toc());
    e.publish(&[&chunked], &[ZSTD]);
    let lazy = e.pull_lazy().await.unwrap();
    e.service.complete_image(&lazy.id).await.unwrap();
    let files = file_rows(&e).await;

    publish_arch(
        &e.reg,
        &[&gzip],
        &[GZIP],
        velarx_registry::target::host_arch(),
        "gzip",
    );
    let before = e.reg.requests.load(Ordering::SeqCst);
    let whole = pull_tag(&e, "gzip", false).await.unwrap();
    assert!(e.reg.requests.load(Ordering::SeqCst) > before);
    assert_eq!(
        whole.stats.layers_cached, 0,
        "the layer of the TOC was taken"
    );
    assert_eq!(keys_of(&e, &whole.id).await, [gzip.whole()]);
    assert_eq!(file_rows(&e).await, files);
    assert_eq!(
        files_of(&e, &gzip.whole()).await,
        files_of(&e, &chunked.key()).await
    );
    assert!(e.db.get_layer(&chunked.key()).await.is_ok());

    // the other way: the blob is stored whole (the registry served no
    // range), then another image names it with its labels
    let e = env().await;
    e.publish(&[&chunked], &[ZSTD]);
    *e.reg.mode.lock().unwrap() = RangeMode::Refuse;
    let first = e.pull().await.unwrap();
    assert_eq!(keys_of(&e, &first.id).await, [chunked.whole()]);
    *e.reg.mode.lock().unwrap() = RangeMode::Normal;
    publish_annotated(
        &e.reg,
        &[&chunked],
        &[ZSTD],
        velarx_registry::target::host_arch(),
        "again",
        serde_json::json!({"another": "manifest"}),
    );
    let second = pull_tag(&e, "again", true).await.unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(keys_of(&e, &second.id).await, [chunked.key()]);
    // two layers for one descriptor, each of the route that verified it
    assert!(e.db.get_layer(&chunked.key()).await.is_err());
    assert!(e.area().layer(&chunked.key()).unwrap().is_some());
    assert_eq!(
        e.db.get_layer(&chunked.whole()).await.unwrap().status,
        "ready"
    );
    assert!(e.service.get(&second.id).await.is_err(), "being pulled");
}

/// The descriptor decides, never the blob: a blob with a TOC frame whose
/// descriptor lost its labels (or has half of them) is a layer of its blob,
/// pulled whole, and its TOC is not read.
#[tokio::test]
async fn test_a_descriptor_without_the_labels_is_the_layer_of_its_blob() {
    for strip in [&LABELS[..], &LABELS[1..], &LABELS[..1]] {
        for lazy in [false, true] {
            let e = env().await;
            let mut layer = build_chunked(&sample());
            let toc = layer.key();
            for label in strip {
                layer.annotations.remove(*label);
            }
            e.publish(&[&layer], &[ZSTD]);
            let pulled = pull_tag(&e, "latest", lazy).await;
            // (a lazy pull of a layer that cannot be lazy is refused)
            if lazy {
                assert!(
                    matches!(pulled, Err(velarx_types::ImageError::NotLazy { .. })),
                    "{pulled:?}"
                );
                continue;
            }
            let pulled = pulled.unwrap();
            assert_eq!(e.reg.ranged.load(Ordering::SeqCst), 0, "{strip:?}");
            assert_eq!(keys_of(&e, &pulled.id).await, [layer.whole()]);
            let record = e.db.get_layer(&layer.whole()).await.unwrap();
            assert_eq!(record.diff_id.as_ref(), Some(&layer.diff_id));
            assert!(e.db.get_layer(&toc).await.is_err());
        }
    }
}

/// A chunked layer whose TOC lies about a file, the lie covered by the
/// checksum of the manifest.  The eager pull checks every chunk and file
/// against the TOC: a sha256 or an fs-verity digest that is not the
/// content's refuses the image (as podman does), and nothing is recorded,
/// neither the layer of the TOC nor the one of the blob.  The lazy pull
/// keeps the layer of the TOC unproven, and its completion, which fetches
/// the file, fails and leaves it so: the layer of a TOC is never proven by
/// what it claims.
#[tokio::test]
async fn test_a_toc_that_lies_about_a_file_is_never_proven() {
    let lie = |verity: bool| {
        let mut layer = build_chunked(&sample());
        let p = "io.github.containers.zstd-chunked.";
        let pos = layer.annotations[&format!("{p}manifest-position")].clone();
        let parts: Vec<usize> = pos.split(':').map(|x| x.parse().unwrap()).collect();
        let toc = zstd::decode_all(&layer.blob[parts[0]..parts[0] + parts[1]]).unwrap();
        let (real, forged) = match verity {
            true => (toc_verity(b"hello\n"), toc_verity(b"not hello")),
            false => (sha(b"hello\n").to_string(), sha(b"not hello").to_string()),
        };
        let forged = String::from_utf8(toc).unwrap().replacen(&real, &forged, 1);
        let forged_z = frame(forged.as_bytes());
        let tail: Vec<u8> = layer.blob[parts[0] + parts[1]..].to_vec();
        layer.blob.truncate(parts[0]);
        let header = skippable(forged_z.len());
        let at = parts[0] - header.len();
        layer.blob[at..parts[0]].copy_from_slice(&header);
        layer.blob.extend(&forged_z);
        layer.blob.extend(&tail);
        let shift = forged_z.len() as i64 - parts[1] as i64;
        let ts = layer.annotations[&format!("{p}tarsplit-position")].clone();
        let t: Vec<i64> = ts.split(':').map(|x| x.parse().unwrap()).collect();
        layer.annotations.insert(
            format!("{p}tarsplit-position"),
            format!("{}:{}:{}", t[0] + shift, t[1], t[2]),
        );
        layer.annotations.insert(
            format!("{p}manifest-position"),
            format!("{}:{}:{}:1", parts[0], forged_z.len(), forged.len()),
        );
        layer
            .annotations
            .insert(format!("{p}manifest-checksum"), sha(&forged_z).to_string());
        layer
    };
    for verity in [false, true] {
        let e = env().await;
        let layer = lie(verity);
        e.publish(&[&layer], &[ZSTD]);
        let err = e.pull().await.expect_err("a TOC that lies is refused");
        // (an fs-verity digest is the kernel's to measure, as the files are
        // committed)
        assert!(
            velarx_content::pull::chunked::refuses(&err)
                || verity && matches!(err, velarx_types::ImageError::Storage(_)),
            "{err}"
        );
        assert!(!e.store.contains(&vid(b"not hello")));
        assert!(e.db.list_layers().await.unwrap().is_empty());
        assert_eq!(e.staged_leftovers(), 0);

        let e = env().await;
        e.publish(&[&layer], &[ZSTD]);
        let lazy = e.pull_lazy().await.unwrap();
        assert_eq!(keys_of(&e, &lazy.id).await, [layer.key()]);
        assert!(e.service.complete_image(&lazy.id).await.is_err());
        // nothing was proven: the layer is still staged, the store has none
        assert!(e.db.get_layer(&layer.key()).await.is_err());
        assert!(e.area().layer(&layer.key()).unwrap().is_some());
        assert!(e.service.get(&lazy.id).await.is_err());
        assert!(e.db.get_layer(&layer.whole()).await.is_err());
    }
}

/// An image of layers of a TOC lives as any other: completed, it is pushed,
/// committed on, checked clean, and removed with its layers.
#[tokio::test]
async fn test_an_image_of_toc_layers_is_pushed_committed_checked_and_removed() {
    let e = env().await;
    let (host_b, b) = start_registry().await;
    e.trust(&[&host_b]);
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    let lazy = e.pull_lazy().await.unwrap();
    e.service.complete_image(&lazy.id).await.unwrap();

    let client = client_for(&[&e.host, &host_b]);
    let pushed = e
        .service
        .push_with_client(
            &client,
            &lazy.id,
            &PushOptions {
                destination: Some(format!("{host_b}/copy:v1")),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    assert!(b.has("copy", &sha(&layer.blob)) || pushed.layers_regenerated == 1);

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("added"), b"on top\n").unwrap();
    let committed = e
        .service
        .commit_dir(
            Some(&lazy.id),
            Some(dir.path()),
            &velarx_core::services::CommitOptions {
                names: vec!["committed:v1".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let keys = keys_of(&e, &committed).await;
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], layer.key());
    assert!(
        !keys[1].is_toc(),
        "a layer made here is the layer of its blob"
    );

    let checker = CheckService::new(
        e.db.clone(),
        std::sync::Arc::new((*e.service).clone()),
        e.store.clone(),
        e.staging.clone(),
    );
    let report = checker.check(&CheckSpec::default()).await.unwrap();
    assert!(report.problems.is_empty(), "{:?}", report.problems);

    // the blob a layer of a TOC records is one of a descriptor that names
    // the TOC, not its identity: another one is no damage
    let toc = layer.key().to_string();
    let other = sha(b"another blob").to_string();
    e.db.conn()
        .call(move |c| Ok(c.execute("UPDATE layers SET blob = ?2 WHERE id = ?1", [toc, other])?))
        .await
        .unwrap();
    let quick = CheckSpec {
        quick: true,
        ..Default::default()
    };
    let report = checker.check(&quick).await.unwrap();
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    // a layer without a diff id (nothing proved it), or a layer that is not
    // the one of its descriptor (here the one the commit made, of its
    // blob), is damage
    let (toc, made, id) = (
        layer.key().to_string(),
        keys[1].to_string(),
        lazy.id.clone(),
    );
    // (a layer of a table of contents with no diff id is not damaged: its
    // table verified it)
    for (damage, repair) in [(
        format!("UPDATE image_layers SET layer_id = '{made}' WHERE image_id = '{id}'"),
        format!("UPDATE image_layers SET layer_id = '{toc}' WHERE image_id = '{id}'"),
    )] {
        let sql = damage.clone();
        e.db.conn()
            .call(move |c| Ok(c.execute_batch(&sql)?))
            .await
            .unwrap();
        let report = checker.check(&quick).await.unwrap();
        assert!(
            report
                .problems
                .iter()
                .any(|p| p.kind == "layer_identity_mismatch"),
            "{damage}: {:?}",
            report.problems
        );
        e.db.conn()
            .call(move |c| Ok(c.execute_batch(&repair)?))
            .await
            .unwrap();
    }

    e.service.remove(&committed, false).await.unwrap();
    e.service.remove(&lazy.id, false).await.unwrap();
    assert!(e.db.get_layer(&layer.key()).await.is_err());
    assert!(e.db.list_layers().await.unwrap().is_empty());
}

/// A registry that cannot serve ranges right (it ignores them, refuses
/// them, answers without the range it sent, or short): the layer is pulled
/// whole and is the layer of its blob, or by its TOC when the bytes were
/// the ones asked for; never refused.  One that answers the ranges with
/// other bytes (an offset off) contradicts the TOC the descriptor vouches
/// for: the pull is refused, as podman does, and records nothing.
#[tokio::test]
async fn test_a_registry_that_cannot_serve_ranges_gives_the_blob_whole() {
    let layer = build_chunked(&sample());
    for (mode, cut) in [
        (RangeMode::Ignore, 0),
        (RangeMode::SingleOnly, 0),
        (RangeMode::Refuse, 0),
        (RangeMode::NoContentRange, 0),
        (RangeMode::Normal, 1000),
    ] {
        for lazy in [false, true] {
            let e = env().await;
            e.publish(&[&layer], &[ZSTD]);
            *e.reg.mode.lock().unwrap() = mode;
            e.reg.cut.store(cut, Ordering::SeqCst);
            let pulled = match pull_tag(&e, "latest", lazy).await {
                // (a layer that would be pulled whole cannot be lazy: refused)
                Err(velarx_types::ImageError::NotLazy { .. }) if lazy => continue,
                other => other.unwrap(),
            };
            let keys = keys_of(&e, &pulled.id).await;
            let whole = pulled.stats.layers[0].note.is_some();
            assert_eq!(
                keys,
                [if whole { layer.whole() } else { layer.key() }],
                "lazy {lazy} cut {cut}"
            );
            if matches!(mode, RangeMode::Refuse | RangeMode::NoContentRange) || cut > 0 {
                assert!(whole, "lazy {lazy} cut {cut}: {:?}", pulled.stats.layers[0]);
            }
            if whole {
                let record = e.db.get_layer(&layer.whole()).await.unwrap();
                assert_eq!(record.diff_id.as_ref(), Some(&layer.diff_id));
                assert!(e.db.get_layer(&layer.key()).await.is_err());
            }
        }
    }
    let e = env().await;
    e.publish(&[&layer], &[ZSTD]);
    *e.reg.mode.lock().unwrap() = RangeMode::Lie;
    let err = e.pull().await.expect_err("other bytes for the ranges");
    assert!(velarx_content::pull::chunked::refuses(&err), "{err}");
    assert!(e.db.list_layers().await.unwrap().is_empty());
    assert_eq!(e.staged_leftovers(), 0);
}

/// One TOC named by two blobs (the second has a frame more at its end):
/// one layer, the layer of the TOC, for both images.  Its record names the
/// blob of the last pull with the registry of that pull, so that its lazy
/// fetches ask that registry for a blob it has; neither image is damage for
/// `system check`, and a manifest that names the TOC with both blobs gets
/// the layer of each blob when the TOC cannot be used.
#[tokio::test]
async fn test_one_toc_named_by_two_blobs_is_one_layer() {
    let first = build_chunked(&sample());
    let mut second = Built {
        blob: first.blob.clone(),
        diff_id: first.diff_id,
        annotations: first.annotations.clone(),
    };
    second.blob.extend(skippable(4));
    second.blob.extend(b"more");
    assert_ne!(sha(&first.blob), sha(&second.blob));
    assert_eq!(first.key(), second.key());
    let (host_a, a) = start_registry().await;
    let (host_b, b) = start_registry().await;
    publish_to(&a, &[&first], &[ZSTD]);
    publish_to(&b, &[&second], &[ZSTD]);
    let client = client_for(&[&host_a, &host_b]);
    let s = side_with(Some(&conf_for(&[&host_a, &host_b]))).await;
    let pull = |host: String| {
        let (service, client) = (s.service.clone(), client.clone());
        async move {
            let (tx, mut rx) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            service
                .pull_lazy_with_client(&client, &format!("{host}/test:latest"), tx)
                .await
                .unwrap()
        }
    };
    let one = pull(host_a.clone()).await;
    let two = pull(host_b.clone()).await;
    assert_ne!(one.id, two.id);
    let area = s.service.staging_area();
    let keys = |id: String| {
        let pull = area.pull(&id).unwrap().unwrap();
        pull.layers
            .iter()
            .map(|k| LayerKey::parse(k).unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(keys(one.id.clone()), [first.key()]);
    assert_eq!(keys(two.id.clone()), [first.key()]);
    // (one staged layer: the last pull's blob and registry)
    let record = area
        .layer(&first.key())
        .unwrap()
        .unwrap()
        .record(false)
        .unwrap();
    assert_eq!(record.blob, Some(sha(&second.blob)));
    assert_eq!(record.size, second.blob.len() as i64);
    assert!(
        record.registry_ref.as_deref().unwrap().starts_with(&host_b),
        "{:?}",
        record.registry_ref
    );
    // a file of the first image, fetched from where the record says
    let before = b.hits.lock().unwrap().get(&sha(&second.blob)).copied();
    let at_a = a.hits.lock().unwrap().get(&sha(&first.blob)).copied();
    s.service
        .fetch_lazy_file(&vid(b"hello\n"), &first.key())
        .await
        .unwrap();
    assert!(b.hits.lock().unwrap().get(&sha(&second.blob)).copied() > before);
    assert_eq!(a.hits.lock().unwrap().get(&sha(&first.blob)).copied(), at_a);
    s.service.complete_image(&one.id).await.unwrap();
    let record = s.db.get_layer(&first.key()).await.unwrap();
    assert_eq!(
        record.blob,
        Some(sha(&second.blob)),
        "the completion keeps it"
    );
    let tmp = tempfile::tempdir().unwrap();
    let checker = CheckService::new(
        s.db.clone(),
        std::sync::Arc::new((*s.service).clone()),
        s.store.clone(),
        tmp.path().join("staging"),
    );
    let report = checker.check(&CheckSpec::default()).await.unwrap();
    assert!(
        !report
            .problems
            .iter()
            .any(|p| p.kind == "layer_identity_mismatch"),
        "{:?}",
        report.problems
    );

    let e = env().await;
    e.publish(&[&first, &second], &[ZSTD, ZSTD]);
    *e.reg.mode.lock().unwrap() = RangeMode::Refuse;
    let both = e.pull().await.unwrap();
    assert_eq!(keys_of(&e, &both.id).await, [first.whole(), second.whole()]);
}

/// Pulls of one image, lazily and not, at once and one after the other: one
/// layer of the TOC, the image complete once a pull that is not lazy is
/// done, and a lazy pull of a complete image changes nothing.
#[tokio::test]
async fn test_lazy_and_eager_pulls_of_one_image_make_one_layer() {
    let layer = build_chunked(&sample());
    let e = env().await;
    e.publish(&[&layer], &[ZSTD]);
    let (lazy, eager) = tokio::join!(pull_tag(&e, "latest", true), pull_tag(&e, "latest", false));
    let (lazy, eager) = (lazy.unwrap(), eager.unwrap());
    assert_eq!(lazy.id, eager.id);
    assert_eq!(keys_of(&e, &lazy.id).await, [layer.key()]);
    assert_eq!(e.db.list_layers().await.unwrap().len(), 1);
    // whatever came last, a completion proves it
    e.service.complete_image(&lazy.id).await.unwrap();
    let record = e.db.get_layer(&layer.key()).await.unwrap();
    assert_eq!(record.status, "ready");
    assert_eq!(
        record.diff_id, None,
        "verified by its table, like a lazy layer"
    );
    assert!(!e.service.get(&lazy.id).await.unwrap().is_lazy);

    for first_lazy in [true, false] {
        let e = env().await;
        e.publish(&[&layer], &[ZSTD]);
        let first = pull_tag(&e, "latest", first_lazy).await.unwrap();
        let again = pull_tag(&e, "latest", !first_lazy).await.unwrap();
        assert_eq!(first.id, again.id);
        assert_eq!(keys_of(&e, &again.id).await, [layer.key()]);
        assert_eq!(e.db.list_layers().await.unwrap().len(), 1);
        let refs = e.db.get_layer_file_refs(&layer.key()).await.unwrap();
        assert!(refs.iter().all(|r| r.ref_count >= 1));
        assert!(!e.service.get(&again.id).await.unwrap().is_lazy);
        let erofs =
            velarx_fuse::composefs::layer_image_path(e.store.root(), &layer.key().file_stem());
        assert!(erofs.is_file());
        e.service.remove(&again.id, false).await.unwrap();
        assert!(e.db.list_layers().await.unwrap().is_empty());
        let storage = velarx_config::StorageConfig {
            root: e._tmp.path().to_path_buf(),
            ..Default::default()
        };
        velarx_core::services::GcService::new(
            e.db.clone(),
            e.store.clone(),
            &storage,
            e.service.storage().clone(),
        )
        .collect(Default::default())
        .await
        .unwrap();
        assert!(
            !erofs.exists(),
            "the image of the layer of the TOC is collected"
        );
    }
}
