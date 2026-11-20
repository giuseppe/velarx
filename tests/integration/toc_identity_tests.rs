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

/// A registry that serves no range gives the blob whole, as the transport of
/// the ranges the table names: the layer is the layer of its table, eagerly
/// and lazily, never the layer of its blob.
#[tokio::test]
async fn test_a_chunked_layer_that_cannot_be_ranged_is_still_the_layer_of_its_table() {
    for mode in [RangeMode::Refuse, RangeMode::Ignore] {
        for lazy in [false, true] {
            let e = env().await;
            let layer = build_chunked(&sample());
            e.publish(&[&layer], &[ZSTD]);
            *e.reg.mode.lock().unwrap() = mode;
            let pulled = pull_tag(&e, "latest", lazy).await.unwrap();
            if lazy {
                e.service.complete_image(&pulled.id).await.unwrap();
            }
            assert_eq!(keys_of(&e, &pulled.id).await, [layer.key()]);
            let record = e.db.get_layer(&layer.key()).await.unwrap();
            assert_eq!(record.status, "ready");
            assert!(e.db.get_layer(&layer.whole()).await.is_err());
            assert!(e.store.contains(&vid(b"hello\n")));
        }
    }
}

/// The TOC route needs the tar-split (or a table of version 2): a descriptor
/// with the labels of the TOC and none of the tar-split is refused, naming
/// the layer, eagerly and lazily, and nothing of it is stored.
#[tokio::test]
async fn test_a_chunked_layer_without_its_tar_split_is_refused_and_stores_nothing() {
    let e = env().await;
    let mut layer = build_chunked(&sample());
    layer.annotations.remove(LABELS[2]);
    e.publish(&[&layer], &[ZSTD]);
    let before = e.stored().await;
    for lazy in [true, false] {
        let refused = pull_tag(&e, "latest", lazy).await.unwrap_err().to_string();
        assert!(refused.contains(&sha(&layer.blob).to_string()), "{refused}");
        assert!(refused.contains("no tar-split"), "{refused}");
        assert_eq!(e.stored().await, before);
    }
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

    // the other way: a gzip layer of the blob is stored, then another image
    // names the same blob with the labels of its table
    let e = env().await;
    publish_arch(
        &e.reg,
        &[&gzip],
        &[GZIP],
        velarx_registry::target::host_arch(),
        "gzip",
    );
    let first = pull_tag(&e, "gzip", false).await.unwrap();
    assert_eq!(keys_of(&e, &first.id).await, [gzip.whole()]);
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
    // two layers for one diff id, each of the route that verified it
    assert!(e.db.get_layer(&chunked.key()).await.is_err());
    assert!(e.area().layer(&chunked.key()).unwrap().is_some());
    assert_eq!(e.db.get_layer(&gzip.whole()).await.unwrap().status, "ready");
    assert!(e.service.get(&second.id).await.is_err(), "being pulled");
}

/// The descriptor decides, never the blob: a blob with a TOC frame whose
/// descriptor has none of the labels is a layer of its blob, pulled whole,
/// and its TOC is not read.  Half of the labels is not none: the layer is
/// refused, and nothing is stored.
#[tokio::test]
async fn test_a_descriptor_without_the_labels_is_the_layer_of_its_blob() {
    let layer = build_chunked(&sample());
    let toc = layer.key();
    let mut bare = layer.clone();
    for label in LABELS {
        bare.annotations.remove(label);
    }
    let e = env().await;
    e.publish(&[&bare], &[ZSTD]);
    let before = e.stored().await;
    // (a lazy pull of a layer that cannot be lazy is refused)
    let lazy = pull_tag(&e, "latest", true).await;
    assert!(
        matches!(lazy, Err(velarx_types::ImageError::NotLazy { .. })),
        "{lazy:?}"
    );
    assert_eq!(e.stored().await, before);
    let pulled = e.pull().await.unwrap();
    assert_eq!(e.reg.ranged.load(Ordering::SeqCst), 0);
    assert_eq!(keys_of(&e, &pulled.id).await, [bare.whole()]);
    let record = e.db.get_layer(&bare.whole()).await.unwrap();
    assert_eq!(record.diff_id.as_ref(), Some(&bare.diff_id));
    assert!(e.db.get_layer(&toc).await.is_err());

    for strip in [&LABELS[1..], &LABELS[..1]] {
        let mut half = layer.clone();
        for label in strip {
            half.annotations.remove(*label);
        }
        for lazy in [false, true] {
            let e = env().await;
            e.publish(&[&half], &[ZSTD]);
            let before = e.stored().await;
            let refused = pull_tag(&e, "latest", lazy).await.unwrap_err();
            assert!(refused.to_string().contains("zstd:chunked"), "{refused}");
            assert_eq!(e.stored().await, before);
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

/// A registry that cannot serve ranges (it ignores them, takes one at a time
/// or refuses them) still gives the layer through its table: the blob is the
/// transport.  One whose answers are not what was asked for (no
/// `Content-Range`, cut short every time) refuses the layer, naming it, and
/// stores nothing.
#[tokio::test]
async fn test_a_registry_that_cannot_serve_ranges_gives_the_blob_as_transport() {
    let layer = build_chunked(&sample());
    for mode in [RangeMode::Ignore, RangeMode::SingleOnly, RangeMode::Refuse] {
        for lazy in [false, true] {
            let e = env().await;
            e.publish(&[&layer], &[ZSTD]);
            *e.reg.mode.lock().unwrap() = mode;
            let pulled = pull_tag(&e, "latest", lazy).await.unwrap();
            if lazy {
                e.service.complete_image(&pulled.id).await.unwrap();
            }
            assert_eq!(keys_of(&e, &pulled.id).await, [layer.key()]);
            assert!(e.db.get_layer(&layer.whole()).await.is_err());
            assert!(e.store.contains(&vid(b"hello\n")));
        }
    }
    for (mode, cut) in [(RangeMode::NoContentRange, 0), (RangeMode::Normal, 1000)] {
        for lazy in [false, true] {
            let e = env().await;
            e.publish(&[&layer], &[ZSTD]);
            *e.reg.mode.lock().unwrap() = mode;
            e.reg.cut.store(cut, Ordering::SeqCst);
            let before = e.stored().await;
            let refused = pull_tag(&e, "latest", lazy).await.unwrap_err();
            assert!(
                refused.to_string().contains(&sha(&layer.blob).to_string()),
                "{refused}"
            );
            assert_eq!(e.stored().await, before);
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
    assert_eq!(keys_of(&e, &both.id).await, [first.key(), second.key()]);
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

/// A pull of `layer`, eagerly or lazily, in a store of its own: its table
/// of contents (the stored one, or the staged one of a lazy pull), or the
/// error of a refusal, which leaves the store as it was.
async fn toc_pulled(
    layer: &Built,
    lazy: bool,
) -> Result<velarx_storage::Toc, velarx_types::ImageError> {
    let e = env().await;
    e.publish(&[layer], &[ZSTD]);
    let before = e.stored().await;
    let pulled = match pull_tag(&e, "latest", lazy).await {
        Ok(p) => p,
        Err(err) => {
            assert_eq!(e.stored().await, before, "{err}");
            return Err(err);
        }
    };
    assert_eq!(keys_of(&e, &pulled.id).await, [layer.key()]);
    let text = match lazy {
        true => e
            .area()
            .layer(&layer.key())
            .unwrap()
            .unwrap()
            .toc_text()
            .unwrap(),
        false => e.db.get_layer(&layer.key()).await.unwrap().toc.unwrap(),
    };
    Ok(serde_json::from_str(&text).unwrap())
}

/// `layer` with the entry `name` of its table of contents changed by `edit`.
fn edited(layer: &Built, name: &str, edit: impl FnOnce(&mut serde_json::Value)) -> Built {
    with_toc(layer, |j| {
        let at = j["entries"]
            .as_array()
            .unwrap()
            .iter()
            .position(|e| e["name"] == name)
            .unwrap();
        edit(&mut j["entries"][at]);
    })
}

/// A dual view image: the manifest vouches for a table of contents that
/// describes another filesystem than the tar stream of the layer (the
/// tar-split and the blob).  Whichever way it is pulled, the layer is
/// refused with an error that names it and nothing of it is stored: it is
/// never the layer of the stream, and a table the tar-split contradicts
/// would make another tar again than the layer that was stored.  A pull
/// that is not lazy refuses it at once; a lazy pull checks the table
/// against its digests only, and its completion, which replays the
/// tar-split before it commits the layer, refuses it.
#[tokio::test]
async fn test_a_table_that_differs_from_the_tar_stream_is_refused() {
    let layer = build_chunked(&sample());
    let dual = [
        edited(&layer, "etc/small", |e| e["mode"] = 0o4755.into()),
        edited(&layer, "etc/small", |e| e["uid"] = 1000.into()),
        edited(&layer, "etc/small", |e| e["name"] = "etc/renamed".into()),
        edited(&layer, "etc/small", |e| {
            e["xattrs"] = serde_json::json!({"security.capability": "AQID"})
        }),
        with_toc(&layer, |j| {
            let entries = j["entries"].as_array_mut().unwrap();
            let at = entries.iter().position(|e| e["name"] == "etc/copy");
            entries.remove(at.unwrap());
        }),
        with_toc(&layer, |j| {
            j["entries"].as_array_mut().unwrap().push(serde_json::json!(
                {"type": "symlink", "name": "etc/only-in-the-table", "linkName": "/etc/shadow", "mode": 0o777}
            ));
        }),
    ];
    for lazy in [false, true] {
        let honest = toc_pulled(&layer, lazy).await.unwrap();
        let small = honest.find_by_name("etc/small").unwrap();
        assert_eq!(small.mode & 0o7777, 0o644);
    }
    for (i, dual) in dual.iter().enumerate() {
        let refused = toc_pulled(dual, false).await.unwrap_err();
        assert!(
            refused.to_string().contains(&sha(&dual.blob).to_string()),
            "{i}: {refused}"
        );
        let refused = completion_refused(dual).await;
        assert!(
            matches!(refused, velarx_types::ImageError::Contradicted(_))
                && refused.to_string().contains("tar-split differ"),
            "{i} (lazy): {refused}"
        );
    }
    // another content: the files are checked against the table, which the
    // stream cannot make right
    let content = edited(&layer, "etc/small", |e| {
        e["digest"] = sha(b"not hello").to_string().into();
        e["chunkDigest"] = sha(b"not hello").to_string().into();
        e["fsverity"] = toc_verity(b"not hello").into();
    });
    let refused = toc_pulled(&content, false).await.unwrap_err();
    assert!(
        refused
            .to_string()
            .contains(&sha(&content.blob).to_string()),
        "{refused}"
    );
    completion_refused(&content).await;
}

/// The error of the completion of a lazy pull of `layer`, which the pull
/// accepted: the layer is not committed and the pull stays staged.
async fn completion_refused(layer: &Built) -> velarx_types::ImageError {
    let e = env().await;
    e.publish(&[layer], &[ZSTD]);
    let pulled = pull_tag(&e, "latest", true).await.unwrap();
    let refused = e.service.complete_image(&pulled.id).await.unwrap_err();
    assert!(e.db.list_layers().await.unwrap().is_empty(), "{refused}");
    assert!(e.area().pull(&pulled.id).unwrap().is_some());
    refused
}

/// A table of version 1 that lists one digest with two sizes is refused
/// for that, before its tar-split is compared with it.
#[tokio::test]
async fn test_a_table_of_version_1_with_one_digest_and_two_sizes_is_refused() {
    let layer = build_chunked(&sample());
    let lying = with_toc(&layer, |j| {
        let entries = j["entries"].as_array_mut().unwrap();
        let mut copy = entries
            .iter()
            .find(|e| e["name"] == "etc/small")
            .unwrap()
            .clone();
        copy["name"] = "zz".into();
        copy["size"] = 4096.into();
        entries.push(copy);
    });
    for lazy in [false, true] {
        let refused = toc_pulled(&lying, lazy).await.unwrap_err().to_string();
        assert!(
            refused.contains(&sha(&lying.blob).to_string()) && refused.contains("two sizes"),
            "(lazy {lazy}): {refused}"
        );
    }
}

/// A table that gives a content the store holds another size is refused,
/// and the store is as it was.
#[tokio::test]
async fn test_a_digest_of_the_store_listed_with_another_size_is_refused() {
    let a = build_chunked(&[Item::File {
        name: "a",
        data: b"hello\n".to_vec(),
        chunk: 4096,
    }]);
    // (`b` has 4096 bytes in the tar and the tar-split: its table gives it
    // the digests of the content of `a`)
    let b = build_chunked(&[Item::File {
        name: "b",
        data: vec![9u8; 4096],
        chunk: 4096,
    }]);
    let b = edited(&b, "b", |e| {
        e["digest"] = sha(b"hello\n").to_string().into();
        e["chunkDigest"] = sha(b"hello\n").to_string().into();
        e["fsverity"] = toc_verity(b"hello\n").into();
    });
    for lazy in [false, true] {
        let e = env().await;
        e.publish(&[&a], &[ZSTD]);
        e.pull().await.unwrap();
        e.publish(&[&b], &[ZSTD]);
        let before = e.stored().await;
        let refused = pull_tag(&e, "latest", lazy).await.unwrap_err().to_string();
        assert!(
            refused.contains(&sha(&b.blob).to_string()),
            "lazy {lazy}: {refused}"
        );
        assert_eq!(e.stored().await, before, "lazy {lazy}");
        let checker = CheckService::new(
            e.db.clone(),
            std::sync::Arc::new((*e.service).clone()),
            e.store.clone(),
            e.staging.clone(),
        );
        let report = checker.check(&CheckSpec::default()).await.unwrap();
        assert!(report.problems.is_empty(), "{:?}", report.problems);

        // (both in one image, in a store that has neither)
        let e = env().await;
        e.publish(&[&a, &b], &[ZSTD, ZSTD]);
        let before = e.stored().await;
        assert!(pull_tag(&e, "latest", lazy).await.is_err(), "lazy {lazy}");
        assert_eq!(e.stored().await, before, "lazy {lazy}");
    }
}
