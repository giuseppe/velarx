// SPDX-License-Identifier: Apache-2.0
//! Layers of zstd:chunked version 2: the canonical tar of their table of
//! contents, no tar-split.  What pulls them, lazily or not, and what refuses
//! a table that claims to be of version 2 and is not.

use crate::common::*;
use std::collections::HashMap;
use std::io::Read;
use velarx_content::layer::reproduce::StoredLayer;
use velarx_content::layer::writer::Compression;
use velarx_storage::{canonical, Toc};

const PREFIX: &str = "io.github.containers.zstd-chunked.";

/// `layer` with the table of contents `edit` makes of its own: the blob
/// ends with the table and the footer, which are written again, and the
/// annotations say where and what they are.  The layer is the one of a
/// writer that has no binary table, so the JSON is what a pull reads.
fn edited(
    layer: &Built,
    edit: impl FnOnce(&mut Toc),
    annotate: impl FnOnce(&mut HashMap<String, String>),
) -> Built {
    rewritten(layer, edit, annotate, false)
}

/// [`edited`] with the binary table of the edited table of contents before
/// it, which the annotations name and a pull reads instead of the JSON.
fn with_table(
    layer: &Built,
    edit: impl FnOnce(&mut Toc),
    annotate: impl FnOnce(&mut HashMap<String, String>),
) -> Built {
    rewritten(layer, edit, annotate, true)
}

fn rewritten(
    layer: &Built,
    edit: impl FnOnce(&mut Toc),
    annotate: impl FnOnce(&mut HashMap<String, String>),
    table: bool,
) -> Built {
    let a = |k: &str| layer.annotations[&format!("{PREFIX}{k}")].clone();
    let position: Vec<usize> = a("manifest-position")
        .split(':')
        .map(|n| n.parse().unwrap())
        .collect();
    let mut toc: Toc = serde_json::from_slice(
        &zstd::decode_all(&layer.blob[position[0]..position[0] + position[1]]).unwrap(),
    )
    .unwrap();
    edit(&mut toc);
    // (the metadata starts with the table, when the layer has one)
    let start = layer
        .annotations
        .get(&format!("{PREFIX}table-position"))
        .map_or(position[0], |p| {
            p.split(':').next().unwrap().parse().unwrap()
        });
    let mut blob = layer.blob[..start - 8].to_vec();
    let mut annotations = layer.annotations.clone();
    annotations.retain(|k, _| !k.starts_with(&format!("{PREFIX}table-")));
    if table {
        let table = velarx_storage::table::encode(&toc, Algorithm::Sha256).unwrap();
        let z = zstd::encode_all(&table[..], 3).unwrap();
        blob.extend(skippable(z.len()));
        annotations.insert(
            format!("{PREFIX}table-position"),
            format!("{}:{}:{}", blob.len(), z.len(), table.len()),
        );
        annotations.insert(format!("{PREFIX}table-checksum"), sha(&z).to_string());
        blob.extend(&z);
    }
    let json = serde_json::to_vec(&toc).unwrap();
    let z = zstd::encode_all(&json[..], 3).unwrap();
    blob.extend(skippable(z.len()));
    let toc_offset = blob.len() as u64;
    blob.extend(&z);
    let mut footer = Vec::new();
    for v in [toc_offset, z.len() as u64, json.len() as u64, 1, 0, 0, 0] {
        footer.extend(v.to_le_bytes());
    }
    footer.extend(b"GNUlInUx");
    blob.extend(skippable(footer.len()));
    blob.extend(footer);
    annotations.insert(
        format!("{PREFIX}manifest-position"),
        format!("{toc_offset}:{}:{}:1", z.len(), json.len()),
    );
    annotations.insert(format!("{PREFIX}manifest-checksum"), sha(&z).to_string());
    annotate(&mut annotations);
    Built {
        blob,
        diff_id: layer.diff_id,
        annotations,
    }
}

async fn eager_env() -> Env {
    env_with(velarx_config::PullConfig {
        lazy_window_files: 0,
        ..Default::default()
    })
    .await
}

/// The stream of the layer `key` of `e`, which is checked against `diff_id`.
async fn stream_of(
    e: &Env,
    key: &velarx_db::LayerKey,
    diff_id: &velarx_types::digest::Digest,
) -> Vec<u8> {
    let layer = StoredLayer::load_expecting(&e.db, key, Some(diff_id.alg()), Some(diff_id))
        .await
        .unwrap();
    let mut out = Vec::new();
    layer
        .verified_stream(e.store.clone())
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    out
}

async fn assert_stored_without_tar_split(e: &Env, key: &velarx_db::LayerKey, lazy: bool) {
    let record = e.db.get_layer(key).await.unwrap();
    assert_eq!(record.status, "ready", "lazy: {lazy}");
    let toc = stored_toc(&e.db, key).await;
    assert!(toc.is_canonical() && toc.tar_split_digest.is_none());
    assert_eq!(
        e.db.get_layer_tarsplit(key).await.unwrap(),
        Some(Vec::new())
    );
}

#[tokio::test]
async fn test_a_layer_of_version_2_is_pulled_without_a_tar_split() {
    for lazy in [false, true] {
        let e = eager_env().await;
        let layer = build_canonical(&sample());
        e.publish(&[&layer], &[ZSTD]);
        if lazy {
            let result = e.pull_lazy().await.unwrap();
            // the table is staged as it is, and a file is fetched on demand
            let staged = e.area().layer(&layer.key()).unwrap().unwrap();
            assert!(staged.tarsplit().unwrap().is_empty());
            assert!(staged_toc(&staged).is_canonical());
            let path = e
                .service
                .fetch_lazy_file(&vid(b"hello\n"), &layer.key())
                .await
                .unwrap();
            assert_eq!(std::fs::read(path).unwrap(), b"hello\n");
            e.service
                .complete_image(&format!("{}/test:latest", e.host))
                .await
                .unwrap();
            assert!(e.service.get(&result.id).await.is_ok());
        } else {
            e.pull().await.unwrap();
        }
        assert_stored_without_tar_split(&e, &layer.key(), lazy).await;
        // its stream is the canonical tar the diff id is the digest of
        let tar = stream_of(&e, &layer.key(), &layer.diff_id).await;
        assert_eq!(sha(&tar), layer.diff_id);
        canonical::validate_tar(&tar[..]).unwrap();
    }
}

/// An image of layers of the three kinds, a layer with no table, one of
/// version 1 and one of version 2, pulled eagerly; the last two lazily.
#[tokio::test]
async fn test_an_image_of_layers_of_both_versions_is_pulled() {
    let v1 = build_chunked(&sample());
    let v2 = build_canonical(&[Item::File {
        name: "etc/small",
        data: b"two\n".to_vec(),
        chunk: 4096,
    }]);
    let gz = build_gzip(&sample());
    let e = eager_env().await;
    e.publish(&[&gz, &v1, &v2], &[GZIP, ZSTD, ZSTD]);
    e.pull().await.unwrap();
    assert!(e
        .db
        .get_layer_tarsplit(&v1.key())
        .await
        .unwrap()
        .is_some_and(|t| !t.is_empty()));
    assert_stored_without_tar_split(&e, &v2.key(), false).await;
    assert_eq!(
        sha(&stream_of(&e, &v2.key(), &v2.diff_id).await),
        v2.diff_id
    );
    assert_eq!(
        sha(&stream_of(&e, &v1.key(), &v1.diff_id).await),
        v1.diff_id
    );

    let e = eager_env().await;
    e.publish(&[&v1, &v2], &[ZSTD, ZSTD]);
    e.pull_lazy().await.unwrap();
    e.service
        .complete_image(&format!("{}/test:latest", e.host))
        .await
        .unwrap();
    assert_stored_without_tar_split(&e, &v2.key(), true).await;
    assert!(e
        .db
        .get_layer_tarsplit(&v1.key())
        .await
        .unwrap()
        .is_some_and(|t| !t.is_empty()));
    assert_eq!(
        sha(&stream_of(&e, &v2.key(), &v2.diff_id).await),
        v2.diff_id
    );
}

/// The table of version 2 is the one thing that says the layer is: whatever
/// the annotations say, one that is not canonical is an error that names the
/// layer, and no other way of pulling is tried instead.
#[tokio::test]
async fn test_a_table_of_version_2_that_is_not_canonical_is_refused() {
    let good = build_canonical(&sample());
    let swapped = edited(&good, |toc| toc.entries.swap(1, 2), |_| {});
    let unnamed = edited(
        &good,
        |toc| {
            let e = toc
                .entries
                .iter_mut()
                .find(|e| e.name == "./etc/small")
                .unwrap();
            e.name = "etc/small".into();
        },
        |_| {},
    );
    let unproven = edited(
        &good,
        |toc| {
            let e = toc
                .entries
                .iter_mut()
                .find(|e| e.name == "./etc/small")
                .unwrap();
            e.fsverity = None;
        },
        |_| {},
    );
    let with_split = edited(
        &good,
        |toc| toc.tar_split_digest = Some(sha(b"split").to_string()),
        |_| {},
    );
    let tar_split = |a: &mut HashMap<String, String>| {
        a.insert(format!("{PREFIX}tarsplit-position"), "10:20:30".into());
    };
    let says_so_json = edited(&good, |_| {}, tar_split);
    // (the layer as the writer made it, read by its binary table: a table
    // has its paths in order, each a path, each file with its fs-verity
    // digest, and no tar-split when it is canonical; what it can be told
    // otherwise is the annotation)
    let mut says_so_table = good.clone();
    tar_split(&mut says_so_table.annotations);
    for (name, layer) in [
        ("swapped", &swapped),
        ("unnamed", &unnamed),
        ("unproven", &unproven),
        ("with a tar-split digest", &with_split),
        ("with a tar-split position", &says_so_json),
        ("a binary table with a tar-split position", &says_so_table),
    ] {
        for lazy in [false, true] {
            let e = eager_env().await;
            e.publish(&[layer], &[ZSTD]);
            let result = if lazy {
                e.pull_lazy().await
            } else {
                e.pull().await
            };
            let err = result
                .err()
                .unwrap_or_else(|| panic!("{name} (lazy: {lazy}) was pulled"))
                .to_string();
            assert!(
                err.contains("invalid zstd:chunked version 2 table of contents")
                    && err.contains(&sha(&layer.blob).to_string()),
                "{name} (lazy: {lazy}): {err}"
            );
            assert!(e.db.list_layers().await.unwrap().is_empty());
        }
    }
}

/// A layer of a table of version 1 stays one whatever the annotation says: a
/// tool that copies a layer keeps the annotations it does not know.
#[tokio::test]
async fn test_a_stale_version_annotation_on_a_table_of_version_1_is_ignored() {
    let e = eager_env().await;
    let mut v1 = build_chunked(&sample());
    v1.annotations
        .insert(format!("{PREFIX}version"), "2".into());
    e.publish(&[&v1], &[ZSTD]);
    e.pull().await.unwrap();
    let toc = stored_toc(&e.db, &v1.key()).await;
    assert!(!toc.is_canonical());
    assert!(e
        .db
        .get_layer_tarsplit(&v1.key())
        .await
        .unwrap()
        .is_some_and(|t| !t.is_empty()));
}

/// The diff id of a layer of version 2 is a claim that nothing checks when it
/// is pulled: a push recreates the canonical tar from the table and refuses
/// a stream that is not the diff id of the configuration, naming the layer,
/// whatever the compression.
#[tokio::test]
async fn test_a_pulled_layer_of_version_2_whose_tar_is_not_its_diff_id_is_not_pushed() {
    use velarx_core::services::PushOptions;
    let e = eager_env().await;
    let (host_b, b) = start_registry().await;
    e.trust(&[&host_b]);
    let mut layer = build_canonical(&sample());
    layer.diff_id = sha(b"another layer");
    e.publish(&[&layer], &[ZSTD]);
    e.pull().await.unwrap();
    for compression in [Compression::ZstdChunked, Compression::Gzip] {
        let err = e
            .service
            .push_with_client(
                &client_for(&[&e.host, &host_b]),
                &format!("{}/test:latest", e.host),
                &PushOptions {
                    destination: Some(format!("{host_b}/x:latest")),
                    compression: Some(compression),
                    ..PushOptions::default()
                },
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&format!("layer {}", sha(&layer.blob)))
                && err.contains("does not describe the canonical tar the image claims"),
            "{compression:?}: {err}"
        );
    }
    assert!(!b
        .blobs
        .lock()
        .unwrap()
        .keys()
        .any(|k| k.starts_with("manifest:")));
}

/// A table that lists one digest with two sizes, or whose files do not fit
/// a layer, is refused before anything is fetched or stored, eagerly and
/// lazily: the store is as it was, nothing is left to complete, and the
/// error names the layer.
#[tokio::test]
async fn test_a_table_whose_sizes_are_not_possible_is_refused_and_stores_nothing() {
    let good = build_canonical(&sample());
    // a file at the end of the table, as `./etc/small` is, of `size` bytes
    let another = |toc: &mut Toc, name: &str, digest: &str, size: u64| {
        let mut e = toc
            .entries
            .iter()
            .find(|e| e.name == "./etc/small")
            .unwrap()
            .clone();
        e.name = name.into();
        e.size = size;
        if e.chunk_size != 0 {
            e.chunk_size = size;
        }
        if !digest.is_empty() {
            e.fsverity = velarx_types::digest::parse_toc_fsverity(&format!(
                "sha256-12:{}",
                digest.repeat(32)
            ));
        }
        toc.entries.push(e);
    };
    let two_sizes = edited(&good, |t| another(t, "./zz", "", 6 + 4096), |_| {});
    let huge = edited(&good, |t| another(t, "./zz", "ab", u64::MAX), |_| {});
    let wraps = edited(
        &good,
        |t| {
            another(t, "./zz", "ab", 1 << 63);
            another(t, "./zzz", "cd", 1 << 63);
        },
        |_| {},
    );
    let too_big = edited(&good, |t| another(t, "./zz", "ab", 2 << 30), |_| {});
    // the same, read by the binary table a writer gives them
    let huge_table = with_table(&good, |t| another(t, "./zz", "ab", u64::MAX), |_| {});
    let wraps_table = with_table(
        &good,
        |t| {
            another(t, "./zz", "ab", 1 << 63);
            another(t, "./zzz", "cd", 1 << 63);
        },
        |_| {},
    );
    let too_big_table = with_table(&good, |t| another(t, "./zz", "ab", 2 << 30), |_| {});
    let hello = vid(b"hello\n");
    for (name, layer, says) in [
        ("two sizes", &two_sizes, "two sizes"),
        ("2^64-1 bytes", &huge, "tar is larger"),
        ("2^64 bytes in two files", &wraps, "tar is larger"),
        ("more than a layer may be", &too_big, "tar is larger"),
        ("table: 2^64-1 bytes", &huge_table, "tar is larger"),
        (
            "table: 2^64 bytes in two files",
            &wraps_table,
            "tar is larger",
        ),
        (
            "table: more than a layer may be",
            &too_big_table,
            "tar is larger",
        ),
    ] {
        for lazy in [false, true] {
            let e = env_with(velarx_config::PullConfig {
                lazy_window_files: 0,
                max_layer_gib: 1,
                ..Default::default()
            })
            .await;
            e.publish(&[layer], &[ZSTD]);
            let before = e.stored().await;
            let result = if lazy {
                e.pull_lazy().await
            } else {
                e.pull().await
            };
            let err = result
                .err()
                .unwrap_or_else(|| panic!("{name} (lazy: {lazy}) was pulled"))
                .to_string();
            assert!(
                err.contains(&sha(&layer.blob).to_string()) && err.contains(says),
                "{name} (lazy: {lazy}): {err}"
            );
            if says == "two sizes" {
                assert!(err.contains(&hello), "{err}");
            }
            assert_eq!(e.stored().await, before, "{name} (lazy: {lazy})");
            // there is nothing to complete
            let image = format!("{}/test:latest", e.host);
            let done = tokio::time::timeout(
                std::time::Duration::from_secs(60),
                e.service.complete_image(&image),
            )
            .await
            .expect("the completion ends");
            assert!(done.is_err(), "{name} (lazy: {lazy})");
            assert_eq!(e.stored().await, before, "{name} (lazy: {lazy})");
        }
    }
}
