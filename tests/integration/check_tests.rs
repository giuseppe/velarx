// SPDX-License-Identifier: Apache-2.0
//! `system check` against stores that were damaged on purpose.

use crate::common::*;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use velarx_core::services::{CheckService, ImageService};
use velarx_db::{ContainerRecord, RecordState};
use velarx_fuse::composefs as cfs;
use velarx_proto::system::{CheckAction, CheckReport, CheckSpec};
use velarx_storage::StorageLock;

/// An environment whose images get their composefs images, with one image
/// pulled: its id.
pub(crate) async fn pulled() -> (Env, String) {
    let e = composefs_env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    let id = e.pull().await.unwrap().id;
    (e, id)
}

/// [`pulled`] in a directory of `base`.
async fn pulled_in(base: &std::path::Path) -> (Env, String) {
    let e = env_built_in(
        Some(base),
        velarx_db::Database::open_in_memory().await.unwrap(),
        Default::default(),
        Default::default(),
        Default::default(),
        None,
        |service| service.with_composefs("auto"),
    )
    .await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    let id = e.pull().await.unwrap().id;
    (e, id)
}

pub(crate) async fn composefs_env() -> Env {
    let mut e = env().await;
    let service: ImageService = (*e.service).clone().with_composefs("auto");
    e.service = std::mem::ManuallyDrop::new(service);
    e
}

fn checker(e: &Env) -> CheckService {
    CheckService::new(
        e.db.clone(),
        Arc::new((*e.service).clone()),
        e.store.clone(),
        e.staging.clone(),
    )
    .with_grace(Duration::ZERO)
}

/// The checker of the store of `e` as one that requires fs-verity.
fn requiring(e: &Env) -> CheckService {
    CheckService::new(
        e.db.clone(),
        Arc::new((*e.service).clone()),
        Arc::new(
            velarx_storage::FileStore::new(e.store.root())
                .unwrap()
                .with_verity(velarx_storage::VerityMode::Require),
        ),
        e.staging.clone(),
    )
    .with_grace(Duration::ZERO)
}

fn request(quick: bool, repair: bool) -> CheckSpec {
    CheckSpec {
        quick,
        repair,
        ..Default::default()
    }
}

async fn check(e: &Env, quick: bool, repair: bool) -> CheckReport {
    checker(e).check(&request(quick, repair)).await.unwrap()
}

fn kinds(r: &CheckReport) -> Vec<&str> {
    let mut k: Vec<&str> = r.problems.iter().map(|p| p.kind.as_str()).collect();
    k.sort();
    k
}

/// The object of the file `name` of the image.
async fn object_of(e: &Env, image: &str, name: &str) -> PathBuf {
    for l in e.db.get_image_layers(image).await.unwrap() {
        let toc = stored_toc(&e.db, &l.key).await;
        if let Some(entry) = toc.entries.iter().find(|x| x.name == name) {
            return e.store.local_path(&entry.verity().unwrap()).unwrap();
        }
    }
    panic!("no file {name}");
}

/// The EROFS image of the top layer of the image.
async fn layer_image(e: &Env, image: &str) -> PathBuf {
    let layers = e.db.get_image_layers(image).await.unwrap();
    cfs::layer_image_path(e.store.root(), &layers.last().unwrap().key.file_stem())
}

pub(crate) fn rewrite(path: &std::path::Path, f: impl FnOnce(Vec<u8>) -> Vec<u8>) {
    let mode = std::fs::metadata(path).unwrap().permissions().mode();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let data = f(std::fs::read(path).unwrap());
    std::fs::write(path, data).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

async fn add_container(e: &Env, image: &str) {
    e.db.insert_container(&ContainerRecord {
        id: "c0ffee".repeat(10),
        name: Some("user".into()),
        image_id: image.into(),
        config: "{}".into(),
        state: RecordState::Created,
        created_at: "2024-01-01T00:00:00Z".into(),
        ..Default::default()
    })
    .await
    .unwrap();
}

/// The EROFS image of a layer is the layer's own, made of its table alone:
/// pulled over different layers into two stores, it is the same file, the
/// image of its table.
#[tokio::test]
async fn a_layer_image_is_the_same_whatever_is_below_it() {
    let below = [build_chunked(&sample()), build_chunked(&sample()[..2])];
    // (it adds to `etc/`, which it does not list)
    let top = build_chunked(&[Item::File {
        name: "etc/added",
        data: b"added\n".to_vec(),
        chunk: 4096,
    }]);
    let mut images = Vec::new();
    for base in &below {
        let e = composefs_env().await;
        publish_arch(&e.reg, &[base, &top], &[ZSTD, ZSTD], "amd64", "latest");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let image = format!("{}/test:latest", e.host);
        let id = e
            .service
            .pull_with_client(&e.client(), &image, tx)
            .await
            .unwrap()
            .id;
        let layers = e.db.get_image_layers(&id).await.unwrap();
        assert_eq!(layers.len(), 2);
        let layer = layers.last().unwrap();
        let toc = stored_toc(&e.db, &layer.key).await;
        let path = cfs::layer_image_path(e.store.root(), &layer.key.file_stem());
        let image = std::fs::read(&path).unwrap();
        assert_eq!(
            image,
            velarx_fuse::layer_erofs::layer_image(&toc.entries)
                .unwrap()
                .image
        );
        images.push((layers[0].key, layer.key, image));
    }
    assert_ne!(images[0].0, images[1].0, "the layers below differ");
    assert_eq!(images[0].1, images[1].1);
    assert!(
        images[0].2 == images[1].2,
        "the image of the layer is the same"
    );
}

#[tokio::test]
async fn a_whole_store_has_no_problem() {
    let (e, id) = pulled().await;
    assert!(layer_image(&e, &id).await.is_file());
    for quick in [true, false] {
        let r = check(&e, quick, false).await;
        assert!(r.ok(), "{:?}", r.problems);
        assert!(r.problems.is_empty(), "{:?}", r.problems);
        assert_eq!(
            (r.images_total, r.images_checked, r.images_unchecked),
            (1, 1, 0)
        );
        assert!(r.files_checked > 0);
        assert_eq!(r.bytes_read > 0, !quick);
    }
}

#[tokio::test]
async fn a_truncated_object_is_found_even_when_quick() {
    let (e, id) = pulled().await;
    rewrite(&object_of(&e, &id, "usr/big").await, |mut d| {
        d.truncate(d.len() - 1);
        d
    });
    for quick in [true, false] {
        let r = check(&e, quick, false).await;
        assert!(!r.ok());
        let p = r.problems.iter().find(|p| p.kind == "wrong_size").unwrap();
        assert_eq!(p.image.as_deref(), Some(id.as_str()));
        assert!(
            p.name.as_deref().unwrap().ends_with("/test:latest"),
            "{p:?}"
        );
        assert!(p.path.as_deref().unwrap().contains("/objects/"), "{p:?}");
        assert_eq!(p.action, CheckAction::None);
    }
}

#[tokio::test]
async fn a_flipped_bit_is_found_by_the_full_check_only() {
    let (e, id) = pulled().await;
    rewrite(&object_of(&e, &id, "usr/big").await, |mut d| {
        d[1000] ^= 1;
        d
    });
    assert!(check(&e, true, false).await.ok());
    let r = check(&e, false, false).await;
    assert!(!r.ok());
    let k = kinds(&r);
    assert!(k.contains(&"verity_mismatch"), "{k:?}");
}

#[tokio::test]
async fn a_missing_object_is_found() {
    let (e, id) = pulled().await;
    std::fs::remove_file(object_of(&e, &id, "usr/big").await).unwrap();
    let r = check(&e, true, false).await;
    assert!(!r.ok());
    assert!(kinds(&r).contains(&"object_missing"), "{:?}", r.problems);
}

#[tokio::test]
async fn a_file_without_a_row_is_found() {
    let (e, id) = pulled().await;
    let path = object_of(&e, &id, "usr/big").await;
    e.db.delete_files(vec![{
        let layers = e.db.get_image_layers(&id).await.unwrap();
        let toc = stored_toc(&e.db, &layers[0].key).await;
        toc.entries
            .iter()
            .find(|x| x.name == "usr/big")
            .unwrap()
            .verity()
            .unwrap()
    }])
    .await
    .unwrap();
    let r = check(&e, true, false).await;
    let k = kinds(&r);
    assert!(k.contains(&"unmapped_file"), "{k:?}");
    // (and its object is an orphan now)
    assert!(k.contains(&"orphan_object"), "{k:?}");
    assert!(path.exists());
}

#[tokio::test]
async fn the_composefs_image_is_looked_at() {
    let (e, id) = pulled().await;
    let image = layer_image(&e, &id).await;
    let original = std::fs::read(&image).unwrap();

    std::fs::remove_file(&image).unwrap();
    for quick in [true, false] {
        assert_eq!(kinds(&check(&e, quick, false).await), ["artifact_missing"]);
    }
    std::fs::write(&image, &original).unwrap();
    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o444)).unwrap();
    assert!(check(&e, false, false).await.ok());

    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(kinds(&check(&e, true, false).await), ["artifact_writable"]);
    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o444)).unwrap();

    // damaged: not the digest its layer records, not what the table of
    // contents makes
    rewrite(&image, |d| vec![0xa5; d.len()]);
    let r = check(&e, false, false).await;
    let k = kinds(&r);
    assert_eq!(k, ["artifact_differs", "artifact_id_mismatch"], "{k:?}");
    // a bit of metadata changed
    let other = {
        let mut o = original.clone();
        let n = o.len();
        o[n - 1] ^= 1;
        o
    };
    rewrite(&image, |_| other);
    let r = check(&e, false, false).await;
    let k = kinds(&r);
    assert!(k.contains(&"artifact_differs"), "{k:?}");
    rewrite(&image, |_| original.clone());
    assert!(check(&e, false, false).await.ok());
}

#[tokio::test]
async fn the_store_is_looked_at() {
    let (e, id) = pulled().await;
    let objects = e.store.root().to_path_buf();
    // an object nothing records, a temporary file, an image's temporary file
    let orphan = {
        let o =
            velarx_storage::Object::new(&format!("fsverity-sha256-12:{}", "cd".repeat(32)), false)
                .unwrap();
        let p = e.store.object_path(&o);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"nobody has a row for me").unwrap();
        p
    };
    let tmp = objects.join("ab").join(".tmpX1y2z3");
    std::fs::create_dir_all(tmp.parent().unwrap()).unwrap();
    std::fs::write(&tmp, b"half a file").unwrap();
    let cfs_tmp = objects.parent().unwrap().join("composefs").join(".imageQ9");
    std::fs::create_dir_all(cfs_tmp.parent().unwrap()).unwrap();
    std::fs::write(&cfs_tmp, b"half an image").unwrap();
    let gone = format!("fsverity-sha256-12:{}", "12".repeat(32));
    e.db.record_files(vec![velarx_db::FileRecord {
        digest: gone.clone(),
        size: 1,
        created_at: "2026-01-01T00:00:00Z".into(),
        checked: false,
    }])
    .await
    .unwrap();
    // staging of a pull that died
    let pull = e.staging.join("pull-0123abcd");
    std::fs::create_dir_all(pull.join("files")).unwrap();

    let r = check(&e, true, false).await;
    assert!(!r.ok());
    let by = |k: &str| r.problems.iter().filter(|p| p.kind == k).count();
    assert_eq!(by("orphan_object"), 1, "{:?}", r.problems);
    assert_eq!(by("stale_temp"), 2, "{:?}", r.problems);
    assert_eq!(by("stale_row"), 1, "{:?}", r.problems);
    assert_eq!(by("stale_staging"), 1, "{:?}", r.problems);
    assert!(r.problems.iter().all(|p| p.image.is_none()));
    assert!(orphan.exists() && tmp.exists() && pull.exists());

    let r = check(&e, true, true).await;
    assert!(r.ok(), "{:?}", r.problems);
    assert_eq!(r.problems.len(), 5, "{:?}", r.problems);
    for p in [&orphan, &tmp, &cfs_tmp, &pull] {
        assert!(!p.exists(), "{}", p.display());
    }
    assert!(e.db.file_objects(vec![gone]).await.unwrap().is_empty());
    assert!(e.db.get_image(&id).await.is_ok());
    let r = check(&e, false, false).await;
    assert!(r.ok() && r.problems.is_empty(), "{:?}", r.problems);
}

#[tokio::test]
async fn what_may_belong_to_a_running_process_is_left_alone() {
    let (e, _) = pulled().await;
    let tmp = e.store.root().join("ab").join(".tmpX1y2z3");
    std::fs::create_dir_all(tmp.parent().unwrap()).unwrap();
    std::fs::write(&tmp, b"being written").unwrap();
    let held = velarx_content::pull::holds::Hold::create(&e.staging, "pull-0123abcd").unwrap();
    let live = held.path().to_path_buf();
    let svc = CheckService::new(
        e.db.clone(),
        Arc::new((*e.service).clone()),
        e.store.clone(),
        e.staging.clone(),
    );
    let r = svc.check(&request(false, true)).await.unwrap();
    assert!(r.problems.is_empty(), "{:?}", r.problems);
    assert!(tmp.exists() && live.exists());
}

#[tokio::test]
async fn a_repair_makes_the_composefs_image_again() {
    let (e, id) = pulled().await;
    let image = layer_image(&e, &id).await;
    let original = std::fs::read(&image).unwrap();

    for damage in 0..3 {
        match damage {
            0 => std::fs::remove_file(&image).unwrap(),
            1 => rewrite(&image, |d| vec![0; d.len()]),
            _ => std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o666)).unwrap(),
        }
        let r = check(&e, false, true).await;
        assert!(r.ok(), "{damage}: {:?}", r.problems);
        assert!(!r.problems.is_empty(), "{damage}");
        assert!(
            r.problems.iter().all(|p| p.action == CheckAction::Repaired),
            "{damage}: {:?}",
            r.problems
        );
        assert!(e.db.get_image(&id).await.is_ok());
        assert_eq!(std::fs::read(&image).unwrap(), original, "{damage}");
        assert_eq!(
            std::fs::metadata(&image).unwrap().permissions().mode() & 0o222,
            0
        );
        let after = check(&e, false, false).await;
        assert!(after.problems.is_empty(), "{damage}: {:?}", after.problems);
    }
}

#[tokio::test]
async fn a_repair_removes_an_image_whose_objects_are_damaged() {
    let (e, id) = pulled().await;
    let big = object_of(&e, &id, "usr/big").await;
    rewrite(&big, |mut d| {
        d[0] ^= 0xff;
        d
    });
    let r = check(&e, false, true).await;
    assert!(!r.problems.is_empty());
    assert!(r.ok(), "{:?}", r.problems);
    assert!(r
        .problems
        .iter()
        .filter(|p| p.image.is_some())
        .all(|p| p.action == CheckAction::ImageRemoved));
    assert!(e.db.get_image(&id).await.is_err());
    // its layers were released and the files went with them
    assert!(e.db.list_layers().await.unwrap().is_empty());
    assert!(!big.exists());
    let again = check(&e, false, false).await;
    assert!(again.problems.is_empty(), "{:?}", again.problems);
    assert_eq!(again.images_total, 0);
}

/// A layer whose table of contents is damaged (a file that is not the one its
/// row names) is the damage of its images alone: the check reports them,
/// goes on with the others, and a repair removes only them.
#[tokio::test]
async fn a_damaged_layer_row_is_reported_for_its_image_alone() {
    let (e, id) = pulled().await;
    let other = build_chunked(&[Item::File {
        name: "usr/other",
        data: b"other\n".to_vec(),
        chunk: 4096,
    }]);
    e.publish(&[&other], &[ZSTD]);
    let second = e.pull().await.unwrap().id;
    assert_ne!(id, second);
    let layer = e.db.get_image_layers(&id).await.unwrap()[0].key;
    let toc_z = e.db.get_layer_toc_z(&layer).await.unwrap().unwrap();
    let toc = velarx_db::layer_files::file(
        e.store.root().parent().unwrap(),
        &layer,
        velarx_db::layer_files::TOC,
        &velarx_types::digest::Digest::of(layer.digest().alg(), &toc_z),
    );
    std::fs::write(toc, [0x00, 0x11, 0x22, 0x33]).unwrap();
    let r = check(&e, false, false).await;
    assert_eq!(kinds(&r), ["bad_toc"], "{:?}", r.problems);
    assert_eq!(r.problems[0].image.as_deref(), Some(id.as_str()));
    let r = check(&e, false, true).await;
    assert!(r.ok(), "{:?}", r.problems);
    assert!(e.db.get_image(&id).await.is_err());
    assert!(e.db.get_image(&second).await.is_ok());
}

#[tokio::test]
async fn a_repair_removes_an_image_whose_object_is_gone() {
    let (e, id) = pulled().await;
    std::fs::remove_file(object_of(&e, &id, "usr/big").await).unwrap();
    let r = check(&e, true, true).await;
    assert!(r.ok(), "{:?}", r.problems);
    assert!(e.db.get_image(&id).await.is_err());
    // (no row of a file that is gone is left)
    let again = check(&e, true, false).await;
    assert!(again.problems.is_empty(), "{:?}", again.problems);
    e.pull().await.unwrap();
    let whole = check(&e, false, false).await;
    assert!(whole.problems.is_empty(), "{:?}", whole.problems);
}

#[tokio::test]
async fn an_image_a_container_uses_is_not_removed() {
    let (e, id) = pulled().await;
    add_container(&e, &id).await;
    rewrite(&object_of(&e, &id, "usr/big").await, |mut d| {
        d[0] ^= 0xff;
        d
    });
    let r = check(&e, false, true).await;
    assert!(!r.ok());
    assert!(r
        .problems
        .iter()
        .all(|p| p.action == CheckAction::ImageInUse));
    assert!(r.problems[0].message.contains("used by the container"));
    assert!(e.db.get_image(&id).await.is_ok());
}

#[tokio::test]
async fn a_lossy_repair_without_the_means_to_remove_containers_keeps_the_image() {
    let (e, id) = pulled().await;
    add_container(&e, &id).await;
    rewrite(&object_of(&e, &id, "usr/big").await, |mut d| {
        d[0] ^= 0xff;
        d
    });
    let r = checker(&e)
        .check(&CheckSpec {
            repair: true,
            repair_lossy: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!r.ok());
    assert!(r.removed_containers.is_empty());
    assert!(e.db.get_image(&id).await.is_ok());
    let shape = velarx_shape::system::check(&r);
    assert_eq!(shape["Errors"], true);
    assert!(shape["RemovedImages"].is_null());
}

#[tokio::test]
async fn an_image_is_kept_when_only_another_is_damaged() {
    let e = composefs_env().await;
    let a = build_chunked(&sample());
    e.publish(&[&a], &[ZSTD]);
    let first = e.pull().await.unwrap().id;
    let b = build_chunked(&[
        Item::Dir("etc/"),
        Item::File {
            name: "etc/other",
            data: vec![9u8; 30_000],
            chunk: 4096,
        },
    ]);
    e.publish(&[&b], &[ZSTD]);
    let second = e.pull().await.unwrap().id;
    assert_ne!(first, second);
    rewrite(&object_of(&e, &second, "etc/other").await, |mut d| {
        d[5] ^= 1;
        d
    });
    let r = check(&e, false, true).await;
    assert!(r.ok(), "{:?}", r.problems);
    assert!(e.db.get_image(&second).await.is_err());
    assert!(e.db.get_image(&first).await.is_ok());
    assert!(check(&e, false, false).await.problems.is_empty());
}

#[tokio::test]
async fn max_limits_the_images_and_the_oldest_checked_go_first() {
    let e = composefs_env().await;
    let mut ids = Vec::new();
    for n in 0..3u8 {
        let l = build_chunked(&[
            Item::Dir("etc/"),
            Item::File {
                name: "etc/f",
                data: vec![n + 1; 10_000],
                chunk: 4096,
            },
        ]);
        e.publish(&[&l], &[ZSTD]);
        ids.push(e.pull().await.unwrap().id);
    }
    let svc = checker(&e);
    let none = svc
        .check(&CheckSpec {
            quick: true,
            repair: false,
            timeout_ms: Some(0),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        (
            none.images_total,
            none.images_checked,
            none.images_unchecked
        ),
        (3, 0, 3)
    );
    assert!(e.db.image_check_times().await.unwrap().is_empty());

    // some were checked before: the ones never checked come first
    e.db.set_image_checked(&ids[0], 100).await.unwrap();
    e.db.set_image_checked(&ids[2], 200).await.unwrap();
    // damage the one never checked and the oldest checked: with a budget
    // that allows one image, the never checked one is the one looked at
    for id in [&ids[1], &ids[0]] {
        rewrite(&object_of(&e, id, "etc/f").await, |mut d| {
            d[0] ^= 1;
            d
        });
    }
    // (a budget the first image takes whole)
    let r = svc
        .check(&CheckSpec {
            quick: false,
            repair: false,
            timeout_ms: Some(1),
            ..Default::default()
        })
        .await
        .unwrap();
    let times = e.db.image_check_times().await.unwrap();
    let now = |i: usize| times.get(&ids[i]).is_some_and(|t| *t > 1000);
    // (the order is the never checked, then by time of the last check)
    assert!(!now(0) || now(1));
    assert!(!now(2) || now(0));
    assert_eq!(r.images_checked, (0..3).filter(|i| now(*i)).count() as u64);
    // without a limit all are looked at and have a time
    let all = svc.check(&request(false, false)).await.unwrap();
    assert_eq!((all.images_checked, all.images_unchecked), (3, 0));
    let times = e.db.image_check_times().await.unwrap();
    assert!(ids.iter().all(|i| times[i] > 200));
    assert_eq!(
        all.problems
            .iter()
            .filter(|p| p.kind == "verity_mismatch")
            .count(),
        2
    );
}

/// The pull of a lazy image is in the staging area, not in the store: the
/// check of the store finds nothing, the check of the staging area finds the
/// image of a layer that is gone, a pooled file nothing wants, a stalled
/// pull, and mends what can be made again.
#[tokio::test]
async fn a_pull_in_progress_is_checked_in_the_staging_area() {
    let e = composefs_env().await;
    let layer = build_chunked(&sample());
    e.publish(&[&layer], &[ZSTD]);
    let id = e.pull_lazy().await.unwrap().id;
    assert!(e.db.get_image(&id).await.is_err());
    assert!(e.db.get_layer(&layer.key()).await.is_err());
    for quick in [true, false] {
        let r = check(&e, quick, false).await;
        // (nobody completes it: the check says so, the remedy being a command)
        assert_eq!(kinds(&r), ["stalled_pull"], "{:?}", r.problems);
        assert!(r.problems[0].message.contains("velarx image complete"));
    }
    // the image of the staged layer is looked at
    let erofs = cfs::layer_image_path(&e.area().objects_stand_in(), &layer.key().file_stem());
    assert!(erofs.exists());
    std::fs::remove_file(&erofs).unwrap();
    assert!(kinds(&check(&e, true, false).await).contains(&"artifact_missing"));
    // a file the table of the layer does not name is reported and removed
    let stray = e
        .area()
        .layer_files(&layer.key())
        .join("00")
        .join("1".repeat(62));
    std::fs::create_dir_all(stray.parent().unwrap()).unwrap();
    std::fs::write(&stray, b"nobody wants this").unwrap();
    assert!(kinds(&check(&e, true, false).await).contains(&"unwanted_staged_file"));
    // the repair makes the image again, removes the file, and completes the
    // pull that nothing completes
    let r = check(&e, true, true).await;
    assert!(
        r.problems.iter().all(|p| p.action == CheckAction::Repaired),
        "{:?}",
        r.problems
    );
    assert!(!stray.exists());
    assert!(e.db.get_image(&id).await.is_ok());
    assert!(check(&e, false, false).await.ok());
}

#[tokio::test]
async fn a_check_waits_for_a_collection_and_a_repair_for_a_pull() {
    let (e, _) = pulled().await;
    let lock = StorageLock::path_of_staging(&e.staging);
    let svc = Arc::new(checker(&e));

    // a collection holds the lock: the check waits for it
    let gc = StorageLock::exclusive(&lock).await.unwrap();
    let running = {
        let svc = svc.clone();
        tokio::spawn(async move { svc.check(&request(true, false)).await.unwrap() })
    };
    // (asleep in the lock, and so not ended while it is held)
    crate::common::wait_for_lock_waiter(&lock).await;
    assert!(!running.is_finished());
    drop(gc);
    assert!(running.await.unwrap().ok());

    // a pull holds it shared: a check goes on, a repair waits for the pull
    let pull = StorageLock::shared(&lock).await.unwrap();
    assert!(svc.check(&request(true, false)).await.unwrap().ok());
    let repairing = {
        let svc = svc.clone();
        tokio::spawn(async move { svc.check(&request(true, true)).await.unwrap() })
    };
    // (asleep in the lock, and so not ended while the pull holds it)
    crate::common::wait_for_lock_waiter(&lock).await;
    assert!(!repairing.is_finished());
    drop(pull);
    assert!(repairing.await.unwrap().ok());
}

/// The image of a layer is the same bytes in every store that pulls it (a
/// store elsewhere, later, eagerly or lazily): the same fs-verity digest,
/// recorded with the layer.
#[tokio::test]
async fn the_image_of_a_layer_is_the_same_in_every_store() {
    let layer = build_chunked(&sample());
    let mut images = Vec::new();
    for (n, lazy) in [false, true, false].into_iter().enumerate() {
        let e = composefs_env().await;
        e.publish(&[&layer], &[ZSTD]);
        let id = match lazy {
            true => {
                // (the image of the staged layer is the same bytes as the
                // store's it becomes)
                let id = e.pull_lazy().await.unwrap().id;
                let staged = e.service.staged_layers(&id).await.unwrap();
                let staged_bytes = std::fs::read(cfs::layer_image_path(
                    &e.area().objects_stand_in(),
                    &staged.last().unwrap().key.file_stem(),
                ))
                .unwrap();
                e.service.complete_staged(&id).await.unwrap();
                let l = e.db.get_image_layers(&id).await.unwrap();
                let moved = std::fs::read(cfs::layer_image_path(
                    e.store.root(),
                    &l.last().unwrap().key.file_stem(),
                ))
                .unwrap();
                assert_eq!(staged_bytes, moved);
                id
            }
            false => e.pull().await.unwrap().id,
        };
        let layers = e.db.get_image_layers(&id).await.unwrap();
        let l = layers.last().unwrap();
        let bytes =
            std::fs::read(cfs::layer_image_path(e.store.root(), &l.key.file_stem())).unwrap();
        assert_eq!(
            l.erofs.as_deref(),
            Some(
                velarx_storage::composefs_digest_of(
                    velarx_types::digest::Algorithm::Sha256,
                    &bytes
                )
                .as_str()
            )
        );
        images.push(bytes);
        // (another time for the next store: the clock moves on by more than
        // a second, the resolution of the times an EROFS image could take
        // from the files it is made of; nothing reads a clock to fake: a
        // stimulus, not a wait, so not after the last store)
        if n < 2 {
            tokio::time::sleep(Duration::from_millis(1100)).await;
        }
    }
    assert!(images.windows(2).all(|w| w[0] == w[1]));
}

/// `system check` compares the digest the manifest states for a layer with the
/// EROFS image of the layer: under `composefs_digests = "require"` a mismatch
/// is reported (and mended where the image is what is wrong), and so is a
/// manifest that states none; a list with none of ours is another writer's
/// where the digests are not required.
#[tokio::test]
async fn the_digests_the_manifest_states_are_looked_at() {
    let layer = build_chunked(&sample());
    // the digest of the image velarx makes of the layer
    let (probe, _) = pulled().await;
    let layers = probe
        .db
        .get_image_layers(&probe_id(&probe).await)
        .await
        .unwrap();
    let ours = layers[0].erofs.clone().unwrap();
    let mut e = composefs_env().await;
    let mut annotated = Built {
        blob: layer.blob.clone(),
        diff_id: layer.diff_id,
        annotations: layer.annotations.clone(),
    };
    annotated
        .annotations
        .insert("io.containers.composefs.digest".into(), ours.clone());
    e.publish(&[&annotated], &[ZSTD]);
    let id = e.pull().await.unwrap().id;
    assert!(check(&e, false, false).await.ok());

    // the record of the image is not the digest the manifest states: not
    // looked at where the digests are not required
    let layers = e.db.get_image_layers(&id).await.unwrap();
    let wrong = format!("fsverity-sha256-12:{}", "ab".repeat(32));
    e.db.set_layer_erofs(&layers[0].key, &wrong, layers[0].owners.as_deref().unwrap())
        .await
        .unwrap();
    let r = check(&e, true, false).await;
    assert!(
        !kinds(&r).contains(&"annotation_mismatch"),
        "{:?}",
        kinds(&r)
    );
    let service: ImageService = (*e.service)
        .clone()
        .with_composefs_digests(velarx_config::ComposefsDigests::Require);
    e.service = std::mem::ManuallyDrop::new(service);
    let r = check(&e, true, false).await;
    let k = kinds(&r);
    assert!(k.contains(&"annotation_mismatch"), "{k:?}");
    // making the image again mends the record
    let r = check(&e, false, true).await;
    assert!(check(&e, false, false).await.ok(), "{:?}", r.problems);

    // no digest stated, and the service wants one
    let (mut plain, _) = pulled().await;
    let service: ImageService = (*plain.service)
        .clone()
        .with_composefs_digests(velarx_config::ComposefsDigests::Require);
    plain.service = std::mem::ManuallyDrop::new(service);
    let r = check(&plain, true, false).await;
    assert_eq!(kinds(&r), ["annotation_missing"], "{:?}", r.problems);
}

async fn probe_id(e: &Env) -> String {
    e.db.list_images().await.unwrap()[0].id.clone()
}

/// What a pull stores of the layers of the image, asked as the pull asks.
async fn stored(e: &Env, id: &str) -> usize {
    let layers = e.db.get_image_layers(id).await.unwrap();
    // (the diff ids the configuration gives: a layer of a table of contents
    // has none of its own)
    let image = e.db.get_image(id).await.unwrap();
    let diffs: Vec<velarx_types::digest::Digest> =
        serde_json::from_str::<velarx_types::OciConfig>(&image.config)
            .unwrap()
            .rootfs
            .diff_ids;
    let asked: Vec<velarx_core::storage_driver::LayerRef> = layers
        .iter()
        .zip(velarx_types::chain_ids(&diffs))
        .enumerate()
        .map(|(i, (l, chain_id))| velarx_core::storage_driver::LayerRef {
            key: l.key,
            diff_id: diffs[i],
            chain_id,
        })
        .collect();
    let have = e.service.storage().has_layers(&asked).await.unwrap();
    assert_eq!(have.len(), asked.len(), "one answer for each layer asked");
    have.into_iter().filter(|h| *h).count()
}

/// The plan of a create of the image, as the create asks.
async fn plan(
    e: &Env,
    id: &str,
) -> Result<velarx_core::storage_driver::Planned, velarx_types::ImageError> {
    let image = e.db.get_image(id).await.unwrap();
    let layers = e.db.get_image_layers(id).await.unwrap();
    marked_root(e, &image, &layers).await
}

/// The root of a container made of `image`, as a create asks (a layer whose
/// image is gone is marked incomplete).
async fn marked_root(
    e: &Env,
    image: &velarx_db::ImageRecord,
    layers: &[velarx_db::LayerRecord],
) -> Result<velarx_core::storage_driver::Planned, velarx_types::ImageError> {
    use velarx_core::storage_driver::{MountRequest, Purpose, VerityAsk, Writable};
    let container = Writable::new("check", "/velarx-check/bundle");
    e.service
        .image_volume_create(&MountRequest {
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
        .await
}

#[tokio::test]
async fn a_lost_composefs_image_marks_its_layer_incomplete_and_a_pull_makes_it_again() {
    let e = composefs_env().await;
    let shared = build_chunked(&sample());
    let extra = build_chunked(&[Item::File {
        name: "extra",
        data: b"extra\n".to_vec(),
        chunk: 4096,
    }]);
    e.publish(&[&shared], &[ZSTD]);
    let first = e.pull().await.unwrap().id;
    publish_arch(&e.reg, &[&shared, &extra], &[ZSTD, ZSTD], "amd64", "second");
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let second = e
        .service
        .pull_with_client(&e.client(), &format!("{}/test:second", e.host), tx)
        .await
        .unwrap()
        .id;
    assert_eq!(stored(&e, &second).await, 2);
    assert!(plan(&e, &first).await.is_ok());

    // the image of the shared layer is lost
    let erofs = layer_image(&e, &first).await;
    let original = std::fs::read(&erofs).unwrap();
    std::fs::remove_file(&erofs).unwrap();
    let name = format!("{}/test:latest", e.host);
    let key = e.db.get_image_layers(&first).await.unwrap()[0].key;
    let expect =
        format!("the image {name} is damaged (layer {key} has no EROFS image): pull it again");
    // (the first start says so, and so does the next: it is the same)
    for _ in 0..2 {
        let err = plan(&e, &first).await.unwrap_err();
        assert_eq!(err.to_string(), format!("storage error: {expect}"));
    }
    // the layer is not stored any more, the other is, and the image stays
    assert_eq!(stored(&e, &first).await, 0);
    assert_eq!(stored(&e, &second).await, 1);
    let layer = e.db.get_layer(&key).await.unwrap();
    assert!(layer.erofs.is_some());
    assert!(e.db.get_image(&first).await.is_ok());
    // (the objects of the layer stay)
    assert!(object_of(&e, &first, "usr/big").await.exists());
    // the image that shares the layer is unaffected until it starts, and
    // then it is told the same of its own name
    assert!(kinds(&check(&e, true, false).await).contains(&"artifact_missing"));
    let err = plan(&e, &second).await.unwrap_err().to_string();
    assert!(
        err.contains(&format!("the image {}/test:second is damaged", e.host)),
        "{err}"
    );

    // a pull fetches the layer again, as if it was never pulled, and the
    // objects it has are not downloaded again
    let hits = e.reg.requests.load(std::sync::atomic::Ordering::SeqCst);
    let ranges = e.reg.range_log.lock().unwrap().len();
    e.pull().await.unwrap();
    assert_eq!(stored(&e, &first).await, 1);
    assert_eq!(std::fs::read(&erofs).unwrap(), original);
    assert!(plan(&e, &first).await.is_ok());
    assert!(e.reg.requests.load(std::sync::atomic::Ordering::SeqCst) > hits);
    let fetched: Vec<String> = e.reg.range_log.lock().unwrap()[ranges..].to_vec();
    assert!(fetched.len() <= 2, "{fetched:?}");
    assert!(check(&e, false, false).await.ok());
    // (and the second image, with its layer back)
    assert_eq!(stored(&e, &second).await, 2);
    assert!(plan(&e, &second).await.is_ok());
}

/// A pull over an object of the store that is not as long as the table says
/// (damaged, or replaced) puts the content back, and the image is made
/// again: the object is not taken for held because it has a name.
#[tokio::test]
async fn a_pull_replaces_a_store_object_that_is_not_the_size_of_its_table() {
    for damage in [&b"x"[..], &b"the content of the file and more bytes"[..]] {
        let (e, id) = pulled().await;
        let object = object_of(&e, &id, "etc/small").await;
        let original = std::fs::read(&object).unwrap();
        rewrite(&object, |_| damage.to_vec());
        assert!(kinds(&check(&e, false, false).await).contains(&"wrong_size"));
        // (the image of the layer is gone, which a pull makes again)
        std::fs::remove_file(layer_image(&e, &id).await).unwrap();
        assert!(plan(&e, &id).await.is_err());
        e.pull().await.unwrap();
        assert_eq!(std::fs::read(&object).unwrap(), original);
        assert!(check(&e, false, false).await.ok());
        assert!(plan(&e, &id).await.is_ok());
    }
}

#[tokio::test]
async fn two_starts_of_an_image_whose_composefs_image_is_lost_say_the_same() {
    let (e, id) = pulled().await;
    std::fs::remove_file(layer_image(&e, &id).await).unwrap();
    let (a, b) = tokio::join!(plan(&e, &id), plan(&e, &id));
    let (a, b) = (a.unwrap_err().to_string(), b.unwrap_err().to_string());
    assert!(a.contains("is damaged") && a == b, "{a} / {b}");
    assert_eq!(stored(&e, &id).await, 0);
    e.pull().await.unwrap();
    assert!(plan(&e, &id).await.is_ok());
}

#[tokio::test]
async fn a_healthy_image_and_a_lazy_one_are_not_marked() {
    let (e, id) = pulled().await;
    assert!(plan(&e, &id).await.is_ok());
    assert_eq!(stored(&e, &id).await, 1);
    // (an artifact that is back by the time the lock is held marks nothing)
    let image = e.db.get_image(&id).await.unwrap();
    let layers = e.db.get_image_layers(&id).await.unwrap();
    let error = velarx_core::storage_driver::DriverError::missing(
        "composefs",
        Some(&layers[0].key),
        "the EROFS image of the layer is not there",
        velarx_core::storage_driver::Remedy::Repair,
    );
    e.service.damaged(&image, &layers, error).await.unwrap();
    assert_eq!(stored(&e, &id).await, 1);
    // (and an error that is no missing layer is the caller's as it is)
    let error = velarx_core::storage_driver::DriverError::storage("composefs", "no space");
    let err = e.service.damaged(&image, &layers, error).await.unwrap_err();
    assert_eq!(err.to_string(), "storage error: no space");
}

#[tokio::test]
async fn a_lazy_image_with_a_lost_composefs_image_is_left_to_the_repair() {
    let (e, id) = pulled().await;
    let image = velarx_db::ImageRecord {
        is_lazy: true,
        ..e.db.get_image(&id).await.unwrap()
    };
    let layers = e.db.get_image_layers(&id).await.unwrap();
    std::fs::remove_file(layer_image(&e, &id).await).unwrap();
    let err = marked_root(&e, &image, &layers)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.ends_with("`velarx system check --repair` makes it again"),
        "{err}"
    );
    assert_eq!(stored(&e, &id).await, 1);
}

#[tokio::test]
async fn a_repair_makes_the_image_of_a_layer_that_a_start_found_lost() {
    let (e, id) = pulled().await;
    std::fs::remove_file(layer_image(&e, &id).await).unwrap();
    plan(&e, &id).await.unwrap_err();
    let r = check(&e, true, true).await;
    assert!(
        r.problems.iter().all(|p| p.action == CheckAction::Repaired),
        "{:?}",
        r.problems
    );
    assert!(plan(&e, &id).await.is_ok());
    assert!(check(&e, false, false).await.ok());
    // (the layer still lacks its tar-split: the next pull brings it)
    assert_eq!(stored(&e, &id).await, 0);
    e.pull().await.unwrap();
    assert_eq!(stored(&e, &id).await, 1);
}

#[tokio::test]
async fn a_lost_composefs_image_of_a_layer_made_here_is_left_to_the_repair() {
    let (e, id) = pulled().await;
    // (as a layer of a commit, a build or a load: no registry has it)
    e.db.conn()
        .call(|conn| {
            conn.execute("UPDATE layers SET registry_ref = NULL", [])?;
            Ok(())
        })
        .await
        .unwrap();
    std::fs::remove_file(layer_image(&e, &id).await).unwrap();
    let err = plan(&e, &id).await.unwrap_err().to_string();
    assert!(
        err.ends_with("`velarx system check --repair` makes it again"),
        "{err}"
    );
    // its tar-split stays: the repair makes the image and it is whole again
    assert_eq!(stored(&e, &id).await, 1);
    check(&e, true, true).await;
    assert!(plan(&e, &id).await.is_ok());
    assert!(check(&e, false, false).await.ok());
}

/// Where fs-verity is required, the objects pulled without it are found, and
/// the image is whole: a repair that cannot enable fs-verity (the file system
/// of the test has none) keeps the image, says why, and the store is still
/// not as it should be.
#[tokio::test]
async fn objects_without_the_required_fs_verity_are_found() {
    let (e, id) = pulled().await;
    assert!(check(&e, false, false).await.ok());
    let r = requiring(&e).check(&request(false, false)).await.unwrap();
    assert!(!r.ok());
    assert!(r
        .problems
        .iter()
        .all(|p| p.kind == "no_verity" && p.action == CheckAction::None));
    let r = requiring(&e).check(&request(false, true)).await.unwrap();
    assert!(!r.ok());
    assert!(r.problems.iter().all(|p| p.kind == "no_verity"
        && p.action == CheckAction::None
        && p.message.contains("(and cannot be repaired: ")));
    assert!(e.db.list_images().await.unwrap().iter().any(|i| i.id == id));
}

/// On a file system with fs-verity (`VELARX_VERITY_DIR`) a repair enables it
/// on the objects pulled without it, which the kernel measures then: nothing
/// is found by the next check.
#[tokio::test]
async fn a_repair_enables_the_required_fs_verity() {
    let Some(base) = std::env::var_os("VELARX_VERITY_DIR") else {
        eprintln!("VELARX_VERITY_DIR not set: skipped");
        return;
    };
    // (fs-verity has to work there, or the test would pass for the wrong reason)
    let probe = tempfile::tempdir_in(&base).unwrap();
    std::fs::write(probe.path().join("probe"), b"probe").unwrap();
    velarx_storage::VerityMode::Require
        .manager()
        .unwrap()
        .enable(&probe.path().join("probe"))
        .unwrap();
    let (e, id) = pulled_in(base.as_ref()).await;
    let object = object_of(&e, &id, "usr/big").await;
    let measured = |path: &std::path::Path| {
        velarx_storage::measure_file(&std::fs::File::open(path).unwrap()).is_ok()
    };
    assert!(!measured(&object));
    let r = requiring(&e).check(&request(false, false)).await.unwrap();
    assert!(r.problems.iter().any(|p| p.kind == "no_verity"));
    let r = requiring(&e).check(&request(false, true)).await.unwrap();
    assert!(r.ok(), "{:?}", r.problems);
    assert!(r
        .problems
        .iter()
        .all(|p| p.kind == "no_verity" && p.action == CheckAction::Repaired));
    assert!(measured(&object));
    let r = requiring(&e).check(&request(false, false)).await.unwrap();
    assert!(r.problems.is_empty(), "{:?}", r.problems);
}
