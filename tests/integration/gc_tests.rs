// SPDX-License-Identifier: Apache-2.0
//! The garbage collection against pulls in progress: the lock of the store,
//! the leases of the pulls and the staging directories they leave.

use crate::common::*;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use velarx_config::StorageConfig;
use velarx_content::pull::holds;
use velarx_core::services::{GcOptions, GcService};
use velarx_db::{Database, RecordState};
use velarx_storage::StorageLock;

fn gc(e: &Env) -> GcService {
    let storage = StorageConfig {
        root: e._tmp.path().to_path_buf(),
        ..Default::default()
    };
    GcService::new(
        e.db.clone(),
        e.store.clone(),
        &storage,
        e.service.storage().clone(),
    )
}

fn layer(name: &'static str, data: &[u8]) -> Built {
    build_chunked(&[
        Item::Dir("etc/"),
        Item::File {
            name,
            data: data.to_vec(),
            chunk: 4096,
        },
    ])
}

/// Every file the layers of the image reference is in the store.
async fn all_files_stored(db: &Database, store: &velarx_storage::FileStore, image: &str) {
    let layers = db.get_image_layers(image).await.unwrap();
    assert!(!layers.is_empty());
    for l in layers {
        let toc = crate::common::stored_toc(db, &l.key).await;
        for entry in &toc.entries {
            if let Some(d) = entry.verity() {
                assert!(store.contains(&d), "{} of {} is gone", entry.name, l.key);
            }
        }
    }
}

#[tokio::test]
async fn gc_during_a_pull_never_removes_its_files() {
    let e = env().await;
    let shared = layer("etc/shared", &[3u8; 20_000]);
    e.publish(&[&shared], &[ZSTD]);
    let first = e.pull().await.unwrap();
    // the layer is still stored but no image uses it any more (the row
    // alone is removed: a removal through the service releases the layers)
    e.db.delete_image(&first.id).await.unwrap();

    let new = layer("etc/new", &[4u8; 20_000]);
    e.publish(&[&shared, &new], &[ZSTD, ZSTD]);
    e.reg.delay_ms.store(1500, Ordering::SeqCst);
    let pull = {
        let (service, client, image) = (
            (*e.service).clone(),
            e.client(),
            format!("{}/test:latest", e.host),
        );
        tokio::spawn(async move {
            let (tx, mut rx) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            service.pull_with_client(&client, &image, tx).await
        })
    };
    // the pull found the shared layer stored and fetches the new one
    let new_digest = sha(&new.blob);
    // (its metadata is asked before the pull is held)
    crate::common::poll_until("the pull fetches the layer and has a hold", || async {
        e.reg.hits.lock().unwrap().contains_key(&new_digest)
            && holds::pinned(&e.staging)
                .unwrap()
                .layers
                .contains(&shared.key().to_string())
    })
    .await;
    assert!(e.reg.hits.lock().unwrap().contains_key(&new_digest));
    // the pull takes the hold under the lock of the store and lets go of
    // it right after: the lock is free once it is ours, and the pull
    // downloads (for the delay of the registry) until the commit asks for it
    // (unlocked, not only closed: a program that another test starts holds
    // a copy of the descriptor until it is executed; the limit only keeps a
    // pull that never lets go from hanging the test)
    let lock = StorageLock::path(e._tmp.path());
    let wait = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let file = std::fs::File::open(lock)?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)?;
        Ok(rustix::fs::flock(
            &file,
            rustix::fs::FlockOperation::Unlock,
        )?)
    });
    tokio::time::timeout(std::time::Duration::from_secs(60), wait)
        .await
        .expect("the pull lets go of the lock of the store")
        .unwrap()
        .unwrap();

    // the download holds no lock: a collection runs, and the hold keeps
    // what the pull uses
    let quick = gc(&e)
        .collect(GcOptions {
            wait: false,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!quick.skipped, "the download holds the lock of the store");
    assert_eq!(quick.layers_removed, 0);
    let report = gc(&e).collect(GcOptions::default()).await.unwrap();
    let second = pull.await.unwrap().unwrap();
    assert!(!report.skipped);
    assert_eq!(report.layers_removed, 0);
    all_files_stored(&e.db, &e.store, &second.id).await;
    assert!(!holds::any_live(&e.staging).unwrap());
    assert_eq!(e.staged_leftovers(), 0);

    e.service.remove(&second.id, true).await.unwrap();
    assert!(!e.store.contains(&vid(&[4u8; 20_000])));
    let report = gc(&e).collect(GcOptions::default()).await.unwrap();
    assert_eq!(report.layers_removed, 0, "the removal released them");
}

/// The removal of an image does not wait for the download of a pull of
/// another: the lock of the store is held for the check of what it has and
/// for the commit, not between.
#[tokio::test]
async fn removing_an_image_does_not_wait_for_a_pull_in_progress() {
    let e = env().await;
    let old = layer("etc/old", &[8u8; 20_000]);
    e.publish(&[&old], &[ZSTD]);
    let first = e.pull().await.unwrap();

    let new = layer("etc/new", &[9u8; 20_000]);
    e.publish(&[&new], &[ZSTD]);
    e.reg.delay_ms.store(3000, Ordering::SeqCst);
    let pull = {
        let (service, client, image) = (
            (*e.service).clone(),
            e.client(),
            format!("{}/test:latest", e.host),
        );
        tokio::spawn(async move {
            let (tx, mut rx) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            service.pull_with_client(&client, &image, tx).await
        })
    };
    // the pull downloads: its layers are pinned by its hold
    let new_digest = sha(&new.blob);
    // (its metadata is asked before the pull is held)
    crate::common::poll_until("the pull fetches the layer and has a hold", || async {
        e.reg.hits.lock().unwrap().contains_key(&new_digest) && holds::any_live(&e.staging).unwrap()
    })
    .await;
    assert!(e.reg.hits.lock().unwrap().contains_key(&new_digest));
    // (bounded well under the delay of the registry: a removal that waits
    // for the pull would end after it)
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        e.service.remove(&first.id, true),
    )
    .await
    .expect("the removal waited for the pull")
    .unwrap();
    assert!(!pull.is_finished());
    e.reg.delay_ms.store(0, Ordering::SeqCst);
    let second = pull.await.unwrap().unwrap();
    all_files_stored(&e.db, &e.store, &second.id).await;
}

/// What a pull in progress has is not collected: the files its staged
/// layers name that the store has already, the pool; what nothing names is.
/// A cancelled pull goes with its staged layers and its pool.
#[tokio::test]
async fn gc_keeps_what_a_pull_in_progress_has() {
    let e = env_with(velarx_config::PullConfig {
        lazy_window_files: 0,
        ..Default::default()
    })
    .await;
    let lazy = layer("etc/lazy", b"hello\n");
    e.publish(&[&lazy], &[ZSTD]);
    let pulled = e.pull_lazy().await.unwrap();
    assert!(e.service.get(&pulled.id).await.is_err());
    // a file of the lazy layer that the store has (another image's), and an
    // orphan of the store
    let shared = e
        .store
        .put(velarx_types::digest::Algorithm::Sha256, b"hello\n")
        .unwrap();
    let area = e.area();
    let stray = e
        .store
        .put(velarx_types::digest::Algorithm::Sha256, b"nobody's")
        .unwrap();
    gc(&e).collect(GcOptions::default()).await.unwrap();
    assert!(
        e.store.contains(&shared),
        "the file of the staged layer went"
    );
    assert!(!e.store.contains(&stray), "an orphan stays");
    assert!(area.layer(&lazy.key()).unwrap().is_some());
    assert!(!area.pulls().is_empty());

    // cancelled: it, its staged layer and the layer it pinned go
    e.service
        .cancel_pull(&format!("{}/test:latest", e.host), false)
        .await
        .unwrap();
    gc(&e).collect(GcOptions::default()).await.unwrap();
    assert!(area.pulls().is_empty());
    assert!(area.layer(&lazy.key()).unwrap().is_none());
}

#[tokio::test]
async fn gc_removes_the_temporary_files_of_dead_writers_only() {
    let e = env().await;
    let stray = e
        .store
        .put(velarx_types::digest::Algorithm::Sha256, b"nobody's")
        .unwrap();
    let stray = e.store.get_path(&stray).unwrap();
    let objects = stray.parent().unwrap().to_path_buf();
    // a writer that lives holds the lock of its temporary file; a dead
    // one left a file, however young
    let (live, lock) = velarx_storage::create_locked(&objects, ".tmp", 0o644).unwrap();
    let (dead, dead_lock) = velarx_storage::create_locked(&objects, ".tmp", 0o644).unwrap();
    let dead = dead.into_temp_path().keep().unwrap();
    unlock(dead_lock.file());
    drop(dead_lock);
    gc(&e).collect(GcOptions::default()).await.unwrap();
    assert!(live.path().exists(), "the file of a live writer went");
    assert!(!dead.exists(), "the file of a dead writer stays");
    assert!(!stray.exists(), "an orphan stays");
    drop(lock);
}

#[tokio::test]
async fn removing_an_image_releases_the_layers_no_other_image_uses() {
    let e = env().await;
    let shared = layer("etc/shared", &[5u8; 20_000]);
    let own = layer("etc/own", &[6u8; 20_000]);
    let other = layer("etc/other", &[7u8; 20_000]);
    e.publish(&[&shared, &own], &[ZSTD, ZSTD]);
    let first = e.pull().await.unwrap();
    e.publish(&[&shared, &other], &[ZSTD, ZSTD]);
    let second = e.pull().await.unwrap();
    assert_ne!(first.id, second.id);

    e.service.remove(&first.id, false).await.unwrap();
    assert!(
        e.db.get_layer(&own.key()).await.is_err(),
        "its own layer is gone"
    );
    assert!(!e.store.contains(&vid(&[6u8; 20_000])), "and its file");
    let own_file = vid(&[6u8; 20_000]);
    let locations: i64 =
        e.db.conn()
            .call(move |c| {
                Ok(c.query_row(
                    "SELECT count(*) FROM chunk_locations WHERE file_digest = ?1",
                    [&own_file],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
    assert_eq!(locations, 0, "and where its chunks were");
    assert!(
        e.db.get_layer(&shared.key()).await.is_ok(),
        "a shared layer stays"
    );
    all_files_stored(&e.db, &e.store, &second.id).await;

    // a layer a lease pins (a pull in progress) stays
    let held = holds::Hold::create(&e.staging, "pull-0000cafe").unwrap();
    held.pin(holds::LAYER, [other.key()]).unwrap();
    e.service.remove(&second.id, false).await.unwrap();
    assert!(
        e.db.get_layer(&other.key()).await.is_ok(),
        "the leased layer stays"
    );
    assert!(e.db.get_layer(&shared.key()).await.is_err());
    // (its files stay while a pull runs: the pull may have found one of
    // them in the store for a file of its own; the next collection takes
    // them)
    assert!(e.store.contains(&vid(&[5u8; 20_000])));
    // (a collection meanwhile too: their rows stay, so their objects are
    // no orphans)
    gc(&e).collect(GcOptions::default()).await.unwrap();
    assert!(e.store.contains(&vid(&[5u8; 20_000])));
    drop(held);
    gc(&e).collect(GcOptions::default()).await.unwrap();
    assert!(!e.store.contains(&vid(&[5u8; 20_000])));

    e.reg.hits.lock().unwrap().clear();
    let again = e.pull().await.unwrap();
    assert!(e.reg.hits.lock().unwrap().contains_key(&sha(&shared.blob)));
    all_files_stored(&e.db, &e.store, &again.id).await;
}

/// What the removal of an image frees is its record and the layers it
/// released, each layer once: the layer two images share is freed with the
/// last of them, not with each (nor with neither).
#[tokio::test]
async fn removing_images_frees_each_layer_once() {
    let e = env().await;
    let shared = layer("etc/shared", &[5u8; 20_000]);
    let own = layer("etc/own", &[6u8; 20_000]);
    let other = layer("etc/other", &[7u8; 30_000]);
    e.publish(&[&shared, &own], &[ZSTD, ZSTD]);
    let first = e.pull().await.unwrap();
    e.publish(&[&shared, &other], &[ZSTD, ZSTD]);
    let second = e.pull().await.unwrap();
    let size = |key| {
        let db = e.db.clone();
        async move { db.get_layer(&key).await.unwrap().stream_size.unwrap() as u64 }
    };
    let (shared_size, own_size, other_size) = (
        size(shared.key()).await,
        size(own.key()).await,
        size(other.key()).await,
    );
    assert!(own_size > 0 && other_size > own_size);
    let meta = |id: &str| {
        let service = e.service.clone();
        let id = id.to_string();
        async move { service.get(&id).await.unwrap().metadata_size() }
    };
    let (first_meta, second_meta) = (meta(&first.id).await, meta(&second.id).await);

    let freed = e.service.remove(&first.id, false).await.unwrap();
    assert_eq!(freed, first_meta + own_size);
    let freed = e.service.remove(&second.id, false).await.unwrap();
    assert_eq!(freed, second_meta + shared_size + other_size);

    // pruned together: the sum is what the store freed, the shared layer
    // once
    e.publish(&[&shared, &own], &[ZSTD, ZSTD]);
    let first = e.pull().await.unwrap();
    e.publish(&[&shared, &other], &[ZSTD, ZSTD]);
    let second = e.pull().await.unwrap();
    let pruned = e.service.prune(true, &[]).await.unwrap();
    assert_eq!(pruned.len(), 2);
    let total: u64 = pruned.iter().map(|(_, n)| n).sum();
    assert_eq!(
        total,
        first_meta + second_meta + shared_size + own_size + other_size
    );
    assert!(pruned.iter().any(|(id, _)| *id == first.id));
    assert!(pruned.iter().any(|(id, _)| *id == second.id));
}

/// The collection removes what no process holds: the staging directories of
/// pulls that died and the leftovers of a birth that did not end, and leaves
/// the one a process holds and what is no hold.
#[tokio::test]
async fn stale_holds_are_swept() {
    let e = env().await;
    std::fs::create_dir_all(&e.staging).unwrap();
    let (dead, orphan, born) = ("pull-0000dead", "build-0000beef", ".new-0000cafe");
    for d in [dead, orphan, born, "not-a-session"] {
        std::fs::create_dir_all(e.staging.join(d).join("sub")).unwrap();
    }
    let live = holds::Hold::create(&e.staging, "pull-0000a11e").unwrap();

    let report = gc(&e).collect(GcOptions::default()).await.unwrap();
    assert_eq!(report.staging_removed, 3);
    assert!(!e.staging.join(dead).exists());
    assert!(!e.staging.join(orphan).exists());
    assert!(!e.staging.join(born).exists());
    assert!(live.path().exists());
    assert!(e.staging.join("not-a-session").exists());
}

/// A command that starts while a pull downloads (the pull holds its hold,
/// not the lock of the store) leaves the session of that pull alone; the
/// session of a pull that ended goes, and so does the staging of a layer no
/// process holds the lease of.
#[tokio::test]
async fn a_new_service_sweeps_the_sessions_of_dead_pulls_only() {
    let e = env().await;
    let dead = "pull-0000dead";
    std::fs::create_dir_all(e.staging.join(dead).join("sub")).unwrap();
    let live = holds::Hold::create(&e.staging, "pull-0000a11e").unwrap();
    std::fs::create_dir_all(live.path().join("sub")).unwrap();
    let (fetching, left) = ("sha256-0a11", "sha256-0dead");
    for l in [fetching, left] {
        std::fs::create_dir_all(e.staging.join("layers").join(l).join("files")).unwrap();
    }
    std::fs::create_dir_all(e.staging.join("meta").join(fetching)).unwrap();
    let lease = std::fs::File::create(e.staging.join("meta").join(fetching).join("lease")).unwrap();
    rustix::fs::flock(&lease, rustix::fs::FlockOperation::LockExclusive).unwrap();
    // The service sweeps only when nobody holds the lock of the store, and
    // a copy of a descriptor of it that another test of this process took
    // with a fork keeps it held until that child execs: wait until it is
    // free (a flock is released with the last copy), and make the service
    // again in the rare case that a fork copied the descriptor of the wait.
    let lock = StorageLock::path_of_staging(&e.staging);
    for _ in 0..50 {
        drop(StorageLock::exclusive(&lock).await.unwrap());
        // (never dropped: it owns a runtime)
        let _other = std::mem::ManuallyDrop::new(velarx_core::services::ImageService::new(
            e.db.clone(),
            e.store.clone(),
            e.staging.clone(),
            velarx_storage::VerityMode::Off,
        ));
        if !e.staging.join(dead).exists() {
            break;
        }
    }
    assert!(live.path().join("sub").exists());
    assert!(!e.staging.join(dead).exists());
    assert!(e
        .staging
        .join("layers")
        .join(fetching)
        .join("files")
        .exists());
    assert!(!e.staging.join("layers").join(left).exists());
}

#[tokio::test]
async fn a_leased_layer_is_kept_and_chunk_locations_go_with_their_file() {
    let e = env().await;
    let l = layer("etc/f", &[5u8; 20_000]);
    e.publish(&[&l], &[ZSTD]);
    let pulled = e.pull().await.unwrap();
    let digest = l.key();
    let file = vid(&[5u8; 20_000]);
    assert!(e
        .db
        .get_chunk_location(&velarx_types::digest::Digest::of(
            velarx_types::digest::Algorithm::Sha256,
            &[5u8; 20_000]
        ),)
        .await
        .is_ok());
    // the row alone: the collection is what is tested
    e.db.delete_image(&pulled.id).await.unwrap();

    let held = holds::Hold::create(&e.staging, "pull-00aa").unwrap();
    held.pin(holds::LAYER, [digest]).unwrap();
    let report = gc(&e).collect(GcOptions::default()).await.unwrap();
    assert_eq!(report.layers_removed, 0);
    assert!(e.store.contains(&file));

    drop(held);
    let report = gc(&e).collect(GcOptions::default()).await.unwrap();
    assert_eq!(report.layers_removed, 1);
    assert!(!e.store.contains(&file));
    let locations: i64 =
        e.db.conn()
            .call(move |c| {
                Ok(c.query_row(
                    "SELECT count(*) FROM chunk_locations WHERE file_digest = ?1",
                    [&file],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
    assert_eq!(locations, 0);
}

#[tokio::test]
async fn gc_waits_for_another_holder_of_the_lock() {
    let e = env().await;
    let lock = StorageLock::shared(&StorageLock::path(e._tmp.path()))
        .await
        .unwrap();
    let skipped = gc(&e)
        .collect(GcOptions {
            wait: false,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(skipped.skipped);
    let service = Arc::new(gc(&e));
    let waiting = {
        let service = service.clone();
        tokio::spawn(async move { service.collect(GcOptions::default()).await })
    };
    // (asleep in the lock, and so not ended while it is held)
    crate::common::wait_for_lock_waiter(&StorageLock::path(e._tmp.path())).await;
    assert!(!waiting.is_finished());
    drop(lock);
    assert!(!waiting.await.unwrap().unwrap().skipped);
}

#[tokio::test]
async fn the_layers_of_a_container_are_never_released() {
    let e = env().await;
    let l = layer("etc/kept", &[8u8; 20_000]);
    e.publish(&[&l], &[ZSTD]);
    let pulled = e.pull().await.unwrap();
    let digest = l.key();
    let file = vid(&[8u8; 20_000]);
    e.db.insert_container(&velarx_db::ContainerRecord {
        id: "c-kept".into(),
        name: Some("kept".into()),
        image_id: pulled.id.clone(),
        config: "{}".into(),
        state: RecordState::Created,
        created_at: "now".into(),
        ..Default::default()
    })
    .await
    .unwrap();
    e.db.set_container_layers("c-kept", vec![digest])
        .await
        .unwrap();
    // Whatever becomes of the references of the image, the container's
    // record keeps its layers from the release and from a collection.
    let id = pulled.id.clone();
    e.db.conn()
        .call(move |c| {
            c.execute("DELETE FROM image_layers WHERE image_id = ?1", [&id])?;
            Ok(())
        })
        .await
        .unwrap();
    let released = GcService::of_store(
        e.service.storage().clone(),
        e.db.clone(),
        e.store.clone(),
        &e.staging,
    )
    .release_unused_layers()
    .await
    .unwrap();
    assert_eq!(released.layers_removed, 0);
    let report = gc(&e).collect(GcOptions::default()).await.unwrap();
    assert_eq!(report.layers_removed, 0);
    assert!(e.db.get_layer(&digest).await.is_ok());
    assert!(e.store.contains(&file));

    e.db.delete_container("c-kept").await.unwrap();
    assert!(e.db.container_layers("c-kept").await.unwrap().is_empty());
    let released = GcService::of_store(
        e.service.storage().clone(),
        e.db.clone(),
        e.store.clone(),
        &e.staging,
    )
    .release_unused_layers()
    .await
    .unwrap();
    assert_eq!(released.layers_removed, 1);
    assert!(!e.store.contains(&file));
}

#[tokio::test]
async fn the_collection_removes_the_lock_files_nothing_holds() {
    let e = env().await;
    let dir = e.store.root().with_file_name("locks");
    let held = velarx_storage::locks::lock(&dir.join("held"), false)
        .unwrap()
        .unwrap();
    // (a lock file nobody locked: one taken and dropped here could still
    // be held for a moment, see `unlock`)
    std::fs::File::create(dir.join("free")).unwrap();
    gc(&e).collect(GcOptions::default()).await.unwrap();
    assert!(dir.join("held").exists());
    assert!(!dir.join("free").exists());
    unlock(&held);
    drop(held);
    gc(&e).collect(GcOptions::default()).await.unwrap();
    assert!(!dir.join("held").exists());
}

/// The files nothing references go in a few transactions, not one each.
#[tokio::test]
async fn unreferenced_files_are_removed_in_batches() {
    let e = env().await;
    const FILES: usize = 5000;
    e.db.conn()
        .call(|c| {
            let tx = c.transaction()?;
            for i in 0..FILES {
                tx.execute(
                    "INSERT INTO files (digest, size, created_at) VALUES (?1, 10, '2026-01-01T00:00:00Z')",
                    [format!("sha256:{i:064x}")],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .unwrap();
    // the last file cannot be removed: its transaction is rolled back with
    // the files it removes (2000 a transaction)
    let last = format!("sha256:{:064x}", FILES - 1);
    e.db.conn()
        .call(move |c| {
            c.execute_batch(&format!(
                "CREATE TRIGGER stuck BEFORE DELETE ON files WHEN OLD.digest = '{last}'
                 BEGIN SELECT RAISE(ABORT, 'stuck'); END;"
            ))?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(gc(&e).collect(GcOptions::default()).await.is_err());
    assert_eq!(e.db.list_files().await.unwrap().len(), FILES - 4000);

    e.db.conn()
        .call(|c| Ok(c.execute_batch("DROP TRIGGER stuck")?))
        .await
        .unwrap();
    let report = gc(&e).collect(GcOptions::default()).await.unwrap();
    assert_eq!(report.files_removed, FILES - 4000);
    assert!(e.db.list_files().await.unwrap().is_empty());
}

/// Rows that name files by no object (the `sha256:HEX` names of a store of
/// another velarx): the collection removes no file it cannot tell from an
/// orphan, and says why; `system check` refuses such a store by name.
#[tokio::test]
async fn rows_that_name_no_object_keep_their_files() {
    let e = env().await;
    let l = layer("etc/kept", &[8u8; 20_000]);
    e.publish(&[&l], &[ZSTD]);
    e.pull().await.unwrap();
    let kept = vid(&[8u8; 20_000]);
    assert!(e.store.contains(&kept));
    e.db.conn()
        .call(|c| {
            c.execute_batch(
                "PRAGMA foreign_keys = OFF;
                 UPDATE files SET digest = replace(digest, 'fsverity-sha256-12:', 'sha256:');
                 UPDATE file_refs SET file_digest = replace(file_digest, 'fsverity-sha256-12:', 'sha256:');
                 PRAGMA foreign_keys = ON;",
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let report = gc(&e).collect(GcOptions::default()).await.unwrap();
    assert!(
        e.store.contains(&kept),
        "a file of a row of the old form went"
    );
    assert!(
        report
            .errors
            .iter()
            .any(|m| m.contains("which is no fs-verity digest of an object")),
        "{:?}",
        report.errors
    );
    let e2 = e.db.all_file_objects().await.unwrap_err().to_string();
    assert!(e2.contains("a store of another velarx"), "{e2}");
}

/// A build in progress keeps an image it uses from a prune and from the
/// removal of the unused build images, as long as it lives; once it is gone
/// (it ended, or was killed) the image can be pruned.
#[tokio::test]
async fn an_image_a_build_uses_is_not_pruned_until_the_build_is_gone() {
    let e = env().await;
    let l = layer("etc/b", &[6u8; 20_000]);
    e.publish(&[&l], &[ZSTD]);
    let id = e.pull().await.unwrap().id;
    e.service
        .build_cache_put(velarx_db::BUILD_SCRATCH, "step", &id)
        .await
        .unwrap();

    let build = e.service.hold_build().unwrap();
    let got = e
        .service
        .build_cache_get(velarx_db::BUILD_SCRATCH, "step", build.name())
        .await
        .unwrap();
    assert_eq!(got.as_deref(), Some(id.as_str()));
    assert!(e.service.prune(true, &[]).await.unwrap().is_empty());
    assert!(e.service.prune_build_cache().await.unwrap().0.is_empty());
    assert!(e.db.get_image(&id).await.is_ok());

    drop(build);
    let pruned = e.service.prune(true, &[]).await.unwrap();
    assert_eq!(pruned.len(), 1);
    assert_eq!(pruned[0].0, id);
}

/// A removal that waits for the lock while another removes the image
/// answers that the image is not there, as one that comes after it does,
/// not an error of the database: concurrent removals of one image are
/// what a CRI client does.
#[tokio::test]
async fn a_removal_that_waited_for_another_finds_no_image() {
    let e = env().await;
    let l = layer("etc/r", &[7u8; 20_000]);
    e.publish(&[&l], &[ZSTD]);
    let id = e.pull().await.unwrap().id;
    let lock = StorageLock::path_of_staging(&e.staging);
    let held = StorageLock::exclusive(&lock).await.unwrap();
    let service = e.service.clone();
    let removing = {
        let id = id.clone();
        tokio::spawn(async move { service.remove(&id, false).await })
    };
    wait_for_lock_waiter(&lock).await;
    // (the other removal, done while this one waits)
    e.db.delete_image(&id).await.unwrap();
    drop(held);
    match removing.await.unwrap() {
        Err(velarx_types::ImageError::NotFound(what)) => assert_eq!(what, id),
        other => panic!("not NotFound: {other:?}"),
    }
}

/// What a publish of a lazy pull that died left, a `.new-` directory in
/// `staging/pulls`, is removed by the collection (not only at a reboot).
#[tokio::test]
async fn the_leftover_of_a_publish_that_died_is_collected() {
    let e = env().await;
    let pulls = e.staging.join("pulls");
    let dead = pulls.join(".new-dead");
    std::fs::create_dir_all(dead.join("sub")).unwrap();
    let report = gc(&e).collect(GcOptions::default()).await.unwrap();
    assert!(!dead.exists());
    assert_eq!(report.staging_removed, 1);
}

/// What the live holds pin is read or the collection stops: a `pins` that
/// cannot be read, or a staging directory that cannot, removes nothing and
/// the error is the collection's.
#[tokio::test]
async fn a_collection_that_cannot_read_what_is_pinned_removes_nothing() {
    use std::os::unix::fs::PermissionsExt;
    if rustix::process::geteuid().is_root() {
        return;
    }
    let e = env().await;
    let l = layer("etc/p", &[2u8; 20_000]);
    e.publish(&[&l], &[ZSTD]);
    let pulled = e.pull().await.unwrap();
    let file = vid(&[2u8; 20_000]);
    // (stored, and no image uses it)
    e.db.delete_image(&pulled.id).await.unwrap();
    let hold = holds::Hold::create(&e.staging, "pull-00bb").unwrap();
    hold.pin(holds::LAYER, [l.key()]).unwrap();

    let pins = hold.path().join(holds::PINS);
    std::fs::set_permissions(&pins, std::fs::Permissions::from_mode(0o000)).unwrap();
    assert!(gc(&e).collect(GcOptions::default()).await.is_err());
    assert!(e.db.get_layer(&l.key()).await.is_ok() && e.store.contains(&file));
    std::fs::set_permissions(&pins, std::fs::Permissions::from_mode(0o600)).unwrap();

    std::fs::set_permissions(&e.staging, std::fs::Permissions::from_mode(0o000)).unwrap();
    let report = gc(&e).collect(GcOptions::default()).await;
    std::fs::set_permissions(&e.staging, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(report.is_err());
    assert!(e.db.get_layer(&l.key()).await.is_ok() && e.store.contains(&file));

    // (read again, it is pinned: and once the hold is gone, collected)
    let report = gc(&e).collect(GcOptions::default()).await.unwrap();
    assert_eq!(report.layers_removed, 0);
    drop(hold);
    let report = gc(&e).collect(GcOptions::default()).await.unwrap();
    assert_eq!(report.layers_removed, 1);
}

/// A prune asks the holds again where it removes the image: a build that
/// pinned it after the pass looked is respected.
#[tokio::test]
async fn a_prune_asks_the_holds_again_before_it_removes_an_image() {
    let e = env().await;
    let l = layer("etc/r", &[3u8; 20_000]);
    e.publish(&[&l], &[ZSTD]);
    let id = e.pull().await.unwrap().id;
    let build = e.service.hold_build().unwrap();
    // (nothing pinned when the pass looked; the build pins it now)
    holds::pin(build.path(), holds::IMAGE, [&id]).unwrap();
    assert!(e.service.remove_unless_pinned(&id).await.unwrap().is_none());
    assert!(e.db.get_image(&id).await.is_ok());
    drop(build);
    assert!(e.service.remove_unless_pinned(&id).await.unwrap().is_some());
    assert!(e.db.get_image(&id).await.is_err());
}
