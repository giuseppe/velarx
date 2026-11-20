// SPDX-License-Identifier: Apache-2.0
//! Tests for database operations

use tempfile::tempdir;
use velarx_db::{
    ContainerRecord, Database, ImageRecord, ImageTag, LayerKey, LayerRecord, RecordState,
};
use velarx_types::digest::Digest;

#[tokio::test]
async fn test_database_open() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let db = Database::open(&db_path).await;
    assert!(db.is_ok());
}

#[tokio::test]
async fn test_database_open_in_memory() {
    let db = Database::open_in_memory().await;
    assert!(db.is_ok());
}

async fn create_test_image(db: &Database) -> String {
    let image_id = "image123".to_string();
    let record = ImageRecord {
        id: image_id.clone(),
        manifest_digest: digest_of(0xa),
        config_digest: digest_of(0xb),
        manifest: "{}".to_string(),
        config: "{}".to_string(),
        created_at: "2024-01-01T00:00:00Z".to_string(),
        is_lazy: false,
    };
    db.insert_image(&record).await.unwrap();
    image_id
}

#[tokio::test]
async fn test_container_crud() {
    let db = Database::open_in_memory().await.unwrap();

    // First create an image (required by foreign key)
    let image_id = create_test_image(&db).await;

    let record = ContainerRecord {
        id: "test123".to_string(),
        name: Some("test-container".to_string()),
        image_id,
        config: "{}".to_string(),
        state: RecordState::Created,
        created_at: "2024-01-01T00:00:00Z".to_string(),
        ..Default::default()
    };

    db.insert_container(&record).await.unwrap();

    let retrieved = db.get_container("test123").await.unwrap();
    assert_eq!(retrieved.id, "test123");
    assert_eq!(retrieved.name, Some("test-container".to_string()));
    assert_eq!(retrieved.state, RecordState::Created);

    let by_name = db.get_container("test-container").await.unwrap();
    assert_eq!(by_name.id, "test123");

    db.update_container_state(
        "test123",
        RecordState::Running,
        Some(12345),
        Some("2024-01-01T00:01:00Z".to_string()),
        None,
        None,
    )
    .await
    .unwrap();

    let updated = db.get_container("test123").await.unwrap();
    assert_eq!(updated.state, RecordState::Running);
    assert_eq!(updated.pid, Some(12345));

    let all = db.list_containers(true).await.unwrap();
    assert!(!all.is_empty());

    db.delete_container("test123").await.unwrap();

    let result = db.get_container("test123").await;
    assert!(result.is_err());
}

/// The dependents of a container and the SELinux levels in use come from
/// what the insert recorded of the configs, not from reading every config.
#[tokio::test]
async fn the_dependents_and_the_levels_are_recorded_with_the_containers() {
    let db = Database::open_in_memory().await.unwrap();
    let image_id = create_test_image(&db).await;
    let id = "8003092664cc4edf481527ada28d1fb08ad62bcfc319380e082970215d8faf34";
    let record = |cid: &str, name: &str, config: serde_json::Value| ContainerRecord {
        id: cid.to_string(),
        name: Some(name.to_string()),
        image_id: image_id.clone(),
        config: config.to_string(),
        state: RecordState::Created,
        created_at: "2024-01-01T00:00:00Z".to_string(),
        ..Default::default()
    };
    let inserts = [
        record(
            id,
            "c1",
            serde_json::json!({"selinux": {"level": "s0:c1,c2"}}),
        ),
        record(
            "a",
            "by-id",
            serde_json::json!({"network_mode": format!("container:{id}")}),
        ),
        record(
            "b",
            "by-name",
            serde_json::json!({"options": {"pid_ns": "container:c1"}}),
        ),
        record(
            "c",
            "by-prefix",
            serde_json::json!({"options": {"ipc_ns": "container:8003092664cc"}}),
        ),
        record("d", "requires", serde_json::json!({"requires": [id]})),
        record(
            "e",
            "other",
            serde_json::json!({"network_mode": "container:other",
            "selinux": {"files": true, "file_level": "s0:c3,c4"}}),
        ),
        record(
            "f",
            "short",
            serde_json::json!({"network_mode": "container:8003"}),
        ),
    ];
    for r in &inserts {
        db.insert_container(r).await.unwrap();
    }
    assert_eq!(
        db.container_dependents(id, "c1").await.unwrap(),
        ["a", "b", "c", "d"]
    );
    assert!(db
        .container_dependents("a", "by-id")
        .await
        .unwrap()
        .is_empty());
    // (`/NAME` is the name too, found by the index of the names)
    assert_eq!(db.get_container("/c1").await.unwrap().id, id);
    let mut levels = db.container_selinux_levels().await.unwrap();
    levels.sort();
    assert_eq!(levels, ["s0:c1,c2", "s0:c3,c4"]);
    // a removed container is nobody's dependent any more
    db.delete_container("by-id").await.unwrap();
    assert_eq!(
        db.container_dependents(id, "c1").await.unwrap(),
        ["b", "c", "d"]
    );
}

/// What a `run` reads of the store does not grow with the images and the
/// containers: the big columns are last (SQLite walks the overflow
/// pages of a column to read one after it), and the levels in use are read
/// from an index.
#[tokio::test]
async fn the_big_columns_are_last_and_the_levels_are_an_index() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    drop(Database::open(&path).await.unwrap());
    let conn = rusqlite::Connection::open(&path).unwrap();
    let columns = |table: &str| -> Vec<String> {
        let mut stmt = conn
            .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert!(columns("layers").ends_with(&["tarsplit".into(), "toc".into()]));
    assert_eq!(
        columns("containers").last().map(String::as_str),
        Some("config")
    );
    let plan: String = conn
        .query_row(
            "EXPLAIN QUERY PLAN SELECT selinux_level FROM containers WHERE selinux_level IS NOT NULL",
            [],
            |r| r.get(3),
        )
        .unwrap();
    assert!(plan.contains("COVERING INDEX"), "{plan}");
}

/// The references an image was pulled by are recorded in the transaction of
/// the image: a fault while they are written leaves no image, so no stored
/// image lacks them.
#[tokio::test]
async fn the_pulls_of_an_image_are_recorded_with_it() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    let db = Database::open(&path).await.unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER fault BEFORE INSERT ON pulled_images
         BEGIN SELECT RAISE(ABORT, 'a fault'); END",
    )
    .unwrap();
    let manifest = digest_of(9);
    let pull = velarx_db::PullCommit {
        layers: Vec::new(),
        image: ImageRecord {
            id: "i".into(),
            manifest_digest: manifest,
            config_digest: digest_of(8),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: "now".into(),
            is_lazy: false,
        },
        image_layers: Vec::new(),
        tags: vec![ImageTag {
            repository: "r.io/a".into(),
            tag: "1".into(),
            image_id: "i".into(),
        }],
        digest_names: Vec::new(),
        sources: Vec::new(),
        pulled: vec![("r.io/a:1".into(), b"sigs".to_vec())],
    };
    assert!(db.commit_pull(pull.clone()).await.is_err());
    assert!(db.list_images().await.unwrap().is_empty());
    assert!(db.pulled_image(&manifest).await.unwrap().is_empty());
    conn.execute_batch("DROP TRIGGER fault").unwrap();
    db.commit_pull(pull).await.unwrap();
    assert_eq!(db.list_images().await.unwrap().len(), 1);
    assert_eq!(
        db.pulled_image(&manifest).await.unwrap(),
        [("r.io/a:1".to_string(), b"sigs".to_vec())]
    );
}

#[tokio::test]
async fn test_container_rename() {
    let db = Database::open_in_memory().await.unwrap();

    // First create an image (required by foreign key)
    let image_id = create_test_image(&db).await;

    let record = ContainerRecord {
        id: "rename-test".to_string(),
        name: Some("old-name".to_string()),
        image_id,
        config: "{}".to_string(),
        state: RecordState::Created,
        created_at: "2024-01-01T00:00:00Z".to_string(),
        ..Default::default()
    };

    db.insert_container(&record).await.unwrap();

    db.rename_container("rename-test", "new-name")
        .await
        .unwrap();

    let renamed = db.get_container("new-name").await.unwrap();
    assert_eq!(renamed.id, "rename-test");
    assert_eq!(renamed.name, Some("new-name".to_string()));

    let old = db.get_container("old-name").await;
    assert!(old.is_err());
}

#[tokio::test]
async fn test_image_crud() {
    let db = Database::open_in_memory().await.unwrap();

    let record = ImageRecord {
        id: "img123".to_string(),
        manifest_digest: digest_of(0xa),
        config_digest: digest_of(0xb),
        manifest: "{}".to_string(),
        config: "{}".to_string(),
        created_at: "2024-01-01T00:00:00Z".to_string(),
        is_lazy: false,
    };

    db.insert_image(&record).await.unwrap();

    let retrieved = db.get_image("img123").await.unwrap();
    assert_eq!(retrieved.id, "img123");
    assert_eq!(retrieved.manifest_digest, digest_of(0xa));

    let all = db.list_images().await.unwrap();
    assert!(!all.is_empty());

    db.delete_image("img123").await.unwrap();
    let result = db.get_image("img123").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_layer_operations() {
    let db = Database::open_in_memory().await.unwrap();

    let image = ImageRecord {
        id: "img-for-layer".to_string(),
        manifest_digest: digest_of(0xc),
        config_digest: digest_of(0xb),
        manifest: "{}".to_string(),
        config: "{}".to_string(),
        created_at: "2024-01-01T00:00:00Z".to_string(),
        is_lazy: false,
    };
    db.insert_image(&image).await.unwrap();

    let key = LayerKey::Whole(digest_of(1));
    let layer = LayerRecord {
        stream_size: Some(0),
        key,
        blob: Some(digest_of(1)),
        diff_id: Some(digest_of(0xd)),
        other_diff_id: None,
        size: 512,
        toc: Some("{\"entries\": []}".to_string()),
        status: "complete".to_string(),
        created_at: "2024-01-01T00:00:00Z".to_string(),
        registry_ref: None,
        erofs: None,
        owners: None,
    };

    db.insert_layer(&layer).await.unwrap();

    db.insert_image_layer("img-for-layer", &key, 0)
        .await
        .unwrap();

    let layers = db.get_image_layers("img-for-layer").await.unwrap();
    assert_eq!(layers.len(), 1);
    assert_eq!(layers[0].key, key);
    assert_eq!(layers[0].toc.as_deref(), Some("{\"entries\": []}"));

    // the same layers without their tables of contents
    let light = db
        .get_image_layers_without_toc("img-for-layer")
        .await
        .unwrap();
    assert_eq!(light.len(), 1);
    assert_eq!(light[0].key, key);
    assert_eq!(light[0].size, 512);
    assert!(light[0].toc.is_none());
}

#[tokio::test]
async fn test_container_not_found() {
    let db = Database::open_in_memory().await.unwrap();

    let result = db.get_container("nonexistent").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_image_not_found() {
    let db = Database::open_in_memory().await.unwrap();

    let result = db.get_image("nonexistent").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_multiple_containers() {
    let db = Database::open_in_memory().await.unwrap();

    // First create an image (required by foreign key)
    let image_id = create_test_image(&db).await;

    for i in 0..5 {
        let record = ContainerRecord {
            id: format!("container-{}", i),
            name: Some(format!("name-{}", i)),
            image_id: image_id.clone(),
            config: "{}".to_string(),
            state: if i % 2 == 0 {
                RecordState::Running
            } else {
                RecordState::Stopped
            },
            pid: if i % 2 == 0 { Some(1000 + i) } else { None },
            created_at: "2024-01-01T00:00:00Z".to_string(),
            ..Default::default()
        };
        db.insert_container(&record).await.unwrap();
    }

    let all = db.list_containers(true).await.unwrap();
    assert_eq!(all.len(), 5);

    let running = db.list_containers(false).await.unwrap();
    assert_eq!(running.len(), 3); // 0, 2, 4 are running
}

/// An image can use a layer twice: a row per position.
#[tokio::test]
async fn test_an_image_can_use_a_layer_twice() {
    let db = Database::open_in_memory().await.unwrap();
    db.conn()
        .call(|c| {
            c.execute_batch(&format!(
                "INSERT INTO images VALUES ('i1', 'sha256:m', 'sha256:c', '{{}}', '{{}}', 'now');
                     INSERT INTO layers (id, blob, size, created_at, stream_size)
                         VALUES ('{l1}', '{l1}', 1, 'now', 1), ('toc:{l2}', '{l1}', 1, 'now', 1);",
                l1 = digest_of(1),
                l2 = digest_of(2)
            ))?;
            Ok(())
        })
        .await
        .unwrap();
    let (l1, l2) = (LayerKey::Whole(digest_of(1)), LayerKey::Toc(digest_of(2)));
    for (key, index) in [(&l1, 0), (&l2, 1), (&l1, 2)] {
        db.insert_image_layer("i1", key, index).await.unwrap();
    }
    let layers = db.get_image_layers("i1").await.unwrap();
    assert_eq!(
        layers.iter().map(|l| l.key).collect::<Vec<_>>(),
        [l1, l2, l1]
    );
}

#[tokio::test]
async fn test_a_stored_layer_is_not_replaced() {
    let db = Database::open_in_memory().await.unwrap();
    let key = LayerKey::Toc(digest_of(3));
    let layer = |toc: &str| LayerRecord {
        stream_size: Some(0),
        key,
        blob: Some(digest_of(4)),
        diff_id: Some(digest_of(0xd)),
        other_diff_id: None,
        size: 1,
        toc: Some(toc.to_string()),
        status: "ready".to_string(),
        created_at: "2024-01-01T00:00:00Z".to_string(),
        registry_ref: None,
        erofs: None,
        owners: None,
    };
    db.insert_layer(&layer("{\"entries\": [1]}")).await.unwrap();
    db.insert_layer(&layer("{\"entries\": [2]}")).await.unwrap();
    let got = db.get_layer(&key).await.unwrap();
    assert_eq!(
        (got.status.as_str(), got.toc.as_deref()),
        ("ready", Some("{\"entries\": [1]}"))
    );
}

#[tokio::test]
async fn test_image_tags_newest_first() {
    let db = Database::open_in_memory().await.unwrap();
    let id = create_test_image(&db).await;
    let tag = |r: &str| velarx_db::ImageTag {
        repository: r.to_string(),
        tag: "latest".to_string(),
        image_id: id.clone(),
    };
    for r in [
        "quay.io/libpod/alpine",
        "quay.io/libpod/busybox",
        "localhost/a",
    ] {
        db.insert_image_tag(&tag(r)).await.unwrap();
    }
    // tagged again: the newest
    db.insert_image_tag(&tag("quay.io/libpod/alpine"))
        .await
        .unwrap();
    let names: Vec<String> = db
        .get_tags_for_image(&id)
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.repository)
        .collect();
    assert_eq!(
        names,
        [
            "quay.io/libpod/alpine",
            "localhost/a",
            "quay.io/libpod/busybox"
        ]
    );
}

#[tokio::test]
async fn the_schema_version_is_recorded_and_another_one_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.sqlite");
    let db = velarx_db::Database::open(&path).await.unwrap();
    let version: i64 = db
        .conn()
        .call(|c| Ok(c.query_row("PRAGMA user_version", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(version, velarx_db::SCHEMA_VERSION);
    db.conn()
        .call(|c| Ok(c.execute_batch("PRAGMA user_version = 999;")?))
        .await
        .unwrap();
    drop(db);
    for _ in 0..2 {
        let e = match velarx_db::Database::open(&path).await {
            Ok(_) => panic!("a database of another schema was opened"),
            Err(e) => e.to_string(),
        };
        assert!(e.contains("schema version 999"), "{e}");
    }
}

#[tokio::test]
async fn a_large_log_is_written_back_and_truncated() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(dir.path().join("db.sqlite")).await.unwrap();
    db.conn()
        .call(|c| {
            c.execute_batch("CREATE TABLE filler (x BLOB)")?;
            for _ in 0..64 {
                c.execute("INSERT INTO filler (x) VALUES (zeroblob(16384))", [])?;
            }
            Ok(())
        })
        .await
        .unwrap();
    let before = db.wal_size();
    assert!(before > 512 * 1024, "the log grew: {before}");
    assert!(!db.compact_wal(before).await.unwrap(), "small enough");
    assert!(db.compact_wal(1024).await.unwrap());
    assert_eq!(db.wal_size(), 0);
    let n: i64 = db
        .conn()
        .call(|c| Ok(c.query_row("SELECT count(*) FROM filler", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(n, 64);
    assert_eq!(Database::open_in_memory().await.unwrap().wal_size(), 0);
}

/// Whether a file may be given to peers is a lookup by file, not a scan of
/// every layer's files.
#[tokio::test]
async fn test_the_files_of_a_layer_are_found_by_file() {
    let db = velarx_db::Database::open_in_memory().await.unwrap();
    let plan: Vec<String> = db
        .conn()
        .call(|c| {
            let mut stmt = c.prepare(
                "EXPLAIN QUERY PLAN SELECT 1 FROM file_refs f JOIN shared_layers s
                 ON s.layer_id = f.layer_id WHERE f.file_digest = ?1",
            )?;
            let rows = stmt
                .query_map(["sha256:x"], |r| r.get::<_, String>(3))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .unwrap();
    let text = plan.join("\n");
    assert!(text.contains("idx_file_refs_file"), "{text}");
    assert!(!text.contains("SCAN f"), "{text}");
}

fn object(c: char, checked: bool) -> velarx_storage::Object {
    velarx_storage::Object::new(
        &format!("fsverity-sha256-12:{}", c.to_string().repeat(64)),
        checked,
    )
    .unwrap()
}

/// The files of the store are kept by their fs-verity digest with whether
/// the kernel measured them, which a later record does not undo, and go
/// with their references.
#[tokio::test]
async fn the_objects_of_files_are_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(dir.path().join("db.sqlite")).await.unwrap();
    let row = |c: char, checked: bool| velarx_db::FileRecord {
        digest: object(c, checked).verity,
        size: 1,
        created_at: "2026-01-01T00:00:00Z".into(),
        checked,
    };
    db.record_files(vec![row('1', true), row('2', false)])
        .await
        .unwrap();
    db.record_files(vec![row('1', false)]).await.unwrap();
    let asked = vec![
        object('1', true).verity,
        object('2', true).verity,
        object('3', true).verity,
    ];
    let found = db.file_objects(asked.clone()).await.unwrap();
    assert_eq!(found.len(), 2);
    assert_eq!(found[&asked[0]], object('1', true));
    assert_eq!(found[&asked[1]], object('2', false));
    db.delete_files(vec![asked[0].clone()]).await.unwrap();
    assert!(!db
        .file_objects(asked.clone())
        .await
        .unwrap()
        .contains_key(&asked[0]));
}

#[tokio::test]
async fn the_lookups_of_the_collector_have_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let db = velarx_db::Database::open(&dir.path().join("db.sqlite"))
        .await
        .unwrap();
    for (table, column) in [
        ("image_layers", "layer_id"),
        ("container_layers", "layer_id"),
        ("containers", "image_id"),
    ] {
        let plan: String = db
            .conn()
            .call(move |c| {
                Ok(c.query_row(
                    &format!("EXPLAIN QUERY PLAN SELECT 1 FROM {table} WHERE {column} = 'x'"),
                    [],
                    |r| r.get::<_, String>(3),
                )?)
            })
            .await
            .unwrap();
        assert!(plan.contains("USING"), "{table}.{column}: {plan}");
        assert!(plan.contains("INDEX"), "{table}.{column}: {plan}");
    }
}

/// What one process records of a container wakes the one that watches the
/// database, whatever the change (insert, state, health, rename, removal).
#[tokio::test]
async fn test_a_change_of_a_container_wakes_the_watcher_of_another_connection() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let writer = Database::open(&db_path).await.unwrap();
    let watcher = Database::open(&db_path).await.unwrap();
    let image_id = create_test_image(&writer).await;
    let mut watch = watcher.watch_changes().unwrap();

    let record = ContainerRecord {
        id: "c1".to_string(),
        name: Some("one".to_string()),
        image_id,
        config: "{}".to_string(),
        state: RecordState::Created,
        created_at: "2024-01-01T00:00:00Z".to_string(),
        ..Default::default()
    };
    writer.insert_container(&record).await.unwrap();
    watch.changed().await.unwrap();
    assert_eq!(
        watcher.get_container("c1").await.unwrap().state,
        RecordState::Created
    );

    writer
        .update_container_state("c1", RecordState::Running, Some(7), None, None, None)
        .await
        .unwrap();
    watch.changed().await.unwrap();
    assert_eq!(
        watcher.get_container("c1").await.unwrap().state,
        RecordState::Running
    );

    let mut ext = writer.get_container_ext("c1").await.unwrap();
    ext.health = Some("{}".to_string());
    writer
        .update_container_ext("c1", move |e| *e = ext)
        .await
        .unwrap();
    watch.changed().await.unwrap();

    writer.rename_container("c1", "two").await.unwrap();
    watch.changed().await.unwrap();
    writer.delete_container("c1").await.unwrap();
    watch.changed().await.unwrap();
    assert!(watcher.get_container("c1").await.is_err());
}

#[tokio::test]
async fn test_a_watch_made_before_a_change_sees_it_whenever_it_is_read() {
    let dir = tempdir().unwrap();
    let db = Database::open(dir.path().join("test.db")).await.unwrap();
    let image_id = create_test_image(&db).await;
    let mut watch = db.watch_changes().unwrap();
    let record = ContainerRecord {
        id: "c2".to_string(),
        name: None,
        image_id,
        config: "{}".to_string(),
        state: RecordState::Created,
        created_at: "2024-01-01T00:00:00Z".to_string(),
        ..Default::default()
    };
    db.insert_container(&record).await.unwrap();
    db.update_container_state("c2", RecordState::Running, None, None, None, None)
        .await
        .unwrap();
    // two changes before the first look: one wake-up or two (the watch of
    // the process tells each event it read), then nothing
    watch.changed().await.unwrap();
    let mut wakeups = 1;
    while tokio::time::timeout(std::time::Duration::from_millis(100), watch.changed())
        .await
        .is_ok()
    {
        wakeups += 1;
        assert!(wakeups <= 2, "no change is left to report");
    }
}

/// A digest made of the hex digit of `n`.
fn digest_of(n: u8) -> Digest {
    format!("sha256:{}", format!("{n:x}").repeat(64))
        .parse()
        .unwrap()
}

/// A layer is found under its own key only: the layer of a TOC is not the
/// layer of its blob, whatever the digests; and a row says what proved it
/// (the diff id it was verified against: the store records no other).
#[tokio::test]
async fn test_a_layer_is_found_by_its_key_only() {
    let db = Database::open_in_memory().await.unwrap();
    let blob = digest_of(1);
    let record = |key: LayerKey, status: &str, diff_id: Option<Digest>| LayerRecord {
        stream_size: Some(0),
        key,
        blob: Some(blob),
        diff_id,
        other_diff_id: None,
        size: 1,
        toc: Some("{}".into()),
        status: status.into(),
        created_at: "now".into(),
        registry_ref: None,
        erofs: None,
        owners: None,
    };
    let checked = |r: LayerRecord, blob_checked: bool| velarx_db::PullCommit {
        layers: vec![velarx_db::LayerCommit {
            record: r,
            files: Vec::new(),
            refs: Vec::new(),
            chunks: Vec::new(),
            tarsplit: None,
            blob_checked,
        }],
        image: ImageRecord {
            id: "i".into(),
            manifest_digest: digest_of(9),
            config_digest: digest_of(8),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: "now".into(),
            is_lazy: false,
        },
        image_layers: Vec::new(),
        tags: Vec::new(),
        digest_names: Vec::new(),
        sources: Vec::new(),
        pulled: Vec::new(),
    };
    let commit = |r: LayerRecord| checked(r, false);
    let (toc, whole) = (LayerKey::Toc(digest_of(2)), LayerKey::Whole(blob));
    // a layer of a table of contents is verified by its table: no diff id is
    // fine for it, and it is refused for a layer of a blob (nothing proved it)
    assert!(db
        .commit_pull(commit(record(toc, "ready", None)))
        .await
        .is_ok());
    assert!(db
        .commit_pull(commit(record(whole, "ready", None)))
        .await
        .is_err());
    db.commit_pull(commit(record(toc, "ready", Some(digest_of(0xd)))))
        .await
        .unwrap();
    assert_eq!(db.get_layer(&toc).await.unwrap().blob, Some(blob));
    // the blob is not the layer of its TOC, nor the TOC digest a blob
    assert!(db.get_layer(&whole).await.is_err());
    assert!(db.get_layer(&LayerKey::Whole(digest_of(2))).await.is_err());
    assert!(db.get_layer(&LayerKey::Toc(blob)).await.is_err());
    // both views of one blob are two layers
    db.commit_pull(commit(record(whole, "ready", Some(digest_of(0xd)))))
        .await
        .unwrap();
    let mut keys = db.layer_digests().await.unwrap();
    keys.sort();
    assert_eq!(keys, [whole, toc]);

    // a layer of the blob whose blob was not hashed (the files the peers
    // have for a diff id) is not proof against another diff id, and gives
    // way to the layer of the blob hashed; that one does not
    assert!(db
        .commit_pull(commit(record(whole, "ready", Some(digest_of(0xe)))))
        .await
        .is_err());
    db.commit_pull(checked(record(whole, "ready", Some(digest_of(0xe))), true))
        .await
        .unwrap();
    assert_eq!(
        db.get_layer(&whole).await.unwrap().diff_id.as_ref(),
        Some(&digest_of(0xe))
    );
    for blob_checked in [false, true] {
        assert!(db
            .commit_pull(checked(
                record(whole, "ready", Some(digest_of(0xd))),
                blob_checked
            ))
            .await
            .is_err());
    }

    // the diff id of the other algorithm (a sha512 configuration over the
    // same sha256 blob) is the other name of the same tar when both pulls
    // hashed the blob: the row keeps its own and gets that one too; a pull
    // that did not hash it proves nothing of the row's tar
    let sha512 = velarx_types::digest::Digest::of(velarx_types::digest::Algorithm::Sha512, b"tar");
    let e = db
        .commit_pull(commit(record(whole, "ready", Some(sha512))))
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("nothing proves that the tar of"), "{e}");
    db.commit_pull(checked(record(whole, "ready", Some(sha512)), true))
        .await
        .unwrap();
    let l = db.get_layer(&whole).await.unwrap();
    assert_eq!(
        (l.diff_id, l.other_diff_id),
        (Some(digest_of(0xe)), Some(sha512))
    );
    assert!(l.has_diff_id(&digest_of(0xe)) && l.has_diff_id(&sha512));
    assert_eq!(
        l.diff_id_in(velarx_types::digest::Algorithm::Sha512),
        Some(&sha512)
    );
    // both stay; another sha512 is another tar
    for d in [digest_of(0xe), sha512] {
        db.commit_pull(checked(record(whole, "ready", Some(d)), true))
            .await
            .unwrap();
    }
    let other512 = velarx_types::digest::Digest::of(velarx_types::digest::Algorithm::Sha512, b"x");
    assert!(db
        .commit_pull(checked(record(whole, "ready", Some(other512)), true))
        .await
        .is_err());
    let l = db.get_layer(&whole).await.unwrap();
    assert_eq!(
        (l.diff_id, l.other_diff_id),
        (Some(digest_of(0xe)), Some(sha512))
    );

    // the layer of a TOC that another blob names, pulled from another
    // registry: the lazy fetches ask that registry for that blob
    let mut other = record(toc, "ready", Some(digest_of(0xd)));
    (other.blob, other.size, other.registry_ref) =
        (Some(digest_of(7)), 2, Some("example.com/other:1".into()));
    db.commit_pull(commit(other)).await.unwrap();
    let got = db.get_layer(&toc).await.unwrap();
    assert_eq!(
        (got.blob, got.size, got.registry_ref.as_deref()),
        (Some(digest_of(7)), 2, Some("example.com/other:1"))
    );
    // (a layer recorded without its registry keeps the one it had)
    db.commit_pull(commit(record(toc, "ready", Some(digest_of(0xd)))))
        .await
        .unwrap();
    assert_eq!(db.get_layer(&toc).await.unwrap().blob, Some(digest_of(7)));
}

/// The containers of every image are counted by one query, with the same
/// answer as asking for each image: those of the image, and those that mount
/// a directory of it, each once.
#[tokio::test]
async fn the_container_counts_of_all_images_are_those_of_each() {
    let db = Database::open_in_memory().await.unwrap();
    let ids = ["img-a", "img-b", "img-c"];
    for (n, id) in ids.iter().enumerate() {
        db.insert_image(&ImageRecord {
            id: id.to_string(),
            manifest_digest: digest_of(1 + n as u8),
            config_digest: digest_of(5 + n as u8),
            manifest: "{}".to_string(),
            config: "{}".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            is_lazy: false,
        })
        .await
        .unwrap();
    }
    // (image of the container, image its volumes mount)
    let containers: &[(&str, &[&str])] = &[
        ("img-a", &[]),
        ("img-a", &["img-b"]),
        ("img-a", &["img-a", "img-a"]),
        ("img-b", &["img-a", "img-c"]),
        ("img-b", &[]),
    ];
    for (n, (image, mounts)) in containers.iter().enumerate() {
        let mounts: Vec<_> = mounts
            .iter()
            .map(|i| serde_json::json!({"image": {"image": i}}))
            .collect();
        db.insert_container(&ContainerRecord {
            id: format!("c{n}"),
            image_id: image.to_string(),
            config: serde_json::json!({"mounts": mounts}).to_string(),
            state: RecordState::Created,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    let counts = db.container_counts_by_image().await.unwrap();
    for id in ids {
        let each = db.containers_using_image(id).await.unwrap().len();
        assert_eq!(counts.get(id).copied().unwrap_or(0), each, "{id}");
    }
    assert_eq!(counts["img-a"], 4);
    assert_eq!(counts["img-b"], 3);
    assert_eq!(counts["img-c"], 1);
}
