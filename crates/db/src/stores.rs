// SPDX-License-Identifier: Apache-2.0
//! Read-only image stores under the store of this instance.
//!
//! The databases of the additional image stores are opened read-only: what
//! this store has not got (an image, its tags and layers, the records of
//! files) is looked up in them, in their order.  Nothing is ever written to
//! them, and what scans the store (the collection, fsck) sees this store
//! alone: only the lookups below go through.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use rusqlite::{OpenFlags, OptionalExtension};
use tokio_rusqlite::Connection;

use super::{Database, ImageRecord, ImageTag, LayerRecord, LayerState, SCHEMA_VERSION};
use velarx_storage::Object;
use velarx_types::digest::Digest;
use velarx_types::{DbError, DbResult, LayerKey};

/// `path` as the file name of an SQLite URI.
fn uri_path(path: &Path) -> String {
    let mut out = String::new();
    for c in path.to_string_lossy().chars() {
        match c {
            '%' => out.push_str("%25"),
            '?' => out.push_str("%3f"),
            '#' => out.push_str("%23"),
            c => out.push(c),
        }
    }
    out
}

fn other(msg: String) -> DbError {
    DbError::Sqlite(tokio_rusqlite::Error::Other(msg.into()))
}

/// Whether `path` plus `suffix` (the `-wal` or `-journal` of a database) is
/// a file with content.
fn side_file_has_content(path: &Path, suffix: &str) -> bool {
    let mut side = path.as_os_str().to_os_string();
    side.push(suffix);
    std::fs::metadata(side).is_ok_and(|m| m.len() > 0)
}

impl Database {
    /// Open the database of a read-only store.  It is not changed in any
    /// way (no schema): it must be of the schema version this build uses.
    ///
    /// Nothing may be written to the store, by any capability: a process
    /// with `CAP_DAC_OVERRIDE` (the root of a user namespace over the
    /// owner's files) passes every permission check, so the permissions of
    /// the store are not what keeps it as it is.  The file is therefore
    /// opened `immutable=1`: SQLite opens it read-only, takes no lock and
    /// makes no `-shm` or `-wal` file.  The cost is that it trusts the file
    /// as it is: what the owner writes after this open is not seen (a
    /// restart sees it), and a database that has changes outside its main
    /// file (a `-wal` with frames, a `-journal`: its owner has it open, or a
    /// crash left them) would be read without them, so that store is
    /// refused.  A store is meant to be left by its owner closed: a command
    /// without a daemon, and a daemon that stops, write the log of the
    /// database back and remove its files (`close`); a daemon that runs, or
    /// a process that was killed, has them.  Shared read-only, or on
    /// read-only media.  An owner that writes while this is open is not
    /// supported: a checkpoint of its WAL can be read half done.
    pub async fn open_read_only(path: &Path) -> DbResult<Self> {
        if !path.is_file() {
            return Err(DbError::NotFound(format!(
                "{}: no database of a store",
                path.display()
            )));
        }
        for (suffix, what) in [("-wal", "a write-ahead log"), ("-journal", "a journal")] {
            if side_file_has_content(path, suffix) {
                return Err(other(format!(
                    "{}: has {what} with changes that are not in the database file \
                     (a velarx uses the store, or one was killed while it did): \
                     a read-only store must be closed by its owner, who stops the \
                     velarx that uses it (a daemon: `velarx varlink`), or, after a kill, \
                     runs any velarx command on the store and lets it end",
                    path.display()
                )));
            }
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let uri = format!("file:{}?immutable=1", uri_path(path));
        let conn = Connection::open_with_flags(&uri, flags)
            .await
            .map_err(DbError::Sqlite)?;
        let version = conn
            .call(|conn| Ok(conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?))
            .await
            .map_err(DbError::Sqlite)?;
        if version != SCHEMA_VERSION {
            return Err(other(format!(
                "{}: the store has schema version {version}, this velarx uses \
                 {SCHEMA_VERSION}",
                path.display()
            )));
        }
        Ok(Self {
            conn: Arc::new(super::Conn::new(conn, false, None)),
            lease_dir: Arc::new(super::leases::lock_dir(Some(path))),
            path: Some(Arc::new(path.to_path_buf())),
            more: Arc::new(Vec::new()),
        })
    }

    /// The database of the store `storage`, with those of its additional
    /// image stores under it.  A store that cannot be used is skipped, and
    /// the log says why.
    /// An additional store of another storage driver than this store's
    /// (what is asked for, else what the store records) is skipped too: its
    /// content is in that driver's form.
    pub async fn open_store(storage: &velarx_config::StorageConfig) -> DbResult<Self> {
        let main = Database::open(storage.database_path()).await?;
        let own = std::fs::canonicalize(&storage.root).ok();
        let driver = match &storage.driver {
            Some(d) => d.clone(),
            None => main.recorded_driver().await?,
        };
        let mut more = Vec::new();
        for root in &storage.additional_image_stores {
            if own.is_some() && std::fs::canonicalize(root).ok() == own {
                tracing::warn!(
                    "The additional image store {} is the store itself: not used",
                    root.display()
                );
                continue;
            }
            match Database::open_read_only(&root.join("db.sqlite")).await {
                Ok(db) => match db.recorded_driver().await {
                    Ok(theirs) if theirs == driver => more.push(db),
                    Ok(theirs) => tracing::warn!(
                        "The additional image store {} was made with the storage driver \
                         {theirs:?}, this store has {driver:?}: not used",
                        root.display()
                    ),
                    Err(e) => tracing::warn!(
                        "The additional image store {}: {e}: not used",
                        root.display()
                    ),
                },
                Err(e) => tracing::warn!(
                    "The additional image store {}: {e}: not used",
                    root.display()
                ),
            }
        }
        Ok(main.with_additional(more))
    }

    /// The storage driver the store was made with (`store_settings`): a
    /// store that has not recorded one was made before the driver was
    /// recorded, when `composefs` was the only one.
    pub async fn recorded_driver(&self) -> DbResult<String> {
        let recorded: Option<String> = self
            .conn
            .call(|conn| {
                Ok(conn
                    .query_row(
                        "SELECT value FROM store_settings WHERE key = 'driver'",
                        [],
                        |r| r.get(0),
                    )
                    .optional()?)
            })
            .await
            .map_err(DbError::Sqlite)?;
        Ok(
            recorded
                .unwrap_or_else(|| velarx_config::StorageDriverKind::DEFAULT.name().to_string()),
        )
    }

    /// The layer, of this store only (not of the read-only stores).
    pub async fn get_own_layer(&self, key: &LayerKey) -> DbResult<LayerRecord> {
        self.get_layer_here(key).await
    }

    /// What the layers `keys` of this store say of themselves (those that
    /// have a row; not the read-only stores' layers), in few queries and
    /// without reading their tables of contents: what a driver answers "which
    /// of these layers are complete" from.
    pub async fn get_own_layer_states(&self, keys: &[LayerKey]) -> DbResult<Vec<LayerState>> {
        self.get_layer_states_here(keys).await
    }

    /// This database, with the read-only stores' under it.
    pub fn with_additional(mut self, more: Vec<Database>) -> Self {
        self.more = Arc::new(more);
        self
    }

    /// Whether the read-only stores have the image and this store has not:
    /// it cannot be removed or untagged.
    #[cfg(test)]
    pub async fn image_is_read_only(&self, id: &str) -> DbResult<bool> {
        Ok(self.image_owner(id).await?.is_some())
    }

    /// The read-only store that has the image, when this one has not.
    async fn image_owner(&self, id: &str) -> DbResult<Option<&Database>> {
        if self.more.is_empty() {
            return Ok(None);
        }
        match self.get_image_here(id).await {
            Ok(_) => return Ok(None),
            Err(DbError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        for db in self.more.iter() {
            if db.get_image_here(id).await.is_ok() {
                return Ok(Some(db));
            }
        }
        Ok(None)
    }

    pub async fn get_image(&self, id: &str) -> DbResult<ImageRecord> {
        let first = self.get_image_here(id).await;
        let Err(DbError::NotFound(_)) = &first else {
            return first;
        };
        for db in self.more.iter() {
            if let Ok(r) = db.get_image_here(id).await {
                return Ok(r);
            }
        }
        first
    }

    pub async fn get_image_by_digest(&self, digest: &Digest) -> DbResult<ImageRecord> {
        let first = self.get_image_by_digest_here(digest).await;
        let Err(DbError::NotFound(_)) = &first else {
            return first;
        };
        for db in self.more.iter() {
            if let Ok(r) = db.get_image_by_digest_here(digest).await {
                return Ok(r);
            }
        }
        first
    }

    pub async fn get_image_by_tag(&self, repository: &str, tag: &str) -> DbResult<ImageRecord> {
        let first = self.get_image_by_tag_here(repository, tag).await;
        let Err(DbError::NotFound(_)) = &first else {
            return first;
        };
        for db in self.more.iter() {
            if let Ok(r) = db.get_image_by_tag_here(repository, tag).await {
                return Ok(r);
            }
        }
        first
    }

    /// The images of this store, then those of the read-only stores it
    /// has not got.
    pub async fn list_images(&self) -> DbResult<Vec<ImageRecord>> {
        let mut images = self.list_images_here().await?;
        if self.more.is_empty() {
            return Ok(images);
        }
        let mut seen: HashSet<String> = images.iter().map(|i| i.id.clone()).collect();
        for db in self.more.iter() {
            match db.list_images_here().await {
                Ok(list) => images.extend(list.into_iter().filter(|i| seen.insert(i.id.clone()))),
                Err(e) => tracing::warn!("A read-only store: {e}"),
            }
        }
        Ok(images)
    }

    /// The tags of an image: this store's, and those the read-only stores
    /// give it that this store does not give another image.
    pub async fn get_tags_for_image(&self, image_id: &str) -> DbResult<Vec<ImageTag>> {
        let mut tags = self.get_tags_for_image_here(image_id).await?;
        for db in self.more.iter() {
            for t in db
                .get_tags_for_image_here(image_id)
                .await
                .unwrap_or_default()
            {
                if tags
                    .iter()
                    .any(|o| (&o.repository, &o.tag) == (&t.repository, &t.tag))
                {
                    continue;
                }
                match self.get_image_by_tag_here(&t.repository, &t.tag).await {
                    Err(DbError::NotFound(_)) => tags.push(t),
                    Ok(_) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(tags)
    }

    /// The read-only store that has the image (whether this one has a
    /// copy of its records or not).
    pub async fn read_only_store_of(&self, id: &str) -> Option<std::path::PathBuf> {
        for db in self.more.iter() {
            if db.get_image_here(id).await.is_ok() {
                return db
                    .path
                    .as_deref()
                    .map(|p| p.parent().unwrap_or(p).to_path_buf());
            }
        }
        None
    }

    /// Whether the name is given by a read-only store, not by this one.
    pub async fn tag_is_read_only(&self, repository: &str, tag: &str) -> DbResult<bool> {
        if self.more.is_empty() {
            return Ok(false);
        }
        match self.get_image_by_tag_here(repository, tag).await {
            Ok(_) => return Ok(false),
            Err(DbError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        for db in self.more.iter() {
            if db.get_image_by_tag_here(repository, tag).await.is_ok() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Copy the records of an image of a read-only store into this store
    /// (the image, its layers and their order; not its tags nor its files,
    /// which stay where they are): what a container or a name of this store
    /// refers to must be here.  Nothing when this store has it already.
    pub async fn import_image(&self, id: &str) -> DbResult<bool> {
        let Some(owner) = self.image_owner(id).await? else {
            return Ok(false);
        };
        let mut tables = vec![
            ("images", owner.rows("images", "id", id.to_string()).await?),
            (
                "image_layers",
                owner
                    .rows("image_layers", "image_id", id.to_string())
                    .await?,
            ),
        ];
        let mut layers = Vec::new();
        for l in owner.get_image_layers_here(id).await? {
            layers.extend(owner.rows("layers", "id", l.key.to_string()).await?);
        }
        // the layers first: the order refers to them
        tables.insert(0, ("layers", layers));
        self.conn
            .call(move |conn| {
                // (a write transaction from the start: one that reads
                // first fails when another connection commits before its
                // first write)
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                for (table, rows) in tables {
                    // The columns of a database that is not ours are data:
                    // only those this table has are written, quoted.
                    let ours = columns_of(&tx, table)?;
                    for (names, values) in rows {
                        let (names, values): (Vec<String>, Vec<rusqlite::types::Value>) = names
                            .into_iter()
                            .zip(values)
                            .filter(|(n, _)| ours.contains(n))
                            .unzip();
                        let sql = format!(
                            "INSERT OR IGNORE INTO {} ({}) VALUES ({})",
                            quote(table),
                            names
                                .iter()
                                .map(|n| quote(n))
                                .collect::<Vec<_>>()
                                .join(", "),
                            vec!["?"; names.len()].join(", ")
                        );
                        tx.execute(&sql, rusqlite::params_from_iter(values))?;
                    }
                }
                tx.commit()?;
                Ok(())
            })
            .await?;
        tracing::info!("The records of the image {id} of a read-only store are copied");
        Ok(true)
    }

    /// The rows of `table` (a table of this module) whose `column` is
    /// `key`: their columns and values, whatever their order.
    async fn rows(
        &self,
        table: &'static str,
        column: &'static str,
        key: String,
    ) -> DbResult<Vec<(Vec<String>, Vec<rusqlite::types::Value>)>> {
        Ok(self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(&format!(
                    "SELECT * FROM {} WHERE {} = ?1",
                    quote(table),
                    quote(column)
                ))?;
                let names: Vec<String> =
                    stmt.column_names().iter().map(|n| n.to_string()).collect();
                let n = names.len();
                let rows = stmt
                    .query_map([key], |row| {
                        (0..n)
                            .map(|i| row.get::<_, rusqlite::types::Value>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows.into_iter().map(|v| (names.clone(), v)).collect())
            })
            .await?)
    }

    /// The layers of an image, from the store that has it.
    pub async fn get_image_layers(&self, image_id: &str) -> DbResult<Vec<LayerRecord>> {
        match self.image_owner(image_id).await? {
            Some(db) => db.get_image_layers_here(image_id).await,
            None => self.get_image_layers_here(image_id).await,
        }
    }

    /// The layers of an image without their tables of contents (`toc` is
    /// None): what a container needs when the image's own records of what
    /// it needs exist.
    pub async fn get_image_layers_without_toc(&self, image_id: &str) -> DbResult<Vec<LayerRecord>> {
        match self.image_owner(image_id).await? {
            Some(db) => db.image_layers_here(image_id, false).await,
            None => self.image_layers_here(image_id, false).await,
        }
    }

    /// The store that has the layer: this one first.
    async fn layer_owner(&self, digest: &LayerKey) -> DbResult<&Database> {
        let first = self.get_layer_here(digest).await;
        match first {
            Ok(_) => return Ok(self),
            Err(DbError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        for db in self.more.iter() {
            if db.get_layer_here(digest).await.is_ok() {
                return Ok(db);
            }
        }
        Ok(self)
    }

    pub async fn get_layer(&self, digest: &LayerKey) -> DbResult<LayerRecord> {
        self.layer_owner(digest).await?.get_layer_here(digest).await
    }

    pub async fn get_layer_tarsplit(&self, digest: &LayerKey) -> DbResult<Option<Vec<u8>>> {
        self.layer_owner(digest)
            .await?
            .get_layer_tarsplit_here(digest)
            .await
    }

    /// The objects of the files `ids` that are recorded, of this store, then
    /// of the read-only stores for those it has not got.
    pub async fn file_objects(&self, digests: Vec<String>) -> DbResult<HashMap<String, Object>> {
        let mut found = self.file_objects_here(digests.clone()).await?;
        for db in self.more.iter() {
            let missing: Vec<String> = digests
                .iter()
                .filter(|d| !found.contains_key(*d))
                .cloned()
                .collect();
            if missing.is_empty() {
                break;
            }
            if let Ok(more) = db.file_objects_here(missing).await {
                found.extend(more);
            }
        }
        Ok(found)
    }
}

/// An SQL identifier as one token, whatever characters it has.
fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn columns_of(conn: &rusqlite::Connection, table: &str) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT name FROM pragma_table_info(?1)")?;
    let names = stmt
        .query_map([table], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<String>>>()?;
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ImageTag;

    fn image(id: &str) -> ImageRecord {
        ImageRecord {
            id: id.into(),
            manifest_digest: Digest::of(
                velarx_types::digest::Algorithm::Sha256,
                format!("m{id}").as_bytes(),
            ),
            config_digest: Digest::of(
                velarx_types::digest::Algorithm::Sha256,
                format!("c{id}").as_bytes(),
            ),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            is_lazy: false,
        }
    }

    /// What the layer rows say of themselves, asked in batches that do not
    /// read the table of contents: only the layers of this store, with
    /// what each has.
    #[tokio::test]
    async fn layer_states_are_those_of_this_stores_rows() {
        use crate::{LayerCommit, LayerKey};
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path().join("main.sqlite"))
            .await
            .unwrap();
        let key = |n: u32| {
            LayerKey::Whole(Digest::of(
                velarx_types::digest::Algorithm::Sha256,
                n.to_string().as_bytes(),
            ))
        };
        let diff = |n: u32| {
            Digest::of(
                velarx_types::digest::Algorithm::Sha256,
                format!("diff{n}").as_bytes(),
            )
        };
        let commit = |n: u32, toc: Option<&str>, tarsplit: Option<&[u8]>| LayerCommit {
            record: LayerRecord {
                stream_size: Some(i64::from(n) * 10),
                key: key(n),
                blob: None,
                diff_id: Some(diff(n)),
                other_diff_id: None,
                size: 1,
                toc: toc.map(String::from),
                status: "ready".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                registry_ref: None,
                erofs: None,
                owners: None,
            },
            files: vec![],
            refs: vec![],
            chunks: vec![],
            tarsplit: tarsplit.map(<[u8]>::to_vec),
            blob_checked: false,
            kept_toc: None,
        };
        db.commit_layers(
            vec![
                commit(1, Some("{}"), Some(b"ts")),
                commit(2, Some("{}"), None),
                commit(3, None, Some(b"ts")),
            ],
            vec![],
            vec![],
        )
        .await
        .unwrap();
        // more keys than one query takes, most of them unknown
        let mut asked: Vec<LayerKey> = (1..=3).map(key).collect();
        asked.extend((100..1300).map(key));
        let mut states = db.get_own_layer_states(&asked).await.unwrap();
        states.sort_by_key(|s| s.key.to_string());
        assert_eq!(states.len(), 3, "only the layers that have a row");
        let by = |n: u32| states.iter().find(|s| s.key == key(n)).unwrap();
        assert!(by(1).has_tarsplit && by(1).has_toc && by(1).has_diff_id(&diff(1)));
        assert!(!by(2).has_tarsplit && by(2).has_toc);
        assert!(by(3).has_tarsplit && !by(3).has_toc);
        assert!(!by(1).has_diff_id(&diff(2)));
        // (the size of the tar is kept with the row)
        assert_eq!(db.get_layer(&key(1)).await.unwrap().stream_size, Some(10));
        assert_eq!(db.get_layer(&key(2)).await.unwrap().stream_size, Some(20));
        // (the table of contents is kept compressed and read back whole)
        assert_eq!(
            db.get_layer(&key(1)).await.unwrap().toc.as_deref(),
            Some("{}")
        );
        assert!(db.get_layer(&key(3)).await.unwrap().toc.is_none());
        assert!(db.get_own_layer_states(&[]).await.unwrap().is_empty());
        // a read-only store's layers are not this store's
        let ro_path = dir.path().join("ro.sqlite");
        {
            let ro = Database::open(&ro_path).await.unwrap();
            ro.commit_layers(vec![commit(9, Some("{}"), Some(b"ts"))], vec![], vec![])
                .await
                .unwrap();
            ro.checkpoint().await.unwrap();
        }
        let ro = Database::open_read_only(&ro_path).await.unwrap();
        let both = db.clone().with_additional(vec![ro]);
        assert!(both
            .get_own_layer_states(&[key(9)])
            .await
            .unwrap()
            .is_empty());
        assert_eq!(both.get_own_layer_states(&[key(1)]).await.unwrap().len(), 1);
    }

    /// An additional store is used only when it was made with the
    /// store's driver; one that records none was made with composefs.
    #[tokio::test]
    async fn an_additional_store_of_another_driver_is_not_used() {
        let dir = tempfile::tempdir().unwrap();
        let store = |name: &str| dir.path().join(name);
        for (name, driver) in [
            ("old", None),
            ("same", Some("composefs")),
            ("other", Some("vfs")),
        ] {
            std::fs::create_dir_all(store(name)).unwrap();
            let db = Database::open(store(name).join("db.sqlite")).await.unwrap();
            db.insert_image(&image(name)).await.unwrap();
            if let Some(d) = driver {
                db.store_setting("driver", d).await.unwrap();
            }
            db.checkpoint().await.unwrap();
        }
        let storage = |driver: Option<&str>| velarx_config::StorageConfig {
            root: store("main"),
            driver: driver.map(String::from),
            additional_image_stores: vec![store("old"), store("same"), store("other")],
            ..Default::default()
        };
        std::fs::create_dir_all(store("main")).unwrap();
        for asked in [None, Some("composefs")] {
            let db = Database::open_store(&storage(asked)).await.unwrap();
            assert!(db.get_image("old").await.is_ok(), "{asked:?}");
            assert!(db.get_image("same").await.is_ok(), "{asked:?}");
            assert!(db.get_image("other").await.is_err(), "{asked:?}");
            assert_eq!(db.recorded_driver().await.unwrap(), "composefs");
        }
        // (a store of the other driver uses the stores of that one)
        let db = Database::open_store(&storage(Some("vfs"))).await.unwrap();
        assert!(db.get_image("other").await.is_ok());
        assert!(db.get_image("same").await.is_err());
    }

    #[tokio::test]
    async fn lookups_go_through_and_nothing_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let ro_path = dir.path().join("ro.sqlite");
        {
            let ro = Database::open(&ro_path).await.unwrap();
            ro.insert_image(&image("aaa")).await.unwrap();
            ro.insert_image_tag(&ImageTag {
                repository: "example.com/ro".into(),
                tag: "1".into(),
                image_id: "aaa".into(),
            })
            .await
            .unwrap();
            ro.insert_image(&image("both")).await.unwrap();
            ro.checkpoint().await.unwrap();
        }
        let before = std::fs::read(&ro_path).unwrap();
        let main = Database::open(dir.path().join("main.sqlite"))
            .await
            .unwrap();
        main.insert_image(&image("both")).await.unwrap();
        main.insert_image(&image("bbb")).await.unwrap();
        let ro = Database::open_read_only(&ro_path).await.unwrap();
        let db = main.with_additional(vec![ro]);

        assert_eq!(db.get_image("aaa").await.unwrap().id, "aaa");
        assert_eq!(
            db.get_image_by_tag("example.com/ro", "1").await.unwrap().id,
            "aaa"
        );
        assert_eq!(db.get_tags_for_image("aaa").await.unwrap().len(), 1);
        assert!(db.image_is_read_only("aaa").await.unwrap());
        // the main store's own copy wins
        assert!(!db.image_is_read_only("both").await.unwrap());
        assert!(!db.image_is_read_only("bbb").await.unwrap());
        assert!(matches!(
            db.get_image("zzz").await,
            Err(DbError::NotFound(_))
        ));
        let mut ids: Vec<String> = db
            .list_images()
            .await
            .unwrap()
            .into_iter()
            .map(|i| i.id)
            .collect();
        ids.sort();
        assert_eq!(ids, ["aaa", "bbb", "both"]);
        // this store has not got it to remove; the read-only one keeps it
        assert!(matches!(
            db.delete_image("aaa").await,
            Err(DbError::NotFound(_))
        ));
        assert_eq!(db.get_image("aaa").await.unwrap().id, "aaa");
        drop(db);
        assert_eq!(std::fs::read(&ro_path).unwrap(), before);
    }

    const L1: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const D1: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    fn m(id: &str) -> Digest {
        Digest::of(
            velarx_types::digest::Algorithm::Sha256,
            format!("m{id}").as_bytes(),
        )
    }

    /// A tag or a container of this store copies the records of the
    /// image (not its tags) from the read-only store.
    #[tokio::test]
    async fn images_referred_to_are_imported() {
        let dir = tempfile::tempdir().unwrap();
        let ro_path = dir.path().join("ro.sqlite");
        {
            let ro = Database::open(&ro_path).await.unwrap();
            ro.insert_image(&image("aaa")).await.unwrap();
            ro.insert_layer(&LayerRecord {
                stream_size: Some(0),
                key: LayerKey::Whole(L1.parse().unwrap()),
                blob: Some(L1.parse().unwrap()),
                diff_id: Some(D1.parse().unwrap()),
                other_diff_id: None,
                size: 7,
                toc: Some("{}".into()),
                status: "ready".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                registry_ref: None,
                erofs: None,
                owners: None,
            })
            .await
            .unwrap();
            ro.insert_image_layer("aaa", &LayerKey::Whole(L1.parse().unwrap()), 0)
                .await
                .unwrap();
            ro.insert_image_tag(&ImageTag {
                repository: "example.com/ro".into(),
                tag: "1".into(),
                image_id: "aaa".into(),
            })
            .await
            .unwrap();
        }
        let main = Database::open(dir.path().join("main.sqlite"))
            .await
            .unwrap();
        let ro = Database::open_read_only(&ro_path).await.unwrap();
        let db = main.with_additional(vec![ro]);
        assert!(db.image_is_read_only("aaa").await.unwrap());
        db.insert_image_tag(&ImageTag {
            repository: "localhost/mine".into(),
            tag: "1".into(),
            image_id: "aaa".into(),
        })
        .await
        .unwrap();
        // this store has it now, with its layers; it is still of the
        // read-only store, whose name it keeps
        assert!(!db.image_is_read_only("aaa").await.unwrap());
        assert!(db.read_only_store_of("aaa").await.is_some());
        let layers = db.get_image_layers_here("aaa").await.unwrap();
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].diff_id, Some(D1.parse().unwrap()));
        let mut tags: Vec<String> = db
            .get_tags_for_image("aaa")
            .await
            .unwrap()
            .into_iter()
            .map(|t| format!("{}:{}", t.repository, t.tag))
            .collect();
        tags.sort();
        assert_eq!(tags, ["example.com/ro:1", "localhost/mine:1"]);
        assert!(db.tag_is_read_only("example.com/ro", "1").await.unwrap());
        assert!(!db.tag_is_read_only("localhost/mine", "1").await.unwrap());
        // again: nothing to do
        assert!(!db.import_image("aaa").await.unwrap());
    }

    /// The columns of a read-only store are its own: one named like SQL
    /// does not run, and the columns this schema lacks are not copied.
    #[tokio::test]
    async fn crafted_column_names_are_not_sql() {
        let dir = tempfile::tempdir().unwrap();
        let ro_path = dir.path().join("ro.sqlite");
        {
            let ro = Database::open(&ro_path).await.unwrap();
            ro.insert_image(&image("aaa")).await.unwrap();
            ro.conn()
                .call(|c| {
                    c.execute_batch(
                        "ALTER TABLE images ADD COLUMN \"x) VALUES (1); DROP TABLE image_tags; --\" TEXT DEFAULT 'y';",
                    )?;
                    Ok(())
                })
                .await
                .unwrap();
        }
        let main = Database::open(dir.path().join("main.sqlite"))
            .await
            .unwrap();
        let ro = Database::open_read_only(&ro_path).await.unwrap();
        let db = main.with_additional(vec![ro]);
        assert!(db.import_image("aaa").await.unwrap());
        assert_eq!(db.get_image_here("aaa").await.unwrap().id, "aaa");
        assert!(db.get_tags_for_image("aaa").await.unwrap().is_empty());
    }

    /// An image of a read-only store keeps its id when pulled again (a
    /// name of this store must name it).
    #[tokio::test]
    async fn the_id_of_an_image_of_a_read_only_store_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let ro_path = dir.path().join("ro.sqlite");
        {
            let ro = Database::open(&ro_path).await.unwrap();
            ro.insert_image(&image("aaa")).await.unwrap();
        }
        let main = Database::open(dir.path().join("main.sqlite"))
            .await
            .unwrap();
        let ro = Database::open_read_only(&ro_path).await.unwrap();
        let db = main.with_additional(vec![ro]);
        assert_eq!(db.image_id_for(&m("aaa"), &m("aaa")).await.unwrap(), "aaa");
        assert_eq!(
            db.image_id_for(&m("bbb"), &m("bbb")).await.unwrap(),
            m("bbb").hex()
        );
        db.insert_image_tag(&ImageTag {
            repository: "example.com/ro".into(),
            tag: "1".into(),
            image_id: db.image_id_for(&m("aaa"), &m("aaa")).await.unwrap(),
        })
        .await
        .unwrap();
        assert_eq!(
            db.get_image_by_tag("example.com/ro", "1").await.unwrap().id,
            "aaa"
        );
    }

    /// Opening a store makes no file next to it, also where the process may
    /// write (the root of a user namespace does), and a database that has
    /// changes outside its main file is refused.
    #[tokio::test]
    async fn a_store_is_opened_without_a_file_next_to_it() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("store");
        std::fs::create_dir(&sub).unwrap();
        let path = sub.join("db.sqlite");
        {
            let owner = Database::open(&path).await.unwrap();
            owner.insert_image(&image("aaa")).await.unwrap();
            owner.checkpoint().await.unwrap();
        }
        let names = || {
            let mut n: Vec<_> = std::fs::read_dir(&sub)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            n.sort();
            n
        };
        let before = names();
        let ro = Database::open_read_only(&path).await.unwrap();
        assert_eq!(ro.get_image("aaa").await.unwrap().id, "aaa");
        assert_eq!(ro.list_images().await.unwrap().len(), 1);
        drop(ro);
        // (the owner may still be removing its own files as it closes)
        let after = names();
        assert!(after.iter().all(|n| before.contains(n)), "{after:?}");
        assert!(!after.iter().any(|n| n.to_string_lossy().ends_with("-shm")));

        // The owner has it open with changes in the WAL.
        let owner = Database::open(&path).await.unwrap();
        owner.insert_image(&image("bbb")).await.unwrap();
        let e = Database::open_read_only(&path).await.err().unwrap();
        assert!(e.to_string().contains("write-ahead log"), "{e}");
        assert!(e.to_string().contains("velarx varlink"), "{e}");
        owner.checkpoint().await.unwrap();
        assert!(Database::open_read_only(&path).await.is_ok());
    }

    #[test]
    fn identifiers_are_quoted() {
        assert_eq!(quote("images"), "\"images\"");
        assert_eq!(quote("a\"b"), "\"a\"\"b\"");
    }

    #[tokio::test]
    async fn a_store_of_another_schema_version_or_none_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Database::open_read_only(&dir.path().join("none.sqlite"))
            .await
            .is_err());
        let p = dir.path().join("other.sqlite");
        {
            let db = Database::open(&p).await.unwrap();
            db.conn()
                .call(|c| Ok(c.execute_batch("PRAGMA user_version = 99;")?))
                .await
                .unwrap();
            db.checkpoint().await.unwrap();
        }
        let e = Database::open_read_only(&p)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("schema version 99"), "{e}");
    }

    #[test]
    fn uri_paths_are_escaped() {
        assert_eq!(uri_path(Path::new("/a?b#c%d")), "/a%3fb%23c%25d");
    }
}
