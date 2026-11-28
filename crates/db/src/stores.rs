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

use super::{
    layer_files, Database, ImageRecord, ImageTag, InlinedFile, LayerRecord, LayerState,
    SCHEMA_VERSION,
};
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

/// What the database at `path` has outside its main file: a `-wal` or a
/// `-journal` with content, named for a message.
fn side_file(path: &Path) -> Option<&'static str> {
    [("-wal", "a write-ahead log"), ("-journal", "a journal")]
        .into_iter()
        .find(|(suffix, _)| {
            let mut side = path.as_os_str().to_os_string();
            side.push(suffix);
            std::fs::metadata(side).is_ok_and(|m| m.len() > 0)
        })
        .map(|(_, what)| what)
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
        if let Some(what) = side_file(path) {
            return Err(other(format!(
                "{}: has {what} with changes that are not in the database file \
                 (a velarx runs on the store, or one ended and left its log): \
                 once none runs on it, its owner runs a command that writes \
                 nothing on it, such as `velarx image list`",
                path.display()
            )));
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
            files: layer_files::of_directory(path.parent()),
            path: Some(Arc::new(path.to_path_buf())),
            more: Arc::new(Vec::new()),
        })
    }

    /// The database of the store `storage`, with those of its additional
    /// image stores under it.  An additional store that is busy (its
    /// database has a write-ahead log or a journal: another velarx runs on
    /// it, or one ended and left it) is skipped with a warning; one that
    /// cannot be used otherwise (absent, of another schema version, or
    /// made with another storage driver than composefs, the only one
    /// whose content this velarx reads) fails the open and the error
    /// names it.
    pub async fn open_store(storage: &velarx_config::StorageConfig) -> DbResult<Self> {
        let main = Database::open(storage.database_path()).await?;
        let own = std::fs::canonicalize(&storage.root).ok();
        let mut more = Vec::new();
        for root in &storage.additional_image_stores {
            if own.is_some() && std::fs::canonicalize(root).ok() == own {
                tracing::warn!(
                    "The additional image store {} is the store itself: not used",
                    root.display()
                );
                continue;
            }
            if let Some(what) = side_file(&root.join("db.sqlite")) {
                tracing::warn!(
                    "additional image store {} is not used: it has {what} (another \
                     velarx is running on it, or one ended and left its log: once \
                     none runs on it, its owner runs a command that writes nothing \
                     on it, such as `velarx image list`)",
                    root.display()
                );
                continue;
            }
            let refuse = |cause: String| {
                other(format!(
                    "additional image store {}: {cause} (to start without it, \
                     remove it from [storage] additional_image_stores)",
                    root.display()
                ))
            };
            let db = Database::open_read_only(&root.join("db.sqlite"))
                .await
                .map_err(|e| refuse(e.to_string()))?;
            let theirs = db
                .recorded_driver()
                .await
                .map_err(|e| refuse(e.to_string()))?;
            if theirs != velarx_config::STORAGE_DRIVER {
                return Err(refuse(format!(
                    "it was made with the storage driver {theirs:?}; this velarx \
                     reads composefs stores only"
                )));
            }
            more.push(db);
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
        Ok(recorded.unwrap_or_else(|| velarx_config::STORAGE_DRIVER.to_string()))
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

    /// The compressed table of contents of the layer, checked against its
    /// digest (none if the layer keeps none): for a layer of a TOC, the
    /// table as the registry sent it.
    pub async fn get_layer_toc_z(&self, digest: &LayerKey) -> DbResult<Option<Vec<u8>>> {
        self.layer_owner(digest)
            .await?
            .get_layer_toc_z_here(digest)
            .await
    }

    /// The compressed tar-split of the layer, checked against its digest:
    /// none while the layer is not complete, empty for a layer that has none.
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

    /// Whether an image of this store or of a read-only one holds any file
    /// itself: when none does, [`Self::inlined_file`] has nothing to find.
    pub async fn has_inlined_files(&self) -> DbResult<bool> {
        if self.has_inlined_files_here().await? {
            return Ok(true);
        }
        for db in self.more.iter() {
            if db.has_inlined_files_here().await.unwrap_or(false) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Where the content of the file `digest` is when no object of the
    /// stores has it: the layer whose EROFS image holds it and the extent,
    /// from this store, then the read-only ones.  (An object, which
    /// [`Self::file_objects`] answers, is the other place a file is.)
    pub async fn inlined_file(&self, digest: &str) -> DbResult<Option<(LayerKey, InlinedFile)>> {
        if let Some(found) = self.inlined_file_here(digest).await? {
            return Ok(Some(found));
        }
        for db in self.more.iter() {
            if let Ok(Some(found)) = db.inlined_file_here(digest).await {
                return Ok(Some(found));
            }
        }
        Ok(None)
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
    use crate::layer_files;
    use crate::ImageTag;
    use crate::InlinedFile;

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
        let sha = |b: &[u8]| Digest::of(velarx_types::digest::Algorithm::Sha256, b);
        // (the files of a layer are written first, as a pull does)
        let commit = |n: u32, toc: &[u8], tarsplit: &[u8]| {
            let root = dir.path();
            for (name, bytes) in [(layer_files::TOC, toc), (layer_files::TARSPLIT, tarsplit)] {
                layer_files::write(root, &key(n), name, bytes).unwrap();
            }
            LayerCommit {
                record: LayerRecord {
                    stream_size: Some(i64::from(n) * 10),
                    inline: 0,
                    key: key(n),
                    blob: None,
                    diff_id: Some(diff(n)),
                    other_diff_id: None,
                    size: 1,
                    status: "ready".into(),
                    created_at: "2026-01-01T00:00:00Z".into(),
                    registry_ref: Some("example.com/image:1".into()),
                    erofs: None,
                    owners: None,
                },
                files: vec![],
                refs: vec![],
                chunks: vec![],
                toc_digest: sha(toc),
                tarsplit: Some(sha(tarsplit)),
                blob_checked: false,
                sealed: false,
                inlined: Vec::new(),
            }
        };
        db.commit_layers(
            vec![commit(1, b"table", b"ts"), commit(2, b"table", b"ts")],
            vec![],
        )
        .await
        .unwrap();
        // (2 lost its tar-split, 3 has no files at all)
        db.mark_layer_incomplete(&key(2)).await.unwrap();
        let mut third = commit(3, b"", b"").record;
        third.registry_ref = None;
        third.blob = Some(diff(3));
        db.insert_layer(&third).await.unwrap();
        // more keys than one query takes, most of them unknown
        let mut asked: Vec<LayerKey> = (1..=3).map(key).collect();
        asked.extend((100..1300).map(key));
        let mut states = db.get_own_layer_states(&asked).await.unwrap();
        states.sort_by_key(|s| s.key.to_string());
        assert_eq!(states.len(), 3, "only the layers that have a row");
        let by = |n: u32| states.iter().find(|s| s.key == key(n)).unwrap();
        assert!(by(1).has_tarsplit && by(1).has_toc && by(1).has_diff_id(&diff(1)));
        assert!(!by(2).has_tarsplit && by(2).has_toc);
        assert!(!by(3).has_tarsplit && !by(3).has_toc);
        assert!(!by(1).has_diff_id(&diff(2)));
        // (the size of the tar is kept with the row)
        assert_eq!(db.get_layer(&key(1)).await.unwrap().stream_size, Some(10));
        assert_eq!(db.get_layer(&key(2)).await.unwrap().stream_size, Some(20));
        // (the files are read back whole, once their digests are checked)
        assert_eq!(
            db.get_layer_toc_z(&key(1)).await.unwrap().as_deref(),
            Some(&b"table"[..])
        );
        assert!(db.get_layer_toc_z(&key(3)).await.unwrap().is_none());
        assert_eq!(
            db.get_layer_tarsplit(&key(1)).await.unwrap().as_deref(),
            Some(&b"ts"[..])
        );
        assert!(db.get_layer_tarsplit(&key(2)).await.unwrap().is_none());
        // a file that is not the one the row names is refused
        for (kind, bytes) in [
            (layer_files::TOC, &b"table"[..]),
            (layer_files::TARSPLIT, b"ts"),
        ] {
            let path = layer_files::file(dir.path(), &key(1), kind, &sha(bytes));
            std::fs::write(path, b"other").unwrap();
        }
        assert!(db.get_layer_toc_z(&key(1)).await.is_err());
        assert!(db.get_layer_tarsplit(&key(1)).await.is_err());
        assert!(db.get_own_layer_states(&[]).await.unwrap().is_empty());
        // a read-only store's layers are not this store's
        let ro_path = dir.path().join("ro.sqlite");
        {
            let ro = Database::open(&ro_path).await.unwrap();
            ro.commit_layers(vec![commit(9, b"table", b"ts")], vec![])
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

    /// An additional store is used only when it was made with composefs
    /// (one that records no driver was); any other fails the open, as does
    /// one that cannot be opened, and the error names it.  A busy one is
    /// skipped and the others are still used.
    #[tokio::test]
    async fn an_unusable_additional_store_is_refused_a_busy_one_skipped() {
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
        std::fs::create_dir_all(store("main")).unwrap();
        let storage = |stores: &[&str]| velarx_config::StorageConfig {
            root: store("main"),
            additional_image_stores: stores.iter().map(|n| store(n)).collect(),
            ..Default::default()
        };
        let db = Database::open_store(&storage(&["old", "same"]))
            .await
            .unwrap();
        assert!(db.get_image("old").await.is_ok());
        assert!(db.get_image("same").await.is_ok());
        let e = Database::open_store(&storage(&["same", "other"]))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("other") && e.contains("\"vfs\""), "{e}");
        assert!(
            e.contains("remove it from [storage] additional_image_stores"),
            "{e}"
        );
        let e = Database::open_store(&storage(&["nowhere"]))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("nowhere"), "{e}");
        // A busy store (its owner has changes in the log) is skipped.
        let owner = Database::open(store("same").join("db.sqlite"))
            .await
            .unwrap();
        owner.insert_image(&image("late")).await.unwrap();
        let db = Database::open_store(&storage(&["same", "old"]))
            .await
            .unwrap();
        assert!(db.get_image("same").await.is_err());
        assert!(db.get_image("late").await.is_err());
        assert!(db.get_image("old").await.is_ok());
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

    /// What an image of a read-only store holds itself is found through this
    /// store, after what its own images hold.
    #[tokio::test]
    async fn the_files_images_hold_are_found_in_read_only_stores_too() {
        use crate::LayerCommit;
        let dir = tempfile::tempdir().unwrap();
        let sha = |b: &[u8]| Digest::of(velarx_types::digest::Algorithm::Sha256, b);
        let file = |d: &[u8], offset| InlinedFile {
            digest: format!("fsverity-sha256-12:{}", sha(d).hex()),
            offset,
            size: 3,
        };
        let commit = |key: LayerKey, files: Vec<InlinedFile>| LayerCommit {
            record: LayerRecord {
                stream_size: Some(0),
                inline: -1,
                key,
                blob: None,
                diff_id: Some(sha(b"diff")),
                other_diff_id: None,
                size: 1,
                status: "ready".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                registry_ref: None,
                erofs: Some("sha256:a".into()),
                owners: Some("[]".into()),
            },
            files: vec![],
            refs: vec![],
            chunks: vec![],
            toc_digest: sha(b"toc"),
            tarsplit: None,
            blob_checked: false,
            sealed: false,
            inlined: files,
        };
        let (own, theirs) = (
            LayerKey::Whole(sha(b"own")),
            LayerKey::Whole(sha(b"theirs")),
        );
        let ro_path = dir.path().join("ro.sqlite");
        {
            let ro = Database::open(&ro_path).await.unwrap();
            ro.commit_layers(
                vec![commit(theirs, vec![file(b"a", 8), file(b"b", 16)])],
                vec![],
            )
            .await
            .unwrap();
            ro.checkpoint().await.unwrap();
        }
        let main = Database::open(dir.path().join("main.sqlite"))
            .await
            .unwrap();
        assert!(!main.has_inlined_files().await.unwrap());
        main.commit_layers(vec![commit(own, vec![file(b"a", 0)])], vec![])
            .await
            .unwrap();
        let db = main.with_additional(vec![Database::open_read_only(&ro_path).await.unwrap()]);
        let (layer, f) = db
            .inlined_file(&file(b"a", 0).digest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((layer, f.offset), (own, 0));
        let (layer, f) = db
            .inlined_file(&file(b"b", 0).digest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((layer, f.offset), (theirs, 16));
        assert!(db
            .inlined_file(&file(b"c", 0).digest)
            .await
            .unwrap()
            .is_none());
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
                inline: 0,
                key: LayerKey::Whole(L1.parse().unwrap()),
                blob: Some(L1.parse().unwrap()),
                diff_id: Some(D1.parse().unwrap()),
                other_diff_id: None,
                size: 7,
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
        assert!(e.to_string().contains("its owner runs a command"), "{e}");
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
