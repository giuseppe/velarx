// SPDX-License-Identifier: Apache-2.0
//! Manifest lists (image indexes) made locally: `podman manifest create`.
//! A list has an id like an image, its index as it is pushed, and names
//! that images do not have at the same time (a name is one or the other).

use super::Database;
use velarx_types::{DbError, DbResult};

pub(super) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS manifest_lists (
    id TEXT PRIMARY KEY,
    manifest TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS manifest_list_names (
    repository TEXT NOT NULL,
    tag TEXT NOT NULL,
    list_id TEXT NOT NULL REFERENCES manifest_lists(id) ON DELETE CASCADE,
    PRIMARY KEY (repository, tag)
);

CREATE INDEX IF NOT EXISTS idx_manifest_list_names_list ON manifest_list_names(list_id);
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestListRecord {
    /// 64 hexadecimal digits.
    pub id: String,
    /// The index (OCI image index JSON).
    pub manifest: String,
    pub created_at: String,
    /// `(repository, tag)`.
    pub names: Vec<(String, String)>,
}

fn names_of(conn: &rusqlite::Connection, id: &str) -> rusqlite::Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare_cached(
        "SELECT repository, tag FROM manifest_list_names WHERE list_id = ?1 ORDER BY repository, tag",
    )?;
    let rows = stmt.query_map([id], |r| Ok((r.get(0)?, r.get(1)?)))?;
    rows.collect()
}

fn record(
    conn: &rusqlite::Connection,
    row: (String, String, String),
) -> rusqlite::Result<ManifestListRecord> {
    let names = names_of(conn, &row.0)?;
    Ok(ManifestListRecord {
        id: row.0,
        manifest: row.1,
        created_at: row.2,
        names,
    })
}

impl Database {
    /// Record a new list named `(repository, tag)`; the name is taken from
    /// the image that had it.
    pub async fn create_manifest_list(&self, list: &ManifestListRecord) -> DbResult<()> {
        let list = list.clone();
        self.conn
            .call(move |conn| {
                let tx = conn.transaction()?;
                tx.execute(
                    "INSERT INTO manifest_lists (id, manifest, created_at) VALUES (?1, ?2, ?3)",
                    rusqlite::params![list.id, list.manifest, list.created_at],
                )?;
                for (repository, tag) in &list.names {
                    tx.execute(
                        "DELETE FROM image_tags WHERE repository = ?1 AND tag = ?2",
                        rusqlite::params![repository, tag],
                    )?;
                    tx.execute(
                        "INSERT OR REPLACE INTO manifest_list_names (repository, tag, list_id) VALUES (?1, ?2, ?3)",
                        rusqlite::params![repository, tag, list.id],
                    )?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// Replace the index of a list by `manifest` if it is still `expected`:
    /// false when it is not (changed since it was read).  Not found when the
    /// list is gone.
    pub async fn swap_manifest_list(
        &self,
        id: &str,
        expected: &str,
        manifest: &str,
    ) -> DbResult<bool> {
        let (owned, expected, manifest) =
            (id.to_string(), expected.to_string(), manifest.to_string());
        let (swapped, there) = self
            .conn
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let n = tx.execute(
                    "UPDATE manifest_lists SET manifest = ?1 WHERE id = ?2 AND manifest = ?3",
                    rusqlite::params![manifest, owned, expected],
                )?;
                let there = n > 0
                    || tx
                        .query_row(
                            "SELECT 1 FROM manifest_lists WHERE id = ?1",
                            [&owned],
                            |_| Ok(()),
                        )
                        .is_ok();
                tx.commit()?;
                Ok((n > 0, there))
            })
            .await
            .map_err(DbError::Sqlite)?;
        if !there {
            return Err(DbError::NotFound(format!("manifest list {id}")));
        }
        Ok(swapped)
    }

    /// Give a list a name (taken from the image or list that had it).
    pub async fn name_manifest_list(&self, id: &str, repository: &str, tag: &str) -> DbResult<()> {
        let (id, repository, tag) = (id.to_string(), repository.to_string(), tag.to_string());
        self.conn
            .call(move |conn| {
                let tx = conn.transaction()?;
                tx.execute(
                    "DELETE FROM image_tags WHERE repository = ?1 AND tag = ?2",
                    rusqlite::params![repository, tag],
                )?;
                tx.execute(
                    "INSERT OR REPLACE INTO manifest_list_names (repository, tag, list_id) VALUES (?1, ?2, ?3)",
                    rusqlite::params![repository, tag, id],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn remove_manifest_list(&self, id: &str) -> DbResult<()> {
        let owned = id.to_string();
        let n = self
            .conn
            .call(move |conn| {
                let tx = conn.transaction()?;
                tx.execute(
                    "DELETE FROM manifest_list_names WHERE list_id = ?1",
                    [&owned],
                )?;
                let n = tx.execute("DELETE FROM manifest_lists WHERE id = ?1", [&owned])?;
                tx.commit()?;
                Ok(n)
            })
            .await
            .map_err(DbError::Sqlite)?;
        if n == 0 {
            return Err(DbError::NotFound(format!("manifest list {id}")));
        }
        Ok(())
    }

    /// The list of this id, of the only id this prefix starts (at least
    /// three digits), or of this name.
    pub async fn find_manifest_list(
        &self,
        id_or_prefix: Option<&str>,
        name: Option<(&str, &str)>,
    ) -> DbResult<Option<ManifestListRecord>> {
        let prefix = id_or_prefix
            .filter(|p| p.len() >= 3 && p.len() <= 64 && p.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(|p| p.to_ascii_lowercase());
        let name = name.map(|(r, t)| (r.to_string(), t.to_string()));
        self.conn
            .call(move |conn| {
                if let Some(p) = prefix {
                    let mut stmt = conn.prepare_cached(
                        "SELECT id, manifest, created_at FROM manifest_lists WHERE id >= ?1 AND id < ?1 || 'g' LIMIT 2",
                    )?;
                    let rows: Vec<(String, String, String)> = stmt
                        .query_map([&p], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                        .collect::<Result<_, _>>()?;
                    if rows.len() == 1 {
                        let row = rows.into_iter().next().ok_or(rusqlite::Error::QueryReturnedNoRows)?;
                        return Ok(Some(record(conn, row)?));
                    }
                }
                if let Some((repository, tag)) = name {
                    let row = conn.query_row(
                        "SELECT l.id, l.manifest, l.created_at FROM manifest_lists l
                         JOIN manifest_list_names n ON n.list_id = l.id
                         WHERE n.repository = ?1 AND n.tag = ?2",
                        rusqlite::params![repository, tag],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    );
                    match row {
                        Ok(row) => return Ok(Some(record(conn, row)?)),
                        Err(rusqlite::Error::QueryReturnedNoRows) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                Ok(None)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn list_manifest_lists(&self) -> DbResult<Vec<ManifestListRecord>> {
        self.conn
            .call(|conn| {
                let rows: Vec<(String, String, String)> = {
                    let mut stmt = conn.prepare(
                        "SELECT id, manifest, created_at FROM manifest_lists ORDER BY created_at DESC",
                    )?;
                    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
                    rows.collect::<Result<_, _>>()?
                };
                rows.into_iter()
                    .map(|row| record(conn, row).map_err(Into::into))
                    .collect()
            })
            .await
            .map_err(DbError::Sqlite)
    }
}
