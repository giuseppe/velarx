// SPDX-License-Identifier: Apache-2.0
//! The cache of the builds: the image a step made on top of an image (its
//! parent), by the key of the step (what it ran or copied, the settings
//! that went into the commit).  A step with the same key on the same
//! parent reuses the image (the latest one if several were made, by
//! `--no-cache` builds).  The images that are parents of others are the
//! intermediate images of the builds.

use super::Database;
use velarx_types::{DbError, DbResult};

pub(super) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS build_cache (
    image_id TEXT PRIMARY KEY REFERENCES images(id) ON DELETE CASCADE,
    parent TEXT NOT NULL,
    key TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_build_cache_step ON build_cache(parent, key);
"#;

/// The parent of an image built from scratch.
pub const SCRATCH: &str = "scratch";

impl Database {
    /// The image a step of key `key` made on `parent`.
    pub async fn build_cache_get(&self, parent: &str, key: &str) -> DbResult<Option<String>> {
        let (parent, key) = (parent.to_string(), key.to_string());
        self.conn
            .call(move |conn| {
                match conn.query_row(
                    "SELECT image_id FROM build_cache WHERE parent = ?1 AND key = ?2
                     ORDER BY rowid DESC LIMIT 1",
                    rusqlite::params![parent, key],
                    |r| r.get(0),
                ) {
                    Ok(id) => Ok(Some(id)),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// Record the image a step made.
    pub async fn build_cache_put(&self, parent: &str, key: &str, image_id: &str) -> DbResult<()> {
        let (parent, key, image_id) = (parent.to_string(), key.to_string(), image_id.to_string());
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO build_cache (image_id, parent, key) VALUES (?3, ?1, ?2)",
                    rusqlite::params![parent, key, image_id],
                )?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// The image each image a build made was built on ([`SCRATCH`] for the
    /// ones built from scratch).
    pub async fn build_lineage(&self) -> DbResult<std::collections::HashMap<String, String>> {
        self.conn
            .call(|conn| {
                let mut stmt = conn.prepare("SELECT image_id, parent FROM build_cache")?;
                let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
                Ok(rows.collect::<Result<_, _>>()?)
            })
            .await
            .map_err(DbError::Sqlite)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cache_entries_go_with_their_image() {
        let db = Database::open_in_memory().await.unwrap();
        for id in ["p", "c", "d"] {
            db.conn
                .call(move |conn| {
                    conn.execute(
                        "INSERT INTO images (id, manifest_digest, config_digest, manifest, config, created_at)
                         VALUES (?1, ?1, ?1, '{}', '{}', '')",
                        [id],
                    )?;
                    Ok(())
                })
                .await
                .unwrap();
        }
        let get = |k: &'static str| {
            let db = db.clone();
            async move { db.build_cache_get("p", k).await.unwrap() }
        };
        db.build_cache_put(SCRATCH, "k0", "p").await.unwrap();
        db.build_cache_put("p", "k", "c").await.unwrap();
        assert_eq!(get("k").await.as_deref(), Some("c"));
        assert_eq!(get("other").await, None);
        // The latest image of a step is taken, the earlier one stays.
        db.build_cache_put("p", "k", "d").await.unwrap();
        assert_eq!(get("k").await.as_deref(), Some("d"));
        let lineage = db.build_lineage().await.unwrap();
        assert_eq!(lineage.len(), 3);
        assert_eq!(
            (lineage["c"].as_str(), lineage["p"].as_str()),
            ("p", SCRATCH)
        );
        db.delete_image("d").await.unwrap();
        assert_eq!(get("k").await.as_deref(), Some("c"));
        db.delete_image("c").await.unwrap();
        assert_eq!(get("k").await, None);
        assert_eq!(db.build_lineage().await.unwrap().len(), 1);
    }
}
