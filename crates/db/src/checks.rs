// SPDX-License-Identifier: Apache-2.0
//! When each image was last checked by `system check`.

use super::Database;
use std::collections::HashMap;
use velarx_types::{DbError, DbResult};

pub(super) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS image_checks (
    image_id TEXT PRIMARY KEY REFERENCES images(id) ON DELETE CASCADE,
    checked_at INTEGER NOT NULL,
    full INTEGER NOT NULL
);
"#;

impl Database {
    /// The time (seconds since the epoch) each image was last checked.
    pub async fn image_check_times(&self) -> DbResult<HashMap<String, i64>> {
        self.conn
            .call(|conn| {
                let mut stmt = conn.prepare("SELECT image_id, checked_at FROM image_checks")?;
                let rows = stmt
                    .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
                    .collect::<Result<_, _>>()?;
                Ok(rows)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// Record that the image was checked at `at`, with the checks of the
    /// content (`full`) or without.
    pub async fn set_image_checked(&self, image_id: &str, at: i64, full: bool) -> DbResult<()> {
        let id = image_id.to_string();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO image_checks (image_id, checked_at, full)
                     SELECT id, ?2, ?3 FROM images WHERE id = ?1",
                    rusqlite::params![id, at, full],
                )?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)
    }
}
