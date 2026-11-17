// SPDX-License-Identifier: Apache-2.0
//! The rows of the named volumes (`volumes`): the SQL of the volume service
//! and of whoever removes the anonymous volumes of a container.

/// The columns of `volumes`, in the order [`VolumeRow::from_row`] reads.
pub const COLUMNS: &str = "name, driver, mountpoint, labels, options, created_at, scope, state";

/// A row of `volumes` as it is stored: JSON texts are not decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeRow {
    pub name: String,
    /// JSON
    pub driver: String,
    pub mountpoint: String,
    /// JSON
    pub labels: String,
    /// JSON
    pub options: String,
    pub created_at: String,
    pub scope: String,
    /// JSON, when there is some
    pub state: Option<String>,
}

impl VolumeRow {
    /// The row of a query of [`COLUMNS`].
    pub fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            name: row.get(0)?,
            driver: row.get(1)?,
            mountpoint: row.get(2)?,
            labels: row.get(3)?,
            options: row.get(4)?,
            created_at: row.get(5)?,
            scope: row.get(6)?,
            state: row.get(7)?,
        })
    }

    /// Whether the volume was made for one container (a mount with no
    /// name): its state says `anonymous`.
    pub fn anonymous(&self) -> bool {
        self.state
            .as_deref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
            .and_then(|v| v.get("anonymous")?.as_bool())
            .unwrap_or(false)
    }
}

/// The volume `name`; `QueryReturnedNoRows` when there is none.
pub fn get(
    conn: &mut rusqlite::Connection,
    name: &str,
) -> Result<VolumeRow, tokio_rusqlite::Error> {
    let mut stmt = conn.prepare(&format!("SELECT {COLUMNS} FROM volumes WHERE name = ?1"))?;
    Ok(stmt.query_row([name], VolumeRow::from_row)?)
}

/// Every volume.
pub fn list(conn: &mut rusqlite::Connection) -> Result<Vec<VolumeRow>, tokio_rusqlite::Error> {
    let mut stmt = conn.prepare(&format!("SELECT {COLUMNS} FROM volumes"))?;
    let rows = stmt
        .query_map([], VolumeRow::from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Forget the volume `name` (its data is not touched).
pub fn delete(conn: &mut rusqlite::Connection, name: &str) -> Result<(), tokio_rusqlite::Error> {
    conn.execute("DELETE FROM volumes WHERE name = ?1", [name])?;
    Ok(())
}
