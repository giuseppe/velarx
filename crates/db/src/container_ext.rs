// SPDX-License-Identifier: Apache-2.0
//! What the monitor and the daemon learn about a container while it runs and
//! that the record does not hold: out of memory kills, restarts, health.

use super::{volatile, Database};
use velarx_types::{DbError, DbResult, LayerKey};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS container_layers (
    container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
    layer_id TEXT NOT NULL,
    PRIMARY KEY (container_id, layer_id)
);
CREATE INDEX IF NOT EXISTS idx_container_layers_layer ON container_layers(layer_id);

CREATE TABLE IF NOT EXISTS container_ext (
    container_id TEXT PRIMARY KEY REFERENCES containers(id) ON DELETE CASCADE,
    oom_killed INTEGER NOT NULL DEFAULT 0,
    restart_count INTEGER NOT NULL DEFAULT 0,
    health TEXT,
    timed_out INTEGER NOT NULL DEFAULT 0,
    stopped_by_user INTEGER NOT NULL DEFAULT 0,
    pause_lease_until INTEGER
);
";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerExt {
    /// The kernel killed a process of the container for lack of memory
    pub oom_killed: bool,
    /// How many times the restart policy started it again
    pub restart_count: u32,
    /// The state of the health checks, as JSON
    pub health: Option<String>,
    /// The last run was killed at the end of its time limit (`--timeout`)
    pub timed_out: bool,
    /// A user stopped it (stop, kill, rm -f): an `unless-stopped` container
    /// is not started at boot
    pub stopped_by_user: bool,
}

impl Database {
    /// Record the layers a container uses (its image's, and those of the
    /// images it mounts): they stay while the container does, whatever
    /// becomes of the images.
    pub async fn set_container_layers(&self, id: &str, layers: Vec<LayerKey>) -> DbResult<()> {
        let id = id.to_string();
        self.conn
            .call(move |conn| {
                let volatile = volatile::container(conn, &id);
                volatile::run(conn, volatile, |conn| {
                    let tx = conn.transaction()?;
                    tx.execute(
                        "DELETE FROM container_layers WHERE container_id = ?1",
                        [&id],
                    )?;
                    for l in &layers {
                        tx.execute(
                            "INSERT OR IGNORE INTO container_layers (container_id, layer_id)
                             VALUES (?1, ?2)",
                            [&id, &l.to_string()],
                        )?;
                    }
                    tx.commit()?;
                    Ok(())
                })
            })
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn container_layers(&self, id: &str) -> DbResult<Vec<LayerKey>> {
        let id = id.to_string();
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT layer_id FROM container_layers WHERE container_id = ?1
                     ORDER BY layer_id",
                )?;
                let v = stmt
                    .query_map([&id], |row| row.get(0))?
                    .collect::<Result<Vec<LayerKey>, _>>()?;
                Ok(v)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn get_container_ext(&self, id: &str) -> DbResult<ContainerExt> {
        let id = id.to_string();
        self.conn
            .call(move |conn| get_container_ext(conn, &id))
            .await
            .map_err(DbError::Sqlite)
    }

    /// What [`Self::get_container_ext`] gives for each of `ids`, in one query
    /// for every 500 ids; a container with no row has none here (its
    /// default is what the single call gives).
    pub async fn get_container_exts(
        &self,
        ids: &[String],
    ) -> DbResult<std::collections::HashMap<String, ContainerExt>> {
        let ids = ids.to_vec();
        self.conn
            .call(move |conn| get_container_exts(conn, &ids))
            .await
            .map_err(DbError::Sqlite)
    }

    /// The lease of the pause of a container: when (milliseconds since the
    /// epoch) the engine unpauses it unless somebody did before; `None`
    /// when there is none.  It is a column of its own, which
    /// [`Database::set_container_ext`] does not write, so that the updates
    /// of the other fields never undo it.
    pub async fn pause_lease(&self, id: &str) -> DbResult<Option<i64>> {
        let id = id.to_string();
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT pause_lease_until FROM container_ext WHERE container_id = ?1",
                )?;
                let mut rows = stmt.query([&id])?;
                Ok(match rows.next()? {
                    Some(row) => row.get(0)?,
                    None => None,
                })
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// Record (or with `None` remove) the lease of the pause of `id`.
    pub async fn set_pause_lease(&self, id: &str, until: Option<i64>) -> DbResult<()> {
        let id = id.to_string();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO container_ext (container_id, pause_lease_until)
                     SELECT ?1, ?2 WHERE EXISTS (SELECT 1 FROM containers WHERE id = ?1)
                     ON CONFLICT(container_id) DO UPDATE SET
                         pause_lease_until = excluded.pause_lease_until",
                    rusqlite::params![id, until],
                )?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// The containers that have a lease, and when it ends.
    pub async fn pause_leases(&self) -> DbResult<Vec<(String, i64)>> {
        self.conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT container_id, pause_lease_until FROM container_ext
                     WHERE pause_lease_until IS NOT NULL",
                )?;
                let v = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(v)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// Change the extra state of a container: read, changed by `f` and
    /// written in one write transaction, so that the changes of several
    /// processes at once all stay.  Nothing is stored for a container that
    /// is gone.
    pub async fn update_container_ext(
        &self,
        id: &str,
        f: impl FnOnce(&mut ContainerExt) + Send + 'static,
    ) -> DbResult<()> {
        let id = id.to_string();
        self.conn
            .call(move |conn| update_container_ext(conn, &id, f))
            .await
            .map_err(DbError::Sqlite)?;
        Ok(())
    }

    pub async fn set_container_ext(&self, id: &str, ext: &ContainerExt) -> DbResult<()> {
        let id = id.to_string();
        let ext = ext.clone();
        self.conn
            .call(move |conn| {
                // A container that is gone has nothing to keep.
                conn.execute(
                    "INSERT INTO container_ext (container_id, oom_killed, restart_count, health, timed_out, stopped_by_user)
                     SELECT ?1, ?2, ?3, ?4, ?5, ?6 WHERE EXISTS (SELECT 1 FROM containers WHERE id = ?1)
                     ON CONFLICT(container_id) DO UPDATE SET
                         oom_killed = excluded.oom_killed,
                         restart_count = excluded.restart_count,
                         health = excluded.health,
                         timed_out = excluded.timed_out,
                         stopped_by_user = excluded.stopped_by_user",
                    rusqlite::params![
                        id,
                        ext.oom_killed as i64,
                        ext.restart_count as i64,
                        ext.health,
                        ext.timed_out as i64,
                        ext.stopped_by_user as i64
                    ],
                )?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)?;
        Ok(())
    }
}

/// The SQL of `Database::update_container_ext`, for a connection of any kind.
pub fn update_container_ext(
    conn: &mut rusqlite::Connection,
    id: &str,
    f: impl FnOnce(&mut ContainerExt),
) -> Result<(), tokio_rusqlite::Error> {
    let volatile = volatile::container(conn, id);
    volatile::run(conn, volatile, |conn| update_container_ext_in(conn, id, f))
}

fn update_container_ext_in(
    conn: &mut rusqlite::Connection,
    id: &str,
    f: impl FnOnce(&mut ContainerExt),
) -> Result<(), tokio_rusqlite::Error> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let mut ext = {
        let mut stmt = tx.prepare(
            "SELECT oom_killed, restart_count, health, timed_out, stopped_by_user
                 FROM container_ext WHERE container_id = ?1",
        )?;
        let mut rows = stmt.query([&id])?;
        match rows.next()? {
            Some(row) => ContainerExt {
                oom_killed: row.get::<_, i64>(0)? != 0,
                restart_count: row.get::<_, i64>(1)? as u32,
                health: row.get(2)?,
                timed_out: row.get::<_, i64>(3)? != 0,
                stopped_by_user: row.get::<_, i64>(4)? != 0,
            },
            None => ContainerExt::default(),
        }
    };
    f(&mut ext);
    tx.execute(
            "INSERT INTO container_ext (container_id, oom_killed, restart_count, health, timed_out, stopped_by_user)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6 WHERE EXISTS (SELECT 1 FROM containers WHERE id = ?1)
             ON CONFLICT(container_id) DO UPDATE SET
                 oom_killed = excluded.oom_killed,
                 restart_count = excluded.restart_count,
                 health = excluded.health,
                 timed_out = excluded.timed_out,
                 stopped_by_user = excluded.stopped_by_user",
            rusqlite::params![
                id,
                ext.oom_killed as i64,
                ext.restart_count as i64,
                ext.health,
                ext.timed_out as i64,
                ext.stopped_by_user as i64
            ],
        )?;
    tx.commit()?;
    Ok(())
}

/// The extra state of a container; the default when it has no row.
pub fn get_container_ext(
    conn: &mut rusqlite::Connection,
    id: &str,
) -> Result<ContainerExt, tokio_rusqlite::Error> {
    let mut rows = get_container_exts(conn, &[id.to_string()])?;
    Ok(rows.remove(id).unwrap_or_default())
}

/// The SQL of `Database::get_container_exts`, for a connection of any kind.
pub fn get_container_exts(
    conn: &mut rusqlite::Connection,
    ids: &[String],
) -> Result<std::collections::HashMap<String, ContainerExt>, tokio_rusqlite::Error> {
    let rows = crate::query_in(
        conn,
        "SELECT container_id, oom_killed, restart_count, health, timed_out, \
             stopped_by_user FROM container_ext WHERE container_id IN ({marks})",
        ids,
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                ContainerExt {
                    oom_killed: row.get::<_, i64>(1)? != 0,
                    restart_count: row.get::<_, i64>(2)?.max(0) as u32,
                    health: row.get(3)?,
                    timed_out: row.get::<_, i64>(4)? != 0,
                    stopped_by_user: row.get::<_, i64>(5)? != 0,
                },
            ))
        },
    )?;
    Ok(rows.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RecordState;

    #[tokio::test]
    async fn the_extra_state_is_kept_and_cascades() {
        let db = Database::open_in_memory().await.unwrap();
        // No container: nothing is stored, the default is returned.
        db.set_container_ext(
            "nope",
            &ContainerExt {
                oom_killed: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            db.get_container_ext("nope").await.unwrap(),
            ContainerExt::default()
        );

        db.conn()
            .call(|c| {
                c.execute_batch(
                    "INSERT INTO images (id, manifest_digest, config_digest, manifest, config, created_at) VALUES ('i','m','c','{}','{}','now');
                     INSERT INTO containers (id, image_id, config, created_at) VALUES ('c1','i','{}','now');",
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let ext = ContainerExt {
            oom_killed: true,
            restart_count: 3,
            health: Some("{\"Status\":\"healthy\"}".into()),
            timed_out: true,
            stopped_by_user: true,
        };
        db.set_container_ext("c1", &ext).await.unwrap();
        assert_eq!(db.get_container_ext("c1").await.unwrap(), ext);
        db.set_container_ext("c1", &ContainerExt::default())
            .await
            .unwrap();
        assert_eq!(
            db.get_container_ext("c1").await.unwrap(),
            ContainerExt::default()
        );
        let batch = db
            .get_container_exts(&["c1".into(), "nope".into()])
            .await
            .unwrap();
        assert_eq!(batch.len(), 1, "a container with no row has none");
        assert_eq!(batch["c1"], ContainerExt::default());
        db.set_container_ext("c1", &ext).await.unwrap();
        assert_eq!(
            db.get_container_exts(&["c1".into()]).await.unwrap()["c1"],
            ext
        );
        db.set_container_ext("c1", &ContainerExt::default())
            .await
            .unwrap();
        assert_eq!(db.pause_lease("c1").await.unwrap(), None);
        db.set_pause_lease("c1", Some(42)).await.unwrap();
        db.set_container_ext("c1", &ext).await.unwrap();
        assert_eq!(db.pause_lease("c1").await.unwrap(), Some(42), "kept");
        assert_eq!(db.pause_leases().await.unwrap(), [("c1".to_string(), 42)]);
        db.set_pause_lease("c1", None).await.unwrap();
        assert!(db.pause_leases().await.unwrap().is_empty());
        db.set_pause_lease("c1", Some(43)).await.unwrap();
        db.delete_container("c1").await.unwrap();
        assert!(db.pause_leases().await.unwrap().is_empty(), "cascades");
        assert_eq!(
            db.get_container_ext("c1").await.unwrap(),
            ContainerExt::default()
        );
    }

    /// The exit of a run is recorded on that run only: the late exit of
    /// the run before leaves a container that started again alone.
    #[tokio::test]
    async fn an_exit_is_recorded_for_its_run_only() {
        let db = Database::open_in_memory().await.unwrap();
        db.conn()
            .call(|c| {
                c.execute_batch(
                    "INSERT INTO images (id, manifest_digest, config_digest, manifest, config, created_at) VALUES ('i','m','c','{}','{}','now');
                     INSERT INTO containers (id, image_id, config, created_at) VALUES ('c1','i','{}','now');",
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let at = |s: u32, ns: u32| format!("2026-10-30T10:00:0{s}.{ns:09}+00:00");
        db.update_container_state(
            "c1",
            RecordState::Running,
            Some(7),
            Some(at(2, 0)),
            None,
            None,
        )
        .await
        .unwrap();
        let late = db
            .record_container_exit("c1", "t".into(), 3, Some(at(1, 0)))
            .await
            .unwrap();
        assert!(!late, "the exit of the run before");
        assert_eq!(
            db.get_container("c1").await.unwrap().state,
            RecordState::Running
        );
        let own = db
            .record_container_exit("c1", "t".into(), 4, Some(at(2, 0)))
            .await
            .unwrap();
        assert!(own);
        let c = db.get_container("c1").await.unwrap();
        assert_eq!((c.state, c.exit_code), (RecordState::Stopped, Some(4)));
        // (a start recorded a moment before the monitor's own: a monitor
        // that waited for a client to start the container)
        db.update_container_state(
            "c1",
            RecordState::Running,
            Some(8),
            Some(at(3, 216_386_104)),
            None,
            None,
        )
        .await
        .unwrap();
        assert!(db
            .record_container_exit("c1", "t".into(), 3, Some(at(3, 220_390_552)))
            .await
            .unwrap());
        // (an end nobody saw has no run)
        db.update_container_state(
            "c1",
            RecordState::Running,
            Some(9),
            Some(at(4, 0)),
            None,
            None,
        )
        .await
        .unwrap();
        assert!(db
            .record_container_exit("c1", "t".into(), 255, None)
            .await
            .unwrap());
    }

    /// What announces an exit is written before the exit can be seen by
    /// another connection, and only by the call that records it.
    #[tokio::test]
    async fn an_exit_is_announced_before_it_is_visible() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let db = Database::open(&path).await.unwrap();
        db.conn()
            .call(|c| {
                c.execute_batch(
                    "INSERT INTO images (id, manifest_digest, config_digest, manifest, config, created_at) VALUES ('i','m','c','{}','{}','now');
                     INSERT INTO containers (id, image_id, config, created_at) VALUES ('c1','i','{}','now');",
                )?;
                Ok(())
            })
            .await
            .unwrap();
        db.update_container_state("c1", RecordState::Running, Some(7), None, None, None)
            .await
            .unwrap();
        let state_seen_by_another = {
            let path = path.clone();
            move || -> String {
                rusqlite::Connection::open(&path)
                    .unwrap()
                    .query_row("SELECT state FROM containers WHERE id = 'c1'", [], |r| {
                        r.get(0)
                    })
                    .unwrap()
            }
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let seen = state_seen_by_another.clone();
        let recorded = db
            .record_container_exit_announcing(
                "c1",
                "t".into(),
                3,
                None,
                false,
                Box::new(move || tx.send(seen()).unwrap()),
            )
            .await
            .unwrap();
        assert!(recorded);
        assert_eq!(
            rx.recv().unwrap(),
            "running",
            "not stopped yet when announced"
        );
        assert_eq!(state_seen_by_another(), "stopped");
        // (the exit is recorded already: nothing to announce)
        let (tx, rx) = std::sync::mpsc::channel();
        let again = db
            .record_container_exit_announcing(
                "c1",
                "t".into(),
                3,
                None,
                false,
                Box::new(move || tx.send(()).unwrap()),
            )
            .await
            .unwrap();
        assert!(!again);
        assert!(rx.try_recv().is_err());
        // a restart by the policy is announced the same way
        db.update_container_state("c1", RecordState::Running, Some(8), None, None, None)
            .await
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let seen = state_seen_by_another.clone();
        db.record_container_restarting(
            "c1",
            "t".into(),
            5,
            Box::new(move || tx.send(seen()).unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(rx.recv().unwrap(), "running");
        assert_eq!(state_seen_by_another(), "stopped");
    }

    /// The exit of a container that goes with it marks the row in the same
    /// transaction; the mark is cleared when the removal is given up, and
    /// goes with the row.
    #[tokio::test]
    async fn a_removal_is_marked_with_the_exit_until_it_is_done() {
        let db = Database::open_in_memory().await.unwrap();
        db.conn()
            .call(|c| {
                c.execute_batch(
                    "INSERT INTO images (id, manifest_digest, config_digest, manifest, config, created_at) VALUES ('i','m','c','{}','{}','now');
                     INSERT INTO containers (id, image_id, config, created_at, state) VALUES ('c1','i','{}','now','running');
                     INSERT INTO containers (id, image_id, config, created_at, state) VALUES ('c2','i','{}','now','running');",
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(db.removals_pending().await.unwrap().is_empty());
        for (id, removal) in [("c1", true), ("c2", false)] {
            db.record_container_exit_announcing(id, "t".into(), 0, None, removal, Box::new(|| {}))
                .await
                .unwrap();
        }
        assert_eq!(db.removals_pending().await.unwrap(), ["c1"]);
        assert!(db.removal_pending("c1").await.unwrap());
        assert!(!db.removal_pending("c2").await.unwrap());
        db.conn()
            .call(|c| crate::clear_removal(c, "c1"))
            .await
            .unwrap();
        assert!(db.removals_pending().await.unwrap().is_empty());
        // (the mark is of the exit: another one sets it again)
        db.update_container_state("c1", RecordState::Running, Some(2), None, None, None)
            .await
            .unwrap();
        db.record_container_exit_announcing("c1", "t".into(), 0, None, true, Box::new(|| {}))
            .await
            .unwrap();
        assert_eq!(db.removals_pending().await.unwrap(), ["c1"]);
        db.delete_container("c1").await.unwrap();
        assert!(db.removals_pending().await.unwrap().is_empty());
        assert!(!db.removal_pending("c1").await.unwrap());
    }

    /// Changes of different fields at once all stay (the row is read and
    /// written in one transaction).
    #[tokio::test]
    async fn changes_of_the_extra_state_at_once_all_stay() {
        let db = Database::open_in_memory().await.unwrap();
        db.conn()
            .call(|c| {
                c.execute_batch(
                    "INSERT INTO images (id, manifest_digest, config_digest, manifest, config, created_at) VALUES ('i','m','c','{}','{}','now');
                     INSERT INTO containers (id, image_id, config, created_at) VALUES ('c1','i','{}','now');",
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let mut tasks = Vec::new();
        for n in 0..32u32 {
            let db = db.clone();
            tasks.push(tokio::spawn(async move {
                match n % 3 {
                    0 => {
                        db.update_container_ext("c1", |e| e.stopped_by_user = true)
                            .await
                    }
                    1 => db.update_container_ext("c1", |e| e.oom_killed = true).await,
                    _ => {
                        db.update_container_ext("c1", move |e| e.restart_count += 1)
                            .await
                    }
                }
                .unwrap()
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let ext = db.get_container_ext("c1").await.unwrap();
        assert!(ext.stopped_by_user && ext.oom_killed);
        assert_eq!(ext.restart_count, 10);
    }
}
