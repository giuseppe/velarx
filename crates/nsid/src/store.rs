// SPDX-License-Identifier: Apache-2.0
//! The namespaces of a boot, in the tables of the store's database.
//!
//! What identifies the namespaces is kept here under the key `boot_id`
//! (`/proc/sys/kernel/random/boot_id`): the rows of another boot describe
//! namespaces that are gone and are never read.  The functions take a plain
//! connection: they are used before the process has any thread, where an
//! asynchronous database is not available.
//!
//! `namespaces` has one row per kind of namespace of a scope: the file
//! handle of `name_to_handle_at` (it carries the unique id of the
//! namespace) and the device and inode of the namespace file.  A scope is
//! whoever the namespaces belong to: [`TREE`] for the user and mount
//! namespaces of the rootless tree, [`ROOTLESS_NETNS`] for the network
//! namespace of the rootless bridge networks, [`container_scope`] for the
//! network namespace of a container.  `holders` lists the processes known
//! to live in the namespaces of a scope (monitors, helpers, the daemon),
//! each with its start time so that a recycled pid is not taken for them:
//! where a new process can join the namespaces from.  Dropping a scope
//! forgets its namespaces and its holders and no other.
//!
//! They are tables of the store's database (`velarx_db::namespaces` has the
//! schema and the connection that is opened before the threads), not of a
//! file of their own: one database for everything.  What is of one boot is
//! pruned by the first namespace write of the next ([`store`], in the
//! transaction of that write), and a command that only reads the store
//! reads these tables and writes nothing: a process records itself (as a
//! holder) only when it makes the namespaces, outlives the command or
//! starts what does.

use crate::{Handle, Holder, Kind, NamespaceId, Stored};
use rusqlite::{params, Connection};

/// The boot id of the running kernel.
pub fn boot_id() -> std::io::Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_string())
}

/// The pids of the live holders of `scope` of this boot: a process with
/// the start time recorded for it.
pub fn live_holders(conn: &Connection, boot_id: &str, scope: &str) -> rusqlite::Result<Vec<i32>> {
    Ok(load(conn, boot_id, scope)?
        .holders
        .into_iter()
        .filter(|h| crate::start_time(h.pid) == Some(h.start))
        .map(|h| h.pid)
        .collect())
}

/// A connection to the store at `db` for the namespaces of the boot, opened
/// before any thread (`velarx_db::volatile::open`: made if it is not there,
/// its commits not synced).
pub fn open(db: &std::path::Path) -> std::io::Result<velarx_db::volatile::Connection> {
    velarx_db::volatile::open(db).map_err(|e| {
        std::io::Error::other(format!(
            "the namespaces in the database ({}): {e}",
            db.display()
        ))
    })
}

/// The scope of the user and mount namespaces of the rootless tree.
pub const TREE: &str = "tree";

/// The scope of the network namespace of the rootless bridge networks.
pub const ROOTLESS_NETNS: &str = "rootless-netns";

/// The scope of the network namespace of the container `id`.
pub fn container_scope(id: &str) -> String {
    format!("container/{id}")
}

/// What is recorded for `scope` of `boot_id`.
pub fn load(conn: &Connection, boot_id: &str, scope: &str) -> rusqlite::Result<Stored> {
    let mut stmt = conn.prepare(
        "SELECT kind, dev, ino, handle_type, mount_id, handle FROM namespaces
         WHERE boot_id = ?1 AND scope = ?2 ORDER BY rowid",
    )?;
    let mut namespaces = Vec::new();
    for row in stmt.query_map(params![boot_id, scope], |r| {
        let kind: String = r.get(0)?;
        let handle_type: Option<i32> = r.get(3)?;
        let mount_id: Option<i32> = r.get(4)?;
        let bytes: Option<Vec<u8>> = r.get(5)?;
        let kind = Kind::parse(&kind).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                format!("unknown kind of namespace {kind:?}").into(),
            )
        })?;
        Ok((
            kind,
            NamespaceId {
                dev: r.get::<_, i64>(1)? as u64,
                ino: r.get::<_, i64>(2)? as u64,
                handle: match (handle_type, mount_id, bytes) {
                    (Some(handle_type), Some(mount_id), Some(bytes)) => Some(Handle {
                        handle_type,
                        mount_id,
                        bytes,
                    }),
                    _ => None,
                },
            },
        ))
    })? {
        namespaces.push(row?);
    }
    let mut stmt = conn.prepare(
        "SELECT pid, start, role FROM holders WHERE boot_id = ?1 AND scope = ?2 ORDER BY rowid",
    )?;
    let holders = stmt
        .query_map(params![boot_id, scope], |r| {
            Ok(Holder {
                pid: r.get(0)?,
                start: r.get::<_, i64>(1)? as u64,
                role: r.get(2)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(Stored {
        namespaces,
        holders,
    })
}

/// Record the namespace of `kind` of `scope` of `boot_id`, and forget the
/// rows of the other boots.
pub fn store(
    conn: &Connection,
    boot_id: &str,
    scope: &str,
    kind: Kind,
    id: &NamespaceId,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM namespaces WHERE boot_id != ?1",
        params![boot_id],
    )?;
    conn.execute("DELETE FROM holders WHERE boot_id != ?1", params![boot_id])?;
    let h = id.handle.as_ref();
    conn.execute(
        "INSERT OR REPLACE INTO namespaces
             (boot_id, scope, kind, dev, ino, handle_type, mount_id, handle)
         VALUES (?1, ?8, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            boot_id,
            kind.name(),
            id.dev as i64,
            id.ino as i64,
            h.map(|h| h.handle_type),
            h.map(|h| h.mount_id),
            h.map(|h| h.bytes.as_slice()),
            scope,
        ],
    )?;
    Ok(())
}

/// Record a process that lives in the namespaces of `scope`.
pub fn add_holder(
    conn: &Connection,
    boot_id: &str,
    scope: &str,
    holder: &Holder,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO holders (boot_id, scope, pid, start, role)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![boot_id, scope, holder.pid, holder.start as i64, holder.role],
    )?;
    Ok(())
}

/// Forget the processes `gone`.
pub fn remove_holders(
    conn: &Connection,
    boot_id: &str,
    scope: &str,
    gone: &[Holder],
) -> rusqlite::Result<()> {
    for h in gone {
        conn.execute(
            "DELETE FROM holders WHERE boot_id = ?1 AND scope = ?2 AND pid = ?3 AND start = ?4",
            params![boot_id, scope, h.pid, h.start as i64],
        )?;
    }
    Ok(())
}

/// Forget every process of `scope`: the namespaces they lived in are not
/// the ones that are recorded any more.
pub fn clear_holders(conn: &Connection, boot_id: &str, scope: &str) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM holders WHERE boot_id = ?1 AND scope = ?2",
        params![boot_id, scope],
    )?;
    Ok(())
}

/// Forget `scope`: its namespaces and its holders (the namespace of a
/// container that ended).  The other scopes stay.
pub fn drop_scope(conn: &Connection, boot_id: &str, scope: &str) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM namespaces WHERE boot_id = ?1 AND scope = ?2",
        params![boot_id, scope],
    )?;
    clear_holders(conn, boot_id, scope)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The store's own tables, on a file in a directory that lives as long
    /// as the connection (and goes after it).
    struct Db {
        conn: velarx_db::volatile::Connection,
        _dir: tempfile::TempDir,
    }

    impl std::ops::Deref for Db {
        type Target = Connection;
        fn deref(&self) -> &Connection {
            &self.conn
        }
    }

    fn db() -> Db {
        let dir = tempfile::tempdir().unwrap();
        Db {
            conn: velarx_db::volatile::open(&dir.path().join("db.sqlite")).unwrap(),
            _dir: dir,
        }
    }

    fn id(ino: u64, with_handle: bool) -> NamespaceId {
        NamespaceId {
            dev: 4,
            ino,
            handle: with_handle.then(|| Handle {
                handle_type: 241,
                mount_id: 7,
                bytes: ino.to_le_bytes().to_vec(),
            }),
        }
    }

    fn holder(pid: i32) -> Holder {
        Holder {
            pid,
            start: 1000 + pid as u64,
            role: "monitor".into(),
        }
    }

    #[test]
    fn a_boot_sees_its_own_rows() {
        let conn = db();
        assert_eq!(load(&conn, "boot-a", "s").unwrap(), Stored::default());
        store(&conn, "boot-a", "s", Kind::User, &id(10, true)).unwrap();
        store(&conn, "boot-a", "s", Kind::Mnt, &id(11, false)).unwrap();
        add_holder(&conn, "boot-a", "s", &holder(5)).unwrap();
        let a = load(&conn, "boot-a", "s").unwrap();
        assert_eq!(a.namespace(Kind::User), Some(&id(10, true)));
        assert_eq!(a.namespace(Kind::Mnt), Some(&id(11, false)));
        assert_eq!(a.holders, vec![holder(5)]);
        assert_eq!(load(&conn, "boot-b", "s").unwrap(), Stored::default());
    }

    #[test]
    fn the_rows_of_another_boot_go_with_the_next_store() {
        let conn = db();
        store(&conn, "old", "s", Kind::User, &id(10, true)).unwrap();
        add_holder(&conn, "old", "s", &holder(5)).unwrap();
        store(&conn, "new", "s", Kind::User, &id(20, true)).unwrap();
        assert_eq!(load(&conn, "old", "s").unwrap(), Stored::default());
        assert_eq!(
            load(&conn, "new", "s").unwrap().namespace(Kind::User),
            Some(&id(20, true))
        );
    }

    #[test]
    fn one_kind_is_replaced_and_the_other_stays() {
        let conn = db();
        store(&conn, "b", "s", Kind::User, &id(10, true)).unwrap();
        store(&conn, "b", "s", Kind::Mnt, &id(11, true)).unwrap();
        store(&conn, "b", "s", Kind::Mnt, &id(12, true)).unwrap();
        let s = load(&conn, "b", "s").unwrap();
        assert_eq!(s.namespace(Kind::User), Some(&id(10, true)));
        assert_eq!(s.namespace(Kind::Mnt), Some(&id(12, true)));
    }

    /// Every kind is stored and loaded back; a kind the schema does not
    /// list is refused by the file.
    #[test]
    fn every_kind_is_stored_and_no_other() {
        let conn = db();
        for (i, kind) in Kind::ALL.into_iter().enumerate() {
            store(&conn, "b", "s", kind, &id(10 + i as u64, true)).unwrap();
        }
        let s = load(&conn, "b", "s").unwrap();
        for (i, kind) in Kind::ALL.into_iter().enumerate() {
            assert_eq!(s.namespace(kind), Some(&id(10 + i as u64, true)));
        }
        assert!(conn
            .execute(
                "INSERT INTO namespaces (boot_id, scope, kind, dev, ino) VALUES ('b', 's', 'nope', 1, 2)",
                [],
            )
            .is_err());
    }

    #[test]
    fn holders_are_added_removed_and_cleared() {
        let conn = db();
        for pid in [1, 2, 3] {
            add_holder(&conn, "b", "s", &holder(pid)).unwrap();
        }
        // the same pid with another start time is another process
        let recycled = Holder {
            start: 5,
            ..holder(2)
        };
        add_holder(&conn, "b", "s", &recycled).unwrap();
        assert_eq!(load(&conn, "b", "s").unwrap().holders.len(), 4);
        remove_holders(&conn, "b", "s", &[holder(2)]).unwrap();
        let left = load(&conn, "b", "s").unwrap().holders;
        assert_eq!(left, vec![holder(1), holder(3), recycled]);
        clear_holders(&conn, "b", "s").unwrap();
        assert!(load(&conn, "b", "s").unwrap().holders.is_empty());
    }

    /// A scope has its own namespaces and holders: dropping one leaves the
    /// others, and the same kind lives in each.
    #[test]
    fn scopes_are_kept_apart_and_dropped_alone() {
        let conn = db();
        let (a, b) = (container_scope("a"), container_scope("b"));
        store(&conn, "x", &a, Kind::Net, &id(10, true)).unwrap();
        store(&conn, "x", &b, Kind::Net, &id(20, true)).unwrap();
        store(&conn, "x", TREE, Kind::User, &id(30, true)).unwrap();
        add_holder(&conn, "x", &a, &holder(1)).unwrap();
        add_holder(&conn, "x", &b, &holder(1)).unwrap();
        add_holder(&conn, "x", &b, &holder(2)).unwrap();
        assert_eq!(
            load(&conn, "x", &a).unwrap().namespace(Kind::Net),
            Some(&id(10, true))
        );
        assert_eq!(load(&conn, "x", &b).unwrap().holders.len(), 2);
        remove_holders(&conn, "x", &b, &[holder(1)]).unwrap();
        assert_eq!(load(&conn, "x", &b).unwrap().holders, vec![holder(2)]);
        assert_eq!(load(&conn, "x", &a).unwrap().holders, vec![holder(1)]);
        drop_scope(&conn, "x", &a).unwrap();
        assert_eq!(load(&conn, "x", &a).unwrap(), Stored::default());
        assert_eq!(
            load(&conn, "x", &b).unwrap().namespace(Kind::Net),
            Some(&id(20, true))
        );
        assert_eq!(
            load(&conn, "x", TREE).unwrap().namespace(Kind::User),
            Some(&id(30, true))
        );
        clear_holders(&conn, "x", &b).unwrap();
        assert!(load(&conn, "x", &b).unwrap().holders.is_empty());
        assert!(load(&conn, "x", &b).unwrap().namespace(Kind::Net).is_some());
    }
}
