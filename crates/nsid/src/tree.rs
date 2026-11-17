// SPDX-License-Identifier: Apache-2.0
//! The processes that live in the namespaces of the rootless tree, as the
//! store's database records them.

use crate::{own, start_time, store, Holder, Kind};
use std::io;
use std::path::PathBuf;
use std::sync::OnceLock;

/// The store's database (its namespaces tables) this process joined, and
/// the boot: where the processes it starts record themselves
/// (`register_holder`).
static STORE: OnceLock<(PathBuf, String)> = OnceLock::new();

/// Run `f` on a connection opened for the call at `db`.
fn with_connection<T>(
    db: &std::path::Path,
    f: impl FnOnce(&mut rusqlite::Connection) -> io::Result<T>,
) -> io::Result<T> {
    f(&mut *store::open(db)?)
}

/// Whether `enter` recorded this process as a holder (in its transaction).
static RECORDED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn db_error(what: &'static str) -> impl FnOnce(rusqlite::Error) -> io::Error {
    move |e| io::Error::other(format!("the namespaces in the database ({what}): {e}"))
}

/// This process is in the namespaces that the store `db` records (it was
/// started in them): what it starts can be recorded there.
pub fn remember(db: PathBuf) -> io::Result<()> {
    let boot_id = store::boot_id()?;
    let _ = STORE.set((db, boot_id));
    Ok(())
}

/// Record that process `pid` lives in the namespaces of this one and
/// outlives it perhaps (the monitor of a container, pasta, the DNS server):
/// the next command joins the namespaces through it.  Nothing for a process
/// that did not join them (root).
pub fn register_holder(pid: u32, role: &str) {
    let Some((db, boot_id)) = STORE.get() else {
        return;
    };
    // (`enter` recorded it already)
    if pid == std::process::id() && RECORDED.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let result = (|| -> io::Result<()> {
        let pid = pid as i32;
        // (gone already: nothing to record)
        let Some(start) = start_time(pid) else {
            return Ok(());
        };
        let holder = Holder {
            pid,
            start,
            role: role.to_string(),
        };
        // (one transaction: the holder, and the others that are gone, so the
        // list stays the size of what lives)
        with_connection(db, |conn| {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(db_error("lock"))?;
            // A process that joined or made the namespaces and recorded
            // nothing (a command that only reads, a process started in
            // them) records the pair it is in, if it is not the recorded
            // one, now that it starts what outlives it.
            let recorded = RECORDED.load(std::sync::atomic::Ordering::Relaxed);
            if !recorded {
                record_tree(&tx, boot_id)?;
            }
            store::add_holder(&tx, boot_id, store::TREE, &holder).map_err(db_error("add"))?;
            let gone: Vec<Holder> = store::load(&tx, boot_id, store::TREE)
                .map_err(db_error("read"))?
                .holders
                .into_iter()
                .filter(|h| start_time(h.pid) != Some(h.start))
                .collect();
            store::remove_holders(&tx, boot_id, store::TREE, &gone).map_err(db_error("forget"))?;
            tx.commit().map_err(db_error("commit"))?;
            RECORDED.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        })
    })();
    if let Err(e) = result {
        tracing::warn!("Cannot record the {role} {pid} as a member of the user namespace: {e}");
    }
}

/// Record in `tx` that this process, `me`, is in the pair of the tree:
/// with `fresh` a pair of its own (the holders of the pair recorded before
/// are not in it), with `new_mnt` a mount namespace of its own in the
/// recorded user namespace.  The holders that are `gone` are forgotten.
pub fn record_pair(
    tx: &rusqlite::Connection,
    boot_id: &str,
    fresh: bool,
    new_mnt: bool,
    gone: &[Holder],
    me: &Holder,
) -> io::Result<()> {
    if fresh {
        store::clear_holders(tx, boot_id, store::TREE).map_err(db_error("clear"))?;
        store::store(tx, boot_id, store::TREE, Kind::User, &own(Kind::User)?)
            .map_err(db_error("store user"))?;
    }
    if fresh || new_mnt {
        store::store(tx, boot_id, store::TREE, Kind::Mnt, &own(Kind::Mnt)?)
            .map_err(db_error("store mnt"))?;
    }
    store::remove_holders(tx, boot_id, store::TREE, gone).map_err(db_error("forget"))?;
    store::add_holder(tx, boot_id, store::TREE, me).map_err(db_error("add"))
}

/// This process recorded nothing when it joined: record the pair it is in
/// when it is not the recorded one.  A recorded namespace that a holder
/// lives in is not replaced (this process made its own while the holder of
/// that one was not recorded yet): what this process starts would split the
/// processes of the user in two trees, so it is an error.
fn record_tree(tx: &rusqlite::Transaction<'_>, boot_id: &str) -> io::Result<()> {
    let stored = store::load(tx, boot_id, store::TREE).map_err(db_error("read"))?;
    let is_recorded = |kind: Kind| -> io::Result<bool> {
        let own = own(kind)?;
        Ok(stored.namespace(kind).is_some_and(|s| s.is_same(&own)))
    };
    let (in_user, in_mnt) = (is_recorded(Kind::User)?, is_recorded(Kind::Mnt)?);
    if in_user && in_mnt {
        return Ok(());
    }
    let replaced = if in_user { Kind::Mnt } else { Kind::User };
    if lives(&stored, replaced) {
        return Err(io::Error::other(format!(
            "this process is not in the recorded {} namespace, which a process lives in",
            replaced.name()
        )));
    }
    let pid = std::process::id() as i32;
    let me = Holder {
        pid,
        start: start_time(pid).ok_or_else(|| io::Error::other("cannot read my start time"))?,
        role: "engine".to_string(),
    };
    record_pair(tx, boot_id, !in_user, in_user, &[], &me)
}

/// Whether a holder of `stored` lives in its namespace of `kind`: a live
/// holder whose namespace this process may not open (it is in another user
/// namespace) is taken to be in it.
fn lives(stored: &crate::Stored, kind: Kind) -> bool {
    let Some(recorded) = stored.namespace(kind) else {
        return false;
    };
    stored.holders.iter().any(|h| {
        start_time(h.pid) == Some(h.start)
            && match crate::open_of(&h.pid.to_string(), kind) {
                Ok(fd) => {
                    crate::id_of(std::os::fd::AsFd::as_fd(&fd)).is_ok_and(|id| id.is_same(recorded))
                }
                Err(_) => true,
            }
    })
}

/// The processes that live in the namespaces of this store, as far as the
/// database knows: the pids of the holders that are alive.  Empty for a
/// process that did not join them; a database that cannot be read is an
/// error.  Whoever looks for a process in some
/// other namespace (the network namespace of the bridges, when the process
/// that named it is gone) starts here.
pub fn members() -> io::Result<Vec<i32>> {
    let Some((db, boot_id)) = STORE.get() else {
        return Ok(Vec::new());
    };
    with_connection(db, |conn| {
        store::live_holders(conn, boot_id, store::TREE).map_err(db_error("read"))
    })
}

/// Remember that this process joined the namespaces recorded in `db` (for
/// `boot_id`), and whether `enter` recorded it as a holder in its own
/// transaction.
pub fn joined(db: &std::path::Path, boot_id: &str, recorded: bool) {
    let _ = STORE.set((db.to_path_buf(), boot_id.to_string()));
    RECORDED.store(recorded, std::sync::atomic::Ordering::Relaxed);
}
