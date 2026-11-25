// SPDX-License-Identifier: Apache-2.0
//! The removal of a container that goes with its exit (`--rm`): its files,
//! its anonymous volumes, then its row with the `remove` event.
//!
//! The files go first: a container whose files cannot be removed (the disk
//! says no) stays listed, and the next `rm` finishes it.  [`prepare`] does
//! what a confined thread may not (the unmounts); [`finish`] the rest.

use super::record::{event_details, row, write_event};
use super::{mounts, ImageRef, SettlePlan, SettleResult};
use crate::container::ContainerConfig;
use std::io;
use std::path::{Path, PathBuf};
use velarx_db::sync::Access;
use velarx_db::ContainerRecord;
use velarx_types::{DbError, DbResult};
use velarx_wire::events::{container_event, image_events};
use velarx_wire::monitor::iface::{ImageChange, ImageName};

/// An anonymous volume of the container that goes with it.
#[derive(Debug, Clone)]
pub struct Volume {
    pub name: String,
    pub mountpoint: PathBuf,
    /// The directory the volume service made for it (holding `_data`)
    pub own_dir: Option<PathBuf>,
}

/// What [`prepare`] found.
pub enum Prepare {
    /// The row is gone already
    Gone,
    /// Other containers depend on this one (podman's removal fails then): it
    /// stays stopped
    Kept,
    /// It goes
    Go(Box<Prepared>),
}

/// What [`prepare`] decided.
pub struct Prepared {
    container: ContainerRecord,
    volumes: Vec<Volume>,
    /// The lock of the store, shared until the removal is done: a
    /// collection of the store waits for the removal of a container's root
    _storage: velarx_storage::StorageLock,
    /// The lock of the volumes, shared, when volumes go with the container
    _volumes: Option<velarx_storage::StorageLock>,
}

impl Prepared {
    /// The anonymous volumes that go with the container.
    pub fn volumes(&self) -> &[Volume] {
        &self.volumes
    }
}

/// The volumes `config` mounts that no other container uses and that were
/// made for it.
fn anonymous_volumes(
    a: &impl Access,
    plan: &SettlePlan,
    config: &ContainerConfig,
) -> DbResult<Vec<Volume>> {
    let mut out = Vec::new();
    for name in config.mounts.iter().filter_map(|m| m.volume.as_deref()) {
        let owned = name.to_string();
        let found = match a.call(move |c| velarx_db::volumes::get(c, &owned)) {
            Ok(v) => v,
            Err(DbError::NotFound(_)) => continue,
            Err(e) => return Err(e),
        };
        if !found.anonymous() || used_by_others(a, &plan.id, name, &found.mountpoint)? {
            continue;
        }
        let dir = plan.removal.volumes_dir.join(name);
        out.push(Volume {
            name: name.to_string(),
            own_dir: (Path::new(&found.mountpoint) == dir.join("_data")).then_some(dir),
            mountpoint: PathBuf::from(found.mountpoint),
        });
    }
    Ok(out)
}

/// Whether a container other than `me` mounts the volume `name`
/// (`mountpoint`): a configuration that cannot be read may, so the volume
/// stays.
fn used_by_others(a: &impl Access, me: &str, name: &str, mountpoint: &str) -> DbResult<bool> {
    let containers = a.call(|c| velarx_db::list_containers(c, true))?;
    Ok(containers.into_iter().filter(|c| c.id != me).any(|c| {
        serde_json::from_str::<ContainerConfig>(&c.config).map_or(true, |cfg| {
            cfg.mounts.iter().any(|m| {
                m.volume.as_deref() == Some(name)
                    || m.source == mountpoint
                    || (m.mount_type.as_deref() == Some("volume") && m.source == name)
            })
        })
    }))
}

/// What a confined thread may not do: decide which volumes go and unmount
/// what the container left mounted (the bundle, the root file system, a
/// volume with options).  The caller holds the lock of the container's
/// start; the lock of the store is taken here, shared, then the one of the
/// volumes when some go, and both are held by [`Prepared`] until
/// [`finish`].
pub fn prepare(a: &impl Access, plan: &SettlePlan, with_volumes: bool) -> SettleResult<Prepare> {
    let Some(container) = row(a, &plan.id)? else {
        return Ok(Prepare::Gone);
    };
    let (id, name) = (plan.id.clone(), container.name.clone().unwrap_or_default());
    if !a
        .call(move |c| velarx_db::container_dependents(c, &id, &name))?
        .is_empty()
    {
        // (it stays: nobody finishes a removal that was not due)
        let id = plan.id.clone();
        a.call(move |c| velarx_db::clear_removal(c, &id))?;
        return Ok(Prepare::Kept);
    }
    let volumes = match serde_json::from_str::<ContainerConfig>(&container.config) {
        Ok(config) if with_volumes => anonymous_volumes(a, plan, &config)?,
        _ => Vec::new(),
    };
    let storage = velarx_storage::StorageLock::shared_blocking(&plan.storage_lock)?;
    let r = &plan.removal;
    let volumes_lock = if volumes.is_empty() {
        None
    } else {
        Some(velarx_storage::StorageLock::shared_blocking(
            &r.volumes_lock,
        )?)
    };
    if let Some(public) = r.public_rootfs.as_deref().filter(|p| p.exists()) {
        mounts::detach_mounts_below(public);
    }
    mounts::detach_mounts_below(&r.bundle);
    mounts::detach_mounts_below(&r.mon_dir);
    for v in &volumes {
        mounts::detach_mounts_below(&v.mountpoint);
    }
    Ok(Prepare::Go(Box::new(Prepared {
        container,
        volumes,
        _storage: storage,
        _volumes: volumes_lock,
    })))
}

/// Remove the directory `path` and what is below it; no error when it is not
/// there.
pub fn remove_tree(path: &Path) -> io::Result<()> {
    match velarx_base::tree::remove_dir_all_confined(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

fn remove_file(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// The files of the container: its bundle (with the layer it wrote, which
/// the local drivers keep there), its volumes' data, its logs, its monitor
/// directory, its secrets, the files its configuration named, its lock
/// files.  All of it is tried; the first error is given back.  Also what
/// removes the files of a container no row names (`id`).
pub fn files(id: &str, r: &super::RemovalPlan, volumes: &[Volume]) -> io::Result<()> {
    let mut first = None;
    let mut note = |res: io::Result<()>| {
        if let Err(e) = res {
            first.get_or_insert(e);
        }
    };
    // (the writable layer first: a service that cannot remove it keeps the
    // container, whose files then stay for the next removal)
    match &r.writable {
        velarx_graph::WritableRelease::InBundle { pin } => {
            if let Some(pin) = pin {
                note(remove_file(pin));
            }
        }
        velarx_graph::WritableRelease::Service {
            socket,
            timeout_secs,
            store,
            pin,
        } => {
            let link = velarx_storage_client::Link {
                socket: socket.clone(),
                timeout: std::time::Duration::from_secs(*timeout_secs),
            };
            match velarx_storage_client::remove_root(&link, store, id) {
                Ok(()) => {
                    if let Some(pin) = pin {
                        note(remove_file(pin));
                    }
                }
                Err(e) => {
                    note(Err(io::Error::other(format!(
                        "the layer the storage service holds: {e}"
                    ))));
                    // (the rest stays: the container is still listed and the
                    // next removal does all of it)
                    return first.map_or(Ok(()), Err);
                }
            }
        }
    }
    note(remove_tree(&r.bundle));
    for v in volumes {
        note(remove_tree(&v.mountpoint));
        if let Some(dir) = &v.own_dir {
            note(remove_tree(dir));
        }
    }
    if let Some(public) = r.public_rootfs.as_deref() {
        let _ = std::fs::remove_dir(public);
    }
    for dir in [&r.log_dir, &r.secrets_dir] {
        note(remove_tree(dir));
    }
    for f in r.named_files.iter().chain(r.api_record.iter()) {
        note(remove_file(f));
    }
    // (the monitor directory last: the monitor's own files are in it)
    note(remove_tree(&r.mon_dir));
    for f in &r.lock_files {
        note(remove_file(f));
    }
    first.map_or(Ok(()), Err)
}

/// What the removal came to.
#[derive(Debug)]
pub struct Removal {
    /// The row is gone
    pub removed: bool,
    /// The step that failed
    pub failure: Option<String>,
    /// `--rmi`: what went of the image
    pub image: Option<ImageChange>,
}

/// The removal after [`prepare`]: the files, then the volumes' rows and the
/// container's with its `remove` event.  A file that cannot be removed keeps
/// the container listed.
pub fn finish(
    a: &impl Access,
    plan: &SettlePlan,
    prepared: Prepared,
    code: Option<i32>,
) -> Removal {
    let Prepared {
        container,
        volumes,
        _storage,
        _volumes,
    } = prepared;
    if let Err(e) = files(&plan.id, &plan.removal, &volumes) {
        tracing::warn!("Cannot remove the files of container {}: {e}", plan.id);
        // (reported once; it stays listed for the `rm` that finishes it, and
        // no command that opens the store tries it again)
        let id = plan.id.clone();
        if let Err(e) = a.call(move |c| velarx_db::clear_removal(c, &id)) {
            tracing::warn!("Cannot mark the removal of {} as given up: {e}", plan.id);
        }
        return Removal {
            removed: false,
            failure: Some(format!("the files of the container: {e}")),
            image: None,
        };
    }
    for v in &volumes {
        let name = v.name.clone();
        if let Err(e) = a.call(move |c| velarx_db::volumes::delete(c, &name)) {
            tracing::debug!("The anonymous volume {} stays: {e}", v.name);
        }
    }
    let (image, _) = event_details(&container);
    let mut event = container_event(
        &container.id,
        &container.name.clone().unwrap_or_default(),
        "remove",
    )
    .image(&image);
    if let Some(code) = code {
        event = event.attr("containerExitCode", code.to_string());
    }
    // (the image goes in the transaction of the row: a process that is
    // killed between the two would never remove it, no row says it is due)
    let (id, rmi) = (plan.id.clone(), plan.image.clone());
    let deleted = a.call(move |c| {
        velarx_db::delete_container_then(c, &id, |c| {
            rmi.as_ref().and_then(|i| remove_image(c, &id, i))
        })
    });
    match deleted {
        Ok(image) => {
            write_event(&plan.events, &event);
            for event in image.iter().flat_map(image_events) {
                write_event(&plan.events, &event);
            }
            Removal {
                removed: true,
                failure: None,
                image,
            }
        }
        // (another process that followed it may have removed it: the rest
        // is then that one's)
        Err(DbError::NotFound(_)) => Removal {
            removed: true,
            failure: None,
            image: None,
        },
        Err(e) => Removal {
            removed: false,
            failure: Some(format!("the row of the container: {e}")),
            image: None,
        },
    }
}

/// `--rmi`, once the container's row is gone (in the same transaction): the
/// name the container was made with is untagged when the image has other
/// names, else the image goes, unless another container uses it (podman's
/// `rmi NAME`).  Its layers are released by the next collection
/// (`gc_pending`).  What went is told as events by the caller, once the
/// transaction is committed.  A failure is logged and leaves the image: the
/// container's removal stands.
fn remove_image(
    conn: &mut rusqlite::Connection,
    container: &str,
    image: &ImageRef,
) -> Option<ImageChange> {
    let warn = |why: &dyn std::fmt::Display| {
        tracing::warn!("The image of the container {container} is not removed: {why}");
        None::<ImageChange>
    };
    let tags = match velarx_db::image_tags(conn, &image.id) {
        Ok(tags) => tags,
        Err(e) => return warn(&e),
    };
    // (the name the container was made with must still be one of the
    // image's: a name that moved to another image is that one's)
    if let Some((repository, tag)) = &image.name {
        if !tags
            .iter()
            .any(|t| t.repository == *repository && t.tag == *tag)
        {
            return None;
        }
    }
    match velarx_db::containers_using_image(conn, &image.id) {
        // (podman's words when another container uses it)
        Ok(users) if !users.is_empty() => {
            return warn(&"image is in use by a container");
        }
        Ok(_) => {}
        Err(e) => return warn(&e),
    }
    let only_the_name = image.name.is_some() && tags.len() > 1;
    let names: Vec<ImageName> = if only_the_name {
        image
            .name
            .iter()
            .map(|(repository, tag)| ImageName {
                repository: repository.clone(),
                tag: tag.clone(),
            })
            .collect()
    } else {
        tags.iter()
            .map(|t| ImageName {
                repository: t.repository.clone(),
                tag: t.tag.clone(),
            })
            .collect()
    };
    // (its own savepoint: what fails here leaves the container's removal)
    let done = (|| -> Result<(), String> {
        let sql =
            |c: &mut rusqlite::Connection, s: &str| c.execute_batch(s).map_err(|e| e.to_string());
        sql(conn, "SAVEPOINT rmi")?;
        let written = if let (true, Some((repository, tag))) = (only_the_name, image.name.as_ref())
        {
            velarx_db::delete_image_tag(conn, repository, tag).map_err(|e| e.to_string())
        } else {
            // (the collection is asked for first: an image whose row went
            // with its layers left would otherwise wait for the next prune;
            // a collection that finds the image still there releases
            // nothing)
            velarx_db::set_gc_pending(conn, true)
                .and_then(|()| velarx_db::delete_image_rows(conn, &image.id))
                .map_err(|e| e.to_string())
        };
        match written {
            Ok(()) => sql(conn, "RELEASE rmi"),
            Err(e) => {
                sql(conn, "ROLLBACK TO rmi")?;
                sql(conn, "RELEASE rmi")?;
                Err(e)
            }
        }
    })();
    if let Err(e) = done {
        return warn(&e);
    }
    Some(ImageChange {
        id: image.event_id.clone(),
        names,
        removed: !only_the_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settle::RemovalPlan;
    use velarx_db::sync::Store;
    use velarx_db::{Database, RecordState};
    use velarx_wire::events::log::EventLog;

    const CONFIG: &str = r#"{"image":"localhost/i:1"}"#;

    struct Fixture {
        dir: tempfile::TempDir,
        plan: SettlePlan,
        store: Store,
    }

    /// A store with the image `img` (named `localhost/i:1`) and the
    /// stopped container `c1` whose exit was recorded with its removal
    /// due, and the plan with its files in a directory of their own.
    fn fixture(image: bool) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("db.sqlite");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let d = Database::open(&db).await.unwrap();
            d.conn()
                .call(|c| {
                    c.execute_batch(
                        "INSERT INTO images (id, manifest_digest, config_digest, manifest, config, created_at)
                           VALUES ('img','m','c','{}','{}','now');
                         INSERT INTO image_tags (repository, tag, image_id) VALUES ('localhost/i','1','img');",
                    )?;
                    Ok(())
                })
                .await
                .unwrap();
            d.insert_container(&velarx_db::ContainerRecord { id: "c1".into(), name: Some("c1".into()), image_id: "img".into(), config: CONFIG.into(), state: RecordState::Running, pid: Some(3), created_at: "now".into(), ..Default::default() })
            .await
            .unwrap();
            d.record_container_exit_announcing("c1", "t".into(), 7, None, true, Box::new(|| {}))
                .await
                .unwrap();
            assert_eq!(d.removals_pending().await.unwrap(), ["c1"]);
        });
        drop(rt);
        let bundle = dir.path().join("bundle");
        let mon_dir = dir.path().join("mon");
        for d in [&bundle, &mon_dir] {
            std::fs::create_dir_all(d.join("sub")).unwrap();
            std::fs::write(d.join("sub/file"), b"x").unwrap();
        }
        let plan = SettlePlan {
            id: "c1".into(),
            db: db.clone(),
            start_lock: dir.path().join("c1.lock"),
            storage_lock: dir.path().join("storage.lock"),
            events: EventLog::File {
                path: dir.path().join("events"),
                max_size: 0,
            },
            network: None,
            removal: RemovalPlan {
                bundle,
                mon_dir,
                log_dir: dir.path().join("log"),
                secrets_dir: dir.path().join("secrets"),
                public_rootfs: None,
                named_files: Vec::new(),
                api_record: None,
                volumes_dir: dir.path().join("volumes"),
                volumes_lock: dir.path().join("volumes.lock"),
                lock_files: Vec::new(),
                writable: velarx_graph::WritableRelease::InBundle { pin: None },
            },
            image: image.then(|| ImageRef {
                id: "img".into(),
                event_id: "c".into(),
                name: Some(("localhost/i".into(), "1".into())),
            }),
            pod: None,
            cgroup: None,
        };
        let store = Store::open(&db).unwrap();
        Fixture { dir, plan, store }
    }

    fn rows(f: &Fixture, sql: &'static str) -> i64 {
        f.store
            .call(move |c| Ok(c.query_row(sql, [], |r| r.get(0))?))
            .unwrap()
    }

    fn go(f: &Fixture) -> Prepared {
        match prepare(&f.store, &f.plan, true).unwrap() {
            Prepare::Go(p) => *p,
            _ => panic!("the container goes"),
        }
    }

    /// The row, the image and the mark go in one transaction, and the files
    /// before: a removal that is done again after a kill finds nothing left
    /// of the files and finishes the rest.
    #[test]
    fn a_removal_done_again_finishes_what_was_left() {
        let f = fixture(true);
        // (killed in the middle of the files: some are gone)
        std::fs::remove_dir_all(&f.plan.removal.bundle).unwrap();
        let removal = finish(&f.store, &f.plan, go(&f), Some(7));
        assert!(removal.removed, "{:?}", removal.failure);
        assert!(removal.image.as_ref().is_some_and(|i| i.removed));
        assert_eq!(rows(&f, "SELECT count(*) FROM containers"), 0);
        assert_eq!(rows(&f, "SELECT count(*) FROM images"), 0);
        assert!(!f.plan.removal.mon_dir.exists());
        // (the layers of the image are released by the next collection)
        assert_eq!(
            rows(
                &f,
                "SELECT count(*) FROM store_settings WHERE key = 'gc_pending'"
            ),
            1
        );
        let events = std::fs::read_to_string(f.dir.path().join("events")).unwrap();
        assert!(events.contains("remove"), "{events}");
        // (another process that finished it first: not an error)
        let again = prepare(&f.store, &f.plan, true).unwrap();
        assert!(matches!(again, Prepare::Gone));
    }

    /// A name of an image with other names is untagged, the image stays, and
    /// an image another container uses stays with its container's removal
    /// done.
    #[test]
    fn the_image_goes_with_the_row_or_stays_with_it() {
        let f = fixture(true);
        f.store
            .call(|c| {
                c.execute_batch(
                    "INSERT INTO image_tags (repository, tag, image_id) VALUES ('localhost/i','2','img');",
                )?;
                Ok(())
            })
            .unwrap();
        let removal = finish(&f.store, &f.plan, go(&f), None);
        assert!(removal.removed);
        assert!(removal.image.is_some_and(|i| !i.removed));
        assert_eq!(rows(&f, "SELECT count(*) FROM images"), 1);
        assert_eq!(rows(&f, "SELECT count(*) FROM image_tags"), 1);

        let f = fixture(true);
        f.store
            .call(|c| {
                c.execute_batch(
                    "INSERT INTO containers (id, image_id, config, created_at) VALUES ('c2','img','{}','now');",
                )?;
                Ok(())
            })
            .unwrap();
        let removal = finish(&f.store, &f.plan, go(&f), None);
        assert!(removal.removed && removal.image.is_none());
        assert_eq!(rows(&f, "SELECT count(*) FROM images"), 1);
        assert_eq!(rows(&f, "SELECT count(*) FROM containers"), 1);
    }

    /// A container others depend on stays, and nobody tries its removal
    /// again: the mark is cleared.
    #[test]
    fn a_container_that_stays_is_not_a_removal_to_finish() {
        let f = fixture(false);
        f.store
            .call(|c| {
                c.execute_batch(
                    "INSERT INTO containers (id, name, image_id, config, created_at) VALUES ('c2','c2','img','{}','now');
                     INSERT INTO container_deps (container_id, target) VALUES ('c2','c1');",
                )?;
                Ok(())
            })
            .unwrap();
        assert!(matches!(
            prepare(&f.store, &f.plan, true).unwrap(),
            Prepare::Kept
        ));
        assert_eq!(
            rows(&f, "SELECT count(*) FROM containers WHERE removing = 1"),
            0
        );
        assert!(f.plan.removal.bundle.exists());
    }

    /// Files that cannot be removed keep the container listed, and the mark
    /// is cleared: the failure was reported, `rm` finishes it.
    #[test]
    fn a_failed_removal_is_not_tried_again_by_every_start() {
        let mut f = fixture(false);
        f.plan.removal.writable = velarx_graph::WritableRelease::Service {
            socket: f.dir.path().join("no-such-service"),
            timeout_secs: 1,
            store: "s".into(),
            pin: None,
        };
        let removal = finish(&f.store, &f.plan, go(&f), Some(7));
        assert!(!removal.removed && removal.failure.is_some());
        assert_eq!(rows(&f, "SELECT count(*) FROM containers"), 1);
        assert_eq!(
            rows(&f, "SELECT count(*) FROM containers WHERE removing = 1"),
            0
        );
        assert!(f.plan.removal.bundle.exists());
    }

    /// The volumes that go with the container are removed under the lock of
    /// the volumes, shared: a check of them waits for the removal.
    #[test]
    fn the_volumes_lock_is_held_while_anonymous_volumes_go() {
        let f = fixture(false);
        let config = ContainerConfig {
            id: "c1".into(),
            mounts: vec![crate::container::MountConfig {
                source: "/v/anon/_data".into(),
                target: "/d".into(),
                volume: Some("anon".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        f.store
            .call(move |c| {
                c.execute(
                    "UPDATE containers SET config = ?1",
                    [serde_json::to_string(&config).unwrap()],
                )?;
                c.execute_batch(
                    r#"INSERT INTO volumes (name, driver, mountpoint, labels, options, created_at, scope, state)
                         VALUES ('anon', '"local"', '/v/anon/_data', '{}', '{}', 't', 'local', '{"anonymous":true}');"#,
                )?;
                Ok(())
            })
            .unwrap();
        let lock = &f.plan.removal.volumes_lock;
        let prepared = go(&f);
        assert_eq!(prepared.volumes().len(), 1);
        assert!(velarx_storage::StorageLock::try_exclusive(lock)
            .unwrap()
            .is_none());
        assert!(finish(&f.store, &f.plan, prepared, None).removed);
        assert!(velarx_storage::StorageLock::try_exclusive(lock)
            .unwrap()
            .is_some());
        assert_eq!(rows(&f, "SELECT count(*) FROM volumes"), 0);
    }
}
