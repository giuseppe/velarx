// SPDX-License-Identifier: Apache-2.0
//! `system check` of the volumes: the directories under the volumes
//! directory are the truth, the rows of the database a copy of them.
//!
//! A volume is a directory `NAME` holding `_data` and `volume.json` (what
//! the directory alone does not say: labels, options, creation time,
//! state).  The check holds the lock of the volumes exclusive, so it never
//! sees a create, a rename or a removal half done: what it finds is what a
//! change that died left.  A repair writes and deletes rows, writes
//! `volume.json`, sets the mode of a directory, and removes a directory
//! only with `unlink` of `volume.json` and `rmdir`, never a tree: it never
//! deletes data.

use super::volume::{
    valid_volume_name, Volume, VolumeDriver, VolumeError, VolumeMeta, VolumeResult, VolumeService,
    VolumeState, VOLUME_DATA, VOLUME_META,
};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tracing::warn;
use velarx_storage::StorageLock;

/// What a repair does about a finding.
enum Fix {
    /// Nothing is touched.
    None,
    /// Set the mode of the directory to 0700.
    Chmod(PathBuf),
    /// Write the row of the volume.
    Row(Volume),
    /// Write `volume.json` of the directory from the volume, then its row.
    File(Volume, PathBuf),
    /// Delete the row of this name.
    DropRow(String),
    /// Remove the shell of a directory that holds no data (its
    /// `volume.json`, an empty `_data`, itself) and the row of the name.
    Shell(PathBuf, Option<String>),
}

/// A problem of the volumes.
pub struct VolumeFinding {
    pub kind: &'static str,
    /// The name of the entry of the volumes directory, or of the row.
    pub name: String,
    pub message: String,
    pub path: PathBuf,
    /// Whether the repair did what it set out to do.
    pub repaired: bool,
    fix: Fix,
}

/// What the check of the volumes found.
pub struct VolumeCheck {
    /// The entries of the volumes directory that were looked at.
    pub checked: usize,
    pub findings: Vec<VolumeFinding>,
}

impl VolumeFinding {
    fn new(
        kind: &'static str,
        name: &str,
        message: impl Into<String>,
        path: &Path,
        fix: Fix,
    ) -> Self {
        Self {
            kind,
            name: name.to_string(),
            message: message.into(),
            path: path.to_path_buf(),
            repaired: false,
            fix,
        }
    }
}

/// The volume `name` in `dir` as its `volume.json` says it.
fn volume_of(name: &str, dir: &Path, meta: VolumeMeta) -> Volume {
    Volume {
        name: name.to_string(),
        driver: VolumeDriver::Local,
        mountpoint: dir.join(VOLUME_DATA),
        labels: meta.labels,
        options: meta.options,
        created_at: meta.created_at,
        scope: "local".to_string(),
        state: meta.state,
    }
}

/// What differs between the volume the directory says and its row.
fn differs(dir: &Volume, row: &Volume) -> Vec<&'static str> {
    [
        ("mountpoint", dir.mountpoint != row.mountpoint),
        ("driver", dir.driver != row.driver),
        ("scope", dir.scope != row.scope),
        ("labels", dir.labels != row.labels),
        ("options", dir.options != row.options),
        ("created_at", dir.created_at != row.created_at),
        ("state", dir.state != row.state),
    ]
    .into_iter()
    .filter_map(|(field, differs)| differs.then_some(field))
    .collect()
}

/// What the directory `dir` of the entry `name`, which has `_data`, is.
fn whole(name: &str, dir: &Path, mode: u32, row: Option<&Volume>, found: &mut Vec<VolumeFinding>) {
    let finding = |kind, message: String, fix| VolumeFinding::new(kind, name, message, dir, fix);
    if mode & 0o7777 != 0o700 {
        found.push(finding(
            "volume_mode",
            format!(
                "the directory of {name} has mode {:o}, not 700",
                mode & 0o7777
            ),
            Fix::Chmod(dir.to_path_buf()),
        ));
    }
    let said = match VolumeMeta::read(dir) {
        Ok(meta) => volume_of(name, dir, meta),
        Err(e) => {
            let problem = match e.kind() {
                io::ErrorKind::NotFound => format!("volume.json of {name} is missing"),
                _ => format!("volume.json of {name} cannot be read: {e}"),
            };
            // (the row is all that is left of what the file said; with no
            // row there is nothing: the defaults)
            let (volume, from) = match row {
                Some(row) => (row.clone(), "its row"),
                None => (defaults(name, dir), "defaults"),
            };
            found.push(finding(
                "bad_volume_metadata",
                format!("{problem} (made again from {from})"),
                Fix::File(volume, dir.to_path_buf()),
            ));
            return;
        }
    };
    match row {
        None => found.push(finding(
            "orphan_volume",
            "a volume no row of the database names".to_string(),
            Fix::Row(said),
        )),
        Some(row) => {
            let fields = differs(&said, row);
            if !fields.is_empty() {
                found.push(finding(
                    "volume_row_mismatch",
                    format!(
                        "the row of {name} differs from its directory: {}",
                        fields.join(", ")
                    ),
                    Fix::Row(said),
                ));
            }
        }
    }
}

/// A volume that has nothing but its directory: no labels, no options,
/// created when the directory was, the owner of `_data` as its owner.
fn defaults(name: &str, dir: &Path) -> Volume {
    let (created, owner) = fs::metadata(dir)
        .and_then(|d| Ok((d.modified()?, fs::metadata(dir.join(VOLUME_DATA))?)))
        .map(|(modified, data)| (modified, (data.uid(), data.gid())))
        .unwrap_or((std::time::SystemTime::now(), (0, 0)));
    volume_of(
        name,
        dir,
        VolumeMeta {
            labels: HashMap::new(),
            options: HashMap::new(),
            created_at: chrono::DateTime::<chrono::Utc>::from(created).to_rfc3339(),
            state: VolumeState {
                uid: owner.0,
                gid: owner.1,
                ..Default::default()
            },
        },
    )
}

/// Look at the volumes directory and the rows; a volume directory is
/// owned by `me`, the engine's user.
fn scan(volumes: &Path, rows: &HashMap<String, Volume>, me: u32) -> io::Result<VolumeCheck> {
    let mut found = Vec::new();
    let mut names = HashSet::new();
    for entry in fs::read_dir(volumes)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let dir = entry.path();
        let meta = fs::symlink_metadata(&dir)?;
        names.insert(name.clone());
        let bad =
            |why: String| VolumeFinding::new("bad_volume_directory", &name, why, &dir, Fix::None);
        if !meta.is_dir() {
            found.push(bad(format!("{name} is not a directory")));
        } else if name.starts_with(".new-") {
            found.push(VolumeFinding::new(
                "stale_volume_temp",
                &name,
                "the directory of a volume create that did not finish",
                &dir,
                Fix::Shell(dir.clone(), None),
            ));
        } else if !valid_volume_name(&name) {
            found.push(bad(format!("{name} is not a volume name")));
        } else if meta.uid() != me {
            found.push(bad(format!("{name} is owned by the user {}", meta.uid())));
        } else {
            match fs::symlink_metadata(dir.join(VOLUME_DATA)) {
                Ok(data) if data.is_dir() => {
                    whole(&name, &dir, meta.mode(), rows.get(&name), &mut found)
                }
                Ok(_) => found.push(bad(format!("{name}: {VOLUME_DATA} is not a directory"))),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    let others = fs::read_dir(&dir)?
                        .filter_map(Result::ok)
                        .any(|e| e.file_name() != VOLUME_META);
                    if others {
                        found.push(bad(format!("{name} has no {VOLUME_DATA} and other files")));
                    } else {
                        found.push(VolumeFinding::new(
                            "unfinished_volume_removal",
                            &name,
                            format!("{name} was being removed"),
                            &dir,
                            Fix::Shell(dir.clone(), Some(name.clone())),
                        ));
                    }
                }
                Err(e) => found.push(bad(format!("{name} cannot be read: {e}"))),
            }
        }
    }
    let checked = names.len();
    for name in rows.keys().filter(|n| !names.contains(*n)) {
        let dir = volumes.join(name);
        found.push(VolumeFinding::new(
            "stale_volume_row",
            name,
            format!("{name} is recorded and its directory is gone"),
            &dir,
            Fix::DropRow(name.clone()),
        ));
    }
    Ok(VolumeCheck {
        checked,
        findings: found,
    })
}

/// Remove what a volume that holds no data is: an empty `_data`,
/// `volume.json`, the directory.  Anything else makes it fail; a `_data`
/// that holds something before anything is removed.
fn remove_shell(dir: &Path) -> io::Result<()> {
    let absent_ok = |r: io::Result<()>| match r {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    };
    absent_ok(fs::remove_dir(dir.join(VOLUME_DATA)))?;
    absent_ok(fs::remove_file(dir.join(VOLUME_META)))?;
    fs::remove_dir(dir)
}

impl VolumeService {
    /// Check the volumes, and with `repair` make the rows and the files
    /// say what the directories say.  The lock of the volumes is held
    /// exclusive, so no change is in flight.
    pub async fn check(&self, repair: bool) -> VolumeResult<VolumeCheck> {
        let _lock = StorageLock::exclusive(self.lock_path()).await?;
        let rows: HashMap<String, Volume> = self
            .list()
            .await?
            .into_iter()
            .map(|v| (v.name.clone(), v))
            .collect();
        let dir = self.volumes_dir.clone();
        let me = rustix::process::geteuid().as_raw();
        let mut check = crate::off_thread(move || scan(&dir, &rows, me)).await?;
        for f in check
            .findings
            .iter_mut()
            .filter(|f| f.kind == "stale_volume_row")
        {
            let users = self.users(&f.name).await?;
            if !users.is_empty() {
                f.message
                    .push_str(&format!(" (used by the containers {})", users.join(", ")));
            }
        }
        if repair {
            for f in check.findings.iter_mut() {
                f.repaired = match self.fix(&f.fix).await {
                    Ok(done) => done,
                    Err(e) => {
                        warn!("Cannot repair {}: {e}", f.path.display());
                        false
                    }
                };
            }
        }
        Ok(check)
    }

    /// Do what `fix` says: whether there was something to do.
    async fn fix(&self, fix: &Fix) -> VolumeResult<bool> {
        match fix {
            Fix::None => return Ok(false),
            Fix::Chmod(dir) => fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?,
            Fix::Row(volume) => self.store_volume(volume).await?,
            Fix::File(volume, dir) => {
                VolumeMeta::of(volume).write(dir)?;
                self.store_volume(volume).await?;
            }
            Fix::DropRow(name) => self.drop_row(name).await?,
            Fix::Shell(dir, row) => {
                remove_shell(dir)?;
                if let Some(name) = row {
                    self.drop_row(name).await?;
                }
            }
        }
        Ok(true)
    }

    async fn drop_row(&self, name: &str) -> VolumeResult<()> {
        let name = name.to_string();
        self.db
            .conn()
            .call(move |conn| velarx_db::volumes::delete(conn, &name))
            .await
            .map_err(|e| VolumeError::Database(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::volume::CreateVolume;
    use std::sync::Arc;
    use velarx_db::Database;

    async fn service() -> (VolumeService, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_in_memory().await.unwrap();
        (
            VolumeService::new(db, dir.path().join("volumes")).unwrap(),
            dir,
        )
    }

    /// A volume with a label, a file in its data.
    async fn volume(svc: &VolumeService, name: &str) -> Volume {
        let v = svc
            .create(
                name,
                VolumeDriver::Local,
                HashMap::from([("k".to_string(), "v".to_string())]),
                HashMap::new(),
            )
            .await
            .unwrap();
        fs::write(v.mountpoint.join("file"), b"data").unwrap();
        v
    }

    /// The volume as a row has it, with no row statement run.
    async fn forget_row(svc: &VolumeService, name: &str) {
        svc.drop_row(name).await.unwrap();
    }

    fn kinds(c: &VolumeCheck) -> Vec<(&'static str, &str)> {
        let mut k: Vec<_> = c
            .findings
            .iter()
            .map(|f| (f.kind, f.name.as_str()))
            .collect();
        k.sort();
        k
    }

    async fn clean(svc: &VolumeService) {
        let c = svc.check(false).await.unwrap();
        assert!(c.findings.is_empty(), "{:?}", kinds(&c));
    }

    #[tokio::test]
    async fn whole_volumes_are_not_findings() {
        let (svc, _dir) = service().await;
        volume(&svc, "a").await;
        // (made for a container that is gone: the sweep's business)
        svc.create_with(CreateVolume {
            anonymous: true,
            ..Default::default()
        })
        .await
        .unwrap();
        let c = svc.check(true).await.unwrap();
        assert!(c.findings.is_empty(), "{:?}", kinds(&c));
        assert_eq!(c.checked, 2);
    }

    #[tokio::test]
    async fn a_directory_no_row_names_gets_its_row() {
        let (svc, _dir) = service().await;
        let v = volume(&svc, "a").await;
        forget_row(&svc, "a").await;
        let c = svc.check(false).await.unwrap();
        assert_eq!(kinds(&c), [("orphan_volume", "a")]);
        assert!(!c.findings[0].repaired);
        assert!(svc.get("a").await.is_err());

        let c = svc.check(true).await.unwrap();
        assert!(c.findings[0].repaired);
        let back = svc.get("a").await.unwrap();
        assert_eq!(back.labels, v.labels);
        assert_eq!(back.created_at, v.created_at);
        assert_eq!(fs::read(v.mountpoint.join("file")).unwrap(), b"data");
        clean(&svc).await;
    }

    #[tokio::test]
    async fn a_row_without_a_directory_is_deleted_and_names_its_users() {
        let (svc, _dir) = service().await;
        volume(&svc, "a").await;
        volume(&svc, "b").await;
        for name in ["a", "b"] {
            fs::remove_dir_all(svc.volume_path(name)).unwrap();
        }
        let config = crate::container::ContainerConfig {
            mounts: vec![crate::container::MountConfig {
                volume: Some("a".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        svc.db
            .insert_container(&velarx_db::ContainerRecord {
                id: "c0ffee".into(),
                image_id: "i".into(),
                config: serde_json::to_string(&config).unwrap(),
                created_at: "2024-01-01T00:00:00Z".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let c = svc.check(false).await.unwrap();
        assert_eq!(
            kinds(&c),
            [("stale_volume_row", "a"), ("stale_volume_row", "b")]
        );
        let message = |name: &str| {
            let f = c.findings.iter().find(|f| f.name == name).unwrap();
            f.message.clone()
        };
        assert!(message("a").contains("used by the containers c0ffee"));
        assert!(!message("b").contains("used by"));

        let c = svc.check(true).await.unwrap();
        assert!(c.findings.iter().all(|f| f.repaired));
        assert!(svc.list().await.unwrap().is_empty());
        clean(&svc).await;
    }

    #[tokio::test]
    async fn a_row_that_differs_from_its_directory_is_written_again() {
        let (svc, _dir) = service().await;
        let v = volume(&svc, "a").await;
        // (a change that died between the file and the row)
        let mut state = v.state.clone();
        state.copied_up = true;
        VolumeMeta {
            labels: HashMap::from([("k".to_string(), "other".to_string())]),
            options: v.options.clone(),
            created_at: v.created_at.clone(),
            state: state.clone(),
        }
        .write(&svc.volume_path("a"))
        .unwrap();
        let c = svc.check(false).await.unwrap();
        assert_eq!(kinds(&c), [("volume_row_mismatch", "a")]);
        assert!(c.findings[0].message.ends_with("labels, state"));
        assert_eq!(svc.get("a").await.unwrap().labels["k"], "v");

        svc.check(true).await.unwrap();
        let back = svc.get("a").await.unwrap();
        assert_eq!(back.labels["k"], "other");
        assert_eq!(back.state, state);
        clean(&svc).await;
    }

    #[tokio::test]
    async fn a_volume_without_a_readable_file_gets_it_from_its_row() {
        let (svc, _dir) = service().await;
        let v = volume(&svc, "a").await;
        let file = svc.volume_path("a").join(VOLUME_META);
        for (damage, said) in [(None, "missing"), (Some("{"), "cannot be read")] {
            match damage {
                None => fs::remove_file(&file).unwrap(),
                Some(text) => fs::write(&file, text).unwrap(),
            }
            let c = svc.check(false).await.unwrap();
            assert_eq!(kinds(&c), [("bad_volume_metadata", "a")]);
            let message = &c.findings[0].message;
            assert!(
                message.contains(said) && message.contains("its row"),
                "{message}"
            );
            svc.check(true).await.unwrap();
            let meta = VolumeMeta::read(&svc.volume_path("a")).unwrap();
            assert_eq!(meta, VolumeMeta::of(&v));
            clean(&svc).await;
        }
    }

    #[tokio::test]
    async fn a_volume_with_neither_file_nor_row_gets_defaults() {
        let (svc, _dir) = service().await;
        let v = volume(&svc, "a").await;
        forget_row(&svc, "a").await;
        fs::remove_file(svc.volume_path("a").join(VOLUME_META)).unwrap();
        let c = svc.check(false).await.unwrap();
        assert_eq!(kinds(&c), [("bad_volume_metadata", "a")]);
        assert!(c.findings[0].message.contains("defaults"));

        svc.check(true).await.unwrap();
        let back = svc.get("a").await.unwrap();
        assert!(back.labels.is_empty() && back.options.is_empty());
        assert_eq!(back.mountpoint, v.mountpoint);
        let owner = fs::metadata(&v.mountpoint).unwrap();
        assert_eq!((back.state.uid, back.state.gid), (owner.uid(), owner.gid()));
        assert_eq!(fs::read(v.mountpoint.join("file")).unwrap(), b"data");
        clean(&svc).await;
    }

    #[tokio::test]
    async fn the_shell_of_an_unfinished_removal_goes_with_its_row() {
        let (svc, _dir) = service().await;
        volume(&svc, "a").await;
        fs::remove_dir_all(svc.volume_path("a").join(VOLUME_DATA)).unwrap();
        let c = svc.check(false).await.unwrap();
        assert_eq!(kinds(&c), [("unfinished_volume_removal", "a")]);

        svc.check(true).await.unwrap();
        assert!(!svc.volume_path("a").exists());
        assert!(svc.list().await.unwrap().is_empty());
        clean(&svc).await;
    }

    #[tokio::test]
    async fn a_directory_without_data_that_holds_something_is_left_alone() {
        let (svc, _dir) = service().await;
        volume(&svc, "a").await;
        let dir = svc.volume_path("a");
        fs::remove_dir_all(dir.join(VOLUME_DATA)).unwrap();
        fs::write(dir.join("precious"), b"x").unwrap();
        let c = svc.check(true).await.unwrap();
        assert_eq!(kinds(&c), [("bad_volume_directory", "a")]);
        assert!(!c.findings[0].repaired);
        assert_eq!(fs::read(dir.join("precious")).unwrap(), b"x");
        assert!(svc.get("a").await.is_ok());
    }

    #[tokio::test]
    async fn a_temporary_directory_goes_unless_it_holds_data() {
        let (svc, _dir) = service().await;
        let empty = svc.volume_path(".new-a");
        fs::create_dir_all(empty.join(VOLUME_DATA)).unwrap();
        fs::write(empty.join(VOLUME_META), b"{}").unwrap();
        let full = svc.volume_path(".new-b");
        fs::create_dir_all(full.join(VOLUME_DATA)).unwrap();
        fs::write(full.join(VOLUME_DATA).join("file"), b"data").unwrap();
        fs::write(full.join(VOLUME_META), b"{}").unwrap();
        let c = svc.check(false).await.unwrap();
        assert_eq!(
            kinds(&c),
            [
                ("stale_volume_temp", ".new-a"),
                ("stale_volume_temp", ".new-b")
            ]
        );
        let c = svc.check(true).await.unwrap();
        let repaired = |name: &str| c.findings.iter().find(|f| f.name == name).unwrap().repaired;
        assert!(repaired(".new-a") && !repaired(".new-b"));
        assert!(!empty.exists());
        assert_eq!(
            fs::read(full.join(VOLUME_DATA).join("file")).unwrap(),
            b"data"
        );
        // (nothing of it is removed)
        assert_eq!(fs::read(full.join(VOLUME_META)).unwrap(), b"{}");
    }

    /// A directory the engine cannot look into is a finding of its own,
    /// not a check that fails.
    #[tokio::test]
    async fn a_directory_that_cannot_be_read_is_a_finding() {
        let (svc, _dir) = service().await;
        volume(&svc, "a").await;
        volume(&svc, "b").await;
        let dir = svc.volume_path("a");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).unwrap();
        let c = svc.check(false).await;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let c = c.unwrap();
        assert!(!c.findings.is_empty());
        assert!(c.findings.iter().all(|f| f.name == "a"), "{:?}", kinds(&c));
    }

    /// A volume directory is the engine's: one of another user is not
    /// touched (a volume of a container with a mapping has its `_data`
    /// chowned, not its directory).
    #[tokio::test]
    async fn a_directory_of_another_user_stays_open_and_untouched() {
        let (svc, _dir) = service().await;
        volume(&svc, "a").await;
        let me = rustix::process::geteuid().as_raw();
        let rows = HashMap::from([("a".to_string(), svc.get("a").await.unwrap())]);
        let c = scan(svc.volumes_dir(), &rows, me).unwrap();
        assert!(c.findings.is_empty(), "{:?}", kinds(&c));
        let c = scan(svc.volumes_dir(), &rows, me + 1).unwrap();
        assert_eq!(kinds(&c), [("bad_volume_directory", "a")]);
        assert!(matches!(c.findings[0].fix, Fix::None));
        assert!(c.findings[0]
            .message
            .contains(&format!("owned by the user {me}")));
    }

    #[tokio::test]
    async fn a_directory_that_is_not_0700_is_set_to_it() {
        let (svc, _dir) = service().await;
        let v = volume(&svc, "a").await;
        let dir = svc.volume_path("a");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let c = svc.check(false).await.unwrap();
        assert_eq!(kinds(&c), [("volume_mode", "a")]);
        assert!(c.findings[0].message.contains("755"));

        svc.check(true).await.unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o7777, 0o700);
        assert_eq!(fs::read(v.mountpoint.join("file")).unwrap(), b"data");
        clean(&svc).await;
    }

    #[tokio::test]
    async fn what_is_no_volume_stays_open_and_untouched() {
        let (svc, _dir) = service().await;
        let root = svc.volumes_dir().to_path_buf();
        fs::write(root.join("junk"), b"x").unwrap();
        // (a link to a directory that looks like a volume, the engine's)
        let outside = root.parent().unwrap().join("outside");
        fs::create_dir_all(outside.join(VOLUME_DATA)).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        fs::create_dir_all(root.join("bad name").join(VOLUME_DATA)).unwrap();
        fs::create_dir_all(root.join("file")).unwrap();
        fs::write(root.join("file").join(VOLUME_DATA), b"x").unwrap();
        let before = tree(&root);
        let c = svc.check(true).await.unwrap();
        assert_eq!(
            kinds(&c),
            [
                ("bad_volume_directory", "bad name"),
                ("bad_volume_directory", "file"),
                ("bad_volume_directory", "junk"),
                ("bad_volume_directory", "link"),
            ]
        );
        assert!(c.findings.iter().all(|f| !f.repaired));
        assert_eq!(tree(&root), before);
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
        assert!(svc.list().await.unwrap().is_empty());
    }

    /// Every path under `dir` with its mode.
    fn tree(dir: &Path) -> Vec<(PathBuf, u32)> {
        let mut all = Vec::new();
        for e in fs::read_dir(dir).unwrap() {
            let path = e.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                all.extend(tree(&path));
            }
            all.push((path, meta.mode()));
        }
        all.sort();
        all
    }

    /// A change of a volume holds the lock shared, and the check does not
    /// look until it is done.
    #[tokio::test]
    async fn a_check_waits_for_a_change_in_flight() {
        let (svc, _dir) = service().await;
        let svc = Arc::new(svc);
        let lock = svc.lock_path().to_path_buf();
        let change = StorageLock::shared(&lock).await.unwrap();
        let checking = tokio::spawn({
            let svc = svc.clone();
            async move { svc.check(true).await.unwrap() }
        });
        let waiter = lock.clone();
        let waits = tokio::task::spawn_blocking(move || {
            velarx_base::testing::wait_lock_waiter(&waiter, std::time::Duration::from_secs(20))
        });
        assert!(waits.await.unwrap(), "the check does not take the lock");
        assert!(!checking.is_finished());
        drop(change);
        assert!(checking.await.unwrap().findings.is_empty());
    }
}
