// SPDX-License-Identifier: Apache-2.0
//! `pods/<id>.json`: the pods the engine keeps, changed under one lock by
//! every process that changes them (the engine, the daemonless command line
//! and the monitors of the members).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::warn;
use velarx_proto::pod::PodSpec;

/// Why the pod store could not be read or changed.
#[derive(thiserror::Error, Debug)]
pub enum StoreError {
    #[error("pod not found: {0}")]
    NotFound(String),
    #[error("adding pod to state: name \"{0}\" is in use: pod already exists")]
    AlreadyExists(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type StoreResult<T> = Result<T, StoreError>;

/// Pod state
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PodState {
    Created,
    Running,
    Paused,
    Stopped,
    Exited,
    Dead,
}

impl std::fmt::Display for PodState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PodState::Created => write!(f, "created"),
            PodState::Running => write!(f, "running"),
            PodState::Paused => write!(f, "paused"),
            PodState::Stopped => write!(f, "stopped"),
            PodState::Exited => write!(f, "exited"),
            PodState::Dead => write!(f, "dead"),
        }
    }
}

/// Pod information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pod {
    pub id: String,
    pub name: String,
    pub state: PodState,
    pub infra_container_id: Option<String>,
    pub container_ids: Vec<String>,
    pub spec: PodSpec,
    pub created_at: String,
    pub started_at: Option<String>,
    pub exit_code: Option<i32>,
    /// Being removed: no container joins it any more.
    #[serde(default)]
    pub removing: bool,
}

/// What a member of a pod does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberRun {
    Running,
    Paused,
    Idle,
}

/// The state of a pod whose members are `runs`: running if one runs, else
/// paused if one is, else `ended`.  A pod never started stays created.
pub fn settled_state(runs: &[MemberRun], ended: PodState, current: &PodState) -> PodState {
    if runs.contains(&MemberRun::Running) {
        PodState::Running
    } else if runs.contains(&MemberRun::Paused) {
        PodState::Paused
    } else if *current == PodState::Created {
        PodState::Created
    } else {
        ended
    }
}

/// `pods/<id>.json` of the pods, changed only under one lock.
#[derive(Clone)]
pub struct PodStore {
    pub dir: PathBuf,
}

impl PodStore {
    /// Run `f` with the lock of the pod store held: one lock for every
    /// process that changes `pods/` (the engine and the daemonless command
    /// line), taken only for file operations, never across a container call.
    pub fn with_store_lock<T>(&self, f: impl FnOnce(&Path) -> StoreResult<T>) -> StoreResult<T> {
        let dir = self.dir.clone();
        std::fs::create_dir_all(&dir)?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(".lock"))?;
        velarx_sys::flock::flock_retrying(&lock, rustix::fs::FlockOperation::LockExclusive)?;
        f(&dir)
    }

    /// Take the lock `kind` of the pod `id`: `lock` serializes the settling
    /// of its state, held while the members are looked at and the state
    /// written, never while a container is started or stopped; `op.lock`
    /// serializes the operations on the pod (start, stop, kill, remove...),
    /// held across them.
    /// A pod that is gone (`NotFound`) has no lock: its removal unlinks the
    /// file while it holds it, so a lock taken on the file it unlinked, or
    /// on one made again after, is no lock of the pod.
    pub fn lock_file(&self, id: &str, kind: &str) -> StoreResult<std::fs::File> {
        use std::os::unix::fs::MetadataExt;
        std::fs::create_dir_all(&self.dir)?;
        let path = self.dir.join(format!(".{id}.{kind}"));
        loop {
            let lock = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&path)?;
            velarx_sys::flock::flock_retrying(&lock, rustix::fs::FlockOperation::LockExclusive)?;
            let at_path = match std::fs::symlink_metadata(&path) {
                Ok(m) => m.ino() == lock.metadata()?.ino(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                Err(e) => return Err(e.into()),
            };
            if !self.dir.join(format!("{id}.json")).exists() {
                if at_path {
                    let _ = std::fs::remove_file(&path);
                }
                return Err(StoreError::NotFound(id.to_string()));
            }
            if at_path {
                return Ok(lock);
            }
        }
    }

    pub fn write_pod(dir: &Path, pod: &Pod) -> StoreResult<()> {
        let content = serde_json::to_string_pretty(pod)
            .map_err(|e| StoreError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        // (on disk before the rename: a crash leaves the old file or the
        // new one, never an empty one, which the list would skip)
        velarx_base::atomic_file::write_durable(
            &dir.join(format!("{}.json", pod.id)),
            content.as_bytes(),
            0o644,
        )?;
        Ok(())
    }

    /// Store a new pod; a pod of that name that exists is an error.
    pub fn add(&self, pod: &Pod) -> StoreResult<()> {
        self.with_store_lock(|dir| {
            if Self::read_all(dir)?.iter().any(|p| p.name == pod.name) {
                return Err(StoreError::AlreadyExists(pod.name.clone()));
            }
            Self::write_pod(dir, pod)
        })
    }

    /// Change the pod `id` as it is on disk now, under the lock of the
    /// store: `f` sees what the other changes left (a member added while
    /// the caller worked is still in the list), and a pod that was removed
    /// meanwhile stays removed (`NotFound`).
    pub fn modify<R>(&self, id: &str, f: impl FnOnce(&mut Pod) -> R) -> StoreResult<R> {
        self.with_store_lock(|dir| {
            let path = dir.join(format!("{id}.json"));
            let content = std::fs::read_to_string(&path).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => StoreError::NotFound(id.to_string()),
                _ => e.into(),
            })?;
            let mut pod: Pod = serde_json::from_str(&content).map_err(|e| {
                StoreError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?;
            let r = f(&mut pod);
            Self::write_pod(dir, &pod)?;
            Ok(r)
        })
    }

    pub fn remove(&self, id: &str) -> StoreResult<()> {
        self.with_store_lock(|dir| {
            // (the pod first: a lock taken once its file is gone sees it gone)
            match std::fs::remove_file(dir.join(format!("{id}.json"))) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => {}
            }
            let _ = std::fs::remove_file(dir.join(format!(".{id}.lock")));
            let _ = std::fs::remove_file(dir.join(format!(".{id}.op.lock")));
            Ok(())
        })
    }

    pub fn list(&self) -> StoreResult<Vec<Pod>> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }
        Self::read_all(&self.dir)
    }

    pub fn read_all(pods_dir: &Path) -> StoreResult<Vec<Pod>> {
        let mut pods = Vec::new();
        for entry in std::fs::read_dir(pods_dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                let content = match std::fs::read_to_string(&path) {
                    Ok(content) => content,
                    // (removed meanwhile)
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => {
                        warn!("Cannot read the pod {}: {e}", path.display());
                        continue;
                    }
                };
                match serde_json::from_str::<Pod>(&content) {
                    Ok(pod) => pods.push(pod),
                    Err(e) => warn!("Cannot read the pod {}: {e}", path.display()),
                }
            }
        }
        pods.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(pods)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(id: &str, name: &str) -> Pod {
        Pod {
            id: id.into(),
            name: name.into(),
            state: PodState::Created,
            infra_container_id: None,
            container_ids: Vec::new(),
            spec: PodSpec::default(),
            created_at: String::new(),
            started_at: None,
            exit_code: None,
            removing: false,
        }
    }

    /// A link at the name the file was once written through is not followed.
    #[test]
    fn a_pod_is_written_to_a_temporary_name_of_its_own() {
        let d = tempfile::tempdir().unwrap();
        let victim = d.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, d.path().join(".abc.json.tmp")).unwrap();
        PodStore::write_pod(d.path(), &stored("abc", "one")).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        let back: Pod =
            serde_json::from_slice(&std::fs::read(d.path().join("abc.json")).unwrap()).unwrap();
        assert_eq!(back.name, "one");
    }

    #[test]
    fn the_state_of_a_pod_follows_its_members() {
        use MemberRun::*;
        let st = |r: &[MemberRun], e, c| settled_state(r, e, &c);
        assert_eq!(
            st(&[Idle, Running], PodState::Stopped, PodState::Stopped),
            PodState::Running
        );
        assert_eq!(
            st(&[Paused, Running], PodState::Stopped, PodState::Running),
            PodState::Running
        );
        assert_eq!(
            st(&[Paused, Idle], PodState::Stopped, PodState::Running),
            PodState::Paused
        );
        assert_eq!(
            st(&[Idle, Idle], PodState::Exited, PodState::Running),
            PodState::Exited
        );
        assert_eq!(
            st(&[Idle], PodState::Stopped, PodState::Created),
            PodState::Created
        );
        assert_eq!(
            st(&[], PodState::Stopped, PodState::Running),
            PodState::Stopped
        );
    }

    /// Members added while the pod is updated by others are all kept, and a
    /// pod that was removed is not written again by a late change.
    #[test]
    fn changes_of_a_stored_pod_do_not_lose_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(PodStore {
            dir: dir.path().join("pods"),
        });
        store.add(&stored("p1", "one")).unwrap();
        assert!(matches!(
            store.add(&stored("p2", "one")),
            Err(StoreError::AlreadyExists(_))
        ));
        std::thread::scope(|s| {
            for n in 0..16 {
                let store = &store;
                s.spawn(move || {
                    store
                        .modify("p1", |p| p.container_ids.push(format!("c{n}")))
                        .unwrap();
                    store
                        .modify("p1", |p| p.spec.hostname = Some(format!("h{n}")))
                        .unwrap();
                });
            }
        });
        let pod = store.list().unwrap().remove(0);
        assert_eq!(pod.container_ids.len(), 16, "{:?}", pod.container_ids);

        store.remove("p1").unwrap();
        assert!(matches!(
            store.modify("p1", |p| p.state = PodState::Running),
            Err(StoreError::NotFound(_))
        ));
        assert!(store.list().unwrap().is_empty());
    }

    /// Two operations on one pod run one after the other; another pod's
    /// are not held up, and the settling lock is not the operation lock.
    ///
    /// In a process of its own: a lock is released when the last descriptor
    /// of its file goes, and a process another test forks meanwhile holds a
    /// copy of the descriptors until it runs its program.
    #[test]
    fn the_operations_on_a_pod_are_serialised() {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let store = std::sync::Arc::new(PodStore {
                dir: dir.path().join("pods"),
            });
            std::fs::create_dir_all(&store.dir).unwrap();
            for id in ["p1", "p2"] {
                std::fs::write(store.dir.join(format!("{id}.json")), "{}").unwrap();
            }
            let first = store.lock_file("p1", "op.lock").unwrap();
            let other = store.lock_file("p2", "op.lock").unwrap();
            let settling = store.lock_file("p1", "lock").unwrap();
            // (a second descriptor of the lock file does not get it)
            let try_lock = |kind: &str, id: &str| {
                let f = std::fs::File::open(store.dir.join(format!(".{id}.{kind}"))).unwrap();
                rustix::fs::flock(&f, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_ok()
            };
            assert!(!try_lock("op.lock", "p1"));
            assert!(!try_lock("lock", "p1"));
            drop(settling);
            assert!(try_lock("lock", "p1"));
            assert!(!try_lock("op.lock", "p1"));
            drop((first, other));
            assert!(try_lock("op.lock", "p1"));
            assert!(try_lock("op.lock", "p2"));
            // a pod removed while its lock is held, or waited for, has no lock
            // any more: the waiter is told it is gone, and leaves no file
            let held = store.lock_file("p1", "op.lock").unwrap();
            let waiter = {
                let store = store.clone();
                std::thread::spawn(move || store.lock_file("p1", "op.lock").map(drop))
            };
            // (asleep in the lock: the removal comes while it is waited for)
            assert!(
                velarx_base::testing::wait_lock_waiter(
                    &store.dir.join(".p1.op.lock"),
                    std::time::Duration::from_secs(30)
                ),
                "nothing waits for the lock"
            );
            store.remove("p1").unwrap();
            drop(held);
            assert!(matches!(
                waiter.join().unwrap(),
                Err(StoreError::NotFound(_))
            ));
            assert!(matches!(
                store.lock_file("p1", "op.lock"),
                Err(StoreError::NotFound(_))
            ));
            assert!(!store.dir.join(".p1.op.lock").exists());
        });
    }
}
