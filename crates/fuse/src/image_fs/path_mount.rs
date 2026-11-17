// SPDX-License-Identifier: Apache-2.0
//! The mounts of the tests of the FUSE file system at a path: a test reads
//! the files it serves as a process that mounted it, without the privilege
//! the detached mounts of the image server need.

use super::*;

pub(super) struct Mounted {
    path: PathBuf,
    /// Dropping it unmounts the file system: the session's thread then
    /// reads the end of it and ends.
    _unmount: Unmount,
}

/// The unmount of a session, and its thread, which gives the session back
/// when it ends.
struct Unmount(
    fuser::SessionUnmounter,
    Option<std::thread::JoinHandle<fuser::Session<ImageFs>>>,
);

impl Drop for Unmount {
    fn drop(&mut self) {
        let _ = self.0.unmount();
        // (a thread still serving ends at the end of its device; the mount
        // was taken from its session, which then unmounts nothing)
        if let Some(thread) = self.1.take().filter(|t| t.is_finished()) {
            drop(thread.join());
        }
    }
}

impl ImageMounts {
    /// Mounts that tests make at paths below `root`.
    pub(super) fn at(root: PathBuf, store: Arc<FileStore>) -> Self {
        let mut mounts = Self::new(store);
        mounts.root = root;
        mounts
    }

    /// Mount `fs` at `path` and keep its session under `key`.
    pub(super) fn serve(
        &self,
        fs: ImageFs,
        path: &Path,
        allow_other: bool,
        mounts: &mut HashMap<String, Mounted>,
        key: String,
    ) -> FuseResult<PathBuf> {
        detach_stale(path)?;
        std::fs::create_dir_all(path)?;
        let mut options = vec![
            fuser::MountOption::RO,
            fuser::MountOption::FSName("velarx".to_string()),
            fuser::MountOption::Subtype("image".to_string()),
            fuser::MountOption::DefaultPermissions,
        ];
        if allow_other {
            options.push(fuser::MountOption::AllowOther);
        }
        let shared = fs.shared.clone();
        let mut session = fuser::Session::new(fs, path, &options)
            .map_err(|e| FuseError::Mount(format!("cannot mount {}: {e}", path.display())))?;
        let mut unmount = Unmount(session.unmount_callable(), None);
        unmount.1 = Some(self.run_session(session, shared, &path.display().to_string())?);
        mounts.insert(
            key,
            Mounted {
                path: path.to_path_buf(),
                _unmount: unmount,
            },
        );
        Ok(path.to_path_buf())
    }

    /// The layers of `image` served from `tree` at a path: the directory of
    /// the mount, mounting it first if needed.
    pub(super) fn mount_tree(
        &self,
        image: &str,
        tree: Arc<dyn Tree>,
        layers: Vec<String>,
        owners: (Vec<u32>, Vec<u32>),
        translate: Option<&IdTranslate>,
    ) -> FuseResult<PathBuf> {
        let key = format!("{image}-mapped");
        let key = match translate {
            Some(t) => format!("{key}-{}", t.key()),
            None => key,
        };
        let mut mounts = self.mounts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(m) = mounts.get(&key) {
            return Ok(m.path.clone());
        }
        let fs = self.tree_fs(tree, layers, owners, translate)?;
        let path = self.root.join(&key);
        self.serve(fs, &path, translate.is_some(), &mut mounts, key)
    }

    /// Unmount everything.
    pub(super) fn unmount_all(&self) {
        let recording = self
            .recording
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(recording) = recording {
            recording.save();
        }
        let mut mounts = self.mounts.lock().unwrap_or_else(|e| e.into_inner());
        for (_, m) in mounts.drain() {
            // a plain unmount fails while something still holds the file
            // system: detach it
            unmount_or_detach(&m.path);
            drop(m);
        }
    }
}

impl Drop for ImageMounts {
    fn drop(&mut self) {
        self.unmount_all();
    }
}
