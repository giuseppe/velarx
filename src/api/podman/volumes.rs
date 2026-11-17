// SPDX-License-Identifier: Apache-2.0
//! Volumes: podman's VolumeConfigResponse and Docker's Volume.

use super::call::{label_matches, Filters};
use super::convert::record_time_ns;
use super::error::{ApiError, ApiResult};
use super::events::Event;
use crate::api::AppState;
use bytes::Bytes;
use futures::StreamExt;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Component, Path};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use velarx_core::services::{Volume, VolumeDriver};
use velarx_proto::workload::EventKind;
use velarx_proto::workload::{VolumeRecord, VolumeSpec};

/// A volume as the engine answers it.
pub(crate) fn record(v: &Volume) -> VolumeRecord {
    VolumeRecord {
        name: v.name.clone(),
        driver: match &v.driver {
            VolumeDriver::Local => "local".into(),
            VolumeDriver::Named => "named".into(),
            VolumeDriver::Custom(name) => name.clone(),
        },
        mountpoint: v.mountpoint.to_string_lossy().into_owned(),
        created_ns: record_time_ns(&v.created_at),
        labels: v.labels.clone().into_iter().collect(),
        options: v.options.clone().into_iter().collect(),
        scope: v.scope.clone(),
        uid: i64::from(v.state.uid),
        gid: i64::from(v.state.gid),
        anonymous: v.state.anonymous,
        needs_copy_up: v.state.needs_copy_up,
        needs_chown: v.state.needs_chown,
    }
}

/// Create the volume `spec` says (a name of the engine's if it has none);
/// with `ignore_if_exists` a volume of that name is the answer.
pub(crate) async fn create_of(
    state: &Arc<AppState>,
    spec: &VolumeSpec,
    ignore_if_exists: bool,
) -> ApiResult<VolumeRecord> {
    if !spec.driver.is_empty() && spec.driver != "local" {
        return Err(ApiError::not_implemented(format!(
            "the volume driver `{}` is not supported",
            spec.driver
        )));
    }
    let svc = &state.volume_service;
    if ignore_if_exists && !spec.name.is_empty() {
        if let Ok(v) = svc.get(&spec.name).await {
            return Ok(record(&v));
        }
    }
    let v = svc
        .create_with(velarx_core::services::CreateVolume {
            name: (!spec.name.is_empty()).then(|| spec.name.clone()),
            labels: spec.labels.clone().into_iter().collect(),
            options: spec.options.clone().into_iter().collect(),
            ..Default::default()
        })
        .await
        .map_err(|e| match e {
            velarx_core::services::VolumeError::AlreadyExists(_) => {
                ApiError::conflict(e.to_string()).with_cause("volume already exists")
            }
            velarx_core::services::VolumeError::InvalidOption(_)
            | velarx_core::services::VolumeError::Parse(_) => ApiError::bad_request(e.to_string()),
            e => e.into(),
        })?;
    state
        .podman
        .events
        .emit(Event::new(EventKind::Volume, "create", "", &v.name));
    Ok(record(&v))
}

/// podman's MatchLabelFilters: every `KEY` or `KEY=VALUE` matches.
fn labels_match(labels: &HashMap<String, String>, specs: &[String]) -> bool {
    specs.iter().all(|s| label_matches(labels, s))
}

fn bool_filter(key: &str, values: &[String]) -> ApiResult<Vec<bool>> {
    values
        .iter()
        .map(|v| match v.to_lowercase().as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => Err(ApiError::bad_request(format!(
                "{v:?} is not a valid value for the {key:?} filter - must be true or false"
            ))),
        })
        .collect()
}

/// The volumes of `all` that the filters of a list (or, with `prune`, of a
/// prune) select, as podman's GenerateVolumeFilters and
/// GeneratePruneVolumeFilters: the filters are ANDed, the values of one are
/// ORed but for the labels; an unknown filter is an error.
pub(super) async fn select(
    svc: &velarx_core::services::VolumeService,
    filters: &Filters,
    all: Vec<Volume>,
    prune: bool,
) -> ApiResult<Vec<Volume>> {
    let created = |v: &Volume| {
        chrono::DateTime::parse_from_rfc3339(&v.created_at)
            .ok()
            .and_then(|t| t.timestamp_nanos_opt())
            .unwrap_or(0)
    };
    // (checked before the first volume: no volume is no reason to accept
    // a filter that is not one)
    for (key, values) in &filters.0 {
        match key.as_str() {
            "label" | "label!" | "after" | "since" => {}
            "until" => {
                if !values
                    .iter()
                    .any(|u| super::events::parse_since(u).is_some())
                {
                    return Err(ApiError::bad_request(format!(
                        "invalid until filter {values:?}"
                    )));
                }
            }
            "anonymous" => {
                bool_filter(key, values)?;
            }
            "dangling" if !prune => {
                bool_filter(key, values)?;
            }
            "name" | "driver" | "scope" | "opt" if !prune => {}
            _ => {
                return Err(
                    ApiError::bad_request(format!("{key:?} is an invalid volume filter"))
                        .with_cause(format!("{key:?} is an invalid volume filter")),
                )
            }
        }
    }
    let mut out = Vec::new();
    'volumes: for v in all {
        for (key, values) in &filters.0 {
            let ok = match key.as_str() {
                "label" => labels_match(&v.labels, values),
                "label!" => !values.iter().any(|s| label_matches(&v.labels, s)),
                "until" => {
                    let until = values
                        .iter()
                        .filter_map(|u| super::events::parse_since(u))
                        .max()
                        .ok_or_else(|| {
                            ApiError::bad_request(format!("invalid until filter {values:?}"))
                        })?;
                    created(&v) < until
                }
                "anonymous" => bool_filter(key, values)?.contains(&v.state.anonymous),
                "after" | "since" => {
                    let mut after = None;
                    for name in values {
                        let other = svc.get(name).await?;
                        let t = created(&other);
                        after = Some(after.map_or(t, |a: i64| a.min(t)));
                    }
                    after.is_some_and(|a| created(&v) > a)
                }
                // podman's StringMatchRegexSlice: the name, or a regular
                // expression that matches it
                "name" if !prune => values.iter().any(|s| {
                    v.name == *s || regex_lite::Regex::new(s).is_ok_and(|r| r.is_match(&v.name))
                }),
                "driver" if !prune => values.iter().any(|s| s == "local"),
                "scope" if !prune => values.contains(&v.scope),
                "opt" if !prune => values.iter().any(|s| {
                    let (k, want) = s.split_once('=').unwrap_or((s, ""));
                    v.options
                        .get(k)
                        .is_some_and(|o| want.is_empty() || o == want)
                }),
                "dangling" if !prune => {
                    let used = !svc.users(&v.name).await?.is_empty();
                    bool_filter(key, values)?.contains(&!used)
                }
                _ => {
                    return Err(ApiError::bad_request(format!(
                        "{key:?} is an invalid volume filter"
                    ))
                    .with_cause(format!("{key:?} is an invalid volume filter")))
                }
            };
            if !ok {
                continue 'volumes;
            }
        }
        out.push(v);
    }
    Ok(out)
}

/// Give the volume another name.
pub(crate) async fn rename_of(state: &Arc<AppState>, name: &str, new_name: &str) -> ApiResult<()> {
    state
        .volume_service
        .rename(name, new_name)
        .await
        .map_err(|e| match e {
            velarx_core::services::VolumeError::AlreadyExists(_) => {
                ApiError::conflict(e.to_string())
            }
            velarx_core::services::VolumeError::InUse(_) => ApiError::invalid_state(e.to_string()),
            e => e.into(),
        })?;
    state
        .podman
        .events
        .emit(Event::new(EventKind::Volume, "rename", "", new_name).attr("oldName", name));
    Ok(())
}

/// The volumes `filters` selects.
pub(crate) async fn list_of(state: &AppState, filters: &Filters) -> ApiResult<Vec<VolumeRecord>> {
    let svc = &state.volume_service;
    Ok(select(svc, filters, svc.list().await?, false)
        .await?
        .iter()
        .map(record)
        .collect())
}

pub(crate) async fn inspect_of(state: &AppState, name: &str) -> ApiResult<VolumeRecord> {
    Ok(record(&state.volume_service.get(name).await?))
}

/// The volume is there.
pub(crate) async fn exists_of(state: &AppState, name: &str) -> ApiResult<()> {
    state.volume_service.get(name).await?;
    Ok(())
}

/// Remove the volume; with `force`, the containers that use it go first
/// (given `timeout` seconds to stop, none: their own): podman's warnings of
/// the stops that needed the kill.
pub(crate) async fn remove_of(
    state: &Arc<AppState>,
    name: &str,
    force: bool,
    timeout: Option<u64>,
) -> ApiResult<Vec<String>> {
    let svc = &state.volume_service;
    let mut warnings = Vec::new();
    if force {
        for id in svc.users(name).await? {
            let rec = super::lifecycle::resolve(state, &id).await?;
            warnings.extend(
                super::lifecycle::remove_with_timeout(state, &rec, true, false, timeout).await?,
            );
        }
    }
    if let Err(e) = svc.remove(name, force).await {
        return Err(match e {
            velarx_core::services::VolumeError::InUse(_) => {
                // podman's words: who uses it
                let users = svc.users(name).await.unwrap_or_default();
                ApiError::invalid_state(format!(
                    "volume {name} is being used by the following container(s): {}: volume is being used",
                    users.join(", ")
                ))
            }
            e => e.into(),
        });
    }
    state
        .podman
        .events
        .emit(Event::new(EventKind::Volume, "remove", "", name));
    Ok(warnings)
}

/// Mount what the options of a volume ask for: where it is.
pub(crate) async fn mount_of(state: &AppState, name: &str) -> ApiResult<String> {
    let path = state.volume_service.mount(name).await?;
    Ok(path.to_string_lossy().into_owned())
}

/// Unmount what [`mount_of`] mounted.
pub(crate) async fn unmount_of(state: &AppState, name: &str) -> ApiResult<()> {
    Ok(state.volume_service.unmount(name).await?)
}

/// Remove the volumes no container uses that `filters` selects: their names and
/// the bytes they had.  With `dry_run`, only say which: nothing is removed.
pub(crate) async fn prune_of(
    state: &Arc<AppState>,
    filters: &Filters,
    dry_run: bool,
) -> ApiResult<Vec<(String, i64)>> {
    filters.check_prune_until()?;
    let svc = &state.volume_service;
    let mut unused = Vec::new();
    for v in select(svc, filters, svc.list().await?, true).await? {
        if svc.users(&v.name).await?.is_empty() {
            unused.push(v);
        }
    }
    // (before anything is removed: what the volumes had)
    let mountpoints: Vec<_> = unused.iter().map(|v| v.mountpoint.clone()).collect();
    let sizes = tokio::task::spawn_blocking(move || {
        mountpoints
            .iter()
            .map(|p| super::system::dir_usage(p))
            .collect::<Vec<i64>>()
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let mut deleted = Vec::new();
    for (v, size) in unused.into_iter().zip(sizes) {
        if dry_run {
            deleted.push((v.name, size));
        } else if svc.remove(&v.name, false).await.is_ok() {
            state
                .podman
                .events
                .emit(Event::new(EventKind::Volume, "remove", "", &v.name));
            deleted.push((v.name, size));
        }
    }
    Ok(deleted)
}

/// A `Write` that sends what it gets to a response body.
struct ChannelWriter {
    tx: tokio::sync::mpsc::Sender<Result<Bytes, io::Error>>,
    buf: Vec<u8>,
}

impl Write for ChannelWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= 64 * 1024 {
            self.flush()?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let chunk = Bytes::from(std::mem::take(&mut self.buf));
        self.tx
            .blocking_send(Ok(chunk))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "the client is gone"))
    }
}

/// The content of the volume as a tar: nothing is followed, directories
/// have a trailing slash as in the archives of the container engines.
pub(crate) fn write_volume_tar(dir: &Path, w: impl Write) -> io::Result<()> {
    use std::os::fd::BorrowedFd;
    use velarx_base::walk::{Visit, Walk};
    /// The walk of the volume: the state of a directory is its name in the
    /// archive.  The entries are read through the descriptor of their
    /// directory (`/proc/self/fd`), so a name replaced by a link is not
    /// followed.
    struct Tar<'a, W: Write> {
        b: &'a mut tar::Builder<W>,
    }
    impl<W: Write> Visit for Tar<'_, W> {
        type Dir = std::path::PathBuf;

        fn entry(
            &mut self,
            dir: BorrowedFd<'_>,
            name: &std::ffi::OsStr,
            st: &rustix::fs::Stat,
            _: usize,
            prefix: &mut std::path::PathBuf,
        ) -> io::Result<Option<std::path::PathBuf>> {
            use rustix::fs::FileType;
            let mut path = velarx_sys::fd::proc_path(&dir);
            path.push(name);
            let leaf = name;
            let name = prefix.join(name);
            match FileType::from_raw_mode(st.st_mode) {
                FileType::Directory => {
                    let mut with_slash = name.clone().into_os_string();
                    with_slash.push("/");
                    self.b.append_dir(Path::new(&with_slash), &path)?;
                    return Ok(Some(name));
                }
                FileType::RegularFile => {
                    // (a file with holes is a sparse entry)
                    let file = std::fs::File::from(rustix::fs::openat(
                        dir,
                        leaf,
                        rustix::fs::OFlags::RDONLY
                            | rustix::fs::OFlags::NOFOLLOW
                            | rustix::fs::OFlags::NONBLOCK
                            | rustix::fs::OFlags::CLOEXEC,
                        rustix::fs::Mode::empty(),
                    )?);
                    let meta = file.metadata()?;
                    let mut h = tar::Header::new_gnu();
                    h.set_metadata_in_mode(&meta, tar::HeaderMode::Complete);
                    velarx_wire::sparse::append_file(self.b, &mut h, &name, &file, meta.len())?;
                }
                _ => self.b.append_path_with_name(&path, &name)?,
            }
            Ok(None)
        }
    }
    let mut b = tar::Builder::new(w);
    b.follow_symlinks(false);
    Walk {
        max_depth: velarx_base::tree::MAX_DEPTH,
        sorted: true,
        skip_gone: false,
        lenient: false,
    }
    .run(
        velarx_base::tree::open_root(dir)?,
        std::path::PathBuf::new(),
        &mut Tar { b: &mut b },
    )?;
    b.into_inner()?.flush()
}

/// The content of a volume as the body of a response.
pub(crate) fn export_stream(dir: std::path::PathBuf) -> crate::api::ops::ByteStream {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::task::spawn_blocking(move || {
        let w = ChannelWriter {
            tx: tx.clone(),
            buf: Vec::new(),
        };
        if let Err(e) = write_volume_tar(&dir, w) {
            // the stream started: the client sees a truncated tar
            let _ = tx.blocking_send(Err(e));
        }
    });
    Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx))
}

/// The content of the volume `name` as a tar.
pub(crate) async fn export_of(
    state: &AppState,
    name: &str,
) -> ApiResult<crate::api::ops::ByteStream> {
    let v = state.volume_service.get(name).await?;
    Ok(export_stream(v.mountpoint.clone()))
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn errno(e: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(e.raw_os_error())
}

/// Open the directory `name` of `dir`, creating it when it is missing; a
/// symlink or anything else that is not a directory is refused.
fn enter_dir(dir: &OwnedFd, name: &std::ffi::OsStr) -> io::Result<OwnedFd> {
    use rustix::fs::{mkdirat, openat, Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match openat(dir, name, flags, Mode::empty()) {
        Ok(fd) => Ok(fd),
        Err(rustix::io::Errno::NOENT) => {
            mkdirat(dir, name, Mode::from_raw_mode(0o755)).map_err(errno)?;
            openat(dir, name, flags, Mode::empty()).map_err(errno)
        }
        // A symlink (ELOOP) or a file (ENOTDIR) where the archive needs a
        // directory: the archive is refused, not the server at fault.
        Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => Err(invalid(format!(
            "{} in the archive is not a directory",
            name.to_string_lossy()
        ))),
        Err(e) => Err(errno(e)),
    }
}

/// Remove what is at `name` unless it is a directory.
fn clear_leaf(dir: &OwnedFd, name: &std::ffi::OsStr) -> io::Result<()> {
    use rustix::fs::{statat, unlinkat, AtFlags, FileType};
    match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => {
            if FileType::from_raw_mode(st.st_mode) == FileType::Directory {
                return Err(invalid("a directory is replaced by a file"));
            }
            unlinkat(dir, name, AtFlags::empty()).map_err(errno)
        }
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(e) => Err(errno(e)),
    }
}

/// Give a file the owner the archive says, as `tar -x` does for root.  Ids that
/// the daemon cannot give (not mapped in its user namespace, or no privilege)
/// leave the file with the owner of the daemon.
fn give(fd: impl std::os::fd::AsFd, owner: (Option<u32>, Option<u32>)) {
    let (uid, gid) = owner_ids(owner);
    if let Err(e) = rustix::fs::fchown(fd, uid, gid) {
        tracing::debug!("volume import: the owner is not set: {e}");
    }
}

fn give_link(dir: &OwnedFd, name: &std::ffi::OsStr, owner: (Option<u32>, Option<u32>)) {
    let (uid, gid) = owner_ids(owner);
    if let Err(e) = rustix::fs::chownat(dir, name, uid, gid, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
    {
        tracing::debug!("volume import: the owner of {name:?} is not set: {e}");
    }
}

/// The ids of an owner, `(uid_t)-1` meaning no change: it is filtered out.
fn owner_ids(
    owner: (Option<u32>, Option<u32>),
) -> (Option<rustix::fs::Uid>, Option<rustix::fs::Gid>) {
    (
        owner
            .0
            .filter(|u| *u != u32::MAX)
            .map(rustix::fs::Uid::from_raw),
        owner
            .1
            .filter(|g| *g != u32::MAX)
            .map(rustix::fs::Gid::from_raw),
    )
}

/// Extract a tar below `dest`.  Every component is opened with O_NOFOLLOW
/// from the directory before it, so no symlink of the archive (or one that
/// is in the volume) is followed, and `..` and absolute names are refused.
pub(crate) fn extract_tar(dest: &Path, reader: impl Read) -> io::Result<()> {
    use rustix::fs::{fchmod, openat, symlinkat, Mode, OFlags};
    use tar::EntryType;

    let root = rustix::fs::open(
        dest,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno)?;
    let mut ar = velarx_wire::sparse::archive(reader);
    for entry in ar.entries()? {
        let mut e = entry?;
        let path = velarx_wire::sparse::path(&mut e)?;
        let mut names = Vec::new();
        for c in path.components() {
            match c {
                Component::Normal(n) => names.push(n.to_os_string()),
                Component::CurDir => {}
                _ => return Err(invalid(format!("invalid path in the archive: {path:?}"))),
            }
        }
        let Some((leaf, parents)) = names.split_last() else {
            continue;
        };
        let mut dir = rustix::io::dup(&root).map_err(errno)?;
        for p in parents {
            dir = enter_dir(&dir, p)?;
        }
        let mode = e.header().mode().unwrap_or(0o644) & 0o7777;
        let owner = (
            e.header().uid().ok().and_then(|u| u32::try_from(u).ok()),
            e.header().gid().ok().and_then(|g| u32::try_from(g).ok()),
        );
        match e.header().entry_type() {
            EntryType::Directory => {
                let sub = enter_dir(&dir, leaf)?;
                give(&sub, owner);
                fchmod(&sub, Mode::from_raw_mode(mode)).map_err(errno)?;
            }
            EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse => {
                clear_leaf(&dir, leaf)?;
                let fd = openat(
                    &dir,
                    leaf,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )
                .map_err(errno)?;
                let mut f = std::fs::File::from(fd);
                velarx_wire::sparse::copy(&mut e, &mut f, velarx_wire::sparse::MAX_REAL_SIZE)?;
                give(&f, owner);
                fchmod(&f, Mode::from_raw_mode(mode)).map_err(errno)?;
            }
            EntryType::Symlink => {
                let target = e
                    .link_name()?
                    .ok_or_else(|| invalid("a symlink without a target"))?
                    .into_owned();
                clear_leaf(&dir, leaf)?;
                symlinkat(&target, &dir, leaf).map_err(errno)?;
                give_link(&dir, leaf, owner);
            }
            EntryType::XGlobalHeader | EntryType::XHeader => {}
            t => {
                return Err(invalid(format!(
                    "unsupported entry type {t:?} in the archive"
                )))
            }
        }
    }
    Ok(())
}

/// Extract the tar in the body of a request into a volume.  An archive
/// that is not valid is `InvalidData`.
pub(crate) async fn import_stream(
    mountpoint: &Path,
    mut data: crate::api::ops::ByteStream,
) -> io::Result<()> {
    // The archive is staged next to the volumes: /tmp is a small tmpfs.
    let parent = mountpoint
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| mountpoint.to_path_buf());
    let staged = tokio::task::spawn_blocking(move || tempfile::tempfile_in(parent))
        .await
        .map_err(io::Error::other)??;
    let mut file = tokio::fs::File::from_std(staged);
    // (what is not a tar archive is refused at its first block)
    let mut guard =
        velarx_content::archive::guard::Guard::new(velarx_content::archive::guard::Accept::Tar);
    while let Some(chunk) = data.next().await {
        let chunk = chunk.map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("read the archive: {e}"))
        })?;
        guard.feed(&chunk)?;
        file.write_all(&chunk).await?;
    }
    guard.end()?;
    file.flush().await?;
    let mut file = file.into_std().await;
    let dest = mountpoint.to_path_buf();
    tokio::task::spawn_blocking(move || {
        use std::io::Seek;
        file.rewind()?;
        extract_tar(&dest, io::BufReader::new(file))
    })
    .await
    .map_err(io::Error::other)?
}

/// Extract the tar `input` into the volume `name`.
pub(crate) async fn import_of(
    state: &AppState,
    name: &str,
    input: crate::api::ops::ByteStream,
) -> ApiResult<()> {
    let v = state.volume_service.get(name).await?;
    import_stream(&v.mountpoint, input)
        .await
        .map_err(|e| match e.kind() {
            io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => {
                ApiError::bad_request(e.to_string())
            }
            _ => ApiError::internal(e.to_string()),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dangling filter fails when the users of a volume cannot be
    /// read: it does not take every volume for an unused one.
    #[tokio::test]
    async fn a_failed_read_of_the_users_fails_the_dangling_filter() {
        use crate::api::podman::test_store;
        let dir = tempfile::tempdir().unwrap();
        let state = test_store::state_in(dir.path()).await;
        state
            .volume_service
            .create(
                "v1",
                velarx_core::services::VolumeDriver::Local,
                Default::default(),
                Default::default(),
            )
            .await
            .unwrap();
        let dangling = Filters(vec![("dangling".into(), vec!["true".into()])]);
        assert_eq!(list_of(&state, &dangling).await.unwrap().len(), 1);
        test_store::alter(&state, "ALTER TABLE containers RENAME TO gone");
        let e = list_of(&state, &dangling).await.unwrap_err();
        assert!(e.message.contains("no such table"), "{}", e.message);
    }

    fn tar_with(f: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        f(&mut b);
        b.into_inner().unwrap_or_default()
    }

    fn file(b: &mut tar::Builder<Vec<u8>>, name: &str, data: &[u8]) {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, data).unwrap();
    }

    #[test]
    fn the_record_of_a_volume() {
        let v = Volume {
            name: "v".into(),
            driver: VolumeDriver::Local,
            mountpoint: "/x/v".into(),
            labels: std::collections::HashMap::from([("k".to_string(), "x".to_string())]),
            options: std::collections::HashMap::new(),
            created_at: "2026-01-02T03:04:05Z".into(),
            scope: "local".into(),
            state: Default::default(),
        };
        let r = record(&v);
        assert_eq!(r.labels["k"], "x");
        assert_eq!(r.created_ns, 1_767_323_045_000_000_000);
        assert_eq!(r.driver, "local");
        assert_eq!(r.mountpoint, "/x/v");
    }

    #[test]
    fn extract_creates_files_and_dirs() {
        let d = tempfile::tempdir().unwrap();
        let t = tar_with(|b| {
            file(b, "sub/f", b"data");
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            b.append_link(&mut h, "link", "sub/f").unwrap();
        });
        extract_tar(d.path(), &t[..]).unwrap();
        assert_eq!(std::fs::read(d.path().join("sub/f")).unwrap(), b"data");
        assert_eq!(
            std::fs::read_link(d.path().join("link")).unwrap(),
            Path::new("sub/f")
        );
    }

    #[test]
    fn extract_refuses_escapes() {
        let d = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        // a symlink to the outside, then a file through it
        let t = tar_with(|b| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            b.append_link(&mut h, "esc", out.path()).unwrap();
            file(b, "esc/pwned", b"x");
        });
        let e = extract_tar(d.path(), &t[..]).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
        assert!(!out.path().join("pwned").exists());

        // `..` and absolute names cannot be written with the tar builder
        let mut raw = tar_with(|b| file(b, "aaaa", b"x"));
        raw[..4].copy_from_slice(b"/etc");
        // the checksum is wrong now; fix it
        let sum: u32 = raw[..512]
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    b' ' as u32
                } else {
                    *b as u32
                }
            })
            .sum();
        let s = format!("{sum:06o}\0 ");
        raw[148..156].copy_from_slice(s.as_bytes());
        assert!(extract_tar(d.path(), &raw[..]).is_err());
    }

    #[test]
    fn extract_replaces_a_symlink_leaf_without_following_it() {
        let d = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        std::fs::write(out.path().join("t"), "orig").unwrap();
        std::os::unix::fs::symlink(out.path().join("t"), d.path().join("f")).unwrap();
        let t = tar_with(|b| file(b, "f", b"new"));
        extract_tar(d.path(), &t[..]).unwrap();
        assert_eq!(std::fs::read(out.path().join("t")).unwrap(), b"orig");
        assert_eq!(std::fs::read(d.path().join("f")).unwrap(), b"new");
    }

    #[test]
    fn export_has_no_root_entry() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        std::fs::write(d.path().join("sub/f"), "x").unwrap();
        std::os::unix::fs::symlink("sub/f", d.path().join("link")).unwrap();
        let mut out = Vec::new();
        write_volume_tar(d.path(), &mut out).unwrap();
        let mut ar = tar::Archive::new(&out[..]);
        let mut names: Vec<String> = ar
            .entries()
            .unwrap()
            .map(|e| String::from_utf8_lossy(&e.unwrap().path_bytes()).into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["link", "sub/", "sub/f"]);
    }
}
