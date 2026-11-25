// SPDX-License-Identifier: Apache-2.0
//! Archives of a container's file system: `cp` (GET/HEAD/PUT of
//! `/containers/{}/archive`), `export` and the size of the changes.
//!
//! The tar is written and extracted by [`velarx_wire::cp`].  A running container
//! is reached through the root of its process (with its volumes): every
//! path is resolved there with `openat2` (`RESOLVE_IN_ROOT`), so a link in
//! the container cannot lead out of it.  The root file system of a
//! container that does not run is not mounted: its upper directory over
//! its image is read and written through [`StoppedView`], with the same
//! rules; a path of one of its volumes or bind mounts is in the directory of
//! the host that is mounted there, as podman copies it.

use super::error::{ApiError, ApiResult};
use super::lifecycle;
use crate::api::ops::ByteStream;
use crate::api::AppState;
use bytes::Bytes;
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{fstat, openat, FileType, Mode, OFlags};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use velarx_core::services::cpview::{EntryStat, StoppedView};
use velarx_core::services::imagecopy::TreeSource;
use velarx_core::services::procpin::{open_container_root, ContainerRoot};
use velarx_core::storage_driver::{StorageDriver, Writable};
use velarx_db::ContainerRecord;
use velarx_proto::engine::Condition;
use velarx_runtime::container::RootfsDir;
use velarx_wire::cp::{self, ExtractOptions, IdMaps, TreeWriter};

fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    openat(
        rustix::fs::CWD,
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)
}

/// The root of the process `pid`, if it is the container's (its root is
/// the root file system the driver made of the container's writable layer
/// `w`, or the directory of its `--rootfs`); the process is pinned by a
/// pidfd while it is checked, so a reused pid is not entered.
fn open_process_root(
    pid: u32,
    driver: &dyn StorageDriver,
    w: &Writable,
    rootfs: Option<&RootfsDir>,
    mon_dir: &Path,
) -> io::Result<OwnedFd> {
    let pid = i32::try_from(pid).map_err(|_| io::Error::other("invalid pid"))?;
    open_container_root(pid, ContainerRoot::of(rootfs, driver, w, mon_dir))
}

/// What a copy needs of a container.
struct Target {
    /// The pid of a running container.
    pid: Option<u32>,
    /// The writable layer of the container, and the driver that knows it.
    writable: Writable,
    driver: Arc<dyn StorageDriver>,
    /// The `--rootfs` of the container, if it was made with one.
    rootfs: Option<RootfsDir>,
    /// The run directory of the container's monitor, which records the root
    /// it attached.
    mon_dir: PathBuf,
    ids: IdMaps,
    user: String,
    image: Option<ImageParts>,
    /// The volumes and bind mounts of a container that does not run.
    mounts: Vec<HostMount>,
}

/// A volume or a bind mount of a container: the directory of the host that
/// is at `destination` in the container.
struct HostMount {
    destination: String,
    source: PathBuf,
    subpath: Option<String>,
}

/// The mount of `mounts` that has `path` (the deepest), and the path in it,
/// with the final `/` or `/.` of `path`.
fn host_mount_of<'a>(mounts: &'a [HostMount], path: &str) -> Option<(&'a HostMount, String)> {
    let clean = cp::clean_path(path);
    let (m, rest) = mounts
        .iter()
        .filter_map(|m| {
            let rest = clean.strip_prefix(m.destination.as_str())?;
            (rest.is_empty() || rest.starts_with('/') || m.destination == "/").then_some((m, rest))
        })
        .max_by_key(|(m, _)| m.destination.len())?;
    let mut inside = format!("/{}", rest.trim_start_matches('/'));
    if path.ends_with("/.") {
        inside = format!("{}/.", inside.trim_end_matches('/'));
    } else if path.ends_with('/') && !inside.ends_with('/') {
        inside.push('/');
    }
    Some((m, inside))
}

/// The image of a container, read through the images of its layers.
struct ImageParts {
    tree: Arc<dyn velarx_fuse::view::ImageTree>,
    layers: Vec<String>,
    translate: velarx_fuse::IdTranslate,
    /// Where the files of the image are read back from: its storage driver.
    objects: velarx_core::storage_driver::DriverObjects,
    state: Arc<AppState>,
}

/// The root of a container: of its process, or its upper directory over
/// its image.
enum Root<'a> {
    Process(OwnedFd),
    Stopped(StoppedView<'a>),
}

impl Target {
    async fn of(
        state: &Arc<AppState>,
        rec: &ContainerRecord,
        want_process: bool,
    ) -> ApiResult<Target> {
        let st = lifecycle::status(state, rec).await;
        let cfg = lifecycle::config_of(rec)?;
        let maps = |m: &[velarx_wire::request::IdMapping]| {
            m.iter()
                .map(|m| (m.container_id, m.host_id, m.size))
                .collect()
        };
        let pid = (want_process && st.alive() && st.pid > 0).then_some(st.pid as u32);
        let image = match pid {
            Some(_) => None,
            None => {
                let svc = &state.container_service;
                let record = state.db.get_image(&rec.image_id).await?;
                let layers = svc
                    .image_layers(&record)
                    .await
                    .map_err(|e| ApiError::internal(e.to_string()))?;
                let tree = svc
                    .image_view(&layers)
                    .map_err(|e| ApiError::internal(e.to_string()))?;
                Some(ImageParts {
                    tree,
                    layers: layers.iter().map(|l| l.key.to_string()).collect(),
                    translate: svc.translation(&cfg.uid_mappings, &cfg.gid_mappings),
                    objects: state.image_service.objects(),
                    state: state.clone(),
                })
            }
        };
        // (a running container has its mounts in the root of its process)
        let mounts = match pid {
            Some(_) => Vec::new(),
            None => cfg
                .mounts
                .iter()
                .filter(|m| {
                    !m.engine
                        && m.image.is_none()
                        && m.overlay.is_none()
                        && m.mount_type.as_deref().unwrap_or("bind") == "bind"
                        && m.source.starts_with('/')
                })
                .map(|m| HostMount {
                    destination: cp::clean_path(&m.target),
                    source: PathBuf::from(&m.source),
                    subpath: m.subpath.clone(),
                })
                .collect(),
        };
        Ok(Target {
            pid,
            writable: state.container_service.writable(&rec.id),
            driver: state.container_service.storage().clone(),
            rootfs: cfg.rootfs.clone(),
            mon_dir: state.container_service.mon_dir(&rec.id),
            ids: IdMaps {
                uids: maps(&cfg.uid_mappings),
                gids: maps(&cfg.gid_mappings),
            },
            user: cfg.user,
            image,
            mounts,
        })
    }

    /// The root that has `path` of the container, the path in it and the
    /// destination of the mount that root is (none: the container's root):
    /// a path of a volume or a bind mount of a container that does not run
    /// is in the directory of the host mounted there.
    fn open_at(&self, path: &str) -> io::Result<(Root<'_>, String, Option<&str>)> {
        let Some((m, inside)) = host_mount_of(&self.mounts, path) else {
            return Ok((self.open()?, path.to_string(), None));
        };
        let mut dir = open_dir(&m.source)?;
        if let Some(sub) = m.subpath.as_deref().filter(|s| !s.is_empty()) {
            dir = cp::open_in_root(dir.as_fd(), sub, OFlags::PATH | OFlags::DIRECTORY, true)?;
        }
        Ok((Root::Process(dir), inside, Some(&m.destination)))
    }

    fn open(&self) -> io::Result<Root<'_>> {
        if let Some(pid) = self.pid {
            return open_process_root(
                pid,
                &*self.driver,
                &self.writable,
                self.rootfs.as_ref(),
                &self.mon_dir,
            )
            .map(Root::Process);
        }
        let image = self
            .image
            .as_ref()
            .ok_or_else(|| io::Error::other("no image"))?;
        let view = self.driver.stopped_view(
            &self.writable,
            TreeSource {
                tree: &*image.tree,
                layers: &image.layers,
                objects: &image.objects,
                verity: image.state.image_service.verity(),
                fetcher: Some(&*image.state.image_service),
                translate: &image.translate,
            },
        );
        Ok(Root::Stopped(view.map_err(|e| e.into_io())?))
    }
}

/// A tar writer that sends what it writes to the response body.
struct ChanWriter {
    tx: mpsc::Sender<io::Result<Bytes>>,
    buf: Vec<u8>,
}

impl Write for ChanWriter {
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
        let b = Bytes::from(std::mem::take(&mut self.buf));
        self.tx
            .blocking_send(Ok(b))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "client gone"))
    }
}

fn body_channel() -> (ByteStream, mpsc::Sender<io::Result<Bytes>>) {
    let (tx, rx) = mpsc::channel(8);
    (
        Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)),
        tx,
    )
}

/// What `X-Docker-Container-Path-Stat` says about a path.
struct PathStat {
    name: String,
    st: EntryStat,
    link_target: String,
}

/// The last component of a path; "." for the root.
fn base_name(path: &str) -> String {
    let (_, base) = cp::split_path(&cp::clean_path(path));
    if base.is_empty() {
        ".".to_string()
    } else {
        base
    }
}

/// Resolve the path of a cp in the root of a process: links are followed
/// (a link is reported with the path it resolves to, its target is what
/// is copied).
fn stat_path(root: BorrowedFd<'_>, path: &str) -> io::Result<(EntryStat, String)> {
    let real = cp::open_in_root(root, path, OFlags::PATH, true)?;
    let st = fstat(&real)?;
    Ok((
        EntryStat {
            mode: st.st_mode,
            size: st.st_size,
            mtime: st.st_mtime,
            mtime_nsec: st.st_mtime_nsec as i64,
            is_dir: FileType::from_raw_mode(st.st_mode) == FileType::Directory,
        },
        cp::resolve_in_root(root, path)?,
    ))
}

fn path_stat(root: &Root<'_>, path: &str) -> io::Result<PathStat> {
    let (st, link_target) = match root {
        Root::Process(fd) => stat_path(fd.as_fd(), path)?,
        Root::Stopped(v) => v.stat(path)?,
    };
    // the client copies the contents of a directory asked as DIR/.
    let link_target = preserve_base_path(path, &link_target);
    // Docker names the path asked (a link by its name)
    let name = match base_name(path).as_str() {
        "." if !path.ends_with("/.") => "/".to_string(),
        n => n.to_string(),
    };
    Ok(PathStat {
        name,
        st,
        link_target,
    })
}

/// podman's PreserveBasePath: the resolved path keeps a final `/.` and a
/// final separator of the path asked.
fn preserve_base_path(original: &str, resolved: &str) -> String {
    let mut r = resolved.to_string();
    let base = |p: &str| {
        p.trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_string()
    };
    if base(&r) != "." && base(original) == "." && original.trim_end_matches('/').ends_with('.') {
        if !r.ends_with('/') {
            r.push('/');
        }
        r.push('.');
    }
    if !r.ends_with('/') && original.ends_with('/') {
        r.push('/');
    }
    r
}

fn archive_error(e: io::Error, path: &str) -> ApiError {
    match e.raw_os_error() {
        Some(libc::ENOENT) => {
            ApiError::new(404, format!("could not find the file {path} in container"))
                .with_cause("no such file or directory")
        }
        Some(libc::ENOTDIR) | Some(libc::EINVAL) | Some(libc::ELOOP) | Some(libc::EXDEV) => {
            ApiError::bad_request(e.to_string())
        }
        _ if e.kind() == io::ErrorKind::InvalidInput => ApiError::bad_request(e.to_string()),
        _ => ApiError::internal(e.to_string()),
    }
}

/// Write the tar of `path` of the container (its contents with `contents`).
fn write_archive<W: Write>(
    root: &Root<'_>,
    b: &mut tar::Builder<W>,
    path: &str,
    name: &Path,
    contents: bool,
    ids: &IdMaps,
    exclude: &[&str],
) -> io::Result<()> {
    match root {
        Root::Process(fd) => {
            let real = cp::open_in_root(fd.as_fd(), path, OFlags::PATH, true)?;
            TreeWriter {
                builder: b,
                ids: Some(ids),
            }
            .add_tree_excluding(real, name, contents, exclude)
        }
        Root::Stopped(v) => v.archive_excluding(b, path, name, contents, ids, exclude),
    }
}

/// A path of a copy in a container: a relative one is in its working
/// directory, as podman takes it.
fn container_path(working_dir: &str, path: &str) -> String {
    if path.starts_with('/') {
        return path.to_string();
    }
    format!("{}/{}", working_dir.trim_end_matches('/'), path)
}

/// What is at `path` in the container `name`, and with `content` its tar.
pub(crate) async fn archive_get_of(
    state: &Arc<AppState>,
    name: &str,
    path: &str,
    content: bool,
) -> ApiResult<(velarx_proto::engine::PathStat, Option<ByteStream>)> {
    if path.is_empty() {
        return Err(ApiError::bad_request("missing the path"));
    }
    let (path, stat, target, excluded) = stat_of(state, name, path).await?;
    if content {
        refuse_excluded(&excluded, &path)?;
    }
    let shown = velarx_proto::engine::PathStat {
        name: stat.name,
        size: stat.st.size,
        mode: stat.st.mode,
        mtime_ns: stat.st.mtime.max(0) * 1_000_000_000 + stat.st.mtime_nsec,
        link_target: stat.link_target,
        is_dir: stat.st.is_dir,
    };
    Ok((shown, content.then(|| tar_of(target, path))))
}

/// The path of the container `name` that `path` names (relative: in its
/// working directory), what is there, and the container.
async fn stat_of(
    state: &Arc<AppState>,
    name: &str,
    path: &str,
) -> ApiResult<(String, PathStat, Arc<Target>, Excluded)> {
    let rec = lifecycle::resolve(state, name).await?;
    let path = container_path(&lifecycle::config_of(&rec)?.working_dir, path);
    let target = Arc::new(Target::of(state, &rec, true).await?);
    let (t2, p2) = (target.clone(), path.clone());
    let stat = tokio::task::spawn_blocking(move || {
        let (root, inside, mount) = t2.open_at(&p2)?;
        let mut stat = path_stat(&root, &inside)?;
        let excluded = match mount {
            Some(_) => Excluded::None,
            None => excluded(&root, &inside)?,
        };
        // (what a link resolves to is a path of the container)
        if let Some(dest) = mount.filter(|d| *d != "/") {
            stat.link_target = format!("{dest}{}", stat.link_target);
        }
        Ok::<_, io::Error>((stat, excluded))
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(|e| archive_error(e, &path))?;
    Ok((path, stat.0, target, stat.1))
}

/// The error of a copy of what podman leaves out (a file below `/dev`,
/// `/proc` or `/sys`), before any of the archive is sent: podman's copier
/// says "copied no items: no such file or directory".
fn refuse_excluded(excluded: &Excluded, path: &str) -> ApiResult<()> {
    if *excluded == (Excluded::All { dir: false }) {
        return Err(ApiError::new(
            404,
            format!(
                "{path} is not copied: /dev, /proc and /sys of a container are left out of a copy"
            ),
        )
        .with_cause("no such file or directory"));
    }
    Ok(())
}

/// What a copy out of a container leaves out, as podman's: its copier is
/// given `Excludes: ["dev", "proc", "sys"]` (libpod
/// `container_copy_common.go`), patterns of paths relative to the root of
/// the container, whatever path is copied.
#[derive(Debug, PartialEq, Eq)]
enum Excluded {
    /// Nothing (a path elsewhere)
    None,
    /// The root itself: its `dev`, `proc` and `sys` are left out
    /// ([`cp::ROOT_EXCLUDES`])
    Top,
    /// The path is one of them or below one: a directory is copied as an
    /// empty archive, anything else is not found (podman: "copied no
    /// items")
    All { dir: bool },
}

/// What is left out of the copy of `inside` of the root of the container
/// `root` (not of a mount: podman leaves out nothing of a volume or a bind
/// mount of a running container), from the path it resolves to (a link to
/// `/dev` is `/dev`).
fn excluded(root: &Root<'_>, inside: &str) -> io::Result<Excluded> {
    let (st, resolved) = match root {
        Root::Process(fd) => stat_path(fd.as_fd(), inside)?,
        Root::Stopped(v) => v.stat(inside)?,
    };
    let mut comps = resolved.split('/').filter(|c| !matches!(*c, "" | "."));
    Ok(match comps.next() {
        None => Excluded::Top,
        Some(first) if cp::ROOT_EXCLUDES.contains(&first) => Excluded::All { dir: st.is_dir },
        Some(_) => Excluded::None,
    })
}

/// The tar of `path` of a container, written as it is read.
fn tar_of(target: Arc<Target>, path: String) -> ByteStream {
    let (body, tx) = body_channel();
    // DIR/. is the contents of DIR; DIR/ is DIR, as for Docker
    let contents = path.ends_with("/.");
    tokio::task::spawn_blocking(move || {
        let result = (|| -> io::Result<()> {
            let (root, inside, mount) = target.open_at(&path)?;
            let mut b = tar::Builder::new(ChanWriter {
                tx: tx.clone(),
                buf: Vec::new(),
            });
            b.mode(tar::HeaderMode::Complete);
            // the resolved node, named as the path asked for it
            let name = base_name(&path);
            // (as podman, without the devices and the kernel's files of the
            // root of the container)
            let excluded = match mount {
                Some(_) => Excluded::None,
                None => excluded(&root, &inside)?,
            };
            let exclude: &[&str] = match excluded {
                Excluded::None => &[],
                Excluded::Top => &cp::ROOT_EXCLUDES,
                Excluded::All { dir: true } => return b.into_inner()?.flush(),
                Excluded::All { dir: false } => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "{path}: not copied: /dev, /proc and /sys of a container are left out of a copy"
                        ),
                    ))
                }
            };
            write_archive(
                &root,
                &mut b,
                &inside,
                Path::new(&name),
                contents,
                &target.ids,
                exclude,
            )?;
            b.into_inner()?.flush()
        })();
        if let Err(e) = result {
            let _ = tx.blocking_send(Err(e));
        }
    });
    body
}

/// A `std::io::Read` over the chunks of a request body.
struct ChanReader {
    rx: mpsc::Receiver<io::Result<Bytes>>,
    cur: Bytes,
}

impl Read for ChanReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.cur.is_empty() {
            match self.rx.blocking_recv() {
                Some(Ok(b)) => self.cur = b,
                Some(Err(e)) => return Err(e),
                None => return Ok(0),
            }
        }
        let n = out.len().min(self.cur.len());
        out[..n].copy_from_slice(&self.cur[..n]);
        self.cur = self.cur.slice(n..);
        Ok(n)
    }
}

/// The host owner of what is copied into a container: its user, mapped.
fn owner_in(root: &Root<'_>, target: &Target) -> io::Result<(u32, u32)> {
    let (uid, gid) = match root {
        Root::Process(fd) => cp::container_user(fd.as_fd(), &target.user)?,
        Root::Stopped(v) => cp::user_of(&target.user, |p| v.read_file(p, cp::MAX_ID_FILE))?,
    };
    target.ids.to_host(uid, gid).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("the user {uid}:{gid} of the container is not mapped"),
        )
    })
}

/// The tar of a copy into a container, which podman takes compressed with
/// gzip or zstd too (`podman cp - ctr:/dir < x.tar.gz`).
fn decompressed<R: Read + Send + 'static>(input: R) -> io::Result<Box<dyn Read + Send>> {
    Ok(Box::new(velarx_tarsplit::decompress::Decoder::detect(
        io::BufReader::new(input),
    )?))
}

/// How a tar is extracted into a container.
pub(crate) struct PutOptions {
    /// The new names of the first components of the entries
    pub rename: std::collections::HashMap<String, String>,
    /// The files go to the user of the container (else they keep the
    /// owners of the archive)
    pub chown: bool,
    /// A directory and what is not one replace each other
    pub overwrite_dir_non_dir: bool,
}

/// Extract the tar `input` into the directory `path` of the container
/// `name`.
pub(crate) async fn archive_put_of(
    state: &Arc<AppState>,
    name: &str,
    path: &str,
    opts: PutOptions,
    mut input: ByteStream,
) -> ApiResult<()> {
    let rec = lifecycle::resolve(state, name).await?;
    let path = container_path(&lifecycle::config_of(&rec)?.working_dir, path);
    let target = Target::of(state, &rec, true).await?;
    let (tx, rx) = mpsc::channel::<io::Result<Bytes>>(8);
    let p2 = path.clone();
    let job = tokio::task::spawn_blocking(move || -> io::Result<()> {
        // (the owner is the user of the container, the files go to the
        // mount that has the path)
        let owner = owner_in(&target.open()?, &target)?;
        let (root, inside, _) = target.open_at(&p2)?;
        let mut rename = opts.rename;
        let (dest, overlay_upper) = match &root {
            Root::Process(fd) => {
                let inside = through_link(fd.as_fd(), &inside, &mut rename);
                (
                    cp::open_in_root(fd.as_fd(), &inside, OFlags::PATH | OFlags::DIRECTORY, true)?,
                    false,
                )
            }
            Root::Stopped(v) => (v.upper_dir_for(&inside)?, true),
        };
        let extract = ExtractOptions {
            rename,
            owner: Some(owner),
            archive_owners: (!opts.chown).then(|| target.ids.clone()),
            overlay_upper,
            layer: false,
            whiteouts: Default::default(),
            overwrite_dir_non_dir: opts.overwrite_dir_non_dir,
            mask_setid: false,
        };
        cp::extract(
            decompressed(ChanReader {
                rx,
                cur: Bytes::new(),
            })?,
            dest.as_fd(),
            &extract,
        )
    });
    use futures::StreamExt;
    // (what is not a tar archive is refused at its first block, by the
    // guard, not by the words of what reads the archive)
    let mut guard = velarx_content::archive::guard::Guard::new(
        velarx_content::archive::guard::Accept::Compressed,
    );
    let mut refused = None;
    while let Some(item) = input.next().await {
        if let Ok(bytes) = &item {
            if let Err(e) = guard.feed(bytes) {
                refused = Some(e);
                break;
            }
        }
        if tx.send(item).await.is_err() {
            break;
        }
    }
    if refused.is_none() {
        refused = guard.end().err();
    }
    drop(tx);
    let done = job.await.map_err(|e| ApiError::internal(e.to_string()))?;
    if let Some(e) = refused.filter(velarx_content::archive::guard::is_not_an_archive) {
        return Err(ApiError::bad_request(e.to_string()).with_condition(Condition::InvalidArchive));
    }
    done.map_err(|e| {
        tracing::debug!("archive put {path}: {e}");
        // (the path of the entry is below the directory of the copy)
        if e.kind() == io::ErrorKind::AlreadyExists && e.raw_os_error().is_none() {
            let text = e.to_string().replacen(
                "error creating \"/",
                &format!("error creating \"{}/", path.trim_end_matches('/')),
                1,
            );
            return ApiError::internal(text);
        }
        archive_error(e, &path)
    })
}

/// The directory of a copy into `dir` that names what it copies (`rename`,
/// one name) as a link that is there: the link is followed, what it points
/// to is made (in the directory and with the name it points to), as podman
/// resolves the destination of a copy.
fn through_link(
    root: BorrowedFd<'_>,
    dir: &str,
    rename: &mut std::collections::HashMap<String, String>,
) -> String {
    let mut names = rename.values_mut();
    let (Some(name), None) = (names.next(), names.next()) else {
        return dir.to_string();
    };
    let asked = cp::clean_path(&format!("{dir}/{name}"));
    match cp::resolve_in_root(root, &asked) {
        Ok(resolved) if resolved != asked => {
            let (parent, base) = cp::split_path(&resolved);
            *name = base;
            parent
        }
        _ => dir.to_string(),
    }
}

/// The tar of the root file system of the container `name`.
pub(crate) async fn export_of(state: &Arc<AppState>, name: &str) -> ApiResult<ByteStream> {
    let rec = lifecycle::resolve(state, name).await?;
    let (body, tx) = body_channel();
    // the root file system alone (its upper directory over its image): not
    // the mounts of a running container
    let target = Target::of(state, &rec, false).await?;
    tokio::task::spawn_blocking(move || {
        let result = (|| -> io::Result<()> {
            let root = target.open()?;
            let mut b = tar::Builder::new(ChanWriter {
                tx: tx.clone(),
                buf: Vec::new(),
            });
            b.mode(tar::HeaderMode::Complete);
            write_archive(&root, &mut b, "/", Path::new(""), true, &target.ids, &[])?;
            b.into_inner()?.flush()
        })();
        if let Err(e) = result {
            let _ = tx.blocking_send(Err(e));
        }
    });
    Ok(body)
}

/// The directory of the changes a container made on top of its image.
fn upper_dir(state: &AppState, id: &str) -> PathBuf {
    state.container_service.writable_paths(id).upper
}

/// Size of the files a container wrote on top of its image.
pub async fn upper_size(state: &AppState, id: &str) -> i64 {
    let driver = state.container_service.storage().clone();
    let w = state.container_service.writable(id);
    // (a layer the driver cannot measure counts as empty, as an unreadable
    // directory always did)
    tokio::task::spawn_blocking(move || driver.writable_size(&w).unwrap_or(0) as i64)
        .await
        .unwrap_or(0)
}

/// How long a walk of the files a container wrote is reused: a kubelet asks
/// the stats of every container every few seconds, cAdvisor walks a
/// writable layer about once a minute.
const UPPER_USAGE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// The disk the files a container wrote use (allocated blocks) and the
/// number of entries, as `du` counts them: nothing is followed.  A walk is
/// reused for `UPPER_USAGE_TTL`, so asking often costs one walk per period.
pub async fn upper_usage(state: &AppState, id: &str) -> (i64, i64) {
    if let Some(v) = state.podman.upper_usage(id, UPPER_USAGE_TTL) {
        return v;
    }
    let v = walk_usage(upper_dir(state, id)).await;
    state.podman.set_upper_usage(id, v, UPPER_USAGE_TTL);
    v
}

async fn walk_usage(dir: PathBuf) -> (i64, i64) {
    tokio::task::spawn_blocking(move || {
        velarx_base::tree::usage(
            &dir,
            &velarx_base::tree::Measure {
                lenient: true,
                ..Default::default()
            },
        )
        .map_or((0, 0), |u| {
            (
                i64::try_from(u.blocks.saturating_mul(512)).unwrap_or(i64::MAX),
                i64::try_from(u.entries).unwrap_or(i64::MAX),
            )
        })
    })
    .await
    .unwrap_or((0, 0))
}

/// The changes of the container `name` (with `containers`), or of the
/// image (with `images`; the container first with both; `parent` the image
/// to compare with): the paths and the kinds of change.
pub(crate) async fn changes_of(
    state: &Arc<AppState>,
    name: &str,
    containers: bool,
    images: bool,
    parent: Option<&str>,
) -> ApiResult<Vec<(String, velarx_content::layer::dirtar::Change)>> {
    let parent = parent.filter(|p| !p.is_empty());
    let container = if containers {
        lifecycle::resolve(state, name).await
    } else {
        Err(ApiError::not_found(format!("{name}: image not known")))
    };
    let list = match container {
        Ok(rec) if parent.is_none() => state.container_service.changes(&rec.id).await?,
        Ok(_) => {
            return Err(ApiError::not_implemented(
                "the changes of a container from another parent are not supported",
            ))
        }
        Err(e) if e.status == 404 && images => {
            let image = super::images::resolve_image(state, name)
                .await
                .map_err(|_| e)?;
            match parent {
                Some(p) => {
                    let from = super::images::resolve_image(state, p).await?;
                    state
                        .image_service
                        .image_changes_from(&from.id, &image.id)
                        .await?
                }
                None => state.image_service.image_changes(&image.id).await?,
            }
        }
        Err(e) => return Err(e),
    };
    Ok(list)
}

/// Where podman's mount of a container shows its merged root: a link in
/// the bundle to the root of the container's process.
fn merged_link(state: &AppState, id: &str) -> PathBuf {
    state.container_service.bundle_dir(id).join("merged")
}

/// The root of a running container, as a path for its owner: the root of
/// its process (/proc/PID/root), once it is checked to be the container's.
async fn running_root(state: &Arc<AppState>, rec: &ContainerRecord) -> ApiResult<Option<PathBuf>> {
    let st = lifecycle::status(state, rec).await;
    if !st.alive() || st.pid <= 0 {
        return Ok(None);
    }
    let pid = st.pid as u32;
    let driver = state.container_service.storage().clone();
    let w = state.container_service.writable(&rec.id);
    let rootfs = lifecycle::config_of(rec)?.rootfs;
    let mon_dir = state.container_service.mon_dir(&rec.id);
    tokio::task::spawn_blocking(move || {
        open_process_root(pid, &*driver, &w, rootfs.as_ref(), &mon_dir).map(drop)
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(|e| ApiError::internal(format!("mounting the container: {e}")))?;
    Ok(Some(PathBuf::from(format!("/proc/{pid}/root"))))
}

/// Mount the root of the container `name`: where it is.
pub(crate) async fn mount_of(state: &Arc<AppState>, name: &str) -> ApiResult<PathBuf> {
    let rec = lifecycle::resolve(state, name).await?;
    let Some(root) = running_root(state, &rec).await? else {
        return Err(ApiError::not_implemented(format!(
            "container {} does not run: mounting the root of a stopped container is not supported",
            rec.id
        )));
    };
    let link = merged_link(state, &rec.id);
    let at = link.clone();
    crate::api::off_thread(move || {
        let _ = std::fs::remove_file(&at);
        std::os::unix::fs::symlink(&root, &at)
    })
    .await
    .map_err(|e| ApiError::internal(format!("mounting the container: {e}")))?;
    Ok(link)
}

pub(crate) async fn unmount_of(state: &Arc<AppState>, name: &str) -> ApiResult<()> {
    let rec = lifecycle::resolve(state, name).await?;
    let link = merged_link(state, &rec.id);
    match crate::api::off_thread(move || std::fs::remove_file(link)).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ApiError::internal(format!("unmounting the container: {e}"))),
    }
}

/// The containers whose root is mounted, and where.
pub(crate) async fn show_mounted_of(state: &Arc<AppState>) -> ApiResult<Vec<(String, PathBuf)>> {
    let links: Vec<_> = state
        .container_service
        .list(true)
        .await?
        .into_iter()
        .map(|rec| (merged_link(state, &rec.id), rec))
        .collect();
    // (the links read in one turn)
    let linked = crate::api::off_thread(move || {
        Ok(links
            .into_iter()
            .filter_map(|(link, rec)| Some((std::fs::read_link(&link).ok()?, link, rec)))
            .collect::<Vec<_>>())
    })
    .await?;
    let mut out = Vec::new();
    let mut stale = Vec::new();
    for (target, link, rec) in linked {
        // a link left by a container that stopped since is not a mount
        match running_root(state, &rec).await {
            Ok(Some(root)) if root == target => out.push((rec.id.clone(), link)),
            _ => stale.push(link),
        }
    }
    if !stale.is_empty() {
        let _ = crate::api::off_thread(move || {
            stale.iter().for_each(|l| match std::fs::remove_file(l) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => tracing::warn!("Cannot remove {}: {e}", l.display()),
            });
            Ok(())
        })
        .await;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_usage_of_what_a_container_wrote_counts_entries_and_blocks() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("a/b")).unwrap();
        std::fs::write(d.path().join("a/b/f"), vec![1u8; 64 << 10]).unwrap();
        std::os::unix::fs::symlink("/", d.path().join("l")).unwrap();
        let (bytes, inodes) = walk_usage(d.path().to_path_buf()).await;
        assert_eq!(inodes, 4);
        assert!(bytes >= 64 << 10, "{bytes}");
        assert_eq!(walk_usage(d.path().join("nothing")).await, (0, 0));
    }

    #[test]
    fn stats_keep_the_dot_of_a_directory_as_podman() {
        assert_eq!(preserve_base_path("/srv/.", "/srv"), "/srv/.");
        assert_eq!(preserve_base_path("/srv/", "/srv"), "/srv/");
        assert_eq!(preserve_base_path("/l", "/target"), "/target");
        assert_eq!(preserve_base_path("/.", "/"), "/.");
    }

    #[test]
    fn copies_take_compressed_tars() {
        use std::io::Write;
        let tar = b"plain tar bytes".to_vec();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar).unwrap();
        let gz = gz.finish().unwrap();
        let zs = zstd::encode_all(&tar[..], 3).unwrap();
        for input in [tar.clone(), gz, zs] {
            let mut out = Vec::new();
            decompressed(io::Cursor::new(input))
                .unwrap()
                .read_to_end(&mut out)
                .unwrap();
            assert_eq!(out, tar);
        }
    }

    #[test]
    fn relative_paths_are_in_the_working_directory() {
        assert_eq!(container_path("/srv", "."), "/srv/.");
        assert_eq!(container_path("/srv/", "sub/f"), "/srv/sub/f");
        assert_eq!(container_path("", "f"), "/f");
        assert_eq!(container_path("/srv", "/etc/x"), "/etc/x");
    }

    #[test]
    fn a_copy_named_as_a_link_goes_where_it_points() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("tmp/d1")).unwrap();
        std::os::unix::fs::symlink("/tmp/nonesuch", d.path().join("tmp/d1/x")).unwrap();
        let root = open_dir(d.path()).unwrap();
        let mut rename = [("f".to_string(), "x".to_string())].into_iter().collect();
        assert_eq!(through_link(root.as_fd(), "/tmp/d1", &mut rename), "/tmp");
        assert_eq!(rename["f"], "nonesuch");
        let mut rename = [("f".to_string(), "y".to_string())].into_iter().collect();
        assert_eq!(
            through_link(root.as_fd(), "/tmp/d1", &mut rename),
            "/tmp/d1"
        );
        assert_eq!(rename["f"], "y");
    }

    #[test]
    fn a_path_of_a_mount_is_in_the_deepest_mount() {
        let m = |d: &str| HostMount {
            destination: d.to_string(),
            source: PathBuf::from("/host"),
            subpath: None,
        };
        let mounts = [m("/tmp/volume"), m("/tmp/volume/sub"), m("/data")];
        let at =
            |p: &str| host_mount_of(&mounts, p).map(|(m, inside)| (m.destination.clone(), inside));
        let one = |d: &str, i: &str| Some((d.to_string(), i.to_string()));
        assert_eq!(at("/tmp/volume/sub"), one("/tmp/volume/sub", "/"));
        assert_eq!(at("/tmp/volume/sub/x/"), one("/tmp/volume/sub", "/x/"));
        assert_eq!(at("/tmp/volume/subx"), one("/tmp/volume", "/subx"));
        assert_eq!(at("/tmp/volume/."), one("/tmp/volume", "/."));
        assert_eq!(at("//data/../data/f"), one("/data", "/f"));
        assert_eq!(at("/tmp/vol"), None);
        assert_eq!(at("/datax"), None);
    }

    #[test]
    fn stat_of_a_link_is_its_target_in_the_root() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("etc")).unwrap();
        std::fs::write(d.path().join("etc/f"), "x").unwrap();
        std::os::unix::fs::symlink("/etc", d.path().join("l")).unwrap();
        let root = Root::Process(open_dir(d.path()).unwrap());
        let ps = path_stat(&root, "/l").unwrap();
        assert!(ps.st.is_dir);
        assert_eq!((ps.name.as_str(), ps.link_target.as_str()), ("l", "/etc"));
        let ps = path_stat(&root, "/l/f").unwrap();
        assert_eq!(
            (ps.name.as_str(), ps.link_target.as_str(), ps.st.is_dir),
            ("f", "/etc/f", false)
        );
        assert_eq!(path_stat(&root, "/").unwrap().name, "/");
        let e = path_stat(&root, "/nope").err().unwrap();
        assert_eq!(e.raw_os_error(), Some(libc::ENOENT));
    }

    /// podman's copier leaves out `dev`, `proc` and `sys` of the root of
    /// the container, by the path a copy resolves to, and only at the top.
    #[test]
    fn dev_proc_and_sys_of_the_root_are_left_out_of_a_copy() {
        let d = tempfile::tempdir().unwrap();
        for dir in ["dev", "proc/1", "sys", "usr/dev", "lib"] {
            std::fs::create_dir_all(d.path().join(dir)).unwrap();
        }
        std::fs::write(d.path().join("dev/null"), "").unwrap();
        std::os::unix::fs::symlink("/dev", d.path().join("mydev")).unwrap();
        let root = Root::Process(open_dir(d.path()).unwrap());
        let at = |p: &str| excluded(&root, p).unwrap();
        for p in ["/", "/.", "//", "/lib/.."] {
            assert_eq!(at(p), Excluded::Top, "{p}");
        }
        for p in [
            "/dev",
            "/dev/.",
            "/proc/1",
            "/sys/",
            "/mydev",
            "/lib/../dev",
        ] {
            assert_eq!(at(p), Excluded::All { dir: true }, "{p}");
        }
        assert_eq!(at("/dev/null"), Excluded::All { dir: false });
        assert_eq!(at("/mydev/null"), Excluded::All { dir: false });
        for p in ["/usr/dev", "/usr", "/lib"] {
            assert_eq!(at(p), Excluded::None, "{p}");
        }
        assert!(excluded(&root, "/nope").is_err());
    }

    #[tokio::test]
    async fn the_root_of_a_process_must_be_the_container_one() {
        use velarx_core::storage_driver::{ComposefsDriver, ComposefsOptions, ImageServer};
        let me = std::process::id();
        let tmp = tempfile::tempdir().unwrap();
        let driver: Arc<dyn StorageDriver> = Arc::new(ComposefsDriver::new(
            velarx_db::Database::open(tmp.path().join("db"))
                .await
                .unwrap(),
            Arc::new(velarx_storage::FileStore::new(tmp.path().join("objects")).unwrap()),
            tmp.path().join("staging"),
            velarx_storage::VerityMode::Off,
            ComposefsOptions::new(ImageServer::new(
                "velarx-monitor".into(),
                tmp.path().join("run"),
                Arc::new(velarx_config::Config::default()),
            )),
        ));
        // this process: its root is not an overlay with that upper dir
        let w = Writable::new("x", "/var/b/x");
        let driver = &*driver;
        assert!(open_process_root(me, driver, &w, None, Path::new("/nonexistent")).is_err());
        // its root is the directory of a `--rootfs` of `/` (a bind), not of
        // another
        let rootfs = |path: &str, overlay: bool| RootfsDir {
            path: path.into(),
            overlay,
            idmap: None,
            uid_mappings: Vec::new(),
            gid_mappings: Vec::new(),
        };
        assert!(open_process_root(
            me,
            driver,
            &w,
            Some(&rootfs("/", false)),
            Path::new("/nonexistent")
        )
        .is_ok());
        assert!(open_process_root(
            me,
            driver,
            &w,
            Some(&rootfs("/proc", false)),
            Path::new("/nonexistent")
        )
        .is_err());
        // with the overlay option it is the overlay's
        assert!(open_process_root(
            me,
            driver,
            &w,
            Some(&rootfs("/", true)),
            Path::new("/nonexistent")
        )
        .is_err());
    }
}
