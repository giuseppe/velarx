// SPDX-License-Identifier: Apache-2.0
//! The image server: the process that serves the EROFS images of the layers
//! of one container's image by FUSE, builds the overlay over them and hands
//! the overlay to the engine as a detached mount descriptor.
//!
//! It is `velarx-monitor --image-server`, started by the storage driver for
//! the containers whose layers the kernel does not mount (rootless, `squash`,
//! a kernel mount that failed) and for every image that is still being
//! pulled (lazy).  The driver opens and measures the images and the
//! directories of the objects, and passes them with the request; the server
//! works on those descriptors only.  For a lazy image it also asks for the
//! files the store lacks as the container reads them: the driver passes the
//! indexes of the layers and the directory of the startup profile, and the
//! socket and token of the engine that holds the pull (`LazySpec`), which it
//! asks (`org.velarx.ImageFetch`, `crate::monitor::lazy`); it knows no
//! fetcher.  It
//! serves the images through a detached FUSE mount (`velarx_fuse::detached`)
//! that no path names, builds the overlay over the directories of its layers,
//! answers with the overlay and a pidfd of itself, and drops everything it
//! holds.  From then on the file system lives as long as the overlay does
//! (the mounts cloned from the descriptor, the processes in it): when the
//! last reference goes the kernel ends the FUSE session, and the server
//! exits.  Nobody tells it to stop, and it has no mount to unmount.
//!
//! The server forks once and the first process exits at once, so that the
//! process that started it has nothing to reap and the server belongs to
//! nobody's process group, session or wait: its pidfd is what names it, and
//! the monitor of the container puts it in its own cgroup.

use crate::imagemount::{mtab_link, readonly_overlay, writable_overlay, RootOverlay};
use crate::monitor::confine::Fetching;
use crate::monitor::lazy::LazyLoader;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use velarx_fuse::erofs_tree::{layer_dir, Layer, Layers, Stubs};
use velarx_fuse::verity::Verity;
use velarx_fuse::{IdTranslate, ImageMounts};
use velarx_storage::VerityMode;

/// The argument of `velarx-monitor` that makes it an image server.
pub const FLAG: &str = crate::monitor::IMAGE_SERVER_FLAG;

/// The log of a server, in the directory of its container: what the server
/// says (the links of the chain of trust a refused open of the file system
/// breaks, a profile it cannot keep) is appended to it.
pub const LOG_FILE: &str = "image-server.log";

/// The most the log of a server holds: a server that would make it larger
/// empties it first and says so (the latest lines are the ones kept).
const LOG_LIMIT: u64 = 1 << 20;

/// The descriptors one message carries at most; the rest come in the
/// messages after the request.
const FDS_PER_MESSAGE: usize = 200;

/// The most descriptors the server takes: the overlay takes
/// `OVERLAY_MAX_STACK` layers altogether, the data-only ones among them; an
/// image complete in the store has its EROFS images and the directories of
/// the objects of the stores (at most `OVERLAY_MAX_STACK`), a lazy image for
/// each layer its EROFS image, its index and the directory of the files
/// fetched for it (the layer and that directory are two layers of the
/// overlay: at most `3 * OVERLAY_MAX_STACK / 2`), the objects and a
/// directory of the profile on top.
const MAX_FDS: usize = 1100;

/// The largest request.
const MAX_REQUEST: usize = 1 << 22;

/// How long the driver waits for the answer of a server: a server that has
/// not answered by then (a FUSE request it does not answer while the overlay
/// is made) is left, and the plan goes to the monitor; the server ends when
/// its answer finds nobody.
const ANSWER_WITHIN: std::time::Duration = std::time::Duration::from_secs(60);

/// What the server is asked: the descriptors come with the request, the
/// images first (the lowest layer first), then the directories of the
/// objects (the data-only layers, in the order the overlay looks for a file
/// in them; for a lazy image the files fetched for it come last), then, for
/// a lazy image, the index of each layer (the lowest first), the directory
/// of the startup profile if it has one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// The name the process shows in the process list (the container).
    pub name: String,
    /// The keys of the layers, the lowest first, one image for each.
    pub layers: Vec<String>,
    /// The number of directories of objects that follow the images.
    pub datas: usize,
    /// The owners of the files of the layers (uids, gids).
    pub owners: (Vec<u32>, Vec<u32>),
    /// The store whose objects the FUSE file system reads, with the read-only
    /// stores behind it.
    pub store: PathBuf,
    pub more_stores: Vec<PathBuf>,
    /// How the owners are shown.
    pub translate: IdTranslate,
    /// The overlay uses the extended attributes of a user namespace.
    pub userxattr: bool,
    /// The `verity` option of the overlay, and of what the FUSE file system
    /// checks of the files it opens: `off`, `on` or `require`.
    pub verity: String,
    /// The digests are enforced.
    pub enforce: bool,
    /// The run root, where the kernel's answer for the stubs is kept.
    pub run_root: PathBuf,
    /// The SELinux context of the overlay.
    pub label: Option<String>,
    /// The overlay is the root file system of a container (with an upper
    /// layer); else an image mount (read only).
    pub root: Option<RootSpec>,
    /// The image is being pulled: some of its files are not in the store, and
    /// the server fetches them.
    #[serde(default)]
    pub lazy: Option<LazySpec>,
    /// The engine logs at debug: with `enforce` the server logs at debug
    /// too (a file the FUSE file system refuses at an open).
    #[serde(default)]
    pub debug: bool,
}

/// What the server asks for the files an image lacks with
/// (`crate::monitor::lazy`), and the startup profile of the image.
#[derive(Clone, Serialize, Deserialize)]
pub struct LazySpec {
    /// The id of the image, the startup profile's.
    pub image_id: String,
    /// The staging directory of the store (`staging`): the staging
    /// directories of the layers (`layers/<stem>/files`) have the files
    /// fetched for the image.
    pub staging: PathBuf,
    /// `[pull]`: the startup profile.
    pub pull: velarx_config::PullConfig,
    /// `[storage] fsverity` and `fsverity_require`.
    pub fsverity: (bool, bool),
    /// The socket of the engine service of the store
    /// (`velarx_content::imagefetch::socket`).
    pub proxy: PathBuf,
    /// The token of the pull, which the engine asks of each call.
    pub token: String,
    /// The name of the startup profile in the directory that follows the
    /// indexes; none: the image has no profile.
    pub profile: Option<String>,
}

/// (the token is not shown)
impl std::fmt::Debug for LazySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazySpec")
            .field("image_id", &self.image_id)
            .field("staging", &self.staging)
            .field("fsverity", &self.fsverity)
            .field("proxy", &self.proxy)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

impl Request {
    /// The descriptors the request brings: the images, the directories of
    /// the objects, then those of a lazy image.
    pub fn descriptors(&self) -> usize {
        let lazy = self
            .lazy
            .as_ref()
            .map_or(0, |l| self.layers.len() + usize::from(l.profile.is_some()));
        self.layers.len() + self.datas + lazy
    }
}

/// The writable layer of a root file system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSpec {
    pub upper: PathBuf,
    pub work: PathBuf,
    /// The changes are thrown away: the upper layer is never synced.
    pub volatile: bool,
}

/// What the server answers: its descriptors (the overlay, then a pidfd of the
/// server) come with `ok`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reply {
    pub error: Option<String>,
    /// The stubs the overlay follows (`Stubs::Lowest` where the kernel
    /// follows those of the lowest layer only: the files of the layers above
    /// are served whole by FUSE).
    pub lowest_stubs: bool,
}

/// A server that answered.
#[derive(Debug)]
pub struct Served {
    /// The overlay, detached.
    pub overlay: OwnedFd,
    /// The server, as a pidfd.
    pub server: OwnedFd,
    /// The files of the layers above the lowest are served whole by FUSE.
    pub lowest_stubs: bool,
}

/// How a server failed to serve.
#[derive(Debug)]
pub struct ServerError(pub String);

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ServerError {}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// The mode of the files the FUSE file system opens: `verity` of the
/// overlay, strictly where every file must be checked (`require`).
pub(crate) fn fuse_verity(verity: &str, require: bool) -> VerityMode {
    match (require, verity) {
        (true, _) | (false, "require") => VerityMode::Require,
        (false, "on") => VerityMode::On,
        (false, _) => VerityMode::Off,
    }
}

/// The checks of the FUSE file system on the files it opens, for the mounts
/// made from now on.
pub(crate) fn set_verity(mounts: &ImageMounts, verity: &str, require: bool, enforce: bool) {
    let verity = Verity::new(Default::default(), fuse_verity(verity, require || enforce));
    mounts.set_verity(Arc::new(match enforce {
        true => verity.enforced(),
        false => verity,
    }));
}

/// The layers of the checked and open images `files` (the lowest first,
/// each with the name it is shown by in an error).
pub(crate) fn layers_of(
    files: Vec<(File, PathBuf)>,
    indexes: Option<Vec<velarx_fuse::erofs_tree::Index>>,
    userxattr: bool,
    stubs: Stubs,
) -> io::Result<Layers> {
    let layers = files
        .into_iter()
        .map(|(file, name)| Layer::of_checked_file(file, &name))
        .collect::<io::Result<Vec<_>>>()?;
    Ok(Layers::new(layers, indexes, userxattr, stubs))
}

/// The path of the descriptor `fd` of this process.
fn fd_path(fd: BorrowedFd<'_>) -> String {
    velarx_sys::fd::proc_str(&fd)
}

/// The process that runs the server for the descriptor 0 of this process
/// (`velarx-monitor --image-server`): its exit status.
pub fn main(startup: &velarx_sys::fd::Startup) -> i32 {
    // (what the engine had open without close-on-exec, and what its caller
    // left open to it, is not the server's: a lock or a pipe held for as long
    // as the container runs)
    startup.close_from(3);
    let sock = match std::io::stdin().as_fd().try_clone_to_owned() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("velarx-monitor {FLAG}: {e}");
            return 2;
        }
    };
    // (the process that started the server has nothing to wait for: it is
    // not its child, its session, or its process group)
    match velarx_sys::process::fork_single_threaded("the image server") {
        Ok(velarx_sys::process::Fork::Parent(_)) => return 0,
        Ok(velarx_sys::process::Fork::Child(_)) => {}
        Err(e) => {
            refuse(&sock, &e);
            return 2;
        }
    }
    let _ = rustix::process::setsid();
    match run(&sock) {
        Ok(()) => 0,
        Err(e) => {
            refuse(&sock, &e);
            1
        }
    }
}

/// Say why the server cannot serve.
fn refuse(sock: &OwnedFd, why: &io::Error) {
    let reply = Reply {
        error: Some(why.to_string()),
        lowest_stubs: false,
    };
    if let Ok(bytes) = serde_json::to_vec(&reply) {
        let _ = velarx_sys::scm::send(sock, &bytes, &[]);
    }
}

/// Read the request and its descriptors.
fn receive(sock: &OwnedFd) -> io::Result<(Request, Vec<OwnedFd>)> {
    let mut buf = vec![0u8; MAX_REQUEST];
    let first = velarx_sys::scm::recv(
        sock,
        &mut buf,
        FDS_PER_MESSAGE,
        rustix::net::RecvFlags::empty(),
    )?;
    if first.bytes == 0 {
        return Err(io_err("the request is empty"));
    }
    let request: Request = serde_json::from_slice(&buf[..first.bytes])
        .map_err(|e| io_err(format!("the request: {e}")))?;
    let wanted = request.descriptors();
    if wanted > MAX_FDS {
        return Err(io_err(format!(
            "{wanted} descriptors are more than the {MAX_FDS} a server takes"
        )));
    }
    let mut fds = first.fds;
    while fds.len() < wanted {
        let more = velarx_sys::scm::recv(
            sock,
            &mut buf[..1],
            FDS_PER_MESSAGE,
            rustix::net::RecvFlags::empty(),
        )?;
        if more.fds.is_empty() {
            return Err(io_err("the request ended before its descriptors did"));
        }
        fds.extend(more.fds);
    }
    if fds.len() != wanted {
        return Err(io_err(format!(
            "{} descriptors for {} layers and {} directories{}",
            fds.len(),
            request.layers.len(),
            request.datas,
            if request.lazy.is_some() {
                ", and the indexes and profile of a lazy image"
            } else {
                ""
            }
        )));
    }
    Ok((request, fds))
}

/// What the descriptors after the images are, split.
struct Given {
    /// The directories of the objects, then the files fetched for a lazy
    /// image.
    datas: Vec<OwnedFd>,
    /// The index of each layer, the lowest first (lazy).
    indexes: Vec<File>,
    /// The directory of the startup profile (lazy).
    profile_dir: Option<OwnedFd>,
    /// The connections to the engine (lazy): made by a process forked
    /// before the server confines itself, which looks up no socket by name
    connector: Option<Arc<velarx_sys::connector::Connector>>,
}

/// The log of the server: its standard error (the file the engine opened
/// for it, appended to), emptied when it would grow over [`LOG_LIMIT`].
struct Log {
    file: File,
    /// What the file holds
    written: u64,
}

/// The first line of a log that was emptied.
const LOG_EMPTIED: &[u8] = b"the log reached its limit: what was written before is dropped\n";

impl io::Write for Log {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        // (what does not fit at all is cut to its end)
        let room = LOG_LIMIT as usize - LOG_EMPTIED.len();
        let kept = &data[data.len().saturating_sub(room)..];
        if self.written + kept.len() as u64 > LOG_LIMIT {
            // (appended: the writes after the truncation start at 0)
            self.file.set_len(0)?;
            self.file.write_all(LOG_EMPTIED)?;
            self.written = LOG_EMPTIED.len() as u64;
        }
        self.file.write_all(kept)?;
        self.written += kept.len() as u64;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Say what the server says (the `tracing` events) to its standard error,
/// which is the log the engine gave it (nothing when it is not a file).
fn log_to_stderr(request: &Request) {
    let Ok(stderr) = std::io::stderr().as_fd().try_clone_to_owned() else {
        return;
    };
    let file = File::from(stderr);
    let Ok(meta) = file.metadata() else { return };
    if !meta.file_type().is_file() {
        return;
    }
    let level = match request.debug && request.enforce {
        true => tracing::Level::DEBUG,
        false => tracing::Level::INFO,
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_ansi(false)
        .with_writer(std::sync::Mutex::new(Log {
            file,
            written: meta.len(),
        }))
        .try_init();
}

fn run(sock: &OwnedFd) -> io::Result<()> {
    let (request, mut fds) = receive(sock)?;
    log_to_stderr(&request);
    velarx_wire::proctitle::set_cmdline(&format!("velarx-monitor: image server {}", request.name));
    let rest = fds.split_off(request.layers.len());
    let images: Vec<(File, PathBuf)> = fds
        .into_iter()
        .zip(&request.layers)
        .map(|(fd, key)| (File::from(fd), PathBuf::from(format!("of the layer {key}"))))
        .collect();
    let mut given = split(&request, rest);
    // (one thread so far: the process the connections come through is forked now)
    given.connector = request
        .lazy
        .as_ref()
        .map(|l| velarx_sys::connector::Connector::start(&l.proxy).map(Arc::new))
        .transpose()?;
    let served = serve(&request, images, &given)?;
    let overlay = overlay(&request, &served.mount, &given.datas, &served)?;
    let pidfd = velarx_sys::pidfd::open(std::process::id() as i32)?;
    let Made { mount, mounts, .. } = served;
    // what the server holds of the mounts goes now: the overlay it hands over
    // and the clones made from it are the references of the file system
    drop(mount);
    drop(given);
    // The profile of the peers is asked for by a thread of its own, made
    // before this thread is confined (it asks the engine).
    if let Some(ask) = served.peers {
        ask.start();
    }
    // From here the process answers, serves the requests of the kernel and
    // waits: it mounts, opens and starts nothing, so this thread takes the
    // confinement of the session's, and no thread of the server is without
    // it (code that took over a session thread finds none to use).  A thread
    // that cannot is a refusal, the overlay not handed over.
    mounts
        .confine_caller()
        .map_err(|e| io_err(format!("cannot confine the server: {e}")))?;
    let reply = Reply {
        error: None,
        lowest_stubs: served.stubs == Stubs::Lowest,
    };
    let bytes = serde_json::to_vec(&reply).map_err(io_err)?;
    velarx_sys::scm::send(sock, &bytes, &[overlay.as_fd(), pidfd.as_fd()])?;
    drop(overlay);
    drop(pidfd);
    // (the session of the FUSE file system ends with the file system, and
    // the startup profile is saved)
    mounts.wait_detached();
    Ok(())
}

/// The descriptors after the images, by what they are.
fn split(request: &Request, mut rest: Vec<OwnedFd>) -> Given {
    let profile_dir = match &request.lazy {
        Some(l) if l.profile.is_some() => rest.pop(),
        _ => None,
    };
    let indexes = match &request.lazy {
        Some(_) => rest
            .split_off(request.datas)
            .into_iter()
            .map(File::from)
            .collect(),
        None => Vec::new(),
    };
    Given {
        datas: rest,
        indexes,
        profile_dir,
        connector: None,
    }
}

/// What `serve` made.
struct Made {
    /// The detached FUSE mount, a directory per layer.
    mount: OwnedFd,
    mounts: ImageMounts,
    stubs: Stubs,
    /// The files of the layers the overlay lacks come through the FUSE file
    /// system, not the data-only layers of the stores (lazy).
    through_fuse: bool,
    /// The startup profile of the peers is to be asked for.
    peers: Option<AskPeers>,
}

/// The device of the directory `fd`.
fn device(fd: &OwnedFd) -> Option<u64> {
    rustix::fs::fstat(fd).ok().map(|st| st.st_dev)
}

/// Whether every file of the data-only layers has the fs-verity the kernel
/// checks: the objects of the stores; the files the store lacks, which come
/// from the staging of the fetches, only from a staging on the file system
/// of the store where the store has fs-verity (a file fetched there gets its
/// name only with fs-verity).
fn measured(request: &Request, datas: &[OwnedFd]) -> bool {
    request.lazy.is_none()
        || (request.verity != "off"
            && datas
                .first()
                .zip(datas.last())
                .is_some_and(|(objects, files)| {
                    let dev = device(files);
                    dev.is_some() && dev == device(objects)
                }))
}

/// Every file must be checked (`fsverity_require`) and the overlay cannot
/// check all of those of an image that is not all in the stores
/// (`measured`): the files are opened by the FUSE file system, which checks
/// them.  Also where the overlay follows the stubs of its lowest layer only
/// (`Stubs::Lowest`): the files of the layers above are served and checked by
/// the FUSE file system, those of the lowest go the same way.
fn data_through_fuse(request: &Request, stubs: Stubs, measured: bool) -> bool {
    request
        .lazy
        .as_ref()
        .is_some_and(|l| l.fsverity.1 && (stubs == Stubs::Lowest || !measured))
}

/// The `verity` option of the overlay whose files the store lacks come from
/// the staging of the fetches, or else from the FUSE `data` directory: the
/// engine's (off, on or require) where every file of the data-only layers
/// has the fs-verity the kernel checks (`measured`), else `off`: the files of
/// the FUSE file system have none for the kernel (the FUSE server checks
/// them when it opens them, `fuse_verity`); also when the files all go
/// through the FUSE file system (`through_fuse`).
fn overlay_verity(request: &Request, through_fuse: bool, measured: bool) -> &str {
    match request.lazy.is_none() || (!through_fuse && measured) {
        true => &request.verity,
        false => "off",
    }
}

/// The images served by one detached FUSE mount, a directory per layer.
fn serve(request: &Request, images: Vec<(File, PathBuf)>, given: &Given) -> io::Result<Made> {
    let stubs = crate::monitor::image::stubs::followed_stubs(
        request.userxattr,
        request.layers.len(),
        &request.run_root,
    )?;
    let mut store = velarx_storage::FileStore::new(&request.store).map_err(io_err)?;
    store = store.with_additional(request.more_stores.clone());
    let store = Arc::new(store);
    let mounts = ImageMounts::new(store.clone());
    // (the sessions read what the container's processes ask for)
    mounts.set_confinement(Arc::new(|read: &[PathBuf]| {
        crate::monitor::confine::fuse_thread(read)
    }));
    let require = request.lazy.as_ref().is_some_and(|l| l.fsverity.1);
    set_verity(&mounts, &request.verity, require, request.enforce);
    let measured = measured(request, &given.datas);
    let through_fuse = data_through_fuse(request, stubs, measured);
    let mut peers = None;
    let mut indexes = None;
    if let Some(lazy) = &request.lazy {
        peers = start_lazy(request, lazy, given, &store, &mounts)?;
        indexes = Some(
            given
                .indexes
                .iter()
                .map(velarx_fuse::erofs_tree::Index::open_file)
                .collect::<io::Result<Vec<_>>>()?,
        );
    }
    let tree = layers_of(images, indexes, request.userxattr, stubs)?;
    let mount = mounts
        .mount_tree_detached(
            Arc::new(tree),
            request.layers.clone(),
            request.owners.clone(),
            Some(&request.translate),
        )
        .map_err(io_err)?;
    Ok(Made {
        mount,
        mounts,
        stubs,
        through_fuse,
        peers,
    })
}

/// The files the store lacks, asked of the engine, the startup profile of the image
/// (recorded for its window, and read to fetch in its order), for the mounts
/// made from now on.  The peers' profile, when the image has none, is asked
/// for once the overlay is made.
fn start_lazy(
    request: &Request,
    lazy: &LazySpec,
    given: &Given,
    store: &Arc<velarx_storage::FileStore>,
    mounts: &ImageMounts,
) -> io::Result<Option<AskPeers>> {
    // (the staging directories of the layers, in their order: one store
    // that looks in each)
    let dirs = staged_dirs(request, lazy);
    let (first, rest) = dirs
        .split_first()
        .ok_or_else(|| io_err("a lazy image without layers"))?;
    let files = Arc::new(
        velarx_storage::FileStore::new(first)
            .map_err(io_err)?
            .with_additional(rest.to_vec()),
    );
    let connector = given
        .connector
        .clone()
        .ok_or_else(|| io_err("a lazy image with no connection to the engine"))?;
    let loader = Arc::new(LazyLoader::new(
        lazy,
        connector,
        (store.clone(), files.clone()),
    ));
    let reach = fetching(request, lazy);
    mounts.set_staging(files);
    mounts.set_lazy_fetcher(Arc::new(ConfinedFetch {
        loader: loader.clone(),
        reach: reach.clone(),
    }));
    // The first run of a lazy image notes the files looked up; the next
    // fetch them first.
    let pull = &lazy.pull;
    let (Some(name), Some(dir), secs) = (&lazy.profile, &given.profile_dir, pull.lazy_profile_secs)
    else {
        return Ok(None);
    };
    if secs == 0 {
        return Ok(None);
    }
    let held = Arc::new(dir.try_clone()?);
    let place = velarx_fuse::profile::Place::in_dir(held.clone(), name)?;
    let order = place.read(pull.lazy_profile_files);
    // (the thread that saves the profile is made by one that confined itself
    // to the directory of the profile: it has that confinement)
    // (named by the descriptor the profile is written through, which the
    // place holds for as long as the threads that write it live)
    let profile_dir = velarx_sys::fd::proc_path(&*held);
    let recording = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("profile".into())
            .spawn_scoped(scope, || {
                crate::monitor::confine::fetch_thread(&Fetching {
                    make: vec![profile_dir.clone()],
                    ..Fetching::default()
                })?;
                Ok::<_, io::Error>(velarx_fuse::profile::Recording::start(
                    place.clone(),
                    std::time::Duration::from_secs(secs),
                    pull.lazy_profile_files,
                ))
            })
            .map_err(io_err)?
            .join()
            .unwrap_or_else(|_| Err(io_err("the start of the profile panicked")))
    });
    match recording {
        Ok(recording) => mounts.set_recording(recording),
        Err(e) => tracing::info!("no startup profile of the image: {e}"),
    }
    let mut peers = reach;
    peers.make.push(profile_dir);
    Ok(
        (order.is_empty() && pull.lazy_profile_peers).then(|| AskPeers {
            loader,
            image_id: lazy.image_id.clone(),
            place,
            max: pull.lazy_profile_files,
            reach: peers,
        }),
    )
}

/// The staging directories of the layers of the image (`layers/<stem>/files`
/// below the staging directory of the store), in the order of the layers.
fn staged_dirs(request: &Request, lazy: &LazySpec) -> Vec<PathBuf> {
    let area = velarx_content::pull::staged::Staging::new(&lazy.staging);
    request
        .layers
        .iter()
        .filter_map(|l| velarx_types::LayerKey::parse(l))
        .map(|k| area.layer_files(&k))
        .collect()
}

/// What the threads that ask for files reach (`confine::fetch_thread`):
/// they read the stores and the staging directories of the layers of the
/// image (to open and measure what the engine staged); they make no file,
/// and look up no socket (their connections come through the connector).
fn fetching(request: &Request, lazy: &LazySpec) -> Fetching {
    Fetching {
        read: std::iter::once(request.store.clone())
            .chain(request.more_stores.iter().cloned())
            .chain(staged_dirs(request, lazy))
            .collect(),
        make: Vec::new(),
    }
}

thread_local! {
    /// This thread confined itself for fetching, or why it could not.
    static FETCH_CONFINED: std::cell::RefCell<Option<Result<(), String>>> =
        const { std::cell::RefCell::new(None) };
}

/// The fetcher of the FUSE file system of a lazy image: a thread that asks
/// for files (the `fetch` workers) confines itself when it starts, before
/// any request, for good; one that cannot asks for nothing.
struct ConfinedFetch {
    loader: Arc<LazyLoader>,
    reach: Fetching,
}

impl ConfinedFetch {
    fn confined(&self) -> Result<(), String> {
        FETCH_CONFINED.with(|c| {
            c.borrow_mut()
                .get_or_insert_with(|| {
                    crate::monitor::confine::fetch_thread(&self.reach)
                        .map_err(|e| format!("the fetching thread cannot be confined: {e}"))
                })
                .clone()
        })
    }
}

impl velarx_fuse::LazyFileFetcher for ConfinedFetch {
    fn thread_started(&self) -> Result<(), String> {
        self.confined()
    }

    fn fetch_file_blocking(
        &self,
        file_digest: &str,
        layer_digest: &str,
        timeout: Option<std::time::Duration>,
    ) -> Result<PathBuf, String> {
        self.confined()?;
        self.loader
            .fetch_file_blocking(file_digest, layer_digest, timeout)
    }
}

/// How long the profile of the peers is waited for: meanwhile the
/// container runs, its lookups are fetched as they come.
const PEER_PROFILE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The question for the startup profile of an image to the engine (which
/// asks the fetchers of the peers), asked in the background of the
/// container, and kept when the store has none: the completer of the pull
/// fetches in its order.
struct AskPeers {
    loader: Arc<LazyLoader>,
    image_id: String,
    place: velarx_fuse::profile::Place,
    max: usize,
    /// What the thread reaches: what a fetch does, and the directory of the
    /// profile.
    reach: Fetching,
}

impl AskPeers {
    fn start(self) {
        let spawned = std::thread::Builder::new()
            .name("peer-profile".into())
            .spawn(move || {
                let Self {
                    loader,
                    image_id,
                    place,
                    max,
                    reach,
                } = self;
                if let Err(e) = crate::monitor::confine::fetch_thread(&reach) {
                    tracing::info!("no profile of the peers: the thread cannot be confined: {e}");
                    return;
                }
                let shared = loader.peer_profile(max, PEER_PROFILE_WAIT);
                if shared.is_empty() {
                    return;
                }
                tracing::debug!(
                    "Image {image_id}: a startup profile of {} files from the peers",
                    shared.len()
                );
                let text = serde_json::json!({"v": 1, "files": shared}).to_string();
                if let Err(e) = place.keep_if_absent(text.as_bytes()) {
                    tracing::debug!("cannot keep the startup profile of {image_id}: {e}");
                }
            });
        if let Err(e) = spawned {
            tracing::info!("no profile of the peers: {e}");
        }
    }
}

/// The overlay over the directories of the layers of the FUSE mount `mount`
/// and the data-only directories `datas` (or, where the files go through the
/// FUSE file system, its `data` directory).
fn overlay(
    request: &Request,
    mount: &OwnedFd,
    datas: &[OwnedFd],
    served: &Made,
) -> io::Result<OwnedFd> {
    let base = fd_path(mount.as_fd());
    let lowers: Vec<String> = (0..request.layers.len())
        .rev()
        .map(|i| format!("{base}/{}", layer_dir(i)))
        .collect();
    let data: Vec<String> = match served.through_fuse {
        true => vec![format!("{base}/{}", velarx_fuse::erofs_tree::DATA_DIR)],
        false => datas.iter().map(|d| fd_path(d.as_fd())).collect(),
    };
    let verity = overlay_verity(request, served.through_fuse, measured(request, datas));
    let stubs = served.stubs;
    match &request.root {
        None => readonly_overlay(
            &lowers,
            &data,
            verity,
            request.userxattr,
            stubs,
            request.label.as_deref(),
        ),
        Some(root) => {
            let fd = writable_overlay(&RootOverlay {
                lowers: &lowers,
                datas: &data,
                upper: &root.upper,
                work: &root.work,
                verity: Some(verity),
                userxattr: request.userxattr,
                volatile: root.volatile,
                stubs,
                label: request.label.as_deref(),
            })?;
            mtab_link(fd.as_fd()).map_err(|e| io_err(format!("creating /etc/mtab failed: {e}")))?;
            Ok(fd)
        }
    }
}

/// The request and its descriptors to the server on `sock`: the request with
/// the first descriptors, the others in the messages after it.
fn send_request(sock: &OwnedFd, request: &Request, fds: &[BorrowedFd<'_>]) -> io::Result<()> {
    let bytes = serde_json::to_vec(request).map_err(io_err)?;
    let (head, rest) = fds.split_at(fds.len().min(FDS_PER_MESSAGE));
    velarx_sys::scm::send(sock, &bytes, head)?;
    for chunk in rest.chunks(FDS_PER_MESSAGE) {
        velarx_sys::scm::send(sock, b"+", chunk)?;
    }
    Ok(())
}

/// The log `path` of a server, opened by the engine, which the server needs
/// no privilege for (nothing, when it cannot be opened).
fn open_log(path: &Path) -> std::process::Stdio {
    use std::os::unix::fs::OpenOptionsExt;
    match File::options()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file.into(),
        Err(e) => {
            tracing::warn!(
                "cannot open the log of the image server {}: {e}",
                path.display()
            );
            std::process::Stdio::null()
        }
    }
}

/// Start a server for `request`, with the open images (the lowest layer
/// first) and the descriptors after them (`rest`: the directories of the
/// objects, and for a lazy image the indexes and the directory of the
/// profile), by running `program` as the image server.  The overlay and the
/// server's pidfd, or why the server could not serve.
pub fn start(
    program: &Path,
    request: &Request,
    images: &[BorrowedFd<'_>],
    rest: &[BorrowedFd<'_>],
    log: &Path,
) -> Result<Served, ServerError> {
    start_within(program, request, images, rest, log, ANSWER_WITHIN)
}

fn start_within(
    program: &Path,
    request: &Request,
    images: &[BorrowedFd<'_>],
    rest: &[BorrowedFd<'_>],
    log: &Path,
    within: std::time::Duration,
) -> Result<Served, ServerError> {
    let fail = |what: &str, e: io::Error| ServerError(format!("the image server: {what}: {e}"));
    if images.len() != request.layers.len() || images.len() + rest.len() != request.descriptors() {
        return Err(ServerError(
            "the image server: the request does not match its descriptors".into(),
        ));
    }
    let (mine, theirs) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|e| fail("socketpair", e.into()))?;
    rustix::net::sockopt::set_socket_timeout(
        &mine,
        rustix::net::sockopt::Timeout::Recv,
        Some(within),
    )
    .map_err(|e| fail("socket timeout", e.into()))?;
    let mut cmd = std::process::Command::new(program);
    cmd.arg(FLAG)
        .stdin(std::process::Stdio::from(theirs))
        .stdout(std::process::Stdio::null())
        .stderr(open_log(log))
        .env_remove("NOTIFY_SOCKET")
        .env_remove(velarx_base::spawn::SCOPE_ENV);
    let mut child = cmd
        .spawn()
        .map_err(|e| fail(&format!("cannot run {}", program.display()), e))?;
    // (the first process exits at once: it forked the server; the command
    // holds the server's end of the socket until it is dropped, and a server
    // that ended must show as the end of the stream)
    drop(cmd);
    let _ = child.wait();
    let all: Vec<BorrowedFd<'_>> = images.iter().chain(rest).copied().collect();
    send_request(&mine, request, &all).map_err(|e| fail("sending the request", e))?;
    let mut buf = vec![0u8; 1 << 16];
    let got = match velarx_sys::scm::recv(&mine, &mut buf, 2, rustix::net::RecvFlags::empty()) {
        Ok(got) => got,
        // (a server that ended resets the connection as it closes)
        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
            return Err(ServerError(
                "the image server ended without an answer".into(),
            ))
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            return Err(ServerError(format!(
                "the image server did not answer within {} s",
                within.as_secs_f32()
            )))
        }
        Err(e) => return Err(fail("reading the answer", e)),
    };
    if got.bytes == 0 {
        return Err(ServerError(
            "the image server ended without an answer".into(),
        ));
    }
    let reply: Reply =
        serde_json::from_slice(&buf[..got.bytes]).map_err(|e| fail("the answer", io_err(e)))?;
    if let Some(why) = reply.error {
        return Err(ServerError(format!("the image server: {why}")));
    }
    let mut fds = got.fds.into_iter();
    match (fds.next(), fds.next(), fds.next()) {
        (Some(overlay), Some(server), None) => Ok(Served {
            overlay,
            server,
            lowest_stubs: reply.lowest_stubs,
        }),
        _ => Err(ServerError(
            "the image server did not answer with an overlay and its pidfd".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(layers: usize, datas: usize) -> Request {
        Request {
            name: "abc root".into(),
            layers: (0..layers).map(|n| format!("sha256:{n:064x}")).collect(),
            datas,
            owners: (vec![0, 1000], vec![0]),
            store: "/s/objects".into(),
            more_stores: vec!["/ro/objects".into()],
            translate: IdTranslate::default(),
            userxattr: true,
            verity: "on".into(),
            enforce: false,
            run_root: "/run".into(),
            label: Some("system_u:object_r:container_file_t:s0".into()),
            root: Some(RootSpec {
                upper: "/b/upper".into(),
                work: "/b/work".into(),
                volatile: true,
            }),
            lazy: None,
            debug: false,
        }
    }

    fn sockets() -> (OwnedFd, OwnedFd) {
        rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap()
    }

    /// The request and the descriptors of the layers and of the directories
    /// of objects arrive whole, also when they are more than one message
    /// carries (the rest follow in messages of their own), in their order.
    #[test]
    fn the_descriptors_follow_the_request_in_as_many_messages_as_it_takes() {
        for (layers, datas) in [(1, 1), (3, 2), (199, 1), (200, 1), (450, 3)] {
            let (mine, theirs) = sockets();
            let files: Vec<File> = (0..layers + datas)
                .map(|_| File::open("/dev/null").unwrap())
                .collect();
            let fds: Vec<BorrowedFd<'_>> = files.iter().map(|f| f.as_fd()).collect();
            let want = request(layers, datas);
            let sent = want.clone();
            let thread = std::thread::spawn(move || {
                let (request, fds) = receive(&theirs).unwrap();
                assert_eq!(
                    serde_json::to_value(&request).unwrap(),
                    serde_json::to_value(&sent).unwrap()
                );
                assert_eq!(fds.len(), request.descriptors());
            });
            send_request(&mine, &want, &fds).unwrap();
            thread.join().unwrap();
        }
    }

    /// A request that says more descriptors than it brings, or brings more,
    /// or too many, is refused with the count.
    #[test]
    fn a_request_whose_descriptors_do_not_match_it_is_refused() {
        let null = File::open("/dev/null").unwrap();
        let other = File::open("/dev/null").unwrap();
        let cases = [
            (
                request(2, 1),
                4,
                "4 descriptors for 2 layers and 1 directories",
            ),
            (request(MAX_FDS, 1), 1, "more than the"),
        ];
        for (want, brought, error) in cases {
            let (mine, theirs) = sockets();
            let fds: Vec<BorrowedFd<'_>> = (0..brought)
                .map(|n| {
                    if n % 2 == 0 {
                        null.as_fd()
                    } else {
                        other.as_fd()
                    }
                })
                .collect();
            let thread = std::thread::spawn(move || receive(&theirs).unwrap_err().to_string());
            send_request(&mine, &want, &fds).unwrap();
            let e = thread.join().unwrap();
            assert!(e.contains(error), "{e}");
        }
        // an empty message is no request
        let (mine, theirs) = sockets();
        velarx_sys::scm::send(&mine, b"", &[]).unwrap();
        assert!(receive(&theirs).unwrap_err().to_string().contains("empty"));
    }

    /// The server's way of saying why it cannot serve is an error of the
    /// client with the reason, and a server that ends without a word is one
    /// too.
    #[test]
    fn a_server_that_says_why_not_or_says_nothing_is_an_error_with_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let null = File::open("/dev/null").unwrap();
        let script = |name: &str, text: &str| {
            let path = dir.path().join(name);
            // (written by a process of its own: no ETXTBSY from a test that
            // forks meanwhile)
            velarx_base::testing::write_script(&path, text);
            path
        };
        let ask = |program: &Path| {
            start(
                program,
                &request(1, 0),
                &[null.as_fd()],
                &[],
                &dir.path().join(LOG_FILE),
            )
            .unwrap_err()
            .to_string()
        };
        let e = ask(&dir.path().join("none"));
        assert!(e.contains("cannot run"), "{e}");
        // ends at once: nothing to read from it
        let e = ask(&script("silent", "exit 0"));
        assert!(
            e.contains("without an answer") || e.contains("sending"),
            "{e}"
        );
        // keeps the socket and says nothing: not waited for longer than said
        let mute = script("mute", "sleep 2 <&0 &\nexit 0");
        let t = std::time::Instant::now();
        let e = start_within(
            &mute,
            &request(1, 0),
            &[null.as_fd()],
            &[],
            &dir.path().join(LOG_FILE),
            std::time::Duration::from_millis(200),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("did not answer within 0.2 s"), "{e}");
        assert!(t.elapsed() < std::time::Duration::from_secs(2), "{e}");
    }

    /// The checks of the FUSE file system on the files it opens: every file
    /// where it must (`require`, or the digests enforced), the store's where
    /// the engine says `on`, none otherwise.
    #[test]
    fn the_fuse_file_system_checks_what_the_overlay_says() {
        for (verity, require, want) in [
            ("on", false, VerityMode::On),
            ("off", false, VerityMode::Off),
            ("require", false, VerityMode::Require),
            ("off", true, VerityMode::Require),
            ("on", true, VerityMode::Require),
        ] {
            assert_eq!(fuse_verity(verity, require), want, "{verity} {require}");
        }
    }

    /// A request for an image that is being pulled.
    fn lazy_request(verity: &str, require: bool) -> Request {
        let mut r = request(2, 2);
        r.verity = verity.into();
        r.lazy = Some(LazySpec {
            image_id: "a".repeat(64),
            staging: "/s/staging".into(),
            pull: velarx_config::Config::default().pull,
            fsverity: (true, require),
            proxy: "/run/services/image-fetch/engine".into(),
            token: "t".into(),
            profile: Some("abc.profile.json".into()),
        });
        r
    }

    fn dir_fd(path: &Path) -> OwnedFd {
        OwnedFd::from(File::open(path).unwrap())
    }

    /// The overlay checks the files of the data-only layers where they all
    /// have fs-verity: those of the store, and with those of a staging on its
    /// file system; not those of the FUSE file system, nor of a staging on
    /// another file system, nor when the files all go through the FUSE file
    /// system.  A complete image is the engine's word whatever else.
    #[test]
    fn what_the_overlay_checks() {
        let tmp = tempfile::tempdir().unwrap();
        let (objects, staging) = (tmp.path().join("objects"), tmp.path().join("staging"));
        std::fs::create_dir_all(&objects).unwrap();
        std::fs::create_dir_all(&staging).unwrap();
        // (proc is a file system of its own)
        let elsewhere = Path::new("/proc/self");
        for verity in ["off", "on", "require"] {
            let complete = Request {
                verity: verity.into(),
                ..request(2, 1)
            };
            for (through_fuse, measured) in
                [(false, false), (false, true), (true, false), (true, true)]
            {
                assert_eq!(overlay_verity(&complete, through_fuse, measured), verity);
            }
            let same = [dir_fd(&objects), dir_fd(&staging)];
            let other = [dir_fd(&objects), dir_fd(elsewhere)];
            let lazy = lazy_request(verity, false);
            let on_same_device = measured(&lazy, &same);
            assert_eq!(
                on_same_device,
                verity != "off",
                "staging on the store's file system"
            );
            assert!(!measured(&lazy, &other), "staging elsewhere");
            assert!(!measured(&lazy, &[]), "no directory");
            assert_eq!(
                overlay_verity(&lazy, false, on_same_device),
                verity,
                "staging"
            );
            assert_eq!(
                overlay_verity(&lazy, false, false),
                "off",
                "elsewhere or FUSE"
            );
            assert_eq!(overlay_verity(&lazy, true, true), "off", "through FUSE");
        }
    }

    /// With `fsverity_require` the files of a lazy image all go through the
    /// FUSE file system, which checks them, where the overlay cannot check
    /// them all (a staging on another file system than the store), and where
    /// the overlay follows the stubs of the lowest layer only; a complete
    /// image or no requirement never.
    #[test]
    fn what_goes_through_fuse() {
        for (require, stubs, measured, lazy, want) in [
            (true, Stubs::Lowest, true, true, true),
            (true, Stubs::Lowest, false, true, true),
            (true, Stubs::Every, true, true, false),
            (true, Stubs::Every, false, true, true),
            (false, Stubs::Lowest, false, true, false),
            (false, Stubs::Every, false, true, false),
            (true, Stubs::Lowest, false, false, false),
            (true, Stubs::Every, false, false, false),
        ] {
            let mut r = lazy_request("require", require);
            if !lazy {
                r.lazy = None;
            }
            assert_eq!(
                data_through_fuse(&r, stubs, measured),
                want,
                "{require} {stubs:?} {measured} {lazy}"
            );
        }
    }

    /// The descriptors of a lazy image are the layers, the directories, the
    /// indexes and the profile's directory, and they come apart as they
    /// were put together.
    #[test]
    fn the_descriptors_of_a_lazy_image_come_apart() {
        for (layers, datas, profile) in [(1, 2, true), (3, 3, false), (2, 2, true)] {
            let mut r = lazy_request("on", false);
            r.layers = (0..layers).map(|n| format!("sha256:{n:064x}")).collect();
            r.datas = datas;
            let lazy = r.lazy.as_mut().unwrap();
            lazy.profile = profile.then(|| "p.json".to_string());
            assert_eq!(
                r.descriptors(),
                layers + datas + layers + usize::from(profile)
            );
            let rest: Vec<OwnedFd> = (0..r.descriptors() - layers)
                .map(|_| OwnedFd::from(File::open("/dev/null").unwrap()))
                .collect();
            let given = split(&r, rest);
            assert_eq!(given.datas.len(), datas);
            assert_eq!(given.indexes.len(), layers);
            assert_eq!(given.profile_dir.is_some(), profile);
        }
        // an image that is not lazy has the layers and the directories only
        let r = request(2, 3);
        assert_eq!(r.descriptors(), 5);
        let given = split(
            &r,
            (0..3)
                .map(|_| OwnedFd::from(File::open("/dev/null").unwrap()))
                .collect(),
        );
        assert_eq!(given.datas.len(), 3);
        assert!(given.indexes.is_empty() && given.profile_dir.is_none());
    }

    #[test]
    fn the_log_of_a_server_is_appended_and_bounded_keeping_the_latest_lines() {
        use io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LOG_FILE);
        std::fs::write(&path, b"before\n").unwrap();
        let file = File::options().append(true).open(&path).unwrap();
        let mut log = Log { file, written: 7 };
        log.write_all(b"first\n").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, "before\nfirst\n");
        // a line that would make it larger than the limit empties it
        log.written = LOG_LIMIT - 3;
        log.write_all(b"latest\n").unwrap();
        log.write_all(b"and after\n").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text.as_bytes(),
            [LOG_EMPTIED, b"latest\nand after\n"].concat(),
            "{text}"
        );
        assert_eq!(log.written, text.len() as u64);
        // whatever it is told, the log stays within the limit, the end of
        // what came last in it
        let line = vec![b'x'; 300 << 10];
        for _ in 0..10 {
            log.write_all(&line).unwrap();
            let len = std::fs::metadata(&path).unwrap().len();
            assert!(len <= LOG_LIMIT, "{len}");
            assert_eq!(log.written, len);
        }
        let huge = [vec![b'a'; 2 << 20], b"end\n".to_vec()].concat();
        log.write_all(&huge).unwrap();
        let text = std::fs::read(&path).unwrap();
        assert_eq!(text.len() as u64, LOG_LIMIT);
        assert!(text.starts_with(LOG_EMPTIED) && text.ends_with(b"aaaend\n"));
    }
}
