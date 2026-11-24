// SPDX-License-Identifier: Apache-2.0
use crate::storage_driver::{
    self, ComposefsDriver, ComposefsOptions, DriverOptions, DriverParts, StorageDriver,
    VarlinkOptions,
};
use bytes::Bytes;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, info, warn};
use velarx_db::{Database, ImageRecord, ImageTag, LayerKey};
use velarx_storage::{FileStore, StorageLock, Toc, TocEntryType};
use velarx_types::digest::{Algorithm, Digest};
use velarx_types::{
    printable, ImageError, ImageReference, ImageResult, OciConfig, OciDescriptor, OciManifest,
};

/// Whether the repository of `reference` (not its registry, tag or digest)
/// has a capital letter, which no repository name may.
fn repository_has_capitals(reference: &str) -> bool {
    let name = reference.split('@').next().unwrap_or("");
    let name = match name.rsplit_once(':') {
        Some((n, tag)) if !tag.contains('/') => n,
        _ => name,
    };
    let path = match name.split_once('/') {
        Some((first, rest)) if velarx_base::reference::is_registry_domain(first) => rest,
        _ => name,
    };
    path.bytes().any(|b| b.is_ascii_uppercase())
}

fn is_lower_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Debug, Clone)]
pub struct TransferProgress {
    pub subject: meter::Subject,
    pub status: String,
    pub current_bytes: u64,
    pub total_bytes: u64,
    pub complete: bool,
}

/// Progress is advisory: reporting must never wait for the receiver.
///
/// A caller may drop the receiver, forget to drain it or be slower than the
/// pull; a blocking send would then stall the pull forever once the channel
/// is full (which is what made every pull of a layer that is downloaded in
/// many reads hang).  Updates that do not fit are dropped, the result of the
/// pull carries everything that matters.
pub trait ProgressSink {
    fn report(&self, progress: TransferProgress);
}

impl ProgressSink for mpsc::Sender<TransferProgress> {
    fn report(&self, progress: TransferProgress) {
        let _ = self.try_send(progress);
    }
}

/// Format bytes as human-readable string
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Per-pull settings.
#[derive(Debug, Clone)]
pub struct PullOptions {
    /// `false` for `--tls-verify=false`: no certificate checks, and plain
    /// HTTP is accepted.
    pub tls_verify: bool,
    /// `OS/ARCH[/VARIANT]` of the image to pull from an index; by default
    /// linux on the architecture of this host.
    pub platform: Option<String>,
    /// Credentials and certificates the client brought.
    pub access: velarx_registry::auth::RegistryAccess,
    /// The list of fetchers of this pull (`--sources`), the head first;
    /// none: `[pull] sources`
    pub sources: Option<Vec<String>>,
}

impl Default for PullOptions {
    fn default() -> Self {
        Self {
            tls_verify: true,
            platform: None,
            access: Default::default(),
            sources: None,
        }
    }
}

/// Result from pulling an image
#[derive(Debug, Clone)]
pub struct PullResult {
    /// The image ID (short manifest digest)
    pub id: String,
    /// Statistics from the pull operation
    pub stats: TransferStats,
}

/// What a pull moved, by source (the wire type, with what each layer cost)
#[derive(Debug, Clone, Default, Serialize)]
pub struct TransferStats {
    /// By source, in the order they were first seen
    pub by_source: Vec<velarx_proto::workload::BySource>,
    /// Number of layers already present
    pub layers_cached: u64,
    /// Total pull duration in milliseconds
    pub duration_ms: u64,
    /// What each layer cost
    #[serde(default)]
    pub layers: Vec<LayerStats>,
}

impl TransferStats {
    /// Count `bytes` and `files` as moved by the source `name`.
    pub fn add(&mut self, name: &str, bytes: u64, files: u64) {
        velarx_proto::workload::BySource::add_to(&mut self.by_source, name, bytes, files);
    }

    /// The bytes and files the source `name` moved.
    pub fn from(&self, name: &str) -> (u64, u64) {
        velarx_proto::workload::BySource::sum_of(&self.by_source, name)
    }
}

/// The cost of one layer of a pull.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LayerStats {
    pub digest: String,
    /// Bytes requested from the registry
    pub fetched_bytes: u64,
    /// Compressed bytes the store already had
    pub deduplicated_bytes: u64,
    pub fetched_files: u64,
    pub deduplicated_files: u64,
    /// The layer was already stored
    pub cached: bool,
}

pub use velarx_registry::target::Resolver;

mod archive;
mod artifact;
mod artifact_registry;
mod chain;
pub use chain::{
    check_spec, check_taken, index_links, links, links_of_tag, taken_of, verify, Verified,
};
mod changes;
mod commit;
mod completer;
pub use completer::PullHandOff;
mod diff;
mod lazy;
mod lazy_fetch;
mod manifest;
pub mod meter;
mod pause;
pub use pause::{infra_image_name, pause_image_name};
mod pull;
mod pull_origin;
mod pulls;
use pulls::pulling_error;
pub use pulls::PullInfo;
mod push;
pub(crate) mod seal;
pub use seal::{is_merged_annotation, merged_annotation, LAYER_EROFS_ANNOTATION};
mod search;
mod signatures;
pub use signatures::SignatureJudging;
mod squash;
mod storage;

pub use archive::LoadedImage;
pub use artifact::ArtifactOptions;
pub use commit::{Changes, CommitOptions, ConfigEdit};
pub use diff::merged_paths;
pub use manifest::{AddOptions, InstanceOptions, ListPushOptions, ManifestList, ManifestRequest};
pub use push::{check_manifest_format, PathPush, PushOptions, PushResult, TransportPush};
pub use search::{SearchFilter, SearchOptions};
pub use velarx_registry::target::Platform;

#[derive(Clone)]
pub struct ImageService {
    db: Database,
    file_store: Arc<FileStore>,
    staging_dir: PathBuf,
    /// Thread-safe registry client - can be cloned for parallel downloads
    resolver: Resolver,
    /// What fs-verity stored files get
    fsverity: velarx_storage::VerityMode,
    /// Whether the file system of the store has fs-verity, and the files
    /// get it (probed once, with the first answer)
    store_verity: Arc<std::sync::OnceLock<bool>>,
    /// The storage driver: what holds the content of the images and makes
    /// the root file systems of containers (`crate::storage_driver`).
    storage: Arc<dyn StorageDriver>,
    /// Which driver it is (`[storage] driver`, resolved against the store).
    storage_kind: velarx_config::StorageDriverKind,
    /// What `[storage]` says of it (the driver is made again from these
    /// when they change).
    storage_options: ComposefsOptions,
    /// `[storage] composefs`, once read: the options are found out for it
    /// (`ComposefsOptions::for_mode`) when it or the image server is set.
    composefs_mode: Option<String>,
    /// `[storage] verity_chain`.
    verity_chain: velarx_config::VerityChain,
    /// `[storage] fsverity_best_effort`: a driver that checks fs-verity at
    /// pull only is accepted with the settings that enforce it.
    verity_best_effort: bool,
    /// `[storage] vfs_ignore_chown_errors`.
    vfs_ignore_chown_errors: bool,
    /// `[storage.varlink]`, for the `varlink` driver.
    varlink: Option<VarlinkOptions>,
    pull_config: velarx_config::PullConfig,
    push_config: velarx_config::PushConfig,
    /// `[[transports]]`: the processes that are the origin of a scheme
    transports: Arc<Vec<velarx_config::TransportConfig>>,
    /// The algorithm of the images the creating commands make when they are
    /// not asked for one (`[build] digest`)
    default_digest: Algorithm,
    /// The layers pulls are fetching, so that each is downloaded once.
    pulling: Arc<pull::LayerLockMap>,
    /// The fetches of lazy files of this process (`lazy_fetch`).
    funnel: Arc<lazy_fetch::LazyFunnel>,
    /// The registry as a fetcher of another process: the files no source has
    /// come from it, and this process needs no network (none: it fetches from
    /// the registry itself)
    origin: Option<Arc<velarx_content::list::RegistryOrigin>>,
    /// The runtime of the blocking fetches (`LazyFileFetcher`), made on
    /// first use.
    fuse_runtime: Arc<FetchRuntime>,
    /// Who completes the lazy pulls (`completer`)
    owner: completer::Owner,
    /// The fetchers of `[[sources.external]]`, which `[pull] sources` (or a
    /// pull's own list) puts in the list of a pull
    fetchers: Arc<Vec<velarx_config::ExternalSourceConfig>>,
    /// The pushers of `[[sinks.external]]`, which `[push] sinks` (or a
    /// push's own list) puts before the destination's own in the list of a
    /// push
    sinks: Arc<Vec<velarx_config::ExternalSinkConfig>>,
}

/// A runtime for the callers that are not on one (FUSE threads, copies):
/// made when it is first needed, and shut down without waiting when the
/// service goes, which may be on a thread of another runtime (the daemon's,
/// at its end), where waiting is not allowed.
#[derive(Default)]
pub(crate) struct FetchRuntime {
    runtime: std::sync::OnceLock<tokio::runtime::Runtime>,
}

impl FetchRuntime {
    pub(crate) fn get(&self) -> std::io::Result<&tokio::runtime::Runtime> {
        if let Some(rt) = self.runtime.get() {
            return Ok(rt);
        }
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4) // Handle multiple concurrent FUSE requests
            .thread_name("fuse-fetch")
            .enable_all()
            .build()?;
        // Another thread may have made one meanwhile: that one is used.
        if let Err(ours) = self.runtime.set(rt) {
            ours.shutdown_background();
        }
        self.runtime
            .get()
            .ok_or_else(|| std::io::Error::other("no runtime"))
    }
}

impl Drop for FetchRuntime {
    fn drop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_background();
        }
    }
}

/// What the candidates of a short name answered, in the order they were
/// tried: containers/image goes on to the next candidate whatever the
/// failure was (not found, refused, unreachable), and says what each of them
/// answered when none works.
#[derive(Default)]
pub(super) struct Tried(Vec<(String, ImageError)>);

impl Tried {
    pub(super) fn push(&mut self, candidate: &str, error: ImageError) {
        self.0.push((candidate.to_string(), error));
    }

    /// The error of a failure of every candidate: the one error of a single
    /// candidate, else all of them.  An image in a Docker format keeps its
    /// kind, whose status the callers know.
    pub(super) fn into_error(self, reference: &str) -> ImageError {
        if self.0.len() <= 1 {
            return match self.0.into_iter().next() {
                Some((_, e)) => e,
                None => ImageError::NotFound(reference.to_string()),
            };
        }
        let docker = self
            .0
            .iter()
            .any(|(_, e)| matches!(e, ImageError::DockerFormat(_)));
        let message = format!(
            "no candidate of `{reference}` could be pulled ({} tried): {}",
            self.0.len(),
            self.0
                .iter()
                .map(|(c, e)| format!("{c}: {e}"))
                .collect::<Vec<_>>()
                .join("; ")
        );
        if docker {
            ImageError::DockerFormat(message)
        } else {
            ImageError::Registry(message)
        }
    }
}

impl ImageService {
    pub fn new(
        db: Database,
        file_store: Arc<FileStore>,
        staging_dir: PathBuf,
        fsverity: velarx_storage::VerityMode,
    ) -> Result<Self, velarx_base::ids::IdsError> {
        std::fs::create_dir_all(&staging_dir).map_err(|e| {
            velarx_base::ids::IdsError(std::io::Error::new(
                e.kind(),
                format!(
                    "cannot create the staging directory {}: {e}",
                    staging_dir.display()
                ),
            ))
        })?;
        // Only when no one holds the lock of the store (the collection
        // sweeps otherwise), and not the sessions of the pulls that hold
        // their lease: a pull holds the lock of the store only to start and
        // to commit, not through its download.  The stagings of the layers
        // of a process that died with them go too, and the lazy pulls of an
        // earlier boot (the first process of a boot is alone).  What an
        // earlier boot left is not used by anything: a process that finds it
        // waits for the lock and cleans it, whoever holds it.
        let area = velarx_content::pull::staged::Staging::new(&staging_dir);
        let lock_path = StorageLock::path_of_staging(&staging_dir);
        let alone = match area.is_of_this_boot() {
            Ok(true) => StorageLock::try_exclusive(&lock_path),
            _ => StorageLock::exclusive_blocking(&lock_path).map(Some),
        };
        match alone {
            Ok(Some(_alone)) => {
                if let Err(e) = area.forget_earlier_boots() {
                    warn!("Cannot remove the lazy pulls of an earlier boot: {e}");
                }
                velarx_content::pull::session::Session::sweep(&staging_dir, |s| {
                    db.lease_is_held(s)
                });
                if let Err(e) = velarx_content::pull::staged_fetch::sweep(&staging_dir) {
                    warn!("Cannot remove the staging of a layer: {e}");
                }
            }
            Ok(None) => debug!("The store is in use: its staging directory is left alone"),
            Err(e) => warn!("Cannot lock the store: {e}"),
        }

        // (the driver of the store replaces it: `with_driver`; the image
        // server is the engine's own, `with_image_server`)
        let storage_kind = velarx_config::StorageDriverKind::DEFAULT;
        let storage_options = ComposefsOptions::new(storage_driver::ImageServer::new(
            velarx_base::spawn::binary(),
            staging_dir.with_file_name("run"),
            Arc::new(velarx_config::Config::default()),
        ));
        let storage: Arc<dyn StorageDriver> = Arc::new(ComposefsDriver::new(
            db.clone(),
            file_store.clone(),
            staging_dir.clone(),
            fsverity,
            storage_options.clone(),
        ));
        Ok(Self {
            db,
            file_store,
            staging_dir,
            resolver: Resolver::new()?,
            fsverity,
            store_verity: Arc::default(),
            storage,
            storage_kind,
            storage_options,
            composefs_mode: None,
            verity_chain: velarx_config::VerityChain::Auto,
            verity_best_effort: false,
            vfs_ignore_chown_errors: false,
            varlink: None,
            pull_config: velarx_config::PullConfig::default(),
            push_config: velarx_config::PushConfig::default(),
            transports: Arc::default(),
            default_digest: Algorithm::Sha256,
            pulling: Arc::default(),
            funnel: Arc::default(),
            origin: None,
            owner: completer::Owner::default(),
            fetchers: Arc::default(),
            sinks: Arc::default(),
            fuse_runtime: Arc::new(FetchRuntime::default()),
        })
    }

    /// The algorithm of the images that creating commands make when they are
    /// not asked for one (`[build] digest`): never used by pulls.
    pub fn with_default_digest(mut self, alg: Algorithm) -> Self {
        self.default_digest = alg;
        self
    }

    /// The algorithm a creation asked for `requested`, else the default.
    pub fn creation_algorithm(&self, requested: Option<&str>) -> Result<Algorithm, ImageError> {
        match requested.filter(|r| !r.is_empty()) {
            Some(name) => Algorithm::for_creation(name).map_err(ImageError::Invalid),
            None => Ok(self.default_digest),
        }
    }

    /// The registry is reached through `origin`, a fetcher of it in another
    /// process: the files that no source has come from it, and so do the
    /// pulls that need nothing it does not have.
    pub fn with_origin(mut self, origin: Arc<velarx_content::list::RegistryOrigin>) -> Self {
        self.origin = Some(origin);
        // this process asks the fetcher for what the registry holds for
        // it, and holds no credentials of its own
        self.resolver = self.resolver.without_credentials();
        self
    }

    /// The registry fetcher process: every request to a registry goes
    /// through it (this process opens no connection).
    pub(super) fn origin(&self) -> ImageResult<&Arc<velarx_content::list::RegistryOrigin>> {
        self.origin
            .as_ref()
            .ok_or_else(|| ImageError::Registry("no registry fetcher".into()))
    }

    /// The processes of `[[transports]]`, the origins of the schemes of their
    /// own.
    pub fn with_transports(mut self, transports: Vec<velarx_config::TransportConfig>) -> Self {
        self.transports = Arc::new(transports);
        self
    }

    /// The pushers of `[[sinks.external]]`, the engine's list of the pushes.
    pub fn with_sinks(mut self, sinks: Vec<velarx_config::ExternalSinkConfig>) -> Self {
        self.sinks = Arc::new(sinks);
        self
    }

    /// The fetchers of `[[sources.external]]`, the engine's list of the pulls.
    pub fn with_fetchers(mut self, fetchers: Vec<velarx_config::ExternalSourceConfig>) -> Self {
        self.fetchers = Arc::new(fetchers);
        self
    }

    /// Make the root file systems of root containers composefs images
    /// where this process can (`[storage] composefs`: "auto" or "off").
    pub fn with_composefs(mut self, mode: &str) -> Self {
        self.composefs_mode = Some(mode.to_string());
        self.remake_composefs();
        self
    }

    /// Serve the layers the kernel does not mount (rootless, `squash`, an image
    /// that is being pulled) with the image server of `program` (the monitor
    /// binary), which keeps what it finds of the kernel in `run_root` and
    /// fetches the files of a lazy image as `config` says.
    pub fn with_image_server(
        mut self,
        program: std::path::PathBuf,
        run_root: std::path::PathBuf,
        config: Arc<velarx_config::Config>,
    ) -> Self {
        self.storage_options.server = storage_driver::ImageServer::new(program, run_root, config);
        self.remake_composefs();
        self
    }

    /// The options of the composefs driver again, with what the host allows
    /// (`ComposefsOptions::for_mode`) once `[storage] composefs` is known.
    fn remake_composefs(&mut self) {
        if let Some(mode) = &self.composefs_mode {
            let digests = self.storage_options.digests;
            let server = self.storage_options.server.clone();
            self.storage_options = ComposefsOptions::for_mode(mode, server, self.file_store.root());
            self.storage_options.digests = digests;
        }
        self.remake_storage();
    }

    /// What the manifests must say of the fs-verity digests of the EROFS
    /// images of their layers (`[storage] composefs_digests`).
    pub fn with_composefs_digests(mut self, mode: velarx_config::ComposefsDigests) -> Self {
        self.storage_options.digests = mode;
        self.remake_storage();
        self
    }

    /// `[storage] vfs_ignore_chown_errors`.
    pub fn with_vfs_ignore_chown_errors(mut self, ignore: bool) -> Self {
        self.vfs_ignore_chown_errors = ignore;
        self.remake_storage();
        self
    }

    /// `[storage] verity_chain`.
    pub fn with_verity_chain(mut self, mode: velarx_config::VerityChain) -> Self {
        self.verity_chain = mode;
        self
    }

    /// `[storage] verity_chain`.
    pub fn verity_chain(&self) -> velarx_config::VerityChain {
        self.verity_chain
    }

    /// `[storage] fsverity_best_effort`.
    pub fn with_verity_best_effort(mut self, best_effort: bool) -> Self {
        self.verity_best_effort = best_effort;
        self
    }

    /// Whether the digests of the layers are checked at pull only (the driver
    /// cannot check them while a container runs, and the configuration
    /// accepts that): nothing is enforced at a start.
    pub fn verity_pull_only(&self) -> bool {
        !self.storage.capabilities().verity_at_run_time()
    }

    /// Whether what the driver makes of a layer has fs-verity here: the
    /// driver holds the images and the files to their digests while a
    /// container runs, the store sets fs-verity on its files, and its file
    /// system has it.  The layers recorded now are sealed (`layers.sealed`)
    /// when it does.
    pub fn layers_sealed_now(&self) -> bool {
        !self.verity_pull_only()
            && *self.store_verity.get_or_init(|| {
                self.fsverity != velarx_storage::VerityMode::Off
                    && velarx_storage::probe(self.file_store.root()).is_ok()
            })
    }

    /// `[storage] fsverity` is not off: the files of the store get fs-verity.
    pub fn fsverity_on(&self) -> bool {
        self.fsverity != velarx_storage::VerityMode::Off
    }

    /// What the driver of the store cannot do of what the configuration
    /// asks: the digests enforced (`fsverity_require`, `composefs_digests =
    /// "require"`, or `container`: the `--security-opt verity=enforce` of a
    /// container) while the driver checks them at pull only, and the mode that
    /// accepts that (`fsverity_best_effort`) is not set.
    pub fn check_verity_request(&self, fsverity_require: bool, container: bool) -> ImageResult<()> {
        self.check_request(fsverity_require, container, false)
    }

    /// What `[storage]` asks that the driver of the store cannot do: the
    /// digests enforced (see [`check_verity_request`](Self::check_verity_request))
    /// and read-only image stores of the same driver.
    pub fn check_store_config(&self, storage: &velarx_config::StorageConfig) -> ImageResult<()> {
        self.check_request(
            storage.fsverity_require,
            false,
            !storage.additional_image_stores.is_empty(),
        )
    }

    fn check_request(
        &self,
        fsverity_require: bool,
        container: bool,
        shared_stores: bool,
    ) -> ImageResult<()> {
        let enforced = fsverity_require
            || container
            || self.storage_options.digests == velarx_config::ComposefsDigests::Require;
        self.storage
            .capabilities()
            .refuse(
                self.storage.name(),
                &velarx_graph::negotiate::Ask {
                    verity_enforced: enforced,
                    verity_best_effort: self.verity_best_effort,
                    shared_stores,
                    unprivileged: velarx_base::conf::rootless().unwrap_or(false),
                    ..Default::default()
                },
            )
            .map_err(ImageError::from)
    }

    /// The storage driver of the store (`[storage] driver`, as the store
    /// has it).
    pub fn with_driver(mut self, kind: velarx_config::StorageDriverKind) -> Self {
        self.storage_kind = kind;
        self.remake_storage();
        self
    }

    /// The `varlink` driver of the store, opened at the service of
    /// `[storage.varlink]` now (the connection, the store id and the version
    /// are checked, so a service that is not there is the error).  The kind
    /// of the driver is `varlink` from here on.
    pub fn with_varlink(mut self, options: Option<VarlinkOptions>) -> ImageResult<Self> {
        self.storage_kind = velarx_config::StorageDriverKind::Varlink;
        self.varlink = options;
        self.storage = self.open_storage().map_err(ImageError::from)?;
        Ok(self)
    }

    /// The driver of the store, as the options of the service say; the
    /// `varlink` one is kept as it is (it was opened by `with_varlink`, and
    /// no option of the other drivers is one of it).
    fn remake_storage(&mut self) {
        if let Some(storage) =
            storage_driver::open_local(self.storage_kind, self.parts(), &self.driver_options())
        {
            self.storage = storage;
        }
    }

    fn open_storage(&self) -> crate::storage_driver::DriverResult<Arc<dyn StorageDriver>> {
        storage_driver::open(self.storage_kind, self.parts(), &self.driver_options())
    }

    fn parts(&self) -> DriverParts {
        DriverParts {
            db: self.db.clone(),
            store: self.file_store.clone(),
            staging_dir: self.staging_dir.clone(),
            fsverity: self.fsverity,
        }
    }

    fn driver_options(&self) -> DriverOptions {
        DriverOptions {
            composefs: self.storage_options.clone(),
            vfs: velarx_vfs::VfsOptions {
                digests: self.storage_options.digests,
                ignore_chown_errors: self.vfs_ignore_chown_errors,
            },
            varlink: self.varlink.clone(),
        }
    }

    /// The storage driver of the store.
    pub fn storage(&self) -> &Arc<dyn StorageDriver> {
        &self.storage
    }

    /// Use this storage driver of the store instead of the one `[storage]
    /// driver` names (tests, embedders: a driver that wraps the store's own).
    pub fn with_storage_driver(mut self, driver: Arc<dyn StorageDriver>) -> Self {
        self.storage = driver;
        self
    }

    /// Use this registry client instead of the one configured like the
    /// system (tests, embedders).
    pub fn with_resolver(mut self, client: Resolver) -> Self {
        self.resolver = client;
        self
    }

    /// Set how images are pulled.
    pub fn with_pull_config(
        mut self,
        config: velarx_config::PullConfig,
    ) -> Result<Self, velarx_base::ids::IdsError> {
        self.resolver
            .set_min_speed(velarx_content::pull::min_speed(&config));
        self.resolver
            .set_hints(velarx_registry::hints::HintStore::for_pull(
                config.registry_hints,
            )?);
        self.pull_config = config;
        Ok(self)
    }

    /// Get access to the file store for reading extracted files
    pub fn file_store(&self) -> &FileStore {
        &self.file_store
    }

    /// The objects the storage driver holds, as everything that reads the
    /// content of a stored layer or image back takes them: through the driver
    /// ([`StorageDriver::open_object`]), never through a path of the engine's
    /// own file store.
    pub fn objects(&self) -> velarx_graph::DriverObjects {
        velarx_graph::DriverObjects::new(self.storage.clone())
    }

    /// What `[storage] fsverity` asks of the files read back from the driver.
    pub fn verity(&self) -> velarx_storage::VerityMode {
        self.file_store.verity()
    }

    pub async fn pull(
        &self,
        reference: &str,
        lazy: bool,
        progress_tx: mpsc::Sender<TransferProgress>,
    ) -> ImageResult<PullResult> {
        self.pull_with(reference, lazy, &PullOptions::default(), progress_tx)
            .await
    }

    pub async fn pull_with(
        &self,
        reference: &str,
        lazy: bool,
        options: &PullOptions,
        progress_tx: mpsc::Sender<TransferProgress>,
    ) -> ImageResult<PullResult> {
        // (a lazy pull outlives this command: the engine service makes it)
        if lazy {
            if let Some(h) = self.hand_off() {
                return h.pull_lazy(reference, options).await;
            }
        }
        let client = self
            .resolver
            .with_tls_verify(options.tls_verify)
            .with_access(&options.access);
        let platform = options
            .platform
            .as_deref()
            .map(Platform::parse)
            .transpose()
            .map_err(ImageError::Manifest)?;
        let engine = pull::EngineOptions {
            lazy,
            sources: Some(self.sources_of(options.sources.as_deref())?),
            reach: velarx_db::LayerReach {
                tls_verify: options.tls_verify,
                creds: options.access.creds.is_some() || !options.access.auths.is_empty(),
                certs: options.access.certs.is_some(),
            },
            platform,
        };
        // A short name can mean several images: they are tried in order.
        let candidates = self.candidates(reference)?;
        let mut tried = Tried::default();
        for candidate in candidates {
            let result = async {
                // the pull verifies the signatures the policy requires
                self.policy_for(&ImageReference::parse(&candidate)?)?;
                self.pull_engine(&client, &candidate, progress_tx.clone(), &engine)
                    .await
            }
            .await;
            match result {
                Ok(done) => {
                    // (a lazy image is not all in the store: nothing to seal)
                    if !engine.lazy {
                        self.seal_measured(&done.id).await?;
                    }
                    return Ok(done);
                }
                // (the image was found: it is not another candidate's)
                Err(e @ ImageError::NotLazy { .. }) => return Err(e),
                Err(e) => {
                    debug!("Cannot pull {candidate}: {e}");
                    tried.push(&candidate, e);
                }
            }
        }
        Err(tried.into_error(reference))
    }

    /// The fully qualified references `reference` can mean, through the
    /// short name aliases and the unqualified search registries.
    pub fn candidates(&self, reference: &str) -> ImageResult<Vec<String>> {
        self.resolver
            .registries()
            .resolve(reference)
            .map_err(ImageError::Registry)
    }

    /// The signature policy, before anything is fetched: `reject` and `signedBaseLayer`
    /// refuse the image.  Ok: the requirements, which a pull checks against the
    /// signatures of the manifest it gets (`verify_signatures`).
    pub(super) fn policy_for(
        &self,
        image_ref: &ImageReference,
    ) -> ImageResult<Vec<velarx_signature::PolicyRequirement>> {
        let requirements = self.requirements_of(image_ref)?;
        use velarx_signature::evaluate::{precheck, refusal, Mode, Pre};
        if let Pre::Refuse { why, .. } = precheck(Mode::Whole, &requirements) {
            return Err(ImageError::Registry(format!(
                "{}: the signature policy {}",
                image_ref.name(),
                refusal(why)
            )));
        }
        Ok(requirements)
    }

    /// The requirements of policy.json for `image_ref`, as they are.
    pub(super) fn requirements_of(
        &self,
        image_ref: &ImageReference,
    ) -> ImageResult<Vec<velarx_signature::PolicyRequirement>> {
        Ok(self.scoped_requirements_of(image_ref)?.1)
    }

    /// [`Self::requirements_of`], with the scope that applies.
    pub(super) fn scoped_requirements_of(
        &self,
        image_ref: &ImageReference,
    ) -> ImageResult<(String, Vec<velarx_signature::PolicyRequirement>)> {
        use velarx_signature::SignaturePolicy;
        let policy = match &self.pull_config.policy_path {
            Some(path) => SignaturePolicy::load(path),
            None => SignaturePolicy::load_default(),
        }
        .map_err(|e| ImageError::Registry(format!("cannot read the signature policy: {e}")))?;
        let (scope, requirements) =
            policy.scoped_requirements_for("docker", &signatures::intended(image_ref)?);
        if requirements.is_empty() {
            return Err(ImageError::Registry(format!(
                "no signature policy applies to {}",
                image_ref.name()
            )));
        }
        Ok((scope, requirements.to_vec()))
    }

    /// The policy for what reads or copies an image without verifying its
    /// signatures (search, manifest lists, a copy between registries): an
    /// image whose policy requires signatures is refused, failing closed.
    pub(super) fn check_policy(&self, image_ref: &ImageReference) -> ImageResult<()> {
        use velarx_signature::evaluate::{needs_signatures, Mode};
        if needs_signatures(Mode::Whole, &self.policy_for(image_ref)?) {
            return Err(ImageError::Registry(format!(
                "the signature policy requires {} to be signed, and this operation does not verify signatures",
                image_ref.name()
            )));
        }
        Ok(())
    }

    pub async fn list(&self) -> ImageResult<Vec<ImageRecord>> {
        Ok(self.db.list_images().await?)
    }

    pub async fn get_tags(&self, image_id: &str) -> ImageResult<Vec<ImageTag>> {
        Ok(self.db.get_tags_for_image(image_id).await?)
    }

    /// The image `reference` designates, in the order of podman's lookup: a
    /// full id (64 hex digits, or 128 for an image of a sha512 manifest,
    /// with or without `sha256:` or `sha512:`) is an id and nothing else; any other reference is a name first, then an id or the
    /// prefix of one (the config or the manifest digest too).  An id that is
    /// whole wins over longer ids it starts; a prefix that several images
    /// have designates none of them, as with podman.
    pub async fn get(&self, reference: &str) -> ImageResult<ImageRecord> {
        Ok(self.find(reference).await?.0)
    }

    /// The name of the image `id` (repository and tag) that `reference` is,
    /// when it is one of its names, as [`Self::get`] reads a name: what
    /// `--rmi` untags.  None for a reference that is no name of it (an id).
    pub async fn tag_of(&self, reference: &str, id: &str) -> Option<(String, String)> {
        let tags = self.db.get_tags_for_image(id).await.ok()?;
        let parsed = ImageReference::parse(reference).ok()?;
        let tag = parsed.tag.clone().unwrap_or_else(|| "latest".into());
        let mut names = vec![parsed.name()];
        if parsed.registry == "docker.io" && without_registry(reference) {
            if let Ok(local) = ImageReference::parse(&format!("localhost/{reference}")) {
                names.push(local.name());
            }
        }
        for candidate in self.candidates(reference).unwrap_or_default() {
            if let Ok(r) = ImageReference::parse(&candidate) {
                names.push(r.name());
            }
        }
        let short = short_name_and_tag(reference);
        tags.into_iter()
            .find(|t| {
                (t.tag == tag && names.contains(&t.repository))
                    || short.is_some_and(|(name, tag)| {
                        t.tag == tag && repository_ends_with(&t.repository, name)
                    })
            })
            .map(|t| (t.repository, t.tag))
    }

    /// The image `reference` designates, as [`Self::get`] finds it, and
    /// its tags: read once, for the resolution and the signature check.
    pub async fn get_with_tags(
        &self,
        reference: &str,
    ) -> ImageResult<(ImageRecord, Vec<ImageTag>)> {
        let (image, tags) = self.find(reference).await?;
        let tags = match tags {
            Some(tags) => tags,
            None => self.db.get_tags_for_image(&image.id).await?,
        };
        Ok((image, tags))
    }

    /// [`Self::get`], with the tags of the image when the lookup read them.
    /// The store has only complete images: a name that only a pull in
    /// progress has says so.
    async fn find(&self, reference: &str) -> ImageResult<(ImageRecord, Option<Vec<ImageTag>>)> {
        match self.find_stored(reference).await {
            Err(ImageError::NotFound(why)) => match self.staging_area().find(reference) {
                Some(entry) => Err(pulling_error(reference, &entry)),
                None => Err(ImageError::NotFound(why)),
            },
            found => found,
        }
    }

    async fn find_stored(
        &self,
        reference: &str,
    ) -> ImageResult<(ImageRecord, Option<Vec<ImageTag>>)> {
        let (bare, lengths): (&str, &[usize]) = match reference.strip_prefix("sha512:") {
            Some(bare) => (bare, &[128]),
            None => match reference.strip_prefix("sha256:") {
                Some(bare) => (bare, &[64]),
                None => (reference, &[64, 128]),
            },
        };
        let bytes = lengths[0];
        let full = lengths.contains(&bare.len()) && is_lower_hex(bare);
        if reference.len() > bare.len() && !full {
            return Err(ImageError::Invalid(format!(
                "{reference}: invalid format: no {bytes}-byte hexadecimal value"
            )));
        }
        if full {
            return self
                .by_id(bare)
                .await?
                .map(|image| (image, None))
                .ok_or_else(|| ImageError::NotFound(reference.to_string()));
        }
        if repository_has_capitals(reference) {
            return Err(ImageError::Invalid(format!(
                "parsing reference \"{reference}\": repository name must be lowercase"
            )));
        }

        let by_tag = |image_ref: ImageReference| async move {
            let tag = image_ref.tag.as_deref().unwrap_or("latest").to_string();
            self.db.get_image_by_tag(&image_ref.name(), &tag).await
        };
        let parsed = ImageReference::parse(reference)?;
        let unqualified = without_registry(reference);
        // NAME@DIGEST: the image that was pulled by that name, else the image
        // of that manifest when it has that name or no name at all
        if let Some(d) = &parsed.digest {
            if let Ok(image) = self.db.get_image_by_digest_name(&parsed.name(), d).await {
                return Ok((image, None));
            }
            if let Ok(image) = self.db.get_image_by_digest(d).await {
                let tags = self.db.get_tags_for_image(&image.id).await?;
                let name = parsed.name();
                let short = reference.split('@').next().unwrap_or("");
                let short = short
                    .rsplit_once(':')
                    .filter(|(_, t)| !t.contains('/'))
                    .map_or(short, |(n, _)| n);
                // (named: by a tag, which `tags` has, or by a digest name)
                if (tags.is_empty()
                    && self
                        .db
                        .get_digest_names_for_image(&image.id)
                        .await?
                        .is_empty())
                    || tags
                        .iter()
                        .any(|t| t.repository == name || repository_ends_with(&t.repository, short))
                {
                    return Ok((image, Some(tags)));
                }
            }
        }
        // (a digest is no tag: the `latest` of that name is another image)
        if parsed.digest.is_some() && parsed.tag.is_none() {
            return Err(ImageError::NotFound(reference.to_string()));
        }
        if let Ok(image) = by_tag(parsed).await {
            return Ok((image, None));
        }
        // Images committed, built or imported without a registry are
        // `localhost/NAME`, and found by their short name.
        if unqualified {
            if let Ok(image) =
                by_tag(ImageReference::parse(&format!("localhost/{reference}"))?).await
            {
                return Ok((image, None));
            }
        }
        // A short name may have been pulled from another registry.
        if let Ok(candidates) = self.candidates(reference) {
            for candidate in candidates {
                if let Ok(image) = by_tag(ImageReference::parse(&candidate)?).await {
                    return Ok((image, None));
                }
            }
        }
        // Last: a local image whose repository ends with the
        // short name (`alpine` is quay.io/libpod/alpine).
        let mut read = Vec::new();
        if let Some((name, tag)) = short_name_and_tag(reference) {
            for image in self.db.list_images().await? {
                let tags = self.db.get_tags_for_image(&image.id).await?;
                if tags
                    .iter()
                    .any(|t| t.tag == tag && repository_ends_with(&t.repository, name))
                {
                    return Ok((image, Some(tags)));
                }
                read.push((image.id, tags));
            }
        }
        if let Some(image) = self.by_id(bare).await? {
            let tags = read.into_iter().find(|(id, _)| *id == image.id);
            return Ok((image, tags.map(|(_, tags)| tags)));
        }
        Err(ImageError::NotFound(reference.to_string()))
    }

    /// The image with the id `bare` (lowercase hex, any length), or the only
    /// one whose id, config digest or manifest digest it starts.
    async fn by_id(&self, bare: &str) -> ImageResult<Option<ImageRecord>> {
        if !is_lower_hex(bare) {
            return Ok(None);
        }
        let images = self.db.list_images().await?;
        if let Some(image) = images.iter().find(|i| i.id == bare) {
            return Ok(Some(image.clone()));
        }
        let mut hits: Vec<&ImageRecord> = Vec::new();
        for i in &images {
            let matches = i.id.starts_with(bare)
                || i.config_digest.hex().starts_with(bare)
                || i.manifest_digest.hex().starts_with(bare);
            if matches && !hits.iter().any(|h| h.id == i.id) {
                hits.push(i);
            }
        }
        // The records of one configuration (pulled through several
        // manifests) are one image to podman, of that id.
        if hits.len() > 1
            && hits
                .iter()
                .all(|r| r.config_digest == hits[0].config_digest)
        {
            hits.truncate(1);
        }
        if hits.len() > 1 {
            debug!(
                "The prefix {bare} is of {} images: {}",
                hits.len(),
                hits.iter()
                    .map(|h| h.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        Ok(match hits.as_slice() {
            [image] => Some((*image).clone()),
            _ => None,
        })
    }

    /// The name among `tags` (an image's) that `reference` designates, as
    /// [`Self::get`] resolves it (None: an id, or not one of its names).
    pub fn matching_tag(&self, reference: &str, tags: &[ImageTag]) -> Option<ImageTag> {
        let Ok(parsed) = ImageReference::parse(reference) else {
            return None;
        };
        let unqualified = without_registry(reference);
        let tag = parsed.tag.clone().unwrap_or_else(|| "latest".into());
        let mut wanted = vec![parsed.name()];
        if unqualified {
            if let Ok(r) = ImageReference::parse(&format!("localhost/{reference}")) {
                wanted.push(r.name());
            }
            for c in self.candidates(reference).unwrap_or_default() {
                if let Ok(r) = ImageReference::parse(&c) {
                    wanted.push(r.name());
                }
            }
        }
        for w in &wanted {
            if let Some(t) = tags.iter().find(|t| &t.repository == w && t.tag == tag) {
                return Some(t.clone());
            }
        }
        if let Some((name, tag)) = short_name_and_tag(reference) {
            if let Some(t) = tags
                .iter()
                .find(|t| t.tag == tag && repository_ends_with(&t.repository, name))
            {
                return Some(t.clone());
            }
        }
        None
    }

    /// Whether the store can take the objects of images made with `alg`: a
    /// file system with fs-verity but without the hash of the digests of
    /// `alg` (SHA-512 on a kernel or file system that lacks it) fails here,
    /// by name, before anything is made, and never falls back to another
    /// hash.  SHA-256 is what every store takes.
    pub(crate) fn check_digest_algorithm(&self, alg: Algorithm) -> ImageResult<()> {
        if alg == Algorithm::Sha256 || self.fsverity == velarx_storage::VerityMode::Off {
            return Ok(());
        }
        let required = self.fsverity == velarx_storage::VerityMode::Require;
        velarx_storage::probe_algorithm(self.file_store.root(), alg, required).map_err(|e| {
            ImageError::Layer(format!(
                "the store {} cannot take {alg} images: {e}",
                self.file_store.root().display()
            ))
        })
    }

    /// The lock of the store, shared: held while what a pull or a fetch
    /// found in the store and added to it is not recorded yet.
    pub(crate) async fn lock_store(&self) -> ImageResult<StorageLock> {
        StorageLock::shared(&StorageLock::path_of_staging(&self.staging_dir))
            .await
            .map_err(|e| ImageError::Storage(format!("cannot lock the store: {e}")))
    }

    /// Remove the image `reference`.  Returns the space it freed: the bytes of
    /// its manifest and configuration and the layers that went with it (those
    /// no other image, no container and no pull holds), each layer once, as
    /// `system df` sizes layers: [`super::GcReport::layers_size`].  That is how much
    /// smaller the images of the store got, not what a registry would say the
    /// image weighs.
    pub async fn remove(&self, reference: &str, force: bool) -> ImageResult<u64> {
        let image = self.get(reference).await?;
        if let Some(store) = self.db.read_only_store_of(&image.id).await {
            return Err(ImageError::ReadOnly(format!(
                "the image {} is in the read-only image store {}: it cannot be removed",
                &image.id[..12.min(image.id.len())],
                store.display()
            )));
        }
        // A container that uses the image, or mounts a directory of it,
        // needs its record (the database refuses too): the callers remove
        // those containers first when they force (podman's rmi -f).
        if let Some(c) = self.db.containers_using_image(&image.id).await?.first() {
            return Err(ImageError::Storage(format!(
                "image is in use by the container {c}{}",
                if force {
                    ""
                } else {
                    ": remove it first, or force"
                }
            )));
        }
        self.db.delete_image(&image.id).await?;
        // (what the driver keeps of the image is forgotten; one it cannot
        // remove now goes with the next collection, which keeps only what the
        // images have: the removal of the image, recorded above, stands)
        if let Err(e) = self.storage.remove_image(&image.id) {
            warn!("Image {}: {e}", image.id);
        }
        // The layers no other image and no container uses go too: a pull of
        // the image downloads them again.  The containers of a forced
        // removal keep theirs (`container_layers`).
        let layers = self.release_unused_layers(&image.id).await;
        Ok(image.metadata_size().saturating_add(layers))
    }

    /// Release the layers no image and no container uses, for the image
    /// `what` that went; their size, as [`super::GcReport::layers_size`] counts it.
    async fn release_unused_layers(&self, what: &str) -> u64 {
        let gc = super::GcService::of_store(
            self.storage.clone(),
            self.db.clone(),
            self.file_store.clone(),
            &self.staging_dir,
        );
        match gc.release_unused_layers().await {
            Ok(report) => report.layers_size,
            Err(e) => {
                warn!("Cannot release the layers of the image {what}: {e}");
                0
            }
        }
    }

    /// Remove the directories of the layers no row names and the files of a
    /// writer that died ([`velarx_db::layer_files::sweep`]) when no process
    /// holds the lock of the store (a busy store is left to the next
    /// collection, which does it too).
    pub async fn sweep_layer_files(&self) {
        let lock = StorageLock::path_of_staging(&self.staging_dir);
        let _alone = match StorageLock::try_exclusive(&lock) {
            Ok(Some(alone)) => alone,
            Ok(None) => return,
            Err(e) => {
                warn!("Cannot lock the store: {e}");
                return;
            }
        };
        let named = match self.db.layer_digests().await {
            Ok(keys) => keys.iter().map(LayerKey::file_stem).collect(),
            Err(e) => {
                warn!("Cannot list the layers: {e}");
                return;
            }
        };
        let objects = self.file_store.root().to_path_buf();
        let swept = tokio::task::spawn_blocking(move || {
            velarx_db::layer_files::sweep(velarx_db::layer_files::root_of(&objects), &named)
        })
        .await;
        match swept {
            Ok(Ok(freed)) if freed > 0 => debug!("{freed} bytes of the files of layers removed"),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => warn!("Cannot remove the files of the layers no row names: {e}"),
            Err(e) => warn!("Cannot remove the files of the layers no row names: {e}"),
        }
    }

    /// The layers of images a monitor removed (`--rmi`: it cannot collect
    /// them) are released, once.
    pub async fn release_removed(&self) {
        match self.db.gc_pending().await {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                warn!("Cannot read what is left to collect: {e}");
                return;
            }
        }
        // (cleared first: an image removed while this collects is told again)
        if let Err(e) = self.db.set_gc_pending(false).await {
            warn!("Cannot clear what is left to collect: {e}");
            return;
        }
        self.release_unused_layers("removed with its container")
            .await;
    }

    /// Drop the engine's copy of the files of `layers` (every layer, if none
    /// are named) that nothing needs any more: what a lazy image left in the
    /// engine when it was completed into a storage service, once no container
    /// made on the pull is left.  Without waiting for the store (a pull
    /// holds it): a busy store is for the next collection.  The callers hold
    /// no lock of the store.
    pub async fn release_engine_copies(&self, layers: Option<&[LayerKey]>) {
        let gc = super::GcService::of_store(
            self.storage.clone(),
            self.db.clone(),
            self.file_store.clone(),
            &self.staging_dir,
        );
        match gc.release_engine_copies(layers).await {
            Ok(report) => {
                for e in report.errors {
                    warn!("The engine's copy of a lazy image: {e}");
                }
            }
            Err(e) => warn!("The engine's copy of a lazy image is not dropped: {e}"),
        }
    }

    pub async fn tag(&self, source: &str, target: &str) -> ImageResult<()> {
        let image = self.get(source).await?;
        let target_ref = ImageReference::parse(target)?;

        let repository = target_ref.name();
        let tag_name = target_ref.tag.unwrap_or_else(|| "latest".to_string());

        info!(
            "Tagging image {} as {}:{} (image_id={})",
            source, repository, tag_name, image.id
        );

        let tag = ImageTag {
            repository,
            tag: tag_name,
            image_id: image.id,
        };

        self.db.insert_image_tag(&tag).await?;
        info!("Tag inserted successfully");
        Ok(())
    }

    /// Remove names of the image `image`: `names` (a name without a
    /// registry is localhost's, without a tag `latest`), every one if
    /// none.  Returns the names removed; the image stays.
    pub async fn untag(&self, image: &str, names: &[String]) -> ImageResult<Vec<String>> {
        let (rec, tags) = self.get_with_tags(image).await?;
        let digest_names = self.db.get_digest_names_for_image(&rec.id).await?;
        let mut digests_chosen: Vec<(String, Digest)> = Vec::new();
        let chosen: Vec<ImageTag> = if names.is_empty() {
            digests_chosen = digest_names.clone();
            tags
        } else {
            let mut chosen = Vec::new();
            for n in names {
                let (base, digest) = match n.split_once('@') {
                    Some((b, d)) => (b, Some(d)),
                    None => (n.as_str(), None),
                };
                let r = ImageReference::parse(&archive::local_reference(base)?)?;
                if let Some(d) = digest {
                    let not_known =
                        || ImageError::Invalid(format!("{}@{d}: tag not known", r.name()));
                    let d: Digest = d.parse().map_err(|_| not_known())?;
                    // NAME@DIGEST the image was pulled by
                    if digest_names
                        .iter()
                        .any(|(r2, d2)| *r2 == r.name() && *d2 == d)
                    {
                        digests_chosen.push((r.name(), d));
                        continue;
                    }
                    // NAME@DIGEST of this image and of one of its
                    // repositories: a reference, not a name of the image
                    if d == rec.manifest_digest && tags.iter().any(|t| t.repository == r.name()) {
                        continue;
                    }
                    return Err(ImageError::Invalid(format!(
                        "{}@{d}: tag not known",
                        r.name()
                    )));
                }
                let want = (r.name(), r.tag.clone().unwrap_or_else(|| "latest".into()));
                let found = tags
                    .iter()
                    .find(|t| (&t.repository, &t.tag) == (&want.0, &want.1))
                    .ok_or_else(|| {
                        ImageError::Invalid(format!("{}:{}: tag not known", want.0, want.1))
                    })?;
                chosen.push(found.clone());
            }
            chosen
        };
        for t in &chosen {
            self.refuse_read_only_tag(t).await?;
        }
        let mut removed = Vec::new();
        for t in chosen {
            self.db.delete_image_tag(&t.repository, &t.tag).await?;
            removed.push(format!("{}:{}", t.repository, t.tag));
        }
        for (repository, digest) in digests_chosen {
            self.db
                .delete_image_digest_name(&repository, &digest)
                .await?;
            removed.push(format!("{repository}@{digest}"));
        }
        Ok(removed)
    }

    /// A name an additional image store gives cannot be removed.
    pub async fn refuse_read_only_tag(&self, t: &ImageTag) -> ImageResult<()> {
        if self.db.tag_is_read_only(&t.repository, &t.tag).await? {
            return Err(ImageError::ReadOnly(format!(
                "the name {}:{} is of a read-only image store: it cannot be removed",
                t.repository, t.tag
            )));
        }
        Ok(())
    }

    /// Prune unused images: those no container uses (the untagged ones, or
    /// all of them with `all`) that `filters` select: `label=KEY[=VALUE]`,
    /// `label!=KEY[=VALUE]`, `until=TIMESTAMP|DURATION` (created before).
    /// Returns the id and the freed space ([`Self::remove`]) of each image
    /// removed: a layer two of them had is counted for the one whose removal
    /// released it, so the sum is what the prune freed.
    pub async fn prune(&self, all: bool, filters: &[String]) -> ImageResult<Vec<(String, u64)>> {
        let filters = PruneFilters::parse(filters)?;
        let mut deleted: Vec<(String, u64)> = Vec::new();
        // An intermediate image of a build is dangling once the images built
        // on it are gone: pruned again until nothing is.
        loop {
            let before = deleted.len();
            self.prune_once(all, &filters, &mut deleted).await?;
            if deleted.len() == before {
                break;
            }
        }
        Ok(deleted)
    }

    async fn prune_once(
        &self,
        all: bool,
        filters: &PruneFilters,
        deleted: &mut Vec<(String, u64)>,
    ) -> ImageResult<()> {
        let images = self.list().await?;
        let intermediate = if all {
            Default::default()
        } else {
            self.intermediate_images().await?
        };
        for image in images {
            if intermediate.contains(&image.id) || !filters.select(&image) {
                continue;
            }
            // the images of the read-only stores stay
            if self.db.read_only_store_of(&image.id).await.is_some() {
                continue;
            }
            // (a failed query fails the prune: it does not remove an image that
            // containers may use)
            let has_containers = self.db.image_has_containers(&image.id).await?;
            // The intermediate images of a build in progress.
            let leased = self
                .db
                .is_leased(velarx_db::LEASE_IMAGE, &image.id)
                .await
                .unwrap_or(true);
            if has_containers || leased {
                debug!(
                    "Skipping image {} - still referenced by containers or a build",
                    &image.id[..12.min(image.id.len())]
                );
                continue;
            }

            let named = self.db.image_is_named(&image.id).await.unwrap_or(true);

            if !named || all {
                match self.remove(&image.id, true).await {
                    Ok(freed) => deleted.push((image.id.clone(), freed)),
                    Err(e) => warn!("The image {} was not removed: {e}", image.id),
                }
            }
        }
        Ok(())
    }
}

/// The filters of an image prune.
#[derive(Debug, Default)]
struct PruneFilters {
    /// (key, value, must have it)
    labels: Vec<(String, Option<String>, bool)>,
    /// Created before this time.
    until: Option<chrono::DateTime<chrono::Utc>>,
}

impl PruneFilters {
    fn parse(filters: &[String]) -> ImageResult<Self> {
        let invalid =
            |f: &str, why: &str| ImageError::Storage(format!("invalid filter {f:?}: {why}"));
        let mut out = Self::default();
        for f in filters {
            if let Some(v) = f.strip_prefix("label!=") {
                let (k, v) = v.split_once('=').map_or((v, None), |(k, v)| (k, Some(v)));
                out.labels
                    .push((k.to_string(), v.map(str::to_string), false));
            } else if let Some(v) = f.strip_prefix("label=") {
                let (k, v) = v.split_once('=').map_or((v, None), |(k, v)| (k, Some(v)));
                out.labels
                    .push((k.to_string(), v.map(str::to_string), true));
            } else if let Some(v) = f.strip_prefix("until=") {
                let now = chrono::Utc::now();
                let when = if let Ok(secs) = v.parse::<i64>() {
                    chrono::DateTime::from_timestamp(secs, 0)
                } else if let Ok(t) = chrono::DateTime::parse_from_rfc3339(v) {
                    Some(t.with_timezone(&chrono::Utc))
                } else {
                    velarx_proto::duration::parse_go_duration_ns(v)
                        .map(|ns| now - chrono::Duration::nanoseconds(ns))
                };
                out.until = Some(when.ok_or_else(|| invalid(f, "not a timestamp or a duration"))?);
            } else {
                return Err(invalid(
                    f,
                    "label, label! and until are the filters of a prune",
                ));
            }
        }
        Ok(out)
    }

    fn select(&self, image: &ImageRecord) -> bool {
        let config: serde_json::Value = serde_json::from_str(&image.config).unwrap_or_default();
        if let Some(until) = self.until {
            // when the image was made (its configuration says), as podman
            // judges it, else when it was pulled
            let at = |t: &str| {
                chrono::DateTime::parse_from_rfc3339(t)
                    .map(|t| t.with_timezone(&chrono::Utc))
                    .ok()
            };
            let created = config
                .get("created")
                .and_then(|c| c.as_str())
                .and_then(at)
                .or_else(|| at(&image.created_at));
            if !created.is_some_and(|c| c < until) {
                return false;
            }
        }
        if self.labels.is_empty() {
            return true;
        }
        let labels = config.pointer("/config/Labels").and_then(|l| l.as_object());
        self.labels.iter().all(|(k, v, want)| {
            let has = labels.and_then(|l| l.get(k)).is_some_and(|actual| {
                v.as_ref()
                    .is_none_or(|v| actual.as_str() == Some(v.as_str()))
            });
            has == *want
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha_of(seed: &str) -> Digest {
        Digest::of(Algorithm::Sha256, seed.as_bytes())
    }

    fn record(created: &str, labels: &str) -> ImageRecord {
        ImageRecord {
            id: "a".repeat(64),
            manifest_digest: sha_of("m"),
            config_digest: sha_of("c"),
            manifest: "{}".into(),
            config: format!(r#"{{"config":{{"Labels":{labels}}}}}"#),
            created_at: created.into(),
            is_lazy: false,
        }
    }

    /// A process that finds what an earlier boot left in the staging area
    /// waits for the lock of the store, whoever holds it, and cleans it
    /// before it is used.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_staging_of_an_earlier_boot_is_cleaned_before_it_is_used() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = tmp.path().join("staging");
        let area = velarx_content::pull::staged::Staging::new(&staging);
        area.create().unwrap();
        let cut = staging.join("pulls/.cut");
        std::fs::create_dir_all(&cut).unwrap();
        std::fs::write(staging.join("boot"), b"an earlier boot\n").unwrap();
        let held =
            StorageLock::exclusive_blocking(&StorageLock::path_of_staging(&staging)).unwrap();
        let db = Database::open_in_memory().await.unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("objects")).unwrap());
        let (tx, started) = std::sync::mpsc::channel();
        let dir = staging.clone();
        let made = std::thread::spawn(move || {
            tx.send(()).unwrap();
            ImageService::new(db, store, dir, velarx_storage::VerityMode::Off).map(|_| ())
        });
        started.recv().unwrap();
        drop(held);
        made.join().unwrap().unwrap();
        assert!(!cut.exists());
        assert!(area.is_of_this_boot().unwrap());
    }

    #[test]
    fn prune_filters_select_by_label_and_age() {
        let f = |v: &[&str]| {
            PruneFilters::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
        };
        let old = record("2020-01-01T00:00:00Z", r#"{"keep":"yes","env":"ci"}"#);
        let new = record(&chrono::Utc::now().to_rfc3339(), "{}");
        assert!(f(&[]).select(&old) && f(&[]).select(&new));
        assert!(f(&["label=keep"]).select(&old) && !f(&["label=keep"]).select(&new));
        assert!(f(&["label=env=ci"]).select(&old) && !f(&["label=env=prod"]).select(&old));
        assert!(!f(&["label!=keep"]).select(&old) && f(&["label!=keep"]).select(&new));
        assert!(f(&["label=keep", "label=env=ci"]).select(&old));
        assert!(!f(&["label=keep", "label=env=prod"]).select(&old));
        assert!(f(&["until=24h"]).select(&old) && !f(&["until=24h"]).select(&new));
        assert!(f(&["until=1577836801"]).select(&old));
        assert!(!f(&["until=1577836800"]).select(&old));
        assert!(f(&["until=2021-01-01T00:00:00Z", "label=keep"]).select(&old));
        // an image pulled now and made long ago is old (podman's Created)
        let mut pulled = record(&chrono::Utc::now().to_rfc3339(), "{}");
        pulled.config = r#"{"created":"2020-01-01T00:00:00Z","config":{}}"#.into();
        assert!(f(&["until=24h"]).select(&pulled));
        for bad in ["dangling=true", "until=yesterday"] {
            assert!(PruneFilters::parse(&[bad.to_string()]).is_err(), "{bad}");
        }
    }

    const MANIFEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    async fn service_with(
        tags: &[(&str, &str)],
        digest_names: &[&str],
    ) -> (tempfile::TempDir, ImageService) {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open_in_memory().await.unwrap();
        let image = ImageRecord {
            manifest_digest: MANIFEST.parse().unwrap(),
            ..record("2020-01-01T00:00:00Z", "{}")
        };
        db.insert_image(&image).await.unwrap();
        for (repository, tag) in tags {
            db.insert_image_tag(&ImageTag {
                repository: repository.to_string(),
                tag: tag.to_string(),
                image_id: image.id.clone(),
            })
            .await
            .unwrap();
        }
        for repository in digest_names {
            db.insert_image_digest_name(repository, &MANIFEST.parse().unwrap(), &image.id)
                .await
                .unwrap();
        }
        let store = Arc::new(FileStore::new(tmp.path().join("objects")).unwrap());
        let service = ImageService::new(
            db,
            store,
            tmp.path().join("pulls"),
            velarx_storage::VerityMode::Off,
        )
        .unwrap();
        (tmp, service)
    }

    /// The number of lookups of the tags of an image that `f` makes.
    async fn tag_lookups<F: std::future::Future>(f: F) -> (usize, F::Output) {
        let log = velarx_wire::logcapture::capture(tracing::Level::DEBUG);
        let out = f.await;
        (log.text().matches(" tags for image ").count(), out)
    }

    /// A name `repository@digest` finds the image of that manifest when the
    /// image has a tag of that repository, when it has no name at all, and
    /// not when it is named otherwise; the tags are read once.
    #[tokio::test]
    async fn a_digest_reference_reads_the_tags_once() {
        let reference = format!("r.io/a@{MANIFEST}");
        let (_tmp, tagged) = service_with(&[("r.io/a", "1")], &[]).await;
        let (n, found) = tag_lookups(tagged.get(&reference)).await;
        assert!(found.is_ok());
        assert_eq!(n, 1);
        let (_tmp, unnamed) = service_with(&[], &[]).await;
        let (n, found) = tag_lookups(unnamed.get(&reference)).await;
        assert!(found.is_ok());
        assert_eq!(n, 1);
        let (_tmp, other_tag) = service_with(&[("r.io/x", "1")], &[]).await;
        let (n, found) = tag_lookups(other_tag.get(&reference)).await;
        assert!(matches!(found, Err(ImageError::NotFound(_))));
        assert_eq!(n, 1);
        let (_tmp, other_digest) = service_with(&[], &["r.io/b"]).await;
        let (n, found) = tag_lookups(other_digest.get(&reference)).await;
        assert!(matches!(found, Err(ImageError::NotFound(_))));
        assert_eq!(n, 1);
        let (_tmp, same_digest) = service_with(&[], &["r.io/a"]).await;
        assert!(same_digest.get(&reference).await.is_ok());
    }

    /// An image named by a sha512 is found by its tag, by `NAME@sha512:D`,
    /// by `NAME:TAG@sha512:D`, by its whole id of 128 hex digits (with or
    /// without `sha512:`) and by a prefix of it, and by nothing that names
    /// another algorithm.
    #[tokio::test]
    async fn an_image_named_by_a_sha512_is_found_by_every_way_of_naming_it() {
        let (_tmp, service) = service_with(&[], &[]).await;
        let manifest = Digest::of(Algorithm::Sha512, b"manifest");
        let image = ImageRecord {
            id: manifest.hex(),
            manifest_digest: manifest,
            config_digest: Digest::of(Algorithm::Sha512, b"config"),
            ..record("2020-01-01T00:00:00Z", "{}")
        };
        service.db.insert_image(&image).await.unwrap();
        service
            .db
            .insert_image_tag(&ImageTag {
                repository: "r.io/s".into(),
                tag: "1".into(),
                image_id: image.id.clone(),
            })
            .await
            .unwrap();
        let hex = manifest.hex();
        for reference in [
            "r.io/s:1".to_string(),
            format!("r.io/s@{manifest}"),
            format!("r.io/s:1@{manifest}"),
            format!("r.io/s:another@{manifest}"),
            hex.clone(),
            format!("sha512:{hex}"),
            hex[..12].to_string(),
            image.config_digest.hex(),
        ] {
            let found = service.get(&reference).await;
            assert_eq!(found.unwrap().id, image.id, "{reference}");
        }
        // another repository does not name it, nor does the other algorithm
        for reference in [format!("r.io/other@{manifest}"), format!("sha256:{hex}")] {
            assert!(service.get(&reference).await.is_err(), "{reference}");
        }
        let e = service
            .get(&format!("sha256:{hex}"))
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("no 64-byte hexadecimal value"), "{e}");
    }

    /// A tag that only a read-only store gives the image names it: a
    /// digest reference of another repository does not find it.
    #[tokio::test]
    async fn a_tag_of_a_read_only_store_names_the_image() {
        let tmp = tempfile::tempdir().unwrap();
        let ro_path = tmp.path().join("ro.sqlite");
        let image = ImageRecord {
            manifest_digest: MANIFEST.parse().unwrap(),
            ..record("2020-01-01T00:00:00Z", "{}")
        };
        {
            let ro = Database::open(ro_path.clone()).await.unwrap();
            ro.insert_image(&image).await.unwrap();
            ro.insert_image_tag(&ImageTag {
                repository: "r.io/ro".into(),
                tag: "1".into(),
                image_id: image.id.clone(),
            })
            .await
            .unwrap();
        }
        let db = Database::open_in_memory()
            .await
            .unwrap()
            .with_additional(vec![Database::open_read_only(&ro_path).await.unwrap()]);
        let store = Arc::new(FileStore::new(tmp.path().join("objects")).unwrap());
        let service = ImageService::new(
            db,
            store,
            tmp.path().join("pulls"),
            velarx_storage::VerityMode::Off,
        )
        .unwrap();
        let other = service.get(&format!("r.io/x@{MANIFEST}")).await;
        assert!(matches!(other, Err(ImageError::NotFound(_))));
        let (found, tags) = service
            .get_with_tags(&format!("r.io/ro@{MANIFEST}"))
            .await
            .unwrap();
        assert_eq!(found.id, image.id);
        assert_eq!(tags.len(), 1);
    }

    /// The image and its tags, for a create and its signature check, cost
    /// one lookup of the tags whatever the reference is.
    #[tokio::test]
    async fn an_image_comes_with_its_tags_from_one_lookup() {
        let (_tmp, service) = service_with(&[("r.io/a", "1")], &["r.io/b"]).await;
        let id = service.get("r.io/a:1").await.unwrap().id;
        for reference in [
            "r.io/a:1".to_string(),
            format!("r.io/a@{MANIFEST}"),
            format!("r.io/b@{MANIFEST}"),
            id.clone(),
            id[..12].to_string(),
            "a:1".to_string(),
        ] {
            let (n, found) = tag_lookups(service.get_with_tags(&reference)).await;
            let (image, tags) = found.unwrap();
            assert_eq!((n, image.id.as_str()), (1, id.as_str()), "{reference}");
            assert_eq!(tags.len(), 1, "{reference}");
            assert_eq!(
                (tags[0].repository.as_str(), tags[0].tag.as_str()),
                ("r.io/a", "1")
            );
        }
    }

    fn progress(n: u64) -> TransferProgress {
        TransferProgress {
            subject: meter::Subject::Made("x"),
            status: "downloading".into(),
            current_bytes: n,
            total_bytes: 0,
            complete: false,
        }
    }

    /// A receiver that is never drained must not block the sender.
    #[tokio::test]
    async fn test_progress_does_not_block_on_full_channel() {
        let (tx, _rx) = mpsc::channel::<TransferProgress>(4);
        let done = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for n in 0..1000 {
                tx.report(progress(n));
            }
        })
        .await;
        assert!(done.is_ok(), "progress reporting blocked");
    }

    /// A dropped receiver is not an error either.
    #[tokio::test]
    async fn test_progress_after_receiver_dropped() {
        let (tx, rx) = mpsc::channel::<TransferProgress>(1);
        drop(rx);
        tx.report(progress(1));
    }
}

/// Whether `reference` is written without a registry.
fn without_registry(reference: &str) -> bool {
    velarx_base::reference::parse(reference.as_bytes()).is_ok_and(|spans| spans.host_end == 0)
}

/// The repository and the tag (`latest` by default) of a short name: a
/// reference without a registry and without a digest.
fn short_name_and_tag(reference: &str) -> Option<(&str, &str)> {
    if reference.contains('@') {
        return None;
    }
    let component = reference.rfind('/').map_or(0, |i| i + 1);
    let (name, tag) = match reference[component..].find(':') {
        Some(i) => (&reference[..component + i], &reference[component + i + 1..]),
        None => (reference, "latest"),
    };
    let qualified = name
        .split_once('/')
        .is_some_and(|(first, _)| velarx_base::reference::is_registry_domain(first));
    (!qualified && !name.is_empty() && !tag.is_empty()).then_some((name, tag))
}

/// Whether `repository` is `name` or ends with `/name`.
fn repository_ends_with(repository: &str, name: &str) -> bool {
    repository
        .strip_suffix(name)
        .is_some_and(|rest| rest.is_empty() || rest.ends_with('/'))
}

#[cfg(test)]
mod short_name_tests {
    use super::*;
    #[test]
    fn short_names_and_their_tags() {
        assert_eq!(short_name_and_tag("alpine"), Some(("alpine", "latest")));
        assert_eq!(
            short_name_and_tag("libpod/alpine:3"),
            Some(("libpod/alpine", "3"))
        );
        assert_eq!(short_name_and_tag("quay.io/libpod/alpine"), None);
        assert_eq!(short_name_and_tag("localhost/alpine"), None);
        assert_eq!(short_name_and_tag("localhost:5000/alpine"), None);
        assert_eq!(short_name_and_tag("alpine@sha256:abc"), None);
        assert_eq!(short_name_and_tag("alpine:"), None);
    }

    #[test]
    fn repositories_match_on_whole_components() {
        assert!(repository_ends_with("quay.io/libpod/alpine", "alpine"));
        assert!(repository_ends_with(
            "quay.io/libpod/alpine",
            "libpod/alpine"
        ));
        assert!(repository_ends_with("alpine", "alpine"));
        assert!(!repository_ends_with("quay.io/libpod/myalpine", "alpine"));
        assert!(!repository_ends_with("quay.io/alpine/x", "alpine"));
    }
}
