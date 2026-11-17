// SPDX-License-Identifier: Apache-2.0
//! Who owns a lazy pull.  A lazy pull outlives the command that made it:
//! its containers ask for the files they lack after the command ended, and
//! the files of the layers no container reads are fetched in the background
//! until every layer is committed.  So every lazy pull is the engine
//! SERVICE's of the store (`velarx varlink`, one per store, found or
//! started by the command that needs it): its image service is
//! [`ImageService::serve_pulls`], it makes the lazy pulls, completes them
//! on tasks of its own ([`Completions`]) and answers the misses of their
//! containers (`crate::image_fetch`).  A command that runs its own engine
//! hands every lazy pull, every completion it waits for and every cancel
//! to the service ([`PullHandOff`], [`ImageService::with_hand_off`]) and
//! never binds a proxy; an eager pull it finishes itself.  An image service
//! with neither (the tests) completes a pull when it is asked to, in its
//! caller.
//!
//! What a process keeps in memory (the completions it runs, the fetches in
//! flight of `lazy_fetch`) is its own.  Processes meet only in the file
//! system: the lease of a pull (`staging/pulls/<id>/lease`, held by the
//! service while it completes the pull), the lease of a layer
//! (`staging/meta/<stem>/lease`, held while files are fetched into it) and
//! the committed rows.  A service that dies lets go of every lease with its
//! descriptors: the next command finds the open pulls with no holder and
//! starts a service, which takes them over.
//!
//! A completion does not give up.  What may pass is retried with a backoff
//! that doubles from a second to `[pull] lazy_retry_max_secs`: the network,
//! a registry that answers 5xx or 429, a file system with no room left
//! (every minute).  What retrying cannot mend stops it with the staging
//! kept and the reason in the state of the pull (`velarx image pulls`): a
//! layer that is not what its table says, a blob the registry lost,
//! credentials it wants (`needs-credentials`: `velarx image complete
//! --creds` starts it again with them, which are never stored).

use super::lazy::Completion;
use super::*;
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use velarx_content::activation::Activity;
use velarx_content::pull::staged::{PullState, Staging};
use velarx_proto::transfer::FailureClass;
use velarx_registry::auth::RegistryAccess;

/// What a transfer moved, by source, as a line of a log.
fn by_source_text(stats: &TransferStats) -> String {
    stats
        .by_source
        .iter()
        .map(|s| format!("{} bytes from {}", s.bytes, s.name))
        .collect::<Vec<_>>()
        .join(", ")
}

/// What a command's own engine asks of the engine service of its store for
/// the pulls that outlive it (`src/engine/pull_service.rs`).  Each call
/// finds the service, or starts it, under the lock of its socket.
#[async_trait::async_trait]
pub trait PullHandOff: Send + Sync {
    /// Pull `reference` lazily in the service: what it pulled.
    async fn pull_lazy(&self, reference: &str, options: &PullOptions) -> ImageResult<PullResult>;
    /// Complete the pull `id` in the service, and wait for it.
    async fn complete(&self, id: &str, access: &RegistryAccess) -> ImageResult<TransferStats>;
    /// Cancel the pull `id` in the service.
    async fn cancel(&self, id: &str, force: bool) -> ImageResult<()>;
    /// Make sure the service runs: it takes over the open pulls nobody
    /// completes.
    fn ensure(&self) -> ImageResult<()>;
}

/// Who completes the lazy pulls of an image service.
#[derive(Clone, Default)]
pub(super) enum Owner {
    /// The caller, when it asks (the tests)
    #[default]
    Caller,
    /// This process: the engine service of the store
    Service(Arc<Completions>),
    /// The engine service, asked by this command's own engine
    HandOff(Arc<dyn PullHandOff>),
}

/// The completions the engine service runs, one task per pull it holds the
/// lease of.
pub struct Completions {
    running: std::sync::Mutex<HashMap<String, Running>>,
    /// `[pull] lazy_completers`: the background completions at once
    queue: Arc<Semaphore>,
    /// The connections of the service: a completion keeps it from leaving
    activity: std::sync::OnceLock<Arc<Activity>>,
}

/// A completion in progress.
struct Running {
    /// A command waits for it: full speed
    boost: Arc<Notify>,
    speed: Speed,
    /// What it ended with, once it has
    done: tokio::sync::watch::Receiver<bool>,
    task: tokio::task::AbortHandle,
    /// Which completion of the pull this is
    generation: u64,
}

impl Completions {
    fn new(config: &velarx_config::PullConfig) -> Self {
        Self {
            running: Default::default(),
            queue: Arc::new(Semaphore::new(config.lazy_completers)),
            activity: Default::default(),
        }
    }

    fn running(&self) -> std::sync::MutexGuard<'_, HashMap<String, Running>> {
        self.running.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The completion of `id`, told that a command waits for it: when it
    /// ends.  None: this process does not complete it.
    fn hurry(&self, id: &str) -> Option<tokio::sync::watch::Receiver<bool>> {
        let running = self.running();
        let r = running.get(id)?;
        r.speed.full();
        r.boost.notify_one();
        r.boost.notify_waiters();
        Some(r.done.clone())
    }

    /// Stop the completion of `id` (the pull was cancelled): its fetches in
    /// flight are dropped and its lease let go.  When one ran: what says
    /// that its task ended.
    fn stop(&self, id: &str) -> Option<tokio::sync::watch::Receiver<bool>> {
        let r = self.running().remove(id)?;
        r.task.abort();
        Some(r.done)
    }
}

/// Removes the completion from the table when its task ends or is aborted,
/// after the lease is let go.
struct Finished {
    completions: Arc<Completions>,
    id: String,
    lease: Option<velarx_content::pull::staged::Lease>,
    done: tokio::sync::watch::Sender<bool>,
    generation: u64,
}

impl Drop for Finished {
    fn drop(&mut self) {
        drop(self.lease.take());
        let mut running = self.completions.running();
        // (only this task's entry: a stop removed it already)
        if running
            .get(&self.id)
            .is_some_and(|r| r.generation == self.generation)
        {
            running.remove(&self.id);
        }
        drop(running);
        self.done.send_replace(true);
    }
}

impl ImageService {
    /// This process is the engine service of the store: it makes the lazy
    /// pulls and completes them in the background.  `activity` (set when
    /// the service serves) is kept busy while a completion runs.
    pub fn serve_pulls(mut self) -> Self {
        self.owner = Owner::Service(Arc::new(Completions::new(&self.pull_config)));
        self
    }

    /// The connections of the engine service: kept busy while a completion
    /// runs, so that the service does not leave with work in progress.
    pub fn keep_alive_with(&self, activity: Arc<Activity>) {
        if let Owner::Service(c) = &self.owner {
            let _ = c.activity.set(activity);
        }
    }

    /// The lazy pulls of this engine are the engine service's: `hand_off`
    /// reaches it.
    pub fn with_hand_off(mut self, hand_off: Arc<dyn PullHandOff>) -> Self {
        self.owner = Owner::HandOff(hand_off);
        self
    }

    /// The engine service that takes the lazy pulls of this engine, if one
    /// does.
    pub(super) fn hand_off(&self) -> Option<&Arc<dyn PullHandOff>> {
        match &self.owner {
            Owner::HandOff(h) => Some(h),
            _ => None,
        }
    }

    /// Make sure the pull `id` is completed: by a task of this process (the
    /// engine service) unless another process holds its lease, by the
    /// engine service a command's engine finds or starts.  Nothing for a
    /// pull that failed, waits for credentials or was cancelled (a command
    /// that asks for it again opens it again).
    pub fn ensure_completer(&self, id: &str, access: &RegistryAccess) {
        let area = self.staging_area();
        match area.state(id) {
            Ok(s) if s.state.is_open() => {}
            _ => return,
        }
        match &self.owner {
            Owner::Caller => {}
            Owner::HandOff(h) => {
                if !area.lease_held(id) {
                    if let Err(e) = h.ensure() {
                        warn!("The pull {id} is not completed: no engine service: {e}");
                    }
                }
            }
            Owner::Service(c) => {
                let mut running = c.running();
                if running.contains_key(id) {
                    return;
                }
                let lease = match area.take_lease(id) {
                    Ok(Some(lease)) => lease,
                    // another process holds it
                    Ok(None) => return,
                    // (committed or cancelled meanwhile)
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
                    Err(e) => {
                        warn!("Cannot take the lease of the pull {id}: {e}");
                        return;
                    }
                };
                let Ok(runtime) = tokio::runtime::Handle::try_current() else {
                    warn!("The pull {id} is not completed: no runtime");
                    return;
                };
                let (done_tx, done) = tokio::sync::watch::channel(false);
                let boost = Arc::new(Notify::new());
                let permits = Completion::new(&self.pull_config).permits;
                let speed = Speed {
                    permits: permits.clone(),
                    boosted: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    more: self
                        .pull_config
                        .lazy_fetches
                        .saturating_sub(self.pull_config.lazy_complete_fetches),
                };
                let completer = Completer {
                    service: self.clone(),
                    area,
                    id: id.to_string(),
                    access: access.clone(),
                    pull: self.pull_config.clone(),
                    queue: c.queue.clone(),
                };
                static GENERATION: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let generation = GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let finished = Finished {
                    completions: c.clone(),
                    id: id.to_string(),
                    lease: Some(lease),
                    done: done_tx,
                    generation,
                };
                let keep = c.activity.get().map(|a| a.keep());
                let (b, s) = (boost.clone(), speed.clone());
                let task = runtime.spawn(async move {
                    let _keep = keep;
                    let _finished = finished;
                    completer.run(&b, &permits, &s).await;
                });
                running.insert(
                    id.to_string(),
                    Running {
                        boost,
                        speed,
                        done,
                        task: task.abort_handle(),
                        generation,
                    },
                );
            }
        }
    }

    /// Complete the open pulls nobody completes: after a reboot, a kill or
    /// a crash, the engine service does this at its start, and any command
    /// that finds such a pull starts the service.
    pub fn resume_pulls(&self) {
        if matches!(self.owner, Owner::Caller) {
            return;
        }
        let area = self.staging_area();
        if !area.exists() {
            return;
        }
        let orphans: Vec<String> = area
            .pulls()
            .into_iter()
            .filter(|e| e.state.state.is_open() && !e.completer_alive)
            .map(|e| e.pull.id)
            .collect();
        match &self.owner {
            Owner::HandOff(h) if !orphans.is_empty() => {
                if let Err(e) = h.ensure() {
                    warn!(
                        "{} lazy pulls are not completed: no engine service: {e}",
                        orphans.len()
                    );
                }
            }
            Owner::Service(_) => {
                for id in orphans {
                    self.ensure_completer(&id, &RegistryAccess::default());
                }
            }
            _ => {}
        }
    }

    /// Finish the pull `id` for a command that waits for it (`pull`,
    /// `image complete`, a `run` without `--lazy`): the completion goes as
    /// fast as it can, started if there is none, and is waited for; the
    /// credentials of the command go to it.  An error that retrying cannot
    /// mend (the completion stopped on it) is returned with the reason.
    pub async fn complete_waiting(
        &self,
        id: &str,
        access: RegistryAccess,
    ) -> ImageResult<TransferStats> {
        let area = self.staging_area();
        let Some(pull) = area.pull(id)? else {
            return Ok(TransferStats::default());
        };
        let completions = match &self.owner {
            Owner::Caller => {
                return self
                    .complete_pull(
                        id,
                        Completion {
                            access,
                            ..Completion::new(&self.pull_config)
                        },
                    )
                    .await
            }
            Owner::HandOff(h) => return h.complete(id, &access).await,
            Owner::Service(c) => c.clone(),
        };
        let start = std::time::Instant::now();
        for _ in 0..3 {
            // (a pull again of one that stopped starts it over)
            match area.state(id)?.state {
                PullState::Cancelled => {
                    return Err(ImageError::Pulling(format!(
                        "the pull of image {id} was cancelled"
                    )))
                }
                s if !s.is_open() => area.set_state(id, PullState::Queued, None)?,
                _ => {}
            }
            self.ensure_completer(id, &access);
            match completions.hurry(id) {
                Some(mut done) => {
                    let _ = done.wait_for(|d| *d).await;
                }
                // (another process holds the lease: its end is waited for)
                None => {
                    let wait = self.staging_area();
                    let waited = id.to_string();
                    tokio::task::spawn_blocking(move || wait.wait_for_completer(&waited))
                        .await
                        .map_err(|e| ImageError::Storage(e.to_string()))??;
                }
            }
            if self
                .db
                .get_image_by_digest(&pull.manifest_digest)
                .await
                .is_ok()
            {
                return Ok(TransferStats {
                    duration_ms: start.elapsed().as_millis() as u64,
                    ..TransferStats::default()
                });
            }
            match area.state(id)?.state {
                PullState::Failed { reason } => {
                    return Err(ImageError::Pulling(format!(
                        "the pull of image {id} failed: {reason}"
                    )))
                }
                PullState::NeedsCredentials if access.is_empty() => {
                    return Err(ImageError::Unauthorized(format!(
                        "the pull of image {id} waits for the credentials (or certificates) it was made with, which are not stored: `velarx image complete --creds USER:PASSWORD {id}` (or --authfile, --cert-dir)"
                    )))
                }
                // (a completion that ran without them, started before: the
                // next one has them; the last try below says what it got)
                PullState::NeedsCredentials => {}
                PullState::Cancelled => {
                    return Err(ImageError::Pulling(format!(
                        "the pull of image {id} was cancelled"
                    )))
                }
                // the completion ended and the image is not in the store:
                // another process held it and was killed
                _ => {}
            }
        }
        // no completion could be had: this one does it
        self.complete_pull(
            id,
            Completion {
                access,
                ..Completion::new(&self.pull_config)
            },
        )
        .await
    }

    /// Stop the completion of `id` that this process runs, and wait for its
    /// task to end: nothing of it is recorded after this returns.  Whether
    /// one ran.
    pub(super) async fn stop_completion(&self, id: &str) -> bool {
        let Owner::Service(c) = &self.owner else {
            return false;
        };
        match c.stop(id) {
            Some(mut done) => {
                let _ = done.wait_for(|d| *d).await;
                true
            }
            None => false,
        }
    }
}

/// What a completion does with an error.
#[derive(Debug, PartialEq, Eq)]
enum Next {
    /// A failure that may pass: try again after the backoff
    Retry,
    /// The file system is full: try again in a minute
    Space,
    /// The registry wants credentials the completion does not have
    Credentials,
    /// An error that trying again cannot mend
    Stop(String),
}

fn classify(e: &ImageError) -> Next {
    use ImageError as E;
    // ENOSPC is the kind `StorageFull`, which an error made without an errno
    // has too
    let no_room = |io: &std::io::Error| io.kind() == std::io::ErrorKind::StorageFull;
    match e {
        E::Transfer { failure, .. } => match failure.class {
            FailureClass::Unauthorized | FailureClass::Forbidden => Next::Credentials,
            FailureClass::NoSpace => Next::Space,
            // the origin says it does not have it: the blob is gone
            FailureClass::NotFound => {
                Next::Stop(format!("the registry no longer has the blob: {e}"))
            }
            // a party gave what it does not claim: trying again does not mend
            FailureClass::Invalid | FailureClass::Failed => Next::Stop(e.to_string()),
            FailureClass::Unavailable | FailureClass::Transient => Next::Retry,
        },
        E::Unauthorized(_) | E::Forbidden(_) => Next::Credentials,
        E::RegistryNotFound(_) => Next::Stop(format!("the registry no longer has the blob: {e}")),
        E::Contradicted(_) | E::DigestMismatch { .. } | E::ComposefsDigest(_) => {
            Next::Stop(e.to_string())
        }
        E::Manifest(_) | E::Layer(_) | E::Invalid(_) | E::NotFound(_) | E::Pulling(_) => {
            Next::Stop(e.to_string())
        }
        E::ReadOnly(_)
        | E::DockerFormat(_)
        | E::NotLazy { .. }
        | E::TooManyLayers { .. }
        | E::NoOpenFiles { .. } => Next::Stop(e.to_string()),
        E::Io(io) if no_room(io) => Next::Space,
        E::Storage(m) if m.contains("No space left") => Next::Space,
        // the network, a busy registry, a database that is locked, a file
        // that went meanwhile: may pass
        E::Io(_)
        | E::Http(_)
        | E::Registry(_)
        | E::Unreachable(_)
        | E::Database(_)
        | E::Storage(_)
        | E::Json(_)
        | E::Ids(_) => Next::Retry,
    }
}

/// The wait before the try after `failures` failures, doubling from a
/// second to `max` seconds.
fn backoff(failures: u32, max: u64) -> Duration {
    Duration::from_secs(
        1u64.checked_shl(failures.min(20))
            .unwrap_or(u64::MAX)
            .min(max),
    )
}

/// The fetches a completion has in flight: the permits of its settings
/// (`lazy_complete_fetches`), and `more` once a command waits for the pull
/// (to `lazy_fetches`), added once.
#[derive(Clone)]
struct Speed {
    permits: Arc<Semaphore>,
    boosted: Arc<std::sync::atomic::AtomicBool>,
    more: usize,
}

impl Speed {
    fn full(&self) {
        if !self.boosted.swap(true, std::sync::atomic::Ordering::SeqCst) {
            self.permits.add_permits(self.more);
        }
    }

    fn is_full(&self) -> bool {
        self.boosted.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The completion of one pull, on a task of the engine service.
struct Completer {
    service: ImageService,
    area: Staging,
    id: String,
    access: RegistryAccess,
    pull: velarx_config::PullConfig,
    /// `[pull] lazy_completers`
    queue: Arc<Semaphore>,
}

impl Completer {
    async fn run(self, boost: &Arc<Notify>, permits: &Arc<Semaphore>, speed: &Speed) {
        let id = &self.id;
        let mut failures = 0u32;
        let started = Instant::now();
        let _turn = self.turn(boost, speed).await;
        loop {
            if let Ok(PullState::Cancelled) = self.area.state(id).map(|s| s.state) {
                info!("The pull {id} is cancelled");
                return;
            }
            self.record_state(PullState::Running, Some(std::process::id()));
            let progress = Arc::new(ProgressWriter::new(self.area.clone(), id.to_string()));
            let completion = Completion {
                access: self.access.clone(),
                permits: permits.clone(),
                progress: Some({
                    let progress = progress.clone();
                    Arc::new(move |p: &CompletionProgress| progress.report(p))
                }),
            };
            let e = match self.service.complete_pull(id, completion).await {
                Ok(stats) => {
                    info!(
                        "The pull {id} is in the store after {:?}: {}",
                        started.elapsed(),
                        by_source_text(&stats)
                    );
                    return;
                }
                Err(e) => e,
            };
            progress.error(&e.to_string());
            // (a try that got files or layers done starts the backoff over:
            // what failed was not the same thing)
            if progress.reached() > 0 {
                failures = 0;
            }
            match classify(&e) {
                Next::Retry => {
                    let wait = backoff(failures, self.pull.lazy_retry_max_secs);
                    failures = failures.saturating_add(1);
                    warn!("The pull {id}: {e}; trying again in {wait:?}");
                    self.wait(wait, boost).await;
                }
                Next::Space => {
                    warn!("The pull {id}: {e}; the file system is full, trying again in a minute");
                    self.record_state(PullState::WaitingForSpace, Some(std::process::id()));
                    self.wait(Duration::from_secs(60), boost).await;
                }
                Next::Credentials => {
                    warn!("The pull {id} needs credentials: {e}");
                    self.record_state(PullState::NeedsCredentials, None);
                    return;
                }
                Next::Stop(reason) => {
                    tracing::error!("The pull {id} stops: {reason}");
                    self.record_state(PullState::Failed { reason }, None);
                    return;
                }
            }
        }
    }

    /// The turn of the pull among the background completions (`[pull]
    /// lazy_completers`); a pull a container is made on or a command waits
    /// for does not wait for one.  The state is `queued` while it waits.
    async fn turn(&self, boost: &Arc<Notify>, speed: &Speed) -> Option<OwnedSemaphorePermit> {
        let id = &self.id;
        if speed.is_full() || self.service.containers_use(id).await.unwrap_or_default() {
            return None;
        }
        if let Ok(p) = self.queue.clone().try_acquire_owned() {
            return Some(p);
        }
        self.record_state(PullState::Queued, Some(std::process::id()));
        info!("The pull {id} waits for its turn among the background completions");
        tokio::select! {
            p = self.queue.clone().acquire_owned() => p.ok(),
            _ = boost.notified() => None,
        }
    }

    /// Record the state of the pull for whoever looks at it; a state that
    /// cannot be written is said (the pull goes on as the state says).
    fn record_state(&self, state: PullState, pid: Option<u32>) {
        let name = format!("{state:?}");
        if let Err(e) = self.area.set_state(&self.id, state, pid) {
            warn!("The pull {}: cannot record the state {name}: {e}", self.id);
        }
    }

    /// Wait `wait`, or until a command says it waits for the pull.
    async fn wait(&self, wait: Duration, boost: &Arc<Notify>) {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = boost.notified() => {}
        }
    }
}

use tokio::sync::OwnedSemaphorePermit;

/// `progress.json`, written at most once a second.
struct ProgressWriter {
    area: Staging,
    id: String,
    last: std::sync::Mutex<Option<Instant>>,
    error: std::sync::Mutex<Option<String>>,
    /// The files and layers this try got done
    reached: std::sync::atomic::AtomicU64,
}

impl ProgressWriter {
    fn new(area: Staging, id: String) -> Self {
        Self {
            area,
            id,
            last: std::sync::Mutex::new(None),
            error: std::sync::Mutex::new(None),
            reached: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// How far the tries got: the files and layers done.
    fn reached(&self) -> u64 {
        self.reached.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn report(&self, p: &CompletionProgress) {
        self.reached.fetch_max(
            p.files_done + p.layers_done,
            std::sync::atomic::Ordering::Relaxed,
        );
        let finished = p.layers_done >= p.layers_total;
        {
            let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
            if !finished && last.is_some_and(|t| t.elapsed() < Duration::from_secs(1)) {
                return;
            }
            *last = Some(Instant::now());
        }
        self.write(p);
    }

    fn write(&self, p: &CompletionProgress) {
        let progress = velarx_content::pull::staged::Progress {
            files_done: p.files_done,
            files_total: p.files_total,
            bytes_done: p.bytes_done,
            bytes_total: p.bytes_total,
            layers_done: p.layers_done,
            layers_total: p.layers_total,
            error: self.error.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            updated: velarx_content::pull::staged::now(),
        };
        if let Err(e) = self.area.set_progress(&self.id, &progress) {
            debug!("Cannot write the progress of the pull {}: {e}", self.id);
        }
    }

    /// Say what the last try failed on, keeping the numbers of the last
    /// report.
    fn error(&self, message: &str) {
        *self.error.lock().unwrap_or_else(|e| e.into_inner()) = Some(message.to_string());
        let mut p = self.area.progress(&self.id).unwrap_or_default();
        p.error = Some(message.to_string());
        p.updated = velarx_content::pull::staged::now();
        let _ = self.area.set_progress(&self.id, &p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_may_pass_is_retried_and_what_cannot_stops_the_completion() {
        let io = |e: std::io::Error| ImageError::Io(e);
        assert_eq!(classify(&ImageError::Registry("503".into())), Next::Retry);
        assert_eq!(
            classify(&io(std::io::Error::from(
                std::io::ErrorKind::ConnectionReset
            ))),
            Next::Retry
        );
        assert_eq!(
            classify(&io(std::io::Error::from_raw_os_error(libc::ENOSPC))),
            Next::Space
        );
        assert_eq!(
            classify(&io(std::io::Error::from(std::io::ErrorKind::StorageFull))),
            Next::Space
        );
        // a quota is not a full disk here, as before
        assert_eq!(
            classify(&io(std::io::Error::from_raw_os_error(libc::EDQUOT))),
            Next::Retry
        );
        assert_eq!(
            classify(&ImageError::Unauthorized("401".into())),
            Next::Credentials
        );
        assert_eq!(
            classify(&ImageError::Forbidden("403".into())),
            Next::Credentials
        );
        for stops in [
            ImageError::RegistryNotFound("blob".into()),
            ImageError::Contradicted("a chunk".into()),
            ImageError::DigestMismatch {
                expected: "a".into(),
                actual: "b".into(),
            },
            ImageError::Layer("not a file of the layer".into()),
        ] {
            assert!(matches!(classify(&stops), Next::Stop(_)), "{stops}");
        }
    }

    #[test]
    fn the_backoff_doubles_to_its_maximum() {
        let secs: Vec<u64> = (0..12).map(|n| backoff(n, 600).as_secs()).collect();
        assert_eq!(secs, [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 600, 600]);
        assert_eq!(backoff(1000, 30), Duration::from_secs(30));
        assert_eq!(backoff(0, 1), Duration::from_secs(1));
    }
}
