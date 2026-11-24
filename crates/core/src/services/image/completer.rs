// SPDX-License-Identifier: Apache-2.0
//! Who owns a lazy pull.  A lazy pull outlives the command that made it:
//! its containers ask for the files they lack after the command ended, and
//! the files of the layers no container reads are fetched in the background
//! until every layer is committed.  So every lazy pull is the engine
//! SERVICE's of the store (`velarx varlink`, one per store, found or
//! started by the command that needs it): its image service is
//! [`ImageService::serve_pulls`], it makes the lazy pulls, completes them
//! ([`Completions`]: one task that owns the state machine of
//! `velarx-lazy-core` and performs its actions) and answers the misses of
//! their containers (`crate::image_fetch`).  A command that runs its own engine
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

use super::lazy::Plan;
use super::*;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch};
use velarx_content::activation::{Activity, Keep};
use velarx_content::fetcher::fetch::Urgency;
use velarx_content::pull::staged::{Lease, Progress, PullState, Staging};
use velarx_content::pull::staged_fetch::Walked;
use velarx_lazy_core::{
    step, Action, Cfg, Class, Core, Event, GroupFact, GroupId, PullId, State, Tick, Work,
};
use velarx_proto::transfer::FailureClass;
use velarx_proto::workload::{SOURCE_REGISTRY, SOURCE_STORE};
use velarx_registry::auth::RegistryAccess;

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

/// The completions the engine service runs: one task owns them all, with
/// the state machine that decides what each pull and each layer does
/// ([`velarx_lazy_core`]), and does what it says.
pub struct Completions {
    cfg: Cfg,
    /// The mailbox of the task, which starts with the first use
    mailbox: std::sync::OnceLock<mpsc::UnboundedSender<Mail>>,
    /// The connections of the service: a pull held keeps it from leaving
    activity: Arc<std::sync::OnceLock<Arc<Activity>>>,
}

/// What the task is sent: a pull whose lease the sender took, or what to
/// do on the task.
enum Mail {
    Add(Box<Held>),
    Do(Box<dyn FnOnce(&mut Task) + Send>),
}

/// Where the fetches for the starts of containers tell the task that they
/// began and ended.
#[derive(Clone)]
pub(super) struct Starts(mpsc::UnboundedSender<Mail>);

impl Starts {
    pub(super) fn tell(&self, event: Event) {
        let _ = self
            .0
            .send(Mail::Do(Box::new(move |t| t.feed(event, None))));
    }
}

/// What a completion ended with, for the command that waits for it.
#[derive(Clone, Default)]
struct Over {
    /// What the try moved
    moved: TransferStats,
    /// Why the pull stopped when a layer was refused for its table of
    /// contents ([`ImageError::Contradicted`]): the one failure a command
    /// tells from the others, since trying again gives the same
    contradicted: Option<String>,
}

/// A pull the task holds.
struct Held {
    id: String,
    area: Staging,
    lease: Lease,
    access: RegistryAccess,
    /// What the try works on
    plan: Option<Arc<Plan>>,
    /// What the try moved
    stats: TransferStats,
    /// Why a layer was refused, if it was ([`Over::contradicted`])
    contradicted: Option<String>,
    started: Instant,
    /// `progress.json` as last told, and when it was last written
    progress: Progress,
    written: Option<Instant>,
    /// Set to how the try ended when the pull is over
    done: watch::Sender<Option<Over>>,
}

impl Held {
    fn write_progress(&mut self) {
        self.written = Some(Instant::now());
        self.progress.updated = velarx_content::pull::staged::now();
        if let Err(e) = self.area.set_progress(&self.id, &self.progress) {
            debug!("Cannot write the progress of the pull {}: {e}", self.id);
        }
    }
}

impl Completions {
    fn new(config: &velarx_config::PullConfig) -> Self {
        let fetches = config.lazy_complete_fetches.max(1);
        Self {
            cfg: Cfg {
                completers: config.lazy_completers as u32,
                retries: true,
                retry_max: config.lazy_retry_max_secs,
                fetches: fetches as u32,
                boosted_fetches: config.lazy_fetches.max(fetches) as u32,
                driver_pulls: false,
                quiet: 2000,
            },
            mailbox: Default::default(),
            activity: Default::default(),
        }
    }

    /// The mailbox of the task, started on first use.
    fn mailbox(&self, service: &ImageService) -> Option<&mpsc::UnboundedSender<Mail>> {
        if let Some(mailbox) = self.mailbox.get() {
            return Some(mailbox);
        }
        let runtime = tokio::runtime::Handle::try_current().ok()?;
        Some(self.mailbox.get_or_init(|| {
            let (tx, rx) = mpsc::unbounded_channel();
            let task = Task {
                service: service.clone(),
                activity: self.activity.clone(),
                keep: None,
                core: Core::new(Cfg {
                    driver_pulls: !service.storage.holds_objects(),
                    ..self.cfg
                }),
                pulls: HashMap::new(),
                next_pull: 0,
                parts: HashMap::new(),
                next_group: 0,
                work: HashMap::new(),
                next_run: 0,
                wake: None,
                base: tokio::time::Instant::now(),
                mailbox: tx.downgrade(),
            };
            runtime.spawn(task.run(rx));
            tx
        }))
    }

    /// Tell the task `event` of the pull `id`: what is set when the pull is
    /// over.  None: this process does not complete it.
    async fn tell(
        &self,
        id: &str,
        event: fn(PullId) -> Event,
    ) -> Option<watch::Receiver<Option<Over>>> {
        let (reply, answer) = oneshot::channel();
        let id = id.to_string();
        let told = move |t: &mut Task| {
            let (&pull, held) = t.pulls.iter().find(|(_, h)| h.id == id)?;
            let done = held.done.subscribe();
            t.feed(event(pull), None);
            Some(done)
        };
        let mail = Mail::Do(Box::new(move |t| drop(reply.send(told(t)))));
        self.mailbox.get()?.send(mail).ok()?;
        answer.await.ok().flatten()
    }
}

/// The task of the completions: it owns the state machine, tells it what
/// happens and does what it says.
struct Task {
    service: ImageService,
    activity: Arc<std::sync::OnceLock<Arc<Activity>>>,
    keep: Option<Keep>,
    core: Core,
    pulls: HashMap<PullId, Held>,
    next_pull: PullId,
    /// The layers and groups the machine holds, as the plan that named each
    /// and where in it
    parts: HashMap<Work, (Arc<Plan>, usize)>,
    next_group: GroupId,
    /// What runs for each work, to stop it, and which run it is: the answer
    /// of a run that was stopped is not the answer of the next one
    work: HashMap<Work, (u64, tokio::task::JoinHandle<()>)>,
    next_run: u64,
    /// The time the machine asked to be woken at, and the timer
    wake: Option<(Tick, tokio::task::JoinHandle<()>)>,
    base: tokio::time::Instant,
    mailbox: mpsc::WeakUnboundedSender<Mail>,
}

impl Task {
    async fn run(mut self, mut mailbox: mpsc::UnboundedReceiver<Mail>) {
        while let Some(mail) = mailbox.recv().await {
            match mail {
                Mail::Add(held) => {
                    let containers = self.service.containers_use(&held.id).await;
                    let pull = self.next_pull;
                    self.next_pull += 1;
                    self.pulls.insert(pull, *held);
                    let containers = containers.unwrap_or_default();
                    self.feed(Event::Added { pull, containers }, None);
                }
                Mail::Do(f) => f(&mut self),
            }
            // (the service stays while a pull is held)
            if self.pulls.is_empty() {
                self.keep = None;
            } else if self.keep.is_none() {
                self.keep = self.activity.get().map(|a| a.keep());
            }
        }
    }

    /// Tell the state machine, and do what it says.  `failure` is what
    /// failed, when the event is a failure.
    fn feed(&mut self, event: Event, failure: Option<&ImageError>) {
        let mut events = VecDeque::from([event]);
        while let Some(event) = events.pop_front() {
            let mut actions = Vec::new();
            let now = self.base.elapsed().as_millis() as Tick;
            step(&mut self.core, now, event, &mut actions);
            for action in actions {
                events.extend(self.perform(action, now, failure));
            }
        }
    }

    /// Run `job` for `work`; its success goes to `then`, its failure to the
    /// machine.
    fn spawn<T: Send + 'static>(
        &mut self,
        work: Work,
        job: impl Future<Output = ImageResult<T>> + Send + 'static,
        then: impl FnOnce(&mut Task, T) + Send + 'static,
    ) {
        let Some(mailbox) = self.mailbox.upgrade() else {
            return;
        };
        let run = self.next_run;
        self.next_run += 1;
        let task = tokio::spawn(async move {
            let result = job.await;
            let _ = mailbox.send(Mail::Do(Box::new(move |t| {
                // (a run that was stopped answers nothing)
                if t.work.get(&work).is_none_or(|(r, _)| *r != run) {
                    return;
                }
                t.work.remove(&work);
                match result {
                    Ok(value) => then(t, value),
                    Err(e) => t.feed(Event::Done(work, Err(class_of(&e))), Some(&e)),
                }
            })));
        });
        self.work.insert(work, (run, task));
    }

    fn perform(
        &mut self,
        action: Action,
        now: Tick,
        failure: Option<&ImageError>,
    ) -> Option<Event> {
        let service = self.service.clone();
        let done = |work| move |t: &mut Task, ()| t.feed(Event::Done(work, Ok(())), None);
        match action {
            Action::Record(pull, state) => return self.record(pull, state, now, failure),
            Action::Prepare(pull) => {
                let held = self.pulls.get_mut(&pull)?;
                held.progress.error = None;
                held.written = None;
                let (id, access) = (held.id.clone(), held.access.clone());
                let job = async move { service.prepare(&id, access).await };
                self.spawn(Work::Pull(pull), job, move |t, plan| t.prepared(pull, plan));
            }
            Action::Fetch(group) => {
                let (plan, at) = self.parts.get(&Work::Group(group))?.clone();
                let job = async move {
                    let g = &plan.groups[at];
                    let key = &plan.layers[g.layer].key;
                    service
                        .stage_lazy(key, g.files.clone(), Urgency::Background)
                        .await
                };
                self.spawn(Work::Group(group), job, move |t, w| t.fetched(group, w));
            }
            Action::CommitLayer(layer) => {
                let work = Work::Layer(layer);
                let (plan, at) = self.parts.get(&work)?.clone();
                let job = async move {
                    let this = &plan.layers[at];
                    service.commit_layer(this, &plan.layers, Vec::new()).await?;
                    service.release_layer(&this.key).await;
                    Ok(())
                };
                self.spawn(work, job, done(work));
            }
            Action::DriverPull(pull) => {
                let plan = self.pulls.get(&pull)?.plan.clone()?;
                let job = async move {
                    service.pull_staged(&plan).await?;
                    for layer in plan.layers.iter() {
                        service.release_layer(&layer.key).await;
                    }
                    Ok(())
                };
                self.spawn(Work::Pull(pull), job, done(Work::Pull(pull)));
            }
            Action::CommitImage(pull) => {
                let plan = self.pulls.get(&pull)?.plan.clone();
                let job = async move {
                    match plan {
                        Some(plan) => service.commit_planned_image(&plan).await,
                        None => Ok(()),
                    }
                };
                self.spawn(Work::Pull(pull), job, move |t, ()| {
                    if let Some(held) = t.pulls.get(&pull) {
                        let (id, took) = (&held.id, held.started.elapsed());
                        let by_source = held.stats.by_source.iter();
                        let moved: Vec<_> = by_source
                            .map(|s| format!("{} bytes from {}", s.bytes, s.name))
                            .collect();
                        info!(
                            "The pull {id} is in the store after {took:?}: {}",
                            moved.join(", ")
                        );
                    }
                    done(Work::Pull(pull))(t, ())
                });
            }
            // (nothing of a cancelled pull runs once the machine is told)
            Action::Abort(Work::Pull(pull)) => {
                let task = self.work.remove(&Work::Pull(pull));
                let job = async move {
                    if let Some((_, task)) = task {
                        task.abort();
                        let _ = task.await;
                    }
                    Ok(())
                };
                self.spawn(Work::Pull(pull), job, done(Work::Pull(pull)));
            }
            Action::Abort(work) => {
                if let Some((_, task)) = self.work.remove(&work) {
                    task.abort();
                }
            }
            Action::Forget(work) => {
                self.parts.remove(&work);
            }
            Action::End(pull) => {
                let held = self.pulls.remove(&pull)?;
                // (the lease goes before a waiter looks)
                drop(held.lease);
                held.done.send_replace(Some(Over {
                    moved: held.stats,
                    contradicted: held.contradicted,
                }));
            }
            // (one timer, the earliest: the tick asks for the next)
            Action::Wake(at) if self.wake.as_ref().is_some_and(|(t, _)| *t <= at) => {}
            Action::Wake(at) => {
                let mailbox = self.mailbox.upgrade()?;
                let until = self.base + Duration::from_millis(at);
                let timer = tokio::spawn(async move {
                    tokio::time::sleep_until(until).await;
                    let _ = mailbox.send(Mail::Do(Box::new(|t| {
                        t.wake = None;
                        t.feed(Event::Tick, None);
                    })));
                });
                if let Some((_, old)) = self.wake.replace((at, timer)) {
                    old.abort();
                }
            }
        }
        None
    }

    /// What a try of the pull lacks was looked for: the machine is told, by
    /// numbers, and the task keeps what each number is.
    fn prepared(&mut self, pull: PullId, plan: Option<Arc<Plan>>) {
        let (mut layers, mut groups) = (Vec::new(), Vec::new());
        if let Some(plan) = &plan {
            for (at, layer) in plan.layers.iter().enumerate() {
                let id = self.service.funnel.layer_id(&layer.key);
                layers.push(id);
                let part = self.parts.entry(Work::Layer(id));
                part.or_insert_with(|| (plan.clone(), at));
            }
            for (at, group) in plan.groups.iter().enumerate() {
                let id = self.next_group;
                self.next_group += 1;
                let needed_by = group.needed_by.iter().map(|&l| layers[l]).collect();
                groups.push(GroupFact { id, needed_by });
                self.parts.insert(Work::Group(id), (plan.clone(), at));
            }
        }
        if let Some(held) = self.pulls.get_mut(&pull) {
            held.stats = TransferStats::default();
            if let Some(plan) = &plan {
                held.stats.add(SOURCE_STORE, plan.reused.0, plan.reused.1);
            }
            held.plan = plan;
        }
        let prepared = Event::Prepared {
            pull,
            layers,
            groups,
        };
        self.feed(prepared, None);
        self.report(pull);
    }

    /// The group was fetched: what it moved counts for the pull whose plan
    /// named it.
    fn fetched(&mut self, group: GroupId, walked: Walked) {
        if let Some((plan, at)) = self.parts.get(&Work::Group(group)) {
            let sourced: u64 = walked.sources.iter().map(|s| s.files).sum();
            let own = (plan.groups[*at].files.len() as u64).saturating_sub(sourced);
            let planned = |h: &&mut Held| h.plan.as_ref().is_some_and(|p| Arc::ptr_eq(p, plan));
            if let Some(held) = self.pulls.values_mut().find(planned) {
                for s in &walked.sources {
                    held.stats.add(&s.name, s.bytes, s.files);
                }
                held.stats.add(SOURCE_REGISTRY, walked.bytes, own);
            }
        }
        self.feed(Event::Done(Work::Group(group), Ok(())), None);
        let pulls: Vec<PullId> = self.pulls.keys().copied().collect();
        for pull in pulls {
            self.report(pull);
        }
    }

    /// Tell `progress.json` how far the try of the pull is: at most once a
    /// second, and at its end.
    fn report(&mut self, pull: PullId) {
        let Some(held) = self.pulls.get_mut(&pull) else {
            return;
        };
        let (layers_total, layers_done) = self.core.layers_of(pull);
        let mut p = Progress {
            layers_total: layers_total.into(),
            layers_done: layers_done.into(),
            error: held.progress.error.take(),
            ..Progress::default()
        };
        for (group, done) in self.core.groups_of(pull) {
            let Some((plan, at)) = self.parts.get(&Work::Group(group)) else {
                continue;
            };
            let group = &plan.groups[*at];
            p.files_total += group.files.len() as u64;
            p.bytes_total += group.bytes;
            if done {
                p.files_done += group.files.len() as u64;
                p.bytes_done += group.bytes;
            }
        }
        held.progress = p;
        let recent = held
            .written
            .is_some_and(|t| t.elapsed() < Duration::from_secs(1));
        if layers_done >= layers_total || !recent {
            held.write_progress();
        }
    }

    /// Write the state of the pull; a failure is said in the log and in its
    /// progress.  A pull another process cancelled meanwhile is cancelled.
    fn record(
        &mut self,
        pull: PullId,
        state: State,
        now: Tick,
        failure: Option<&ImageError>,
    ) -> Option<Event> {
        let held = self.pulls.get_mut(&pull)?;
        let id = held.id.clone();
        let pid = Some(std::process::id());
        let (written, pid) = match state {
            State::Queued => (PullState::Queued, pid),
            State::Running | State::Backoff(_) => (PullState::Running, pid),
            State::NoSpace(_) => (PullState::WaitingForSpace, pid),
            State::NeedsCredentials => (PullState::NeedsCredentials, None),
            State::Failed => {
                let reason = failure.map(reason_of).unwrap_or_default();
                held.contradicted = match failure {
                    Some(ImageError::Contradicted(why)) => Some(why.clone()),
                    _ => None,
                };
                (PullState::Failed { reason }, None)
            }
        };
        // (an event that fails one pull may record another as running)
        if let (Some(e), false) = (failure, matches!(state, State::Queued | State::Running)) {
            match state {
                State::Backoff(at) => {
                    let wait = Duration::from_millis(at.saturating_sub(now));
                    warn!("The pull {id}: {e}; trying again in {wait:?}")
                }
                State::NoSpace(_) => {
                    warn!("The pull {id}: {e}; the file system is full, trying again in a minute")
                }
                State::NeedsCredentials => warn!("The pull {id} needs credentials: {e}"),
                _ => tracing::error!("The pull {id} stops: {}", reason_of(e)),
            }
            held.progress.error = Some(e.to_string());
            held.write_progress();
        }
        match held.area.advance_state(&id, written, pid) {
            Ok(true) => None,
            Ok(false) => {
                info!("The pull {id} is cancelled");
                Some(Event::Cancel(pull))
            }
            Err(e) => {
                warn!("The pull {id}: cannot record its state: {e}");
                None
            }
        }
    }
}
impl ImageService {
    /// Where the fetches of the starts of containers tell that they began
    /// and ended: the engine service completes the pulls, the others have
    /// none to tell.
    pub(super) fn starts(&self) -> Option<Starts> {
        match &self.owner {
            Owner::Service(c) => c.mailbox(self).cloned().map(Starts),
            _ => None,
        }
    }

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
            // (the pulls held already are kept from now on)
            if let Some(mailbox) = c.mailbox.get() {
                let _ = mailbox.send(Mail::Do(Box::new(|_| {})));
            }
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
            Owner::Service(c) => self.add_completion(c, id, access),
        }
    }

    /// Have the task of `completions` complete the pull `id`, unless another
    /// process holds its lease.
    fn add_completion(&self, completions: &Completions, id: &str, access: &RegistryAccess) {
        let area = self.staging_area();
        let lease = match area.take_lease(id) {
            Ok(Some(lease)) => lease,
            // another process holds it, or this one
            Ok(None) => return,
            // (committed or cancelled meanwhile)
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                warn!("Cannot take the lease of the pull {id}: {e}");
                return;
            }
        };
        let Some(mailbox) = completions.mailbox(self) else {
            warn!("The pull {id} is not completed: no runtime");
            return;
        };
        let _ = mailbox.send(Mail::Add(Box::new(Held {
            progress: Progress::default(),
            id: id.to_string(),
            area,
            lease,
            access: access.clone(),
            plan: None,
            stats: TransferStats::default(),
            contradicted: None,
            started: Instant::now(),
            written: None,
            done: watch::channel(None).0,
        })));
    }

    /// Complete the open pulls nobody completes: after a kill or a crash of
    /// the engine (a reboot discards them), the engine service does this at
    /// its start, and any command that finds such a pull starts the service.
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
            // (the completion of a caller is its own, for this call, and
            // ends on its first failure)
            Owner::Caller => {
                let mut completions = Completions::new(&self.pull_config);
                completions.cfg.retries = false;
                Arc::new(completions)
            }
            Owner::HandOff(h) => return h.complete(id, &access).await,
            Owner::Service(c) => c.clone(),
        };
        let start = std::time::Instant::now();
        let cancelled = || ImageError::Pulling(format!("the pull of image {id} was cancelled"));
        for round in 0..3 {
            // (a pull again of one that stopped starts it over)
            match area.state(id)?.state {
                PullState::Cancelled => return Err(cancelled()),
                s if !s.is_open() => area.set_state(id, PullState::Queued, None)?,
                _ => {}
            }
            self.add_completion(&completions, id, &access);
            let over = match completions.tell(id, Event::Hurry).await {
                Some(mut done) => done
                    .wait_for(Option::is_some)
                    .await
                    .ok()
                    .and_then(|over| over.clone())
                    .unwrap_or_default(),
                // (another process holds the lease: its end is waited for,
                // and what it moved is its own)
                None => {
                    let wait = self.staging_area();
                    let waited = id.to_string();
                    tokio::task::spawn_blocking(move || wait.wait_for_completer(&waited))
                        .await
                        .map_err(|e| ImageError::Storage(e.to_string()))??;
                    Over::default()
                }
            };
            if self.image_stored(&pull.manifest_digest).await {
                return Ok(TransferStats {
                    duration_ms: start.elapsed().as_millis() as u64,
                    ..over.moved
                });
            }
            match area.state(id)?.state {
                PullState::Failed { reason } => {
                    return Err(match over.contradicted {
                        Some(why) => ImageError::Contradicted(why),
                        None => {
                            ImageError::Pulling(format!("the pull of image {id} failed: {reason}"))
                        }
                    })
                }
                // (what was refused says what it needs; a completion that ran
                // without the credentials, started before, is followed by
                // one that has them)
                PullState::NeedsCredentials if access.is_empty() || round == 2 => {
                    let refused = area.progress(id)?.error.unwrap_or_else(|| format!(
                        "the pull of image {id} waits for the credentials (or certificates) it was made with, which are not stored: `velarx image complete --creds USER:PASSWORD {id}` (or --authfile, --cert-dir)"
                    ));
                    return Err(ImageError::Unauthorized(refused));
                }
                PullState::Cancelled => return Err(cancelled()),
                // the completion ended and the image is not in the store:
                // another process held it and was killed
                _ => {}
            }
        }
        Err(ImageError::Pulling(format!(
            "the pull of image {id} was not completed"
        )))
    }

    /// Stop the completion of `id` that this process runs, and wait for its
    /// task to end: nothing of it is recorded after this returns.  Whether
    /// one ran.
    pub(super) async fn stop_completion(&self, id: &str) -> bool {
        let Owner::Service(c) = &self.owner else {
            return false;
        };
        match c.tell(id, Event::Cancel).await {
            Some(mut done) => done.wait_for(Option::is_some).await.is_ok(),
            None => false,
        }
    }
}

/// What an error is to the completion: the class it is mapped to, once.
fn class_of(e: &ImageError) -> Class {
    use ImageError as E;
    // ENOSPC is the kind `StorageFull`, which an error made without an errno
    // has too
    let no_room = |io: &std::io::Error| io.kind() == std::io::ErrorKind::StorageFull;
    match e {
        E::Transfer { failure, .. } => match failure.class {
            FailureClass::Unauthorized | FailureClass::Forbidden => Class::Credentials,
            FailureClass::NoSpace => Class::NoSpace,
            // the origin says it does not have it: the blob is gone; a party
            // gave what it does not claim: trying again does not mend
            FailureClass::NotFound | FailureClass::Invalid | FailureClass::Failed => Class::Fatal,
            FailureClass::Unavailable | FailureClass::Transient => Class::Transient,
        },
        E::Unauthorized(_) | E::Forbidden(_) => Class::Credentials,
        E::RegistryNotFound(_)
        | E::Contradicted(_)
        | E::DigestMismatch { .. }
        | E::ComposefsDigest(_)
        | E::Manifest(_)
        | E::Layer(_)
        | E::Invalid(_)
        | E::NotFound(_)
        | E::Pulling(_)
        | E::ReadOnly(_)
        | E::DockerFormat(_)
        | E::NotLazy { .. }
        | E::TooManyLayers { .. }
        | E::NoOpenFiles { .. } => Class::Fatal,
        E::Io(io) if no_room(io) => Class::NoSpace,
        E::Storage(m) if m.contains("No space left") => Class::NoSpace,
        // the network, a busy registry, a database that is locked, a file
        // that went meanwhile: may pass
        E::Io(_)
        | E::Http(_)
        | E::Registry(_)
        | E::Unreachable(_)
        | E::Database(_)
        | E::Storage(_)
        | E::Json(_)
        | E::Ids(_) => Class::Transient,
    }
}

/// Why a pull stops on `e` (a fatal error).
fn reason_of(e: &ImageError) -> String {
    use ImageError as E;
    match e {
        E::RegistryNotFound(_) => format!("the registry no longer has the blob: {e}"),
        E::Transfer { failure, .. } if failure.class == FailureClass::NotFound => {
            format!("the registry no longer has the blob: {e}")
        }
        _ => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_may_pass_is_retried_and_what_cannot_stops_the_completion() {
        let io = |e: std::io::Error| ImageError::Io(e);
        assert_eq!(
            class_of(&ImageError::Registry("503".into())),
            Class::Transient
        );
        assert_eq!(
            class_of(&io(std::io::Error::from(
                std::io::ErrorKind::ConnectionReset
            ))),
            Class::Transient
        );
        assert_eq!(
            class_of(&io(std::io::Error::from_raw_os_error(libc::ENOSPC))),
            Class::NoSpace
        );
        assert_eq!(
            class_of(&io(std::io::Error::from(std::io::ErrorKind::StorageFull))),
            Class::NoSpace
        );
        // a quota is not a full disk here, as before
        assert_eq!(
            class_of(&io(std::io::Error::from_raw_os_error(libc::EDQUOT))),
            Class::Transient
        );
        assert_eq!(
            class_of(&ImageError::Unauthorized("401".into())),
            Class::Credentials
        );
        assert_eq!(
            class_of(&ImageError::Forbidden("403".into())),
            Class::Credentials
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
            assert_eq!(class_of(&stops), Class::Fatal, "{stops}");
        }
        assert!(reason_of(&ImageError::RegistryNotFound("blob".into()))
            .starts_with("the registry no longer has the blob"));
    }

    /// The answer of a commit that was aborted, late in the mailbox, is not
    /// the answer of the commit that follows it.
    #[tokio::test]
    async fn the_late_answer_of_an_aborted_work_is_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(velarx_storage::FileStore::new(tmp.path().join("objects")).unwrap());
        let db = velarx_db::Database::open_in_memory().await.unwrap();
        let service = ImageService::new(
            db,
            store,
            tmp.path().join("pulls"),
            velarx_storage::VerityMode::Off,
        )
        .unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut task = Task {
            service,
            activity: Default::default(),
            keep: None,
            core: Core::new(Cfg {
                completers: 1,
                retries: true,
                retry_max: 1,
                fetches: 1,
                boosted_fetches: 1,
                driver_pulls: false,
                quiet: 2000,
            }),
            pulls: HashMap::new(),
            next_pull: 0,
            parts: HashMap::new(),
            next_group: 0,
            work: HashMap::new(),
            next_run: 0,
            wake: None,
            base: tokio::time::Instant::now(),
            mailbox: tx.downgrade(),
        };
        let work = Work::Layer(7);
        let answers = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let answered = |n: u32| {
            let answers = answers.clone();
            move |_: &mut Task, (): ()| {
                answers.fetch_add(n, std::sync::atomic::Ordering::SeqCst);
            }
        };
        // the first commit ends, and its answer waits in the mailbox
        task.spawn(work, async { Ok(()) }, answered(1));
        while !task.work[&work].1.is_finished() {
            tokio::task::yield_now().await;
        }
        // it is aborted, and the same layer is committed again
        task.perform(Action::Abort(work), 0, None);
        task.spawn(
            work,
            std::future::pending::<ImageResult<()>>(),
            answered(10),
        );
        // the late answer comes: it is not the second commit's
        let Some(Mail::Do(late)) = rx.recv().await else {
            panic!("no answer")
        };
        late(&mut task);
        assert_eq!(answers.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(task.work.contains_key(&work), "the second commit is lost");
    }
}
