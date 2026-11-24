// SPDX-License-Identifier: Apache-2.0
//! The decisions of the completion of lazy pulls as a state machine: [`step`]
//! takes an event and says, as actions, what the caller is to do.  No
//! dependency, no I/O, no clock, no async: time comes in as milliseconds,
//! pulls, layers and groups are numbers, and what the caller did or saw
//! comes back as events.
//!
//! The pulls share their layers: a layer is fetched and committed once, and
//! every pull that lacks it waits for it.
//!
//! What Aeneas does not translate or its Lean model cannot check (an
//! adapter over `iter_mut`, a closure that holds a reference or writes to
//! a captured one, a parameter named `core`) is avoided in the code
//! (tools/verify/lazy-core).  So is a chain of `filter`, `map`, `all`,
//! `collect` or `extend` where a proof must know what a function returns
//! or appends: `lacking`, `has_all`, `waits_for_groups`, `wanting`, the
//! counts (`in_flight`, `slots_held`, those of `advance`), `next_wake` and
//! the late answer of `prepared` are plain loops, not to be folded into
//! adapters.

/// Milliseconds on a clock the caller keeps.
pub type Tick = u64;
pub type PullId = u32;
/// A layer (one for every layer key the caller sees)
pub type LayerId = u32;
/// A group of the files a layer lacks, fetched by one request
pub type GroupId = u32;

/// The wait before the next try of a pull whose file system is full.
const SPACE_WAIT: Tick = 60_000;

/// The settings the decisions depend on.
#[derive(Debug, Clone, Copy)]
pub struct Cfg {
    /// Background completions at once (`[pull] lazy_completers`)
    pub completers: u32,
    /// A try that failed is tried again, but for want of credentials (the
    /// completion of a caller that waits for it is not)
    pub retries: bool,
    /// The longest wait between two tries, in seconds
    pub retry_max: u64,
    /// Groups a pull has in flight at most
    pub fetches: u32,
    /// Groups a pull a command waits for has in flight at most
    pub boosted_fetches: u32,
    /// The storage driver pulls the layers from the staging, those of a
    /// pull together: a layer is not committed here
    pub driver_pulls: bool,
    /// How long after its last fetch the start of a container is left alone
    /// by the fetches of the pulls that lack its layers: a start reads in
    /// bursts with short gaps between them
    pub quiet: Tick,
}

/// What a failure is to the completion; the caller maps its errors to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// May pass: the network, a busy registry, a layer that went meanwhile
    Transient,
    /// The file system is full
    NoSpace,
    /// The registry wants credentials the completion does not have
    Credentials,
    /// Trying again cannot mend it
    Fatal,
}

/// The state of a pull, as the caller records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Queued,
    Running,
    /// Running, between two tries, until the tick
    Backoff(Tick),
    /// The file system is full: the next try is at the tick
    NoSpace(Tick),
    /// The completion ended: the registry wants credentials it does not have
    NeedsCredentials,
    /// The completion ended on an error that trying again cannot mend
    Failed,
}

/// A group of files a try lacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupFact {
    pub id: GroupId,
    /// The layers that wait for its files, whichever it is fetched into
    pub needed_by: Vec<LayerId>,
}

/// What runs for a pull, a layer or a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Work {
    /// What runs for the pull itself: its preparation, the driver's pull of
    /// its layers, the commit of its image, or its stop
    Pull(PullId),
    Layer(LayerId),
    Group(GroupId),
}

/// What the caller tells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The caller holds the lease of the pull and completes it.
    /// `containers`: a container is made on it, it needs no turn.
    Added {
        pull: PullId,
        containers: bool,
    },
    /// A command waits for the pull
    Hurry(PullId),
    Cancel(PullId),
    /// What the try of the pull lacks: the layers, and the groups of the
    /// files to fetch for them, in the order they are to be fetched.  What
    /// is not taken (a layer held already has its groups) is told back with
    /// `Forget`.
    Prepared {
        pull: PullId,
        layers: Vec<LayerId>,
        groups: Vec<GroupFact>,
    },
    /// What an action started for the work ended (a preparation that did
    /// not fail ends with `Prepared`)
    Done(Work, Result<(), Class>),
    /// A fetch for the start of a container began in the layer
    StartBegan(LayerId),
    /// A fetch for the start of a container ended in the layer
    StartEnded(LayerId),
    /// The time asked for with `Wake` came
    Tick,
}

/// What the caller does.  Each action that starts something for a work
/// is answered with `Done` of that work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Record(PullId, State),
    /// Look for what the pull lacks
    Prepare(PullId),
    Fetch(GroupId),
    /// Commit the layer and remove its staging
    CommitLayer(LayerId),
    /// Have the storage driver pull the layers of the pull, then remove
    /// their staging
    DriverPull(PullId),
    CommitImage(PullId),
    /// Stop what runs for the work, which is then not answered (not even
    /// when it had ended); for a pull, wait for it to end, then answer
    Abort(Work),
    /// Nothing more is asked of the layer or the group
    Forget(Work),
    /// The pull is over: let go of its lease
    End(PullId),
    /// Send `Tick` at this time; one asked earlier and pending makes it
    /// of no use, the `Tick` asks for what is left
    Wake(Tick),
}

/// What a try of a pull is at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Preparing,
    /// Its groups are fetched and its layers committed
    Working,
    DriverPull,
    Image,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waits for its turn among the background completions
    Queued,
    Running(Step),
    /// The try failed: the next one is at the tick
    Waiting(Tick),
    /// What ran for it is being stopped
    Cancelling,
}

#[derive(Debug, Clone)]
struct Pull {
    id: PullId,
    phase: Phase,
    /// Holds one of the `completers` places
    slot: bool,
    /// A command waits for it: it goes as fast as it can
    boosted: bool,
    failures: u32,
    /// The try got files or layers done
    progressed: bool,
    /// The layers the try lacks
    layers: Vec<LayerId>,
}

impl Pull {
    fn lacks(&self, layer: LayerId) -> bool {
        self.layers.contains(&layer)
    }

    fn wants(&self, group: &Group) -> bool {
        group.needed_by.iter().any(|l| self.lacks(*l))
    }

    /// Whether every layer of `layers` it lacks is in a state `done` takes.
    fn has_all(&self, layers: &[Layer], done: impl Fn(LayerState) -> bool) -> bool {
        for l in layers.iter() {
            if self.lacks(l.id) && !done(l.state) {
                return false;
            }
        }
        true
    }

    fn working(&self) -> bool {
        self.phase == Phase::Running(Step::Working)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayerState {
    Fetching,
    /// Its files are all there, the storage driver pulls it
    Ready,
    Committing,
    Stored,
}

#[derive(Debug, Clone)]
struct Layer {
    id: LayerId,
    state: LayerState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupState {
    Todo,
    /// In flight, counted against the window of the pull
    Sent(PullId),
    Done,
}

#[derive(Debug, Clone)]
struct Group {
    id: GroupId,
    state: GroupState,
    /// The layers that wait for the files of the group
    needed_by: Vec<LayerId>,
}

/// The fetches for the starts of containers in a layer.
#[derive(Debug, Clone)]
struct ContainerStart {
    layer: LayerId,
    inflight: u32,
    /// When the last one began or ended
    last: Tick,
}

/// The pulls of one completer, their layers and groups.
#[derive(Debug, Clone)]
pub struct Core {
    cfg: Cfg,
    pulls: Vec<Pull>,
    layers: Vec<Layer>,
    groups: Vec<Group>,
    starts: Vec<ContainerStart>,
}

impl Core {
    pub fn new(cfg: Cfg) -> Self {
        Self {
            cfg,
            pulls: Vec::new(),
            layers: Vec::new(),
            groups: Vec::new(),
            starts: Vec::new(),
        }
    }

    /// The groups the try of the pull waits for, and whether each is done.
    pub fn groups_of(&self, pull: PullId) -> Vec<(GroupId, bool)> {
        let Some(at) = self.pull_at(pull) else {
            return Vec::new();
        };
        let pull = &self.pulls[at];
        let wanted = self.groups.iter().filter(|g| pull.wants(g));
        wanted
            .map(|g| (g.id, g.state == GroupState::Done))
            .collect()
    }

    /// How many layers the try of the pull lacks, and how many of them are
    /// done (their files are there, or they are in the store).
    pub fn layers_of(&self, pull: PullId) -> (u32, u32) {
        let Some(at) = self.pull_at(pull) else {
            return (0, 0);
        };
        let pull = &self.pulls[at];
        let done = self.layers.iter().filter(|l| {
            pull.lacks(l.id) && matches!(l.state, LayerState::Ready | LayerState::Stored)
        });
        (pull.layers.len() as u32, done.count() as u32)
    }

    fn pull_at(&self, pull: PullId) -> Option<usize> {
        self.pulls.iter().position(|p| p.id == pull)
    }

    fn layer_at(&self, layer: LayerId) -> Option<usize> {
        self.layers.iter().position(|l| l.id == layer)
    }

    fn group_at(&self, group: GroupId) -> Option<usize> {
        self.groups.iter().position(|g| g.id == group)
    }

    /// The working pulls that lack one of `layers`.
    fn lacking(&self, layers: &[LayerId]) -> Vec<PullId> {
        let mut lacking = Vec::new();
        for p in self.pulls.iter() {
            if p.working() && layers.iter().any(|l| p.lacks(*l)) {
                lacking.push(p.id);
            }
        }
        lacking
    }

    /// Whether a container starts on a layer the pull lacks: a fetch for it
    /// is in flight, or ended less than `quiet` ago.
    fn starting(&self, pull: &Pull, now: Tick) -> bool {
        self.starts.iter().any(|s| {
            pull.lacks(s.layer) && (s.inflight > 0 || now < s.last.saturating_add(self.cfg.quiet))
        })
    }
}

/// What the machine does with an event.  `now` is the time of the event.
pub fn step(c: &mut Core, now: Tick, event: Event, out: &mut Vec<Action>) {
    match event {
        Event::Added { pull, containers } => add(c, pull, containers, out),
        Event::Hurry(pull) => {
            let Some(at) = c.pull_at(pull) else { return };
            c.pulls[at].boosted = true;
            if matches!(c.pulls[at].phase, Phase::Queued | Phase::Waiting(_)) {
                begin_try(c, at, out);
            }
        }
        Event::Cancel(pull) => cancel(c, pull, out),
        Event::Prepared {
            pull,
            layers,
            groups,
        } => prepared(c, pull, layers, groups, out),
        Event::Done(work, Ok(())) => succeeded(c, work, out),
        Event::Done(work, Err(class)) => failed(c, now, work, class, out),
        // (nothing can go on because a start began or ended: the end asks
        // for the time its quiet ends)
        Event::StartBegan(layer) => {
            let start = start_at(c, layer, now);
            start.inflight = start.inflight.saturating_add(1);
            return;
        }
        Event::StartEnded(layer) => {
            let start = start_at(c, layer, now);
            start.inflight = start.inflight.saturating_sub(1);
            start.last = now;
            out.push(Action::Wake(now.saturating_add(c.cfg.quiet)));
            return;
        }
        Event::Tick => {
            for at in 0..c.pulls.len() {
                if let Phase::Waiting(t) = c.pulls[at].phase {
                    if t <= now {
                        begin_try(c, at, out);
                    }
                }
            }
            advance(c, now, out);
            if let Some(t) = next_wake(c, now) {
                out.push(Action::Wake(t));
            }
            return;
        }
    }
    advance(c, now, out);
}

fn add(c: &mut Core, pull: PullId, containers: bool, out: &mut Vec<Action>) {
    if c.pull_at(pull).is_some() {
        return;
    }
    let free = slots_held(c) < c.cfg.completers;
    c.pulls.push(Pull {
        id: pull,
        phase: Phase::Queued,
        slot: free && !containers,
        boosted: false,
        failures: 0,
        progressed: false,
        layers: Vec::new(),
    });
    if free || containers {
        begin_try(c, c.pulls.len() - 1, out);
    } else {
        out.push(Action::Record(pull, State::Queued));
    }
}

fn cancel(c: &mut Core, pull: PullId, out: &mut Vec<Action>) {
    let Some(at) = c.pull_at(pull) else { return };
    match c.pulls[at].phase {
        Phase::Queued | Phase::Waiting(_) => leave(c, at, out),
        Phase::Running(_) => {
            let mine = c.pulls[at].layers.clone();
            c.pulls[at].phase = Phase::Cancelling;
            let_go(c, at, out);
            out.push(Action::Abort(Work::Pull(pull)));
            // (what the pulls that shared a layer with it hold of it was
            // planned for the cancelled one, whose stagings may go: they
            // prepare again)
            for other in c.lacking(&mine) {
                if let Some(at) = c.pull_at(other) {
                    let_go(c, at, out);
                    begin_try(c, at, out);
                }
            }
        }
        Phase::Cancelling => {}
    }
}

fn prepared(
    c: &mut Core,
    pull: PullId,
    layers: Vec<LayerId>,
    groups: Vec<GroupFact>,
    out: &mut Vec<Action>,
) {
    let at = c.pull_at(pull);
    let at = at.filter(|&at| c.pulls[at].phase == Phase::Running(Step::Preparing));
    let mut fresh = layers.clone();
    fresh.retain(|l| c.layer_at(*l).is_none());
    let Some(at) = at else {
        // (a late answer, for a try that is over)
        for l in fresh {
            out.push(Action::Forget(Work::Layer(l)));
        }
        for g in groups {
            out.push(Action::Forget(Work::Group(g.id)));
        }
        return;
    };
    // (a group is kept for the new layers that wait for it, whatever layer
    // it is fetched into)
    for GroupFact { id, mut needed_by } in groups {
        needed_by.retain(|l| fresh.contains(l));
        if needed_by.is_empty() {
            out.push(Action::Forget(Work::Group(id)));
        } else {
            let state = GroupState::Todo;
            c.groups.push(Group {
                id,
                state,
                needed_by,
            });
        }
    }
    for id in fresh {
        let state = LayerState::Fetching;
        c.layers.push(Layer { id, state });
    }
    c.pulls[at].layers = layers;
    c.pulls[at].phase = Phase::Running(Step::Working);
}

/// What ran for `work` ended well.
fn succeeded(c: &mut Core, work: Work, out: &mut Vec<Action>) {
    match work {
        Work::Group(group) => {
            let Some(g) = c.group_at(group) else {
                return;
            };
            if let GroupState::Sent(_) = c.groups[g].state {
                c.groups[g].state = GroupState::Done;
                let needed_by = c.groups[g].needed_by.clone();
                progress(c, &needed_by);
            }
        }
        Work::Layer(layer) => {
            let Some(l) = c.layer_at(layer) else {
                return;
            };
            if c.layers[l].state == LayerState::Committing {
                c.layers[l].state = LayerState::Stored;
                progress(c, &[layer]);
            }
        }
        Work::Pull(pull) => {
            let Some(at) = c.pull_at(pull) else { return };
            match c.pulls[at].phase {
                Phase::Running(Step::DriverPull) => {
                    let p = &mut c.pulls[at];
                    for l in c.layers.iter_mut() {
                        if l.state == LayerState::Ready && p.lacks(l.id) {
                            l.state = LayerState::Stored;
                        }
                    }
                    p.progressed = true;
                    p.phase = Phase::Running(Step::Working);
                }
                Phase::Running(Step::Image) | Phase::Cancelling => leave(c, at, out),
                _ => {}
            }
        }
    }
}

/// What ran for `work` failed: the tries that wait for it fail.
fn failed(c: &mut Core, now: Tick, work: Work, class: Class, out: &mut Vec<Action>) {
    let failing = match work {
        Work::Group(group) => {
            let Some(g) = c.group_at(group) else {
                return;
            };
            if !matches!(c.groups[g].state, GroupState::Sent(_)) {
                return;
            }
            c.groups[g].state = GroupState::Todo;
            c.lacking(&c.groups[g].needed_by)
        }
        Work::Layer(layer) => {
            let Some(l) = c.layer_at(layer) else {
                return;
            };
            if c.layers[l].state != LayerState::Committing {
                return;
            }
            c.layers[l].state = LayerState::Fetching;
            c.lacking(&[layer])
        }
        Work::Pull(pull) => {
            let Some(at) = c.pull_at(pull) else { return };
            match c.pulls[at].phase {
                Phase::Running(_) => vec![pull],
                Phase::Cancelling => return leave(c, at, out),
                _ => return,
            }
        }
    };
    for pull in failing {
        if let Some(at) = c.pull_at(pull) {
            try_failed(c, now, at, class, out);
        }
    }
}

/// The try of the pull at `at` failed with `class`.  A try that got
/// something done starts the count of the failures over: what failed was
/// not the same thing.
fn try_failed(c: &mut Core, now: Tick, at: usize, class: Class, out: &mut Vec<Action>) {
    let pull = &mut c.pulls[at];
    if pull.progressed {
        pull.failures = 0;
    }
    let state = match class {
        Class::Credentials => State::NeedsCredentials,
        _ if !c.cfg.retries => State::Failed,
        Class::Transient => {
            let wait = backoff(pull.failures, c.cfg.retry_max);
            pull.failures = pull.failures.saturating_add(1);
            State::Backoff(now.saturating_add(wait))
        }
        Class::NoSpace => State::NoSpace(now.saturating_add(SPACE_WAIT)),
        Class::Fatal => State::Failed,
    };
    out.push(Action::Record(pull.id, state));
    match state {
        State::Backoff(until) | State::NoSpace(until) => {
            pull.phase = Phase::Waiting(until);
            let_go(c, at, out);
            out.push(Action::Wake(until));
        }
        _ => leave(c, at, out),
    }
}

/// The wait before the try after `failures` failures, doubling from a
/// second to `max` seconds.
fn backoff(failures: u32, max: u64) -> Tick {
    let secs = 1u64.checked_shl(failures.min(20)).unwrap_or(u64::MAX);
    secs.min(max).saturating_mul(1000)
}

/// The tries that lack one of `layers` got something done.
fn progress(c: &mut Core, layers: &[LayerId]) {
    for p in c.pulls.iter_mut() {
        if p.working() && layers.iter().any(|l| p.lacks(*l)) {
            p.progressed = true;
        }
    }
}

/// The groups in flight counted against the window of the pull.
fn in_flight(c: &Core, pull: PullId) -> u32 {
    let mut sent = 0u32;
    for g in c.groups.iter() {
        if g.state == GroupState::Sent(pull) {
            sent = sent.saturating_add(1);
        }
    }
    sent
}

fn slots_held(c: &Core) -> u32 {
    let mut held = 0u32;
    for p in c.pulls.iter() {
        if p.slot {
            held = held.saturating_add(1);
        }
    }
    held
}

/// A try of the pull at `at` begins.
fn begin_try(c: &mut Core, at: usize, out: &mut Vec<Action>) {
    let pull = &mut c.pulls[at];
    pull.phase = Phase::Running(Step::Preparing);
    pull.progressed = false;
    out.push(Action::Record(pull.id, State::Running));
    out.push(Action::Prepare(pull.id));
}

/// The try of the pull at `at` lets go of its layers: what no other try
/// lacks goes, and what is in flight for nothing else is stopped.
fn let_go(c: &mut Core, at: usize, out: &mut Vec<Action>) {
    let mine = std::mem::take(&mut c.pulls[at].layers);
    let me = c.pulls[at].id;
    let Core {
        pulls,
        layers,
        groups,
        ..
    } = c;
    for l in layers.iter() {
        if !goes(l.id, &mine, pulls) {
            continue;
        }
        if l.state == LayerState::Committing {
            out.push(Action::Abort(Work::Layer(l.id)));
        }
        out.push(Action::Forget(Work::Layer(l.id)));
    }
    layers.retain(|l| !goes(l.id, &mine, pulls));
    for g in groups.iter_mut() {
        let Some(other) = wanting(pulls, g) else {
            if let GroupState::Sent(_) = g.state {
                out.push(Action::Abort(Work::Group(g.id)));
            }
            out.push(Action::Forget(Work::Group(g.id)));
            continue;
        };
        // (what it had in flight counts against the window of another)
        if g.state == GroupState::Sent(me) {
            g.state = GroupState::Sent(other);
        }
    }
    groups.retain(|g| wanting(pulls, g).is_some());
}

/// Whether the layer goes when a try lets go of `mine`: no try lacks it.
fn goes(layer: LayerId, mine: &[LayerId], pulls: &[Pull]) -> bool {
    mine.contains(&layer) && !pulls.iter().any(|p| p.lacks(layer))
}

/// The first working pull that wants the group.
fn wanting(pulls: &[Pull], group: &Group) -> Option<PullId> {
    for p in pulls.iter() {
        if p.working() && p.wants(group) {
            return Some(p.id);
        }
    }
    None
}

/// The pull at `at` is over: it goes, and its place is given to the first
/// that waits.
fn leave(c: &mut Core, at: usize, out: &mut Vec<Action>) {
    let_go(c, at, out);
    let pull = c.pulls.remove(at);
    out.push(Action::End(pull.id));
    for at in 0..c.pulls.len() {
        if slots_held(c) >= c.cfg.completers {
            break;
        }
        if c.pulls[at].phase == Phase::Queued {
            c.pulls[at].slot = true;
            begin_try(c, at, out);
        }
    }
}

/// The record of the starts in the layer, made if there is none; those no
/// start is in or was lately are forgotten.
fn start_at(c: &mut Core, layer: LayerId, now: Tick) -> &mut ContainerStart {
    let quiet = c.cfg.quiet;
    c.starts
        .retain(|s| s.layer == layer || s.inflight > 0 || now < s.last.saturating_add(quiet));
    let at = match c.starts.iter().position(|s| s.layer == layer) {
        Some(at) => at,
        None => {
            c.starts.push(ContainerStart {
                layer,
                inflight: 0,
                last: now,
            });
            c.starts.len() - 1
        }
    };
    &mut c.starts[at]
}

/// The earliest time after `now` something waits for: the next try of a
/// pull, the end of the quiet of a start.
fn next_wake(c: &Core, now: Tick) -> Option<Tick> {
    let mut next = None;
    for p in c.pulls.iter() {
        if let Phase::Waiting(t) = p.phase {
            next = sooner(next, t, now);
        }
    }
    for s in c.starts.iter() {
        if s.inflight == 0 {
            next = sooner(next, s.last.saturating_add(c.cfg.quiet), now);
        }
    }
    next
}

/// The earlier of `next` and `t`, if `t` is after `now`.
fn sooner(next: Option<Tick>, t: Tick, now: Tick) -> Option<Tick> {
    if t <= now {
        return next;
    }
    match next {
        None => Some(t),
        Some(n) => Some(n.min(t)),
    }
}

/// Whether a group that names the layer is not done: its files are not all there.
fn waits_for_groups(groups: &[Group], layer: LayerId) -> bool {
    for g in groups.iter() {
        if g.needed_by.contains(&layer) && g.state != GroupState::Done {
            return true;
        }
    }
    false
}

/// What can go on now does: the layers whose files are there, the pulls
/// whose layers are, and the groups that fit in what a pull has in flight.
fn advance(c: &mut Core, now: Tick, out: &mut Vec<Action>) {
    // (one commit at a time for each working pull)
    let mut working = 0usize;
    for p in c.pulls.iter() {
        if p.working() {
            working += 1;
        }
    }
    let mut committing = 0usize;
    for l in c.layers.iter() {
        if l.state == LayerState::Committing {
            committing += 1;
        }
    }
    let Core { layers, groups, .. } = c;
    for l in layers.iter_mut() {
        if l.state != LayerState::Fetching || waits_for_groups(groups, l.id) {
            continue;
        }
        if c.cfg.driver_pulls {
            l.state = LayerState::Ready;
        } else if committing < working {
            l.state = LayerState::Committing;
            committing += 1;
            out.push(Action::CommitLayer(l.id));
        }
    }
    let Core { pulls, layers, .. } = c;
    for p in pulls.iter_mut() {
        if !p.working() {
            continue;
        }
        if p.has_all(layers, |s| s == LayerState::Stored) {
            p.phase = Phase::Running(Step::Image);
            out.push(Action::CommitImage(p.id));
        } else if p.has_all(layers, |s| {
            matches!(s, LayerState::Ready | LayerState::Stored)
        }) {
            p.phase = Phase::Running(Step::DriverPull);
            out.push(Action::DriverPull(p.id));
        }
    }
    // the groups, the pulls that came first first, but not while a
    // container starts on a layer of the pull
    for p in 0..c.pulls.len() {
        let pull = &c.pulls[p];
        if !pull.working() || c.starting(pull, now) {
            continue;
        }
        let limit = if pull.boosted {
            c.cfg.boosted_fetches
        } else {
            c.cfg.fetches
        };
        let id = pull.id;
        let mut sent = in_flight(c, id);
        for g in 0..c.groups.len() {
            if sent < limit
                && c.groups[g].state == GroupState::Todo
                && c.pulls[p].wants(&c.groups[g])
            {
                c.groups[g].state = GroupState::Sent(id);
                out.push(Action::Fetch(c.groups[g].id));
                sent += 1;
            }
        }
    }
}
#[cfg(test)]
mod walk;

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Cfg {
        Cfg {
            completers: 2,
            retries: true,
            retry_max: 8,
            fetches: 2,
            boosted_fetches: 4,
            driver_pulls: false,
            quiet: 2000,
        }
    }

    fn feed(core: &mut Core, now: Tick, event: Event) -> Vec<Action> {
        let mut out = Vec::new();
        step(core, now, event, &mut out);
        out
    }

    fn ok(work: Work) -> Event {
        Event::Done(work, Ok(()))
    }

    fn failed(work: Work, class: Class) -> Event {
        Event::Done(work, Err(class))
    }

    fn phase(c: &Core, pull: PullId) -> Option<Phase> {
        c.pulls.iter().find(|p| p.id == pull).map(|p| p.phase)
    }

    fn added(pull: PullId) -> Event {
        Event::Added {
            pull,
            containers: false,
        }
    }

    fn group(id: GroupId, needed_by: &[LayerId]) -> GroupFact {
        GroupFact {
            id,
            needed_by: needed_by.to_vec(),
        }
    }

    fn prepared(pull: PullId, layers: &[LayerId], groups: Vec<GroupFact>) -> Event {
        Event::Prepared {
            pull,
            layers: layers.to_vec(),
            groups,
        }
    }

    /// A pull added and told what it lacks.
    fn running(
        core: &mut Core,
        pull: PullId,
        layers: &[LayerId],
        groups: Vec<GroupFact>,
    ) -> Vec<Action> {
        feed(core, 0, added(pull));
        feed(core, 0, prepared(pull, layers, groups))
    }

    fn fetches(actions: &[Action]) -> Vec<GroupId> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Fetch(g) => Some(*g),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_backoff_doubles_to_its_maximum() {
        let secs: Vec<u64> = (0..12).map(|n| backoff(n, 600) / 1000).collect();
        assert_eq!(secs, [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 600, 600]);
        assert_eq!(backoff(u32::MAX, u64::MAX), 1_048_576_000);
    }

    #[test]
    fn a_pull_with_a_free_place_looks_for_what_it_lacks() {
        let mut c = Core::new(cfg());
        assert_eq!(
            feed(&mut c, 0, added(1)),
            [Action::Record(1, State::Running), Action::Prepare(1)]
        );
    }

    #[test]
    fn a_pull_that_lacks_nothing_commits_its_image() {
        let mut c = Core::new(cfg());
        feed(&mut c, 0, added(1));
        assert_eq!(
            feed(&mut c, 0, prepared(1, &[], Vec::new())),
            [Action::CommitImage(1)]
        );
        assert_eq!(feed(&mut c, 1, ok(Work::Pull(1))), [Action::End(1)]);
        assert_eq!(phase(&c, 1), None);
    }

    #[test]
    fn the_groups_go_out_as_the_pull_has_room_and_a_layer_is_committed_with_its_last() {
        let mut c = Core::new(cfg());
        let out = running(
            &mut c,
            1,
            &[10, 11],
            vec![group(1, &[10]), group(2, &[10]), group(3, &[11])],
        );
        assert_eq!(fetches(&out), [1, 2]);
        assert_eq!(feed(&mut c, 0, ok(Work::Group(1))), [Action::Fetch(3)]);
        assert_eq!(
            feed(&mut c, 0, ok(Work::Group(2))),
            [Action::CommitLayer(10)]
        );
        // (one commit at a time for a pull)
        assert_eq!(feed(&mut c, 0, ok(Work::Group(3))), []);
        assert_eq!(
            feed(&mut c, 0, ok(Work::Layer(10))),
            [Action::CommitLayer(11)]
        );
        assert_eq!(
            feed(&mut c, 0, ok(Work::Layer(11))),
            [Action::CommitImage(1)]
        );
        assert_eq!(c.layers_of(1), (2, 2));
        feed(&mut c, 0, ok(Work::Pull(1)));
        assert_eq!(c.layers_of(1), (0, 0));
        assert!(c.groups_of(1).is_empty());
    }

    #[test]
    fn a_layer_waits_for_the_groups_of_the_layers_that_fetch_for_it() {
        let mut c = Core::new(cfg());
        // (a file of both is fetched into the first)
        let out = running(
            &mut c,
            1,
            &[10, 11],
            vec![group(1, &[10, 11]), group(2, &[11])],
        );
        assert_eq!(fetches(&out), [1, 2]);
        assert_eq!(feed(&mut c, 0, ok(Work::Group(2))), []);
        assert_eq!(
            feed(&mut c, 0, ok(Work::Group(1))),
            [Action::CommitLayer(10)]
        );
    }

    #[test]
    fn a_boosted_pull_has_more_in_flight() {
        let mut c = Core::new(cfg());
        let groups: Vec<GroupFact> = (1..=6).map(|g| group(g, &[10])).collect();
        let out = running(&mut c, 1, &[10], groups);
        assert_eq!(fetches(&out), [1, 2]);
        assert_eq!(fetches(&feed(&mut c, 0, Event::Hurry(1))), [3, 4]);
    }

    /// Two pulls name a layer: it is fetched and committed once, and the
    /// pull that came second waits for it.
    #[test]
    fn a_layer_two_pulls_share_is_fetched_once() {
        let mut c = Core::new(cfg());
        let out = running(&mut c, 1, &[10], vec![group(1, &[10])]);
        assert_eq!(fetches(&out), [1]);
        feed(&mut c, 0, added(2));
        // (its own group for the layer is not asked)
        let out = feed(&mut c, 0, prepared(2, &[10], vec![group(5, &[10])]));
        assert_eq!(out, [Action::Forget(Work::Group(5))]);
        assert_eq!(c.groups_of(2), [(1, false)]);
        assert_eq!(c.groups_of(1), [(1, false)]);
        assert_eq!(
            feed(&mut c, 0, ok(Work::Group(1))),
            [Action::CommitLayer(10)]
        );
        assert_eq!(
            feed(&mut c, 0, ok(Work::Layer(10))),
            [Action::CommitImage(1), Action::CommitImage(2)]
        );
    }

    /// A file of a layer one pull holds is a file of a new layer of another
    /// pull, which waits for it: the group is fetched for the new layer.
    #[test]
    fn a_new_layer_waits_for_a_file_fetched_into_a_layer_that_is_held() {
        let mut c = Core::new(cfg());
        let out = running(&mut c, 1, &[10, 11], vec![group(1, &[10]), group(2, &[11])]);
        assert_eq!(fetches(&out), [1, 2]);
        feed(&mut c, 0, added(2));
        // (the file is fetched into 10, which is held, for 10 and 12)
        let out = feed(&mut c, 0, prepared(2, &[10, 12], vec![group(5, &[10, 12])]));
        assert_eq!(fetches(&out), [5]);
        assert!(!out.contains(&Action::CommitLayer(12)));
        assert_eq!(
            feed(&mut c, 0, ok(Work::Group(5))),
            [Action::CommitLayer(12)]
        );
    }

    #[test]
    fn a_pull_that_comes_after_the_commit_of_its_layer_asks_nothing_of_it() {
        let mut c = Core::new(cfg());
        running(&mut c, 1, &[10], vec![group(1, &[10])]);
        feed(&mut c, 0, ok(Work::Group(1)));
        feed(&mut c, 0, ok(Work::Layer(10)));
        feed(&mut c, 0, ok(Work::Pull(1)));
        // (its next try finds the layer in the store: no layer lacks)
        feed(&mut c, 0, added(2));
        assert_eq!(
            feed(&mut c, 0, prepared(2, &[], Vec::new())),
            [Action::CommitImage(2)]
        );
    }

    #[test]
    fn a_cancel_keeps_what_another_pull_waits_for() {
        let mut c = Core::new(cfg());
        let groups = vec![group(1, &[10]), group(2, &[10]), group(3, &[11])];
        running(&mut c, 1, &[10, 11], groups);
        feed(&mut c, 0, added(2));
        feed(&mut c, 0, prepared(2, &[10], Vec::new()));
        let out = feed(&mut c, 0, Event::Cancel(1));
        // (the layer 11 and its group go; 10 and its groups stay, the
        // groups in flight are the other pull's now; the other pull
        // prepares again, for what it holds was planned for the first)
        assert_eq!(
            out[..3],
            [
                Action::Forget(Work::Layer(11)),
                Action::Forget(Work::Group(3)),
                Action::Abort(Work::Pull(1)),
            ]
        );
        assert!(out.contains(&Action::Prepare(2)));
        // (what ran for it ended: it is over, the end of the stop is late)
        assert_eq!(
            feed(&mut c, 0, failed(Work::Pull(1), Class::Fatal)),
            [Action::End(1)]
        );
        assert_eq!(feed(&mut c, 0, ok(Work::Pull(1))), []);
    }

    #[test]
    fn a_cancel_stops_what_only_the_pull_waits_for() {
        let mut c = Core::new(cfg());
        running(&mut c, 1, &[10, 11], vec![group(1, &[10]), group(2, &[11])]);
        feed(&mut c, 0, ok(Work::Group(1)));
        feed(&mut c, 0, ok(Work::Layer(10)));
        let out = feed(&mut c, 0, Event::Cancel(1));
        assert!(out.contains(&Action::Abort(Work::Group(2))));
        assert!(out.contains(&Action::Abort(Work::Pull(1))));
        // (the end of what was aborted)
        assert_eq!(feed(&mut c, 0, ok(Work::Group(2))), []);
        assert_eq!(feed(&mut c, 0, ok(Work::Layer(11))), []);
    }

    /// The commit of a layer is aborted with its pull.
    #[test]
    fn a_cancel_aborts_the_commit_of_a_layer_nobody_waits_for() {
        let mut c = Core::new(cfg());
        running(&mut c, 1, &[10], vec![group(1, &[10])]);
        feed(&mut c, 0, ok(Work::Group(1)));
        let out = feed(&mut c, 0, Event::Cancel(1));
        assert!(out.contains(&Action::Abort(Work::Layer(10))));
    }

    #[test]
    fn a_failed_fetch_ends_the_try_of_every_pull_that_waits_for_it() {
        let mut c = Core::new(cfg());
        running(&mut c, 1, &[10], vec![group(1, &[10]), group(2, &[10])]);
        feed(&mut c, 0, added(2));
        feed(&mut c, 0, prepared(2, &[10], Vec::new()));
        let out = feed(&mut c, 100, failed(Work::Group(1), Class::Transient));
        assert!(out.contains(&Action::Record(1, State::Backoff(1100))));
        assert!(out.contains(&Action::Record(2, State::Backoff(1100))));
        // (what was in flight for them is stopped)
        assert!(out.contains(&Action::Abort(Work::Group(2))));
        // (the next tries start at the wake and look again)
        assert_eq!(
            feed(&mut c, 1100, Event::Tick),
            [
                Action::Record(1, State::Running),
                Action::Prepare(1),
                Action::Record(2, State::Running),
                Action::Prepare(2)
            ]
        );
    }

    #[test]
    fn a_try_that_got_something_done_starts_the_backoff_over() {
        let mut c = Core::new(cfg());
        running(&mut c, 1, &[10], vec![group(1, &[10]), group(2, &[10])]);
        feed(&mut c, 0, ok(Work::Group(1)));
        let out = feed(&mut c, 0, failed(Work::Group(2), Class::Transient));
        assert!(out.contains(&Action::Record(1, State::Backoff(1000))));
        // (the second try gets nothing done: two seconds)
        feed(&mut c, 1000, Event::Tick);
        feed(&mut c, 1000, prepared(1, &[10], vec![group(7, &[10])]));
        let out = feed(&mut c, 1000, failed(Work::Group(7), Class::Transient));
        assert!(out.contains(&Action::Record(1, State::Backoff(3000))));
    }

    #[test]
    fn a_failed_commit_ends_the_tries_that_wait_for_the_layer() {
        let mut c = Core::new(cfg());
        running(&mut c, 1, &[10], vec![group(1, &[10])]);
        feed(&mut c, 0, ok(Work::Group(1)));
        let out = feed(&mut c, 0, failed(Work::Layer(10), Class::Fatal));
        assert_eq!(
            &out[..2],
            [
                Action::Record(1, State::Failed),
                Action::Forget(Work::Layer(10))
            ]
        );
        assert!(out.contains(&Action::End(1)));
    }

    #[test]
    fn the_first_end_of_what_ran_for_a_cancelled_pull_ends_it() {
        let mut c = Core::new(cfg());
        running(&mut c, 1, &[10], vec![group(1, &[10])]);
        feed(&mut c, 0, Event::Cancel(1));
        assert_eq!(feed(&mut c, 0, failed(Work::Group(1), Class::Fatal)), []);
        assert_eq!(feed(&mut c, 0, ok(Work::Pull(1))), [Action::End(1)]);
        assert_eq!(feed(&mut c, 0, failed(Work::Pull(1), Class::Fatal)), []);
        assert_eq!(feed(&mut c, 0, ok(Work::Pull(1))), []);
        assert_eq!(phase(&c, 1), None);
    }

    #[test]
    fn the_driver_pulls_the_layers_of_a_pull_together() {
        let mut c = Core::new(Cfg {
            driver_pulls: true,
            ..cfg()
        });
        running(&mut c, 1, &[10, 11], vec![group(1, &[10]), group(2, &[11])]);
        assert_eq!(feed(&mut c, 0, ok(Work::Group(1))), []);
        assert_eq!(feed(&mut c, 0, ok(Work::Group(2))), [Action::DriverPull(1)]);
        assert_eq!(feed(&mut c, 0, ok(Work::Pull(1))), [Action::CommitImage(1)]);
    }

    /// A layer that needs no fetch is not progress for a driver that pulls
    /// it from the staging on every try: a registry that fails for another
    /// layer is asked again after longer and longer waits.
    #[test]
    fn what_the_driver_finds_ready_is_no_progress() {
        let mut c = Core::new(Cfg {
            driver_pulls: true,
            ..cfg()
        });
        feed(&mut c, 0, added(1));
        let mut now = 0;
        let mut waits = Vec::new();
        for _ in 0..3 {
            let out = feed(&mut c, now, prepared(1, &[10], Vec::new()));
            assert_eq!(out, [Action::DriverPull(1)]);
            let out = feed(&mut c, now, failed(Work::Pull(1), Class::Transient));
            let Some(Action::Wake(at)) = out.last().copied() else {
                panic!("{out:?}")
            };
            waits.push(at - now);
            now = at;
            feed(&mut c, now, Event::Tick);
        }
        assert_eq!(waits, [1000, 2000, 4000]);
    }

    #[test]
    fn a_pull_waits_for_a_place_and_takes_the_one_that_frees() {
        let mut c = Core::new(Cfg {
            completers: 1,
            ..cfg()
        });
        feed(&mut c, 0, added(1));
        assert_eq!(
            feed(&mut c, 0, added(2)),
            [Action::Record(2, State::Queued)]
        );
        assert_eq!(
            feed(&mut c, 0, added(3)),
            [Action::Record(3, State::Queued)]
        );
        feed(&mut c, 0, prepared(1, &[], Vec::new()));
        assert_eq!(
            feed(&mut c, 1, ok(Work::Pull(1))),
            [
                Action::End(1),
                Action::Record(2, State::Running),
                Action::Prepare(2)
            ]
        );
        assert_eq!(phase(&c, 3), Some(Phase::Queued));
    }

    #[test]
    fn a_pull_a_command_waits_for_or_a_container_uses_needs_no_place() {
        let mut c = Core::new(Cfg {
            completers: 0,
            ..cfg()
        });
        assert_eq!(
            feed(&mut c, 0, added(1)),
            [Action::Record(1, State::Queued)]
        );
        assert_eq!(
            feed(&mut c, 0, Event::Hurry(1)),
            [Action::Record(1, State::Running), Action::Prepare(1)]
        );
        let used = Event::Added {
            pull: 2,
            containers: true,
        };
        assert_eq!(
            feed(&mut c, 0, used),
            [Action::Record(2, State::Running), Action::Prepare(2)]
        );
    }

    #[test]
    fn a_failed_try_waits_longer_each_time_until_one_progresses() {
        let mut c = Core::new(cfg());
        feed(&mut c, 0, added(1));
        let mut now = 0;
        let mut waits = Vec::new();
        for _ in 0..5 {
            let out = feed(&mut c, now, failed(Work::Pull(1), Class::Transient));
            let Some(Action::Wake(at)) = out.last().copied() else {
                panic!("{out:?}")
            };
            waits.push(at - now);
            now = at;
            assert_eq!(phase(&c, 1), Some(Phase::Waiting(at)));
            // (a tick before the time does nothing but ask for the time)
            assert_eq!(feed(&mut c, at - 1, Event::Tick), [Action::Wake(at)]);
            assert_eq!(
                feed(&mut c, at, Event::Tick),
                [Action::Record(1, State::Running), Action::Prepare(1)]
            );
        }
        assert_eq!(waits, [1000, 2000, 4000, 8000, 8000]);
    }

    #[test]
    fn a_completion_that_does_not_retry_stops_at_its_first_failure() {
        let mut c = Core::new(Cfg {
            retries: false,
            ..cfg()
        });
        feed(&mut c, 0, added(1));
        assert_eq!(
            feed(&mut c, 0, failed(Work::Pull(1), Class::Transient)),
            [Action::Record(1, State::Failed), Action::End(1)]
        );
        feed(&mut c, 0, added(2));
        assert_eq!(
            feed(&mut c, 0, failed(Work::Pull(2), Class::Credentials)),
            [Action::Record(2, State::NeedsCredentials), Action::End(2)]
        );
    }

    #[test]
    fn a_hurry_ends_the_wait() {
        let mut c = Core::new(cfg());
        feed(&mut c, 0, added(1));
        feed(&mut c, 0, failed(Work::Pull(1), Class::Transient));
        assert_eq!(
            feed(&mut c, 10, Event::Hurry(1)),
            [Action::Record(1, State::Running), Action::Prepare(1)]
        );
        // (the wake of the wait finds a try running)
        assert_eq!(feed(&mut c, 1000, Event::Tick), []);
    }

    #[test]
    fn no_room_is_recorded_and_waited_for_without_counting() {
        let mut c = Core::new(cfg());
        feed(&mut c, 0, added(1));
        assert_eq!(
            feed(&mut c, 0, failed(Work::Pull(1), Class::NoSpace)),
            [
                Action::Record(1, State::NoSpace(60_000)),
                Action::Wake(60_000)
            ]
        );
        feed(&mut c, 60_000, Event::Tick);
        let out = feed(&mut c, 60_000, failed(Work::Pull(1), Class::Transient));
        assert_eq!(out.last(), Some(&Action::Wake(61_000)));
    }

    #[test]
    fn credentials_and_fatal_failures_end_the_pull_and_free_its_place() {
        for (class, state) in [
            (Class::Credentials, State::NeedsCredentials),
            (Class::Fatal, State::Failed),
        ] {
            let mut c = Core::new(Cfg {
                completers: 1,
                ..cfg()
            });
            feed(&mut c, 0, added(1));
            feed(&mut c, 0, added(2));
            assert_eq!(
                feed(&mut c, 3, failed(Work::Pull(1), class)),
                [
                    Action::Record(1, state),
                    Action::End(1),
                    Action::Record(2, State::Running),
                    Action::Prepare(2)
                ]
            );
        }
    }

    #[test]
    fn a_cancel_of_a_pull_that_waits_or_backs_off_ends_it_at_once() {
        let mut c = Core::new(Cfg {
            completers: 1,
            ..cfg()
        });
        feed(&mut c, 0, added(1));
        feed(&mut c, 0, added(2));
        assert_eq!(feed(&mut c, 0, Event::Cancel(2)), [Action::End(2)]);
        feed(&mut c, 0, failed(Work::Pull(1), Class::Transient));
        assert_eq!(feed(&mut c, 0, Event::Cancel(1)), [Action::End(1)]);
        // (the wake of its wait finds nothing)
        assert_eq!(feed(&mut c, 1000, Event::Tick), []);
    }

    #[test]
    fn a_cancel_gives_the_place_back_when_the_pull_is_stopped() {
        let mut c = Core::new(Cfg {
            completers: 1,
            ..cfg()
        });
        feed(&mut c, 0, added(1));
        feed(&mut c, 0, added(2));
        assert_eq!(
            feed(&mut c, 1, Event::Cancel(1)),
            [Action::Abort(Work::Pull(1))]
        );
        assert_eq!(phase(&c, 2), Some(Phase::Queued));
        assert_eq!(
            feed(&mut c, 2, ok(Work::Pull(1))),
            [
                Action::End(1),
                Action::Record(2, State::Running),
                Action::Prepare(2)
            ]
        );
    }

    #[test]
    fn two_completions_of_one_pull_are_one() {
        let mut c = Core::new(cfg());
        feed(&mut c, 0, added(1));
        assert_eq!(feed(&mut c, 0, added(1)), []);
        feed(&mut c, 0, prepared(1, &[], Vec::new()));
        // (a second preparation of the same try: what it names goes)
        assert_eq!(
            feed(&mut c, 0, prepared(1, &[10], Vec::new())),
            [Action::Forget(Work::Layer(10))]
        );
        feed(&mut c, 0, ok(Work::Pull(1)));
        assert_eq!(feed(&mut c, 0, ok(Work::Pull(1))), []);
        assert_eq!(feed(&mut c, 0, failed(Work::Pull(1), Class::Fatal)), []);
        assert_eq!(phase(&c, 1), None);
    }

    #[test]
    fn a_pull_added_again_after_it_ended_starts_over() {
        let mut c = Core::new(cfg());
        feed(&mut c, 0, added(1));
        feed(&mut c, 0, failed(Work::Pull(1), Class::Fatal));
        assert_eq!(
            feed(&mut c, 5, added(1)),
            [Action::Record(1, State::Running), Action::Prepare(1)]
        );
    }

    /// A step that ends a pull and admits another: what is recorded for each
    /// is its own.
    #[test]
    fn the_end_of_a_pull_admits_the_next_one_with_its_own_record() {
        let mut c = Core::new(Cfg {
            completers: 1,
            ..cfg()
        });
        feed(&mut c, 0, added(1));
        feed(&mut c, 0, added(2));
        let out = feed(&mut c, 0, failed(Work::Pull(1), Class::Fatal));
        assert_eq!(
            out,
            [
                Action::Record(1, State::Failed),
                Action::End(1),
                Action::Record(2, State::Running),
                Action::Prepare(2)
            ]
        );
    }

    /// The fetches of a pull wait while a container starts on a layer of its
    /// image, and for the quiet time after it, not for a start of another
    /// image.
    #[test]
    fn a_pull_yields_to_a_start_of_its_image() {
        let mut c = Core::new(cfg());
        // (another image: nothing in the way)
        assert_eq!(feed(&mut c, 0, Event::StartBegan(99)), []);
        feed(&mut c, 0, Event::StartEnded(99));
        feed(&mut c, 5_000, Event::StartBegan(10));
        let groups = vec![group(1, &[10]), group(2, &[10]), group(3, &[10])];
        let out = running(&mut c, 2, &[10], groups);
        assert_eq!(fetches(&out), []);
        // (its start ends: the quiet time follows)
        assert_eq!(
            feed(&mut c, 9_000, Event::StartEnded(10)),
            [Action::Wake(11_000)]
        );
        assert_eq!(feed(&mut c, 10_999, Event::Tick), [Action::Wake(11_000)]);
        assert_eq!(fetches(&feed(&mut c, 11_000, Event::Tick)), [1, 2]);
    }

    #[test]
    fn a_second_start_of_the_layer_keeps_the_pull_waiting() {
        let mut c = Core::new(cfg());
        feed(&mut c, 0, Event::StartBegan(10));
        feed(&mut c, 0, Event::StartBegan(10));
        running(&mut c, 1, &[10], vec![group(1, &[10])]);
        feed(&mut c, 100, Event::StartEnded(10));
        assert_eq!(feed(&mut c, 20_000, Event::Tick), []);
        assert_eq!(
            feed(&mut c, 20_000, Event::StartEnded(10)),
            [Action::Wake(22_000)]
        );
        assert_eq!(fetches(&feed(&mut c, 22_000, Event::Tick)), [1]);
    }
}
