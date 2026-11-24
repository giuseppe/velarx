// SPDX-License-Identifier: Apache-2.0
//! The state machine against a scripted world: every action it asks for is
//! answered, late, in any order, by an event a seeded generator picks (a
//! success, a failure of each class, a cancel, a start of a container, a
//! service that dies and is replaced), and the rules of the machine are
//! checked after every step.  A failure says the seed that replays it.

use std::collections::{BTreeMap, BTreeSet};
use velarx_lazy_core::{
    step, Action, Cfg, Class, Core, Event, GroupFact, GroupId, LayerId, PullId, State, Tick, Work,
};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// What the world has been asked, and has not answered yet.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Task {
    Prepare(PullId),
    Fetch(GroupId),
    Commit(LayerId),
    Stage(PullId),
    Image(PullId),
    /// What ran for a cancelled pull is being stopped
    Stop(PullId),
    Wake(Tick),
}

struct World {
    rng: Rng,
    cfg: Cfg,
    core: Core,
    now: Tick,
    /// What runs, and what was aborted but may still answer
    tasks: Vec<Task>,
    late: Vec<Task>,
    next_group: GroupId,
    next_pull: PullId,
    /// The layers each try was told it lacks
    lacks: BTreeMap<PullId, Vec<LayerId>>,
    // what the rules are checked against
    /// The layers in the store: the world's, not the machine's
    stored: BTreeSet<LayerId>,
    committing: BTreeSet<LayerId>,
    /// The groups a layer waits for, as the facts that made it said
    named: BTreeMap<LayerId, Vec<GroupId>>,
    fetched: BTreeSet<GroupId>,
    asked: BTreeSet<GroupId>,
    cancelled: BTreeSet<PullId>,
    ended: BTreeSet<PullId>,
    /// The pulls the machine holds
    held: BTreeSet<PullId>,
    /// The tries of each pull that failed since one got something done,
    /// and whether this one did
    tries: BTreeMap<PullId, (u32, bool)>,
    /// The fetches of starts in flight, by layer
    starting: BTreeMap<LayerId, u32>,
    /// The number each pull of the world has now: a pull that ended and
    /// is added again is another to the machine
    ids: Vec<PullId>,
    /// What was told and asked, for a failure to say
    log: Vec<String>,
    /// Whether failures and cancels are told
    calm: bool,
}

const PULLS: u32 = 4;
const LAYERS: u32 = 5;

impl World {
    fn new(seed: u64, driver_pulls: bool) -> Self {
        let cfg = Cfg {
            completers: 2,
            retries: true,
            retry_max: 4,
            fetches: 2,
            boosted_fetches: 3,
            driver_pulls,
            quiet: 1000,
        };
        Self {
            rng: Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1),
            cfg,
            core: Core::new(cfg),
            now: 0,
            tasks: Vec::new(),
            late: Vec::new(),
            next_group: 0,
            next_pull: PULLS,
            lacks: BTreeMap::new(),
            stored: BTreeSet::new(),
            committing: BTreeSet::new(),
            named: BTreeMap::new(),
            fetched: BTreeSet::new(),
            asked: BTreeSet::new(),
            cancelled: BTreeSet::new(),
            ended: BTreeSet::new(),
            held: BTreeSet::new(),
            tries: BTreeMap::new(),
            starting: BTreeMap::new(),
            ids: (0..PULLS).collect(),
            log: Vec::new(),
            calm: false,
        }
    }

    /// Tell the machine, check what it says, and keep the tasks it asks for.
    fn tell(&mut self, event: Event, seed: u64) {
        let mut out = Vec::new();
        step(&mut self.core, self.now, event.clone(), &mut out);
        self.log.push(format!("{} {event:?} -> {out:?}", self.now));
        // (what a layer the machine took waits for)
        if let Event::Prepared {
            pull,
            layers,
            groups,
        } = &event
        {
            if self.core.layers_of(*pull).0 as usize == layers.len() {
                for l in layers {
                    let named: Vec<GroupId> = groups
                        .iter()
                        .filter(|g| g.needed_by.contains(l))
                        .map(|g| g.id)
                        .collect();
                    self.named.entry(*l).or_insert(named);
                }
            }
        }
        for action in out {
            self.check(&action, &event, seed);
            match action {
                Action::Prepare(p) => self.tasks.push(Task::Prepare(p)),
                Action::Fetch(g) => self.tasks.push(Task::Fetch(g)),
                Action::CommitLayer(l) => self.tasks.push(Task::Commit(l)),
                Action::DriverPull(p) => self.tasks.push(Task::Stage(p)),
                Action::CommitImage(p) => self.tasks.push(Task::Image(p)),
                Action::Wake(at) => self.tasks.push(Task::Wake(at)),
                Action::Abort(Work::Pull(p)) => {
                    self.cancelled.insert(p);
                    self.forget_tasks(|t| matches!(t, Task::Prepare(q) | Task::Stage(q) | Task::Image(q) if *q == p));
                    self.tasks.push(Task::Stop(p));
                }
                Action::Abort(Work::Group(g)) => {
                    self.forget_tasks(|t| *t == Task::Fetch(g));
                }
                Action::Abort(Work::Layer(l)) => {
                    self.committing.remove(&l);
                    self.forget_tasks(|t| *t == Task::Commit(l));
                }
                Action::Forget(Work::Layer(l)) => {
                    self.committing.remove(&l);
                    self.named.remove(&l);
                }
                Action::Forget(Work::Group(g)) => {
                    self.fetched.remove(&g);
                    self.asked.remove(&g);
                }
                Action::End(p) => {
                    assert!(self.ended.insert(p), "seed {seed}: pull {p} ended twice");
                    self.cancelled.remove(&p);
                    self.lacks.remove(&p);
                    self.held.remove(&p);
                }
                Action::Record(..) | Action::Forget(_) => {}
            }
        }
    }

    /// What an aborted task may still answer is kept as a late one.
    fn forget_tasks(&mut self, aborted: impl Fn(&Task) -> bool) {
        let (gone, kept): (Vec<_>, Vec<_>) = self.tasks.drain(..).partition(|t| aborted(t));
        self.tasks = kept;
        self.late.extend(gone);
    }

    fn check(&mut self, action: &Action, event: &Event, seed: u64) {
        if std::env::var_os("SIM_LOG").is_some() {
            eprintln!("{}", self.log.last().cloned().unwrap_or_default());
        }
        match action {
            Action::Fetch(g) => {
                assert!(self.asked.insert(*g), "seed {seed}: group {g} asked twice");
                assert!(
                    !self.fetched.contains(g),
                    "seed {seed}: group {g} fetched again"
                );
            }
            Action::CommitLayer(l) => {
                assert!(
                    self.committing.insert(*l),
                    "seed {seed}: layer {l} committed twice at once"
                );
                for g in self.named.get(l).into_iter().flatten() {
                    assert!(
                        self.fetched.contains(g),
                        "seed {seed}: layer {l} committed before group {g} ({event:?})"
                    );
                }
            }
            Action::Record(p, state) => {
                assert!(
                    !self.cancelled.contains(p),
                    "seed {seed}: the state of the cancelled pull {p} is written ({event:?})"
                );
                // (the try is over, or a new one begins)
                self.lacks.remove(p);
                // (a try that failed after it got something done starts
                // the count over; one that is planned again counts on)
                let (failed, progressed) = self.tries.entry(*p).or_default();
                if *progressed && matches!(state, State::Backoff(_) | State::NoSpace(_)) {
                    *failed = 0;
                }
                *progressed = false;
                if let State::Backoff(until) = state {
                    let wait = (1 << *failed).min(self.cfg.retry_max) * 1000;
                    assert_eq!(
                        *until,
                        self.now + wait,
                        "seed {seed}: the wait of pull {p} after {failed} failures ({event:?})"
                    );
                    *failed += 1;
                }
            }
            Action::Prepare(p) | Action::DriverPull(p) | Action::CommitImage(p) => {
                let runs = |t: &&Task| matches!(t, Task::Prepare(q) | Task::Stage(q) | Task::Image(q) if q == p);
                let running = self.tasks.iter().find(runs);
                assert_eq!(running, None, "seed {seed}: {action:?} while it runs");
            }
            _ => {}
        }
        if let Action::CommitImage(p) = action {
            let lacked = self.lacks.get(p).cloned().unwrap_or_default();
            for l in lacked {
                assert!(
                    self.stored.contains(&l),
                    "seed {seed}: the image of pull {p} committed, layer {l} is not in the store ({event:?})"
                );
            }
        }
    }

    /// The tries that lack one of the layers got something done.
    fn progressed(&mut self, layers: impl Fn(&LayerId) -> bool) {
        for (pull, lacked) in &self.lacks {
            if lacked.iter().any(&layers) {
                self.tries.entry(*pull).or_default().1 = true;
            }
        }
    }

    /// Facts the world makes up for a pull that asks what it lacks.
    fn prepared(&mut self, pull: PullId) -> Event {
        let mut layers = Vec::new();
        for l in 0..LAYERS {
            // (what the store has is not lacked)
            if self.rng.chance(40) && !self.stored.contains(&(100 + l)) {
                layers.push(100 + l);
            }
        }
        let mut groups = Vec::new();
        for &layer in &layers {
            for _ in 0..self.rng.below(3) {
                let mut needed_by = vec![layer];
                // (a content that a later layer has too is fetched once)
                if let Some(&other) = layers.iter().find(|&&o| o > layer) {
                    if self.rng.chance(30) {
                        needed_by.push(other);
                    }
                }
                groups.push(GroupFact {
                    id: self.next_group,
                    needed_by,
                });
                self.next_group += 1;
            }
        }
        self.lacks.insert(pull, layers.clone());
        Event::Prepared {
            pull,
            layers,
            groups,
        }
    }

    fn class(&mut self) -> Class {
        match self.rng.below(4) {
            0 => Class::NoSpace,
            1 => Class::Credentials,
            2 => Class::Fatal,
            _ => Class::Transient,
        }
    }

    /// The world answers one of its tasks.
    fn answer(&mut self, task: Task, seed: u64) {
        let fails = !self.calm && self.rng.chance(15);
        let class = self.class();
        let class = if self.calm { Class::Transient } else { class };
        match task {
            Task::Prepare(p) => {
                if fails {
                    self.tell(Event::Done(Work::Pull(p), Err(class)), seed);
                } else {
                    let prepared = self.prepared(p);
                    self.tell(prepared, seed);
                }
            }
            Task::Fetch(g) => {
                let asked = self.asked.remove(&g);
                if fails {
                    self.tell(Event::Done(Work::Group(g), Err(class)), seed);
                } else {
                    self.fetched.insert(g);
                    if asked {
                        let named = self.named.clone();
                        self.progressed(|l| named.get(l).is_some_and(|n| n.contains(&g)));
                    }
                    self.tell(Event::Done(Work::Group(g), Ok(())), seed);
                }
            }
            Task::Commit(l) => {
                let committing = self.committing.remove(&l);
                if fails {
                    self.tell(Event::Done(Work::Layer(l), Err(class)), seed);
                } else {
                    self.stored.insert(l);
                    if committing {
                        self.progressed(|lacked| *lacked == l);
                    }
                    self.tell(Event::Done(Work::Layer(l), Ok(())), seed);
                }
            }
            Task::Stage(p) => {
                if fails {
                    self.tell(Event::Done(Work::Pull(p), Err(class)), seed);
                } else {
                    let layers = self.lacks.get(&p).cloned().unwrap_or_default();
                    self.stored.extend(layers);
                    self.tries.entry(p).or_default().1 = true;
                    self.tell(Event::Done(Work::Pull(p), Ok(())), seed);
                }
            }
            Task::Image(p) => {
                if fails {
                    self.tell(Event::Done(Work::Pull(p), Err(class)), seed);
                } else {
                    self.tell(Event::Done(Work::Pull(p), Ok(())), seed);
                }
            }
            Task::Stop(p) => self.tell(Event::Done(Work::Pull(p), Ok(())), seed),
            Task::Wake(at) => {
                self.now = self.now.max(at);
                self.tell(Event::Tick, seed)
            }
        }
    }

    /// The pull of the world `slot`, added: it has a number of its own when
    /// the machine does not hold it.
    fn add(&mut self, slot: usize, containers: bool, seed: u64) {
        if !self.held.contains(&self.ids[slot]) {
            self.next_pull += 1;
            self.ids[slot] = self.next_pull;
        }
        let pull = self.ids[slot];
        self.ended.remove(&pull);
        self.held.insert(pull);
        self.tell(Event::Added { pull, containers }, seed);
    }

    fn step(&mut self, seed: u64) {
        self.now += self.rng.below(700);
        let slot = self.rng.below(PULLS as u64) as usize;
        let pull = self.ids[slot];
        match self.rng.below(20) {
            0 => {
                let containers = self.rng.chance(20);
                self.add(slot, containers, seed);
            }
            1 => self.tell(Event::Hurry(pull), seed),
            2 if !self.calm => self.tell(Event::Cancel(pull), seed),
            3 if !self.calm => {
                let layer = 100 + self.rng.below(LAYERS as u64) as LayerId;
                // (a start ends what it began)
                let ended = self.rng.chance(50) && self.starting.contains_key(&layer);
                if ended {
                    let n = self.starting.entry(layer).or_default();
                    *n -= 1;
                    if *n == 0 {
                        self.starting.remove(&layer);
                    }
                    self.tell(Event::StartEnded(layer), seed);
                } else {
                    *self.starting.entry(layer).or_default() += 1;
                    self.tell(Event::StartBegan(layer), seed);
                }
            }
            4 => self.tell(Event::Tick, seed),
            // (what a task of a dead service says: what the machine does
            // not hold is none of its business)
            5 if !self.late.is_empty() => {
                let at = self.rng.below(self.late.len() as u64) as usize;
                let task = self.late.remove(at);
                self.answer(task, seed);
            }
            _ if !self.tasks.is_empty() => {
                let at = self.rng.below(self.tasks.len() as u64) as usize;
                let task = self.tasks.remove(at);
                self.answer(task, seed);
            }
            _ => {}
        }
    }

    /// The service dies: the machine is made again, what ran is lost (and
    /// may answer to nobody), the pulls the new one finds are added.
    fn die(&mut self) {
        let lost = std::mem::take(&mut self.tasks);
        self.late.extend(lost);
        self.core = Core::new(self.cfg);
        self.committing.clear();
        self.named.clear();
        self.fetched.clear();
        self.asked.clear();
        self.cancelled.clear();
        self.lacks.clear();
        // (nothing the dead one had in flight is held, and the starts of
        // its containers are over with it)
        self.late.clear();
        self.ended.clear();
        self.held.clear();
        self.tries.clear();
        self.starting.clear();
    }
}

fn run(seed: u64, driver_pulls: bool) {
    let mut w = World::new(seed, driver_pulls);
    for _ in 0..300 {
        if w.rng.chance(1) {
            w.die();
        }
        w.step(seed);
    }
    // the world is kind from now on: every pull that was not cancelled or
    // stopped is added again by a command that asks, and ends
    w.calm = true;
    w.late.clear();
    for (layer, n) in std::mem::take(&mut w.starting) {
        for _ in 0..n {
            w.tell(Event::StartEnded(layer), seed);
        }
    }
    for slot in 0..PULLS as usize {
        w.add(slot, false, seed);
    }
    for slot in 0..PULLS as usize {
        let pull = w.ids[slot];
        w.tell(Event::Hurry(pull), seed);
    }
    for _ in 0..5_000 {
        if w.tasks.is_empty() {
            w.now += 5_000;
            w.tell(Event::Tick, seed);
            if w.tasks.is_empty() {
                break;
            }
        }
        let at = w.rng.below(w.tasks.len() as u64) as usize;
        let task = w.tasks.remove(at);
        w.answer(task, seed);
    }
    for slot in 0..PULLS as usize {
        let pull = w.ids[slot];
        assert!(
            !w.held.contains(&pull),
            "seed {seed}: the pull {pull} is not over, tasks: {:?}, {:?}",
            w.tasks,
            w.core
        );
    }
}

#[test]
fn the_rules_hold_whatever_the_world_answers() {
    for seed in 1..=3_000 {
        run(seed, false);
    }
}

#[test]
fn the_rules_hold_when_the_driver_pulls_the_layers() {
    for seed in 1..=3_000 {
        run(seed, true);
    }
}
