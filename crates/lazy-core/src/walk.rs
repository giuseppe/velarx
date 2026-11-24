// SPDX-License-Identifier: Apache-2.0
//! The states the machine reaches with two pulls, two layers and three
//! groups, whatever the caller answers and in whatever order, and the
//! rules of the machine checked at every step of the way: every state a
//! few events reach in the test that always runs, all of them, or as many
//! as there is time for, in the one that is asked for.
//!
//! The caller here keeps its part, which the machine relies on:
//! - the number of a pull is not given again while something that ran
//!   for it may still answer, and the number of a group never;
//! - a `Prepared` names each layer once;
//! - every action that starts a work is answered once; the fetch of a
//!   group or the commit of a layer that was aborted does not answer,
//!   what ran for a pull that was aborted may, once, or never;
//! - the time does not go back, and a `Tick` comes for the earliest `Wake`.

use super::*;
use std::collections::{BTreeMap, BTreeSet, HashSet};

const PULLS: [PullId; 2] = [0, 1];
const LAYERS: [LayerId; 2] = [10, 11];
const GROUPS: [GroupId; 3] = [0, 1, 2];
const ANSWERS: [Result<(), Class>; 5] = [
    Ok(()),
    Err(Class::Transient),
    Err(Class::Fatal),
    Err(Class::NoSpace),
    Err(Class::Credentials),
];
/// What a try may be told it lacks: the layers, and for each group the
/// layers that wait for it.
const PLANS: [(&[LayerId], &[&[LayerId]]); 6] = [
    (&[], &[]),
    (&[10], &[]),
    (&[10], &[&[10]]),
    (&[11], &[&[11]]),
    (&[10, 11], &[&[10, 11]]),
    (&[10, 11], &[&[10], &[11]]),
];

/// What the caller has been asked, and has not answered yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Task {
    Prepare(PullId),
    Fetch(GroupId),
    Commit(LayerId),
    Stage(PullId),
    Image(PullId),
    /// What ran for a cancelled pull is being stopped
    Stop(PullId),
}

impl Task {
    fn of_pull(self, pull: PullId) -> bool {
        use Task::*;
        matches!(self, Prepare(p) | Stage(p) | Image(p) | Stop(p) if p == pull)
    }
}

#[derive(Debug, Clone)]
struct World {
    core: Core,
    now: Tick,
    /// What runs
    tasks: BTreeSet<Task>,
    /// What was aborted and may still answer
    late: BTreeSet<Task>,
    /// The earliest time a `Tick` was asked for
    wake: Option<Tick>,
    /// The layers each try was told it lacks
    lacks: BTreeMap<PullId, Vec<LayerId>>,
    /// The groups a layer waits for, as the facts that made it said
    named: BTreeMap<LayerId, Vec<GroupId>>,
    fetched: BTreeSet<GroupId>,
    /// The layers in the store: the caller's, not the machine's
    stored: BTreeSet<LayerId>,
    /// The fetches of a start in flight in the first layer, and when the
    /// quiet after the last ends
    starting: u32,
    quiet_until: Tick,
    /// What was told and asked, for a failure to say
    log: Vec<String>,
}

fn phase(c: &Core, pull: PullId) -> Option<Phase> {
    c.pulls.iter().find(|p| p.id == pull).map(|p| p.phase)
}

fn sorted(mut ids: Vec<u32>) -> Vec<u32> {
    ids.sort();
    ids
}

/// Whether the action says something of the pull.
fn about(action: &Action, pull: PullId) -> bool {
    use Action::*;
    match *action {
        Record(p, _) | Prepare(p) | DriverPull(p) | CommitImage(p) | End(p) => p == pull,
        Abort(work) => work == Work::Pull(pull),
        _ => false,
    }
}

/// The tables name each thing once, a layer a pull lacks is in the table,
/// a layer of the table is lacked, and a pull that is not past its
/// preparation in a try (it is queued, preparing, waiting or being stopped)
/// lacks nothing.
fn well_formed(c: &Core) -> bool {
    let distinct = |ids: Vec<u32>| ids.iter().collect::<BTreeSet<_>>().len() == ids.len();
    let lacked = |l: &Layer| c.pulls.iter().any(|p| p.lacks(l.id));
    distinct(c.pulls.iter().map(|p| p.id).collect())
        && distinct(c.layers.iter().map(|l| l.id).collect())
        && distinct(c.groups.iter().map(|g| g.id).collect())
        && c.pulls.iter().all(|p| distinct(p.layers.clone()))
        && c.pulls
            .iter()
            .all(|p| p.layers.iter().all(|l| c.layer_at(*l).is_some()))
        && c.layers.iter().all(lacked)
        && c.pulls.iter().all(|p| {
            p.layers.is_empty()
                || matches!(
                    p.phase,
                    Phase::Running(Step::Working | Step::DriverPull | Step::Image)
                )
        })
}

impl World {
    fn new(cfg: Cfg) -> Self {
        Self {
            core: Core::new(cfg),
            now: 0,
            tasks: BTreeSet::new(),
            late: BTreeSet::new(),
            wake: None,
            lacks: BTreeMap::new(),
            named: BTreeMap::new(),
            fetched: BTreeSet::new(),
            stored: BTreeSet::new(),
            starting: 0,
            quiet_until: 0,
            log: Vec::new(),
        }
    }

    /// What tells this state from another: the times count from now (a
    /// time that came is as good as any other that did), and the failures
    /// up to one (`retry_max` is 2: every wait but the first is the same).
    fn key(&self) -> String {
        let mut w = self.clone();
        let from_now = |t: &mut Tick| *t = t.saturating_sub(self.now);
        for p in &mut w.core.pulls {
            if let Phase::Waiting(t) = &mut p.phase {
                from_now(t);
            }
            p.failures = p.failures.min(1);
        }
        for s in &mut w.core.starts {
            s.last += w.core.cfg.quiet;
            from_now(&mut s.last);
        }
        w.wake.iter_mut().for_each(from_now);
        from_now(&mut w.quiet_until);
        w.now = 0;
        w.log.clear();
        format!("{w:?}")
    }

    /// Tell the machine, check the rules of the step and keep what it asks.
    fn tell(&mut self, event: Event) {
        let before = self.core.clone();
        let now = self.now;
        let mut out = Vec::new();
        step(&mut self.core, now, event.clone(), &mut out);
        self.log.push(format!("{now} {event:?} -> {out:?}"));
        let after = self.core.clone();
        let (c, c1) = (&before, &after);
        let log = self.log.join("\n");
        let asked = |a: Action| out.contains(&a);
        let held = |c: &Core, p: PullId| phase(c, p).is_some();
        let forgot = |pick: fn(Work) -> Option<u32>| {
            out.iter().filter_map(move |a| match a {
                Action::Forget(work) => pick(*work),
                _ => None,
            })
        };

        assert!(well_formed(c1), "the tables: {c1:?}\n{log}");
        assert!(
            !c1.pulls.is_empty() || c1.groups.is_empty(),
            "groups are held for no pull\n{log}"
        );

        // what the caller is told of is held, or forgotten once
        let (mut layers, mut groups) = (Vec::new(), Vec::new());
        if let Event::Prepared {
            pull,
            layers: l,
            groups: g,
        } = &event
        {
            layers = l.clone();
            layers.retain(|l| c.layer_at(*l).is_none());
            groups = g.iter().map(|g| g.id).collect();
            // (what a layer the machine takes waits for)
            if phase(c, *pull) == Some(Phase::Running(Step::Preparing)) {
                self.lacks.insert(*pull, l.clone());
                for l in &layers {
                    let named = g.iter().filter(|g| g.needed_by.contains(l));
                    self.named.insert(*l, named.map(|g| g.id).collect());
                }
            }
        }
        let was = c.layers.iter().map(|l| l.id).chain(layers);
        let is = c1.layers.iter().map(|l| l.id).chain(forgot(|w| match w {
            Work::Layer(l) => Some(l),
            _ => None,
        }));
        assert_eq!(sorted(was.collect()), sorted(is.collect()), "{log}");
        let was = c.groups.iter().map(|g| g.id).chain(groups);
        let is = c1.groups.iter().map(|g| g.id).chain(forgot(|w| match w {
            Work::Group(g) => Some(g),
            _ => None,
        }));
        assert_eq!(sorted(was.collect()), sorted(is.collect()), "{log}");
        for p in PULLS {
            assert_eq!(
                held(c, p) && !held(c1, p),
                asked(Action::End(p)),
                "the end of the pull {p}\n{log}"
            );
        }

        // a stopping pull only ends
        for p in c.pulls.iter().filter(|p| p.phase == Phase::Cancelling) {
            let end = Action::End(p.id);
            for a in out.iter().filter(|a| about(a, p.id)) {
                assert_eq!(*a, end, "asked for the stopping pull {}\n{log}", p.id);
            }
            let ended = !held(c1, p.id) && asked(end);
            assert!(
                ended || phase(c1, p.id) == Some(Phase::Cancelling),
                "the stopping pull {} goes on\n{log}",
                p.id
            );
            if matches!(event, Event::Done(Work::Pull(q), _) if q == p.id) {
                assert!(ended, "the end of its stop does not end {}\n{log}", p.id);
            }
        }

        match event {
            // the verdict of a failure
            Event::Done(Work::Pull(p), Err(class))
                if matches!(phase(c, p), Some(Phase::Running(_))) =>
            {
                let over = |state| asked(Action::Record(p, state)) && ended_now(c1, &out, p);
                let max = now + c.cfg.retry_max * 1000;
                let verdict = match (class, c.cfg.retries, phase(c1, p)) {
                    (Class::Credentials, _, _) => over(State::NeedsCredentials),
                    (Class::Fatal, _, _) | (_, false, _) => over(State::Failed),
                    (Class::NoSpace, true, next) => next == Some(Phase::Waiting(now + 60_000)),
                    (Class::Transient, true, Some(Phase::Waiting(t))) => {
                        now + 1000 <= t && t <= max
                    }
                    _ => false,
                };
                assert!(verdict, "the verdict of {class:?} for {p}\n{log}");
            }
            // a cancel makes the pulls that share a layer plan again
            Event::Cancel(p) if matches!(phase(c, p), Some(Phase::Running(_))) => {
                let mine = &c.pulls[c.pull_at(p).unwrap()].layers;
                for q in c.pulls.iter().filter(|q| q.id != p && q.working()) {
                    if q.layers.iter().any(|l| mine.contains(l)) {
                        assert!(
                            phase(c1, q.id) == Some(Phase::Running(Step::Preparing))
                                && asked(Action::Prepare(q.id)),
                            "{} goes on with what the cancelled {p} planned\n{log}",
                            q.id
                        );
                    }
                }
            }
            _ => {}
        }

        // the places: no more than there are, and none free while a pull
        // waits for one
        let places = c1.cfg.completers;
        let queued = c1.pulls.iter().any(|p| p.phase == Phase::Queued);
        assert!(slots_held(c1) <= places, "too many places\n{log}");
        assert!(
            !queued || slots_held(c1) == places,
            "a pull waits for a free place\n{log}"
        );

        for action in &out {
            match *action {
                // one work at a time for a pull
                Action::Prepare(p) | Action::DriverPull(p) | Action::CommitImage(p) => {
                    assert!(
                        !self.tasks.iter().any(|t| t.of_pull(p)),
                        "{action:?} while {:?} run\n{log}",
                        self.tasks
                    );
                }
                // a group is fetched once, within the window of a pull
                // that does not yield to a start
                Action::Fetch(g) => {
                    assert!(
                        !self.tasks.contains(&Task::Fetch(g)) && !self.fetched.contains(&g),
                        "the group {g} is fetched twice\n{log}"
                    );
                    let group = &c1.groups[c1.group_at(g).unwrap()];
                    let GroupState::Sent(p) = group.state else {
                        panic!("the group {g} is not in flight\n{log}");
                    };
                    let pull = &c1.pulls[c1.pull_at(p).unwrap()];
                    let cfg = c1.cfg;
                    let window = if pull.boosted {
                        cfg.boosted_fetches
                    } else {
                        cfg.fetches
                    };
                    assert!(in_flight(c1, p) <= window, "the window of {p}\n{log}");
                    let start = self.starting > 0 || now < self.quiet_until;
                    assert!(
                        !(start && pull.lacks(LAYERS[0])),
                        "{p} fetches while a container starts\n{log}"
                    );
                }
                // a layer is committed once, after the groups named for it
                Action::CommitLayer(l) => {
                    assert!(
                        !self.tasks.contains(&Task::Commit(l)),
                        "the layer {l} is committed twice at once\n{log}"
                    );
                    for g in &self.named[&l] {
                        assert!(
                            self.fetched.contains(g),
                            "the layer {l} is committed before the group {g}\n{log}"
                        );
                    }
                }
                _ => {}
            }
            // an image is committed after its layers
            if let Action::CommitImage(p) = *action {
                for l in &self.lacks[&p] {
                    assert!(
                        self.stored.contains(l),
                        "the image of {p} is committed before the layer {l}\n{log}"
                    );
                }
            }
            self.perform(*action);
        }
    }

    /// The caller does what the machine asks.
    fn perform(&mut self, action: Action) {
        match action {
            Action::Prepare(p) => drop(self.tasks.insert(Task::Prepare(p))),
            Action::Fetch(g) => drop(self.tasks.insert(Task::Fetch(g))),
            Action::CommitLayer(l) => drop(self.tasks.insert(Task::Commit(l))),
            Action::DriverPull(p) => drop(self.tasks.insert(Task::Stage(p))),
            Action::CommitImage(p) => drop(self.tasks.insert(Task::Image(p))),
            Action::Abort(Work::Pull(p)) => {
                self.abort(|t| t.of_pull(p));
                self.tasks.insert(Task::Stop(p));
            }
            Action::Abort(Work::Group(g)) => drop(self.tasks.remove(&Task::Fetch(g))),
            Action::Abort(Work::Layer(l)) => drop(self.tasks.remove(&Task::Commit(l))),
            Action::Forget(Work::Layer(l)) => drop(self.named.remove(&l)),
            Action::Forget(Work::Group(g)) => drop(self.fetched.remove(&g)),
            Action::End(p) => drop(self.lacks.remove(&p)),
            Action::Wake(t) => self.wake = Some(self.wake.map_or(t, |w| w.min(t))),
            Action::Record(..) | Action::Forget(Work::Pull(_)) => {}
        }
    }

    fn abort(&mut self, aborted: impl Fn(Task) -> bool) {
        let gone: Vec<Task> = self.tasks.iter().copied().filter(|t| aborted(*t)).collect();
        for task in gone {
            self.tasks.remove(&task);
            self.late.insert(task);
        }
    }

    /// The facts of the plan, the groups under numbers nothing uses (as
    /// good as new ones).
    fn plan(&self, pull: PullId, plan: usize) -> Option<Event> {
        let (layers, waiting) = PLANS[plan];
        // (what the store has is not lacked)
        if layers.iter().any(|l| self.stored.contains(l)) {
            return None;
        }
        let used =
            |g: &GroupId| self.tasks.contains(&Task::Fetch(*g)) || self.core.group_at(*g).is_some();
        let mut free = GROUPS.into_iter().filter(|g| !used(g));
        let mut groups = Vec::new();
        for needed_by in waiting {
            groups.push(GroupFact {
                id: free.next()?,
                needed_by: needed_by.to_vec(),
            });
        }
        Some(Event::Prepared {
            pull,
            layers: layers.to_vec(),
            groups,
        })
    }

    /// The work the task was ended with `result`.
    fn answer(&mut self, task: Task, result: Result<(), Class>) {
        let work = match task {
            Task::Prepare(p) | Task::Stage(p) | Task::Image(p) | Task::Stop(p) => Work::Pull(p),
            Task::Fetch(g) => Work::Group(g),
            Task::Commit(l) => Work::Layer(l),
        };
        if result.is_ok() {
            match task {
                Task::Fetch(g) => drop(self.fetched.insert(g)),
                Task::Commit(l) => drop(self.stored.insert(l)),
                Task::Stage(p) => self.stored.extend(self.lacks.get(&p).into_iter().flatten()),
                _ => {}
            }
        }
        self.tell(Event::Done(work, result));
    }

    /// Every state one more event leads to.
    fn next(&self) -> Vec<World> {
        let mut next = Vec::new();
        let mut then = |f: &dyn Fn(&mut World)| {
            let mut w = self.clone();
            f(&mut w);
            next.push(w);
        };
        for pull in PULLS {
            if phase(&self.core, pull).is_some() {
                then(&|w| w.tell(Event::Hurry(pull)));
                then(&|w| w.tell(Event::Cancel(pull)));
            } else if !self.tasks.iter().chain(&self.late).any(|t| t.of_pull(pull)) {
                for containers in [false, true] {
                    then(&|w| w.tell(Event::Added { pull, containers }));
                }
            }
        }
        for (tasks, running) in [(&self.tasks, true), (&self.late, false)] {
            for &task in tasks {
                let take = |w: &mut World| {
                    let from = if running { &mut w.tasks } else { &mut w.late };
                    from.remove(&task);
                };
                if !running {
                    // (it never answers)
                    then(&take);
                }
                // (what waits for a group or a layer fails as its pull
                // would: two classes tell the ways apart)
                let results: &[Result<(), Class>] = match task {
                    Task::Stop(_) => &[Ok(())],
                    Task::Prepare(_) | Task::Stage(_) | Task::Image(_) if running => &ANSWERS,
                    _ => &ANSWERS[..3],
                };
                for &result in results {
                    if let (Task::Prepare(p), Ok(())) = (task, result) {
                        for plan in 0..PLANS.len() {
                            if let Some(prepared) = self.plan(p, plan) {
                                then(&|w| {
                                    take(w);
                                    w.tell(prepared.clone());
                                });
                            }
                        }
                    } else {
                        then(&|w| {
                            take(w);
                            w.answer(task, result);
                        });
                    }
                }
            }
        }
        if self.starting == 0 {
            then(&|w| {
                w.starting = 1;
                w.tell(Event::StartBegan(LAYERS[0]));
            });
        } else {
            then(&|w| w.end_start());
        }
        // the time of the wake comes, and its tick, or a tick nobody
        // waits for any more
        if self.wake.is_some_and(|t| t > self.now) {
            then(&|w| w.now = w.wake.unwrap());
        }
        then(&|w| w.tick());
        next
    }

    fn end_start(&mut self) {
        self.starting = 0;
        self.quiet_until = self.now + self.core.cfg.quiet;
        self.tell(Event::StartEnded(LAYERS[0]));
    }

    fn tick(&mut self) {
        if self.wake.is_some_and(|t| t <= self.now) {
            self.wake = None;
        }
        self.tell(Event::Tick);
    }

    /// What nobody waits for is none: an answer for a work that does not
    /// run, a word about a pull that is not held, a pull added twice.  The
    /// machine goes on as it would have.  And what the caller is never to
    /// tell does not stop it.
    fn idle(&self) {
        let told = |event: &Event| {
            let (mut c, mut out) = (self.core.clone(), Vec::new());
            step(&mut c, self.now, event.clone(), &mut out);
            format!("{c:?} {out:?}")
        };
        let c = &self.core;
        let (mut none, mut idle) = (Vec::new(), Vec::new());
        for pull in PULLS {
            if phase(c, pull).is_none() {
                none.extend([Event::Hurry(pull), Event::Cancel(pull)]);
                idle.push(Work::Pull(pull));
            } else {
                let containers = true;
                none.push(Event::Added { pull, containers });
            }
        }
        for l in LAYERS {
            let committing = |x: &Layer| x.id == l && x.state == LayerState::Committing;
            if !c.layers.iter().any(committing) {
                idle.push(Work::Layer(l));
            }
        }
        for g in GROUPS {
            let sent = |x: &Group| x.id == g && matches!(x.state, GroupState::Sent(_));
            if !c.groups.iter().any(sent) {
                idle.push(Work::Group(g));
            }
        }
        for work in idle {
            none.extend([Ok(()), Err(Class::Fatal)].map(|r| Event::Done(work, r)));
        }
        // (none: nothing at all, or what could go on anyway)
        let nothing = [format!("{c:?} []"), told(&Event::Cancel(PullId::MAX))];
        for event in none {
            let log = self.log.join("\n");
            assert!(nothing.contains(&told(&event)), "{event:?} is taken\n{log}");
        }
        for pull in PULLS {
            let twice = GroupFact {
                id: GROUPS[0],
                needed_by: LAYERS.to_vec(),
            };
            told(&Event::Prepared {
                pull,
                layers: vec![LAYERS[0], LAYERS[0]],
                groups: vec![twice.clone(), twice],
            });
        }
    }

    /// No pull is held with nothing owed to it: when everything asked is
    /// answered well and the time comes, every pull ends.
    fn ends(mut self) {
        for _ in 0..100 {
            if self.core.pulls.is_empty() {
                return;
            }
            if let Some(&task) = self.tasks.iter().next() {
                self.tasks.remove(&task);
                match task {
                    Task::Prepare(p) => self.tell(self.plan(p, 0).unwrap()),
                    _ => self.answer(task, Ok(())),
                }
            } else if self.starting > 0 {
                self.end_start();
            } else if let Some(t) = self.wake {
                self.now = self.now.max(t);
                self.tick();
            } else {
                break;
            }
        }
        panic!(
            "a pull does not end: {:?}\n{}",
            self.core,
            self.log.join("\n")
        );
    }
}

/// The pull is over: it is told so and not held.
fn ended_now(c: &Core, out: &[Action], pull: PullId) -> bool {
    phase(c, pull).is_none() && out.contains(&Action::End(pull))
}

/// The states reached with at most `depth` events, each seen once.
fn walk(driver_pulls: bool, retries: bool, depth: u32) -> usize {
    let cfg = Cfg {
        completers: 1,
        retries,
        retry_max: 2,
        fetches: 1,
        boosted_fetches: 2,
        driver_pulls,
        quiet: 500,
    };
    let mut seen = HashSet::new();
    let mut reached = vec![World::new(cfg)];
    for _ in 0..depth {
        let next = reached.iter().flat_map(|world| world.next());
        reached = next.filter(|world| seen.insert(world.key())).collect();
        for world in &reached {
            world.idle();
            world.clone().ends();
        }
        if reached.is_empty() {
            break;
        }
    }
    seen.len()
}

#[test]
fn the_rules_hold_in_the_states_a_few_events_reach() {
    for driver_pulls in [false, true] {
        for retries in [false, true] {
            walk(driver_pulls, retries, 5);
        }
    }
}

/// The same, further: every state there is when a failure ends a pull,
/// and those ten events reach when it is tried again (the waits make
/// them too many to see all).  Ten minutes, 8 million states:
/// `cargo test --release -p velarx-lazy-core -- --ignored`.
#[test]
#[ignore]
fn the_rules_hold_in_every_state_of_a_small_world() {
    for driver_pulls in [false, true] {
        let states = walk(driver_pulls, false, u32::MAX);
        println!("driver_pulls {driver_pulls}, no retries: {states} states, all");
        let states = walk(driver_pulls, true, 10);
        println!("driver_pulls {driver_pulls}, retries: {states} states");
    }
}
