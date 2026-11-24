-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of `step` of crates/lazy-core,
-- in words and in statements, all of them, with no proof.  This file and
-- ../Models.lean are what a reviewer reads; Lean checks the rest (the
-- proofs are in Step.lean, Cancel.lean, Verdict.lean, Names.lean, Stopping.lean,
-- Sharers.lean, Tables.lean, Image.lean, Commits.lean and Held.lean; that `step` returns:
-- Returns.lean, on ReturnsStep.lean and the files `Returns*.lean` it rests on).
--
-- Why it is needed: a proof is worth what its statement says.  Each
-- statement here is a `def ... : Prop`: a claim, which `Theorems.lean`
-- asks Lean to prove.  Each has a comment of what it claims and of what
-- it does NOT.  The small definitions before a claim (`held`, `phase`,
-- `distinct`, `asked`, `over`, `waits`, `after`, `about`, `share`, `PastPreparing`,
-- `WellFormed`, `WellTold`, `Short`, `Roomy`, `Reachable`, `fresh`, `waitedFor`) are its
-- vocabulary.
-- `PullId`, `LayerId` and `Tick` are the names lib.rs gives to a `u32`, a `u32` and a `u64`;
-- `Actions` is short for `Vec<Action>`.
--
-- Read before this file: lib.rs of crates/lazy-core (`step` and the
-- functions it calls), then ../Models.lean.
--
-- Index.  What each claim is about (the Rust function of crates/lazy-core), what is trusted,
-- what is only tested and what is not claimed, in one place.
--
--   Claimed.  Twelve claims are about a `step` that RETURNS ("if it returns, then ..."); two
--   are about `Core::new`; then come the first state (`ANewCoreIsShort`) and four claims that it
--   returns, which are what makes the others hold without the "if" (on the cores the machine
--   reaches):
--     AStepOnlyAddsActions                   step: what `out` had stays, more is added after it
--     ACancelIsNeverLost                     cancel, advance: a cancel ends or stops the pull
--     TheVerdictOfAFailure                   failed, try_failed, advance: what a failure does
--     AStoppingPullOnlyEnds                  step: a pull being stopped asks only for its end
--     TheEndOfTheStopEndsIt                  succeeded, failed: the end of the stop ends the pull
--     TheNamesStayDistinct                   step: no two pulls have the same name
--     ACancelMakesTheSharersPlanAgain        cancel, advance: the sharers of a layer plan again
--     TheTablesStayWellFormed                step: the tables of the core agree
--     AnImageIsCommittedAfterItsLayers       advance: CommitImage only when the layers are stored
--     ADriverPullFollowsItsLayers            advance: DriverPull only when the layers are ready
--     ALayerIsCommittedAfterItsGroups        advance: CommitLayer only when its groups are done
--     AGroupIsHeldForTheNewLayersThatNeedIt  prepared: a group is kept for a new layer or forgotten
--     ANewCoreIsWellFormed                   Core::new
--     ANewCoreHasNoPull                      Core::new
--     ANewCoreIsShort                        Core::new: the first state has short tables
--     AStepAlwaysReturns                     step and everything it calls: it returns (no panic,
--                                            no overflow, no index out of range) on a short core
--     StepReturnsOnEveryReachableCore        step: it returns on every state the machine reaches
--     AStepReturnsAndKeepsTheTablesWellFormed  the same, and the tables agree afterwards
--     TheOtherClaimsHoldWithoutTheIf         step: the schema below, once for all of them
--
--   How a claim "if it returns" becomes one that it returns.  For a claim of the form
--   `step ... = ok (c', o') -> P`: on a reachable core, with an event that leaves room and the
--   claim's own hypotheses, `∃ c' o', step ... = ok (c', o') ∧ P` (`TheOtherClaimsHoldWithoutTheIf`
--   proves it once, for any `P`).  The claims about well-told events still need their own
--   hypothesis `WellTold`, which `Reachable` does not carry.
--
--   Trusted (the proofs rest on them, and a reviewer cannot see them in a statement):
--     - Charon and Aeneas: that the Lean of `step` is what the Rust does (../../pins);
--     - the models of the standard library Aeneas itself has (`Vec::push`, `len`, indexing,
--       the integer operations and their overflow rule): nothing prints them;
--     - the nine models of ../Models.lean, each after the sentence of the std documentation;
--     - the functions of std nothing is assumed of: `run` prints them under each theorem;
--     - `WellTold`: the shell's promise about `Prepared` (it numbers the groups itself and
--       removes the layer keys that come twice); the shell is not checked here;
--     - `Stored` and `Done` are what the caller answered, not what the store has.
--
--   Tested: the walk of crates/lazy-core/src/walk.rs checks every rule at every step of a small
--   world.  Rules no claim here states (the window of fetches, the places, a pull that yields to
--   a container, a group fetched twice, a layer committed twice, a late answer, the progress of
--   a wait) are only tested.
--
--   Not claimed at all: memory exhaustion (an allocation that fails aborts the process); the
--   counters `next_pull` and `next_group` of the shell (`u32` in the completer, crates/core/src/
--   services/image/completer.rs): they only grow over the life of the task and could wrap and
--   reuse a number that is live, which is outside every claim here; that anything is ever asked
--   (no liveness); that an action is asked once;
--   which groups `let_go` keeps (`wanting`); `groups_of` and `layers_of`, which only report the
--   groups and layers of a pull to the shell (`layers_of` gives the counts as a `u32`); the
--   shell (the asynchronous code that feeds the events and does the actions: it is tested, not
--   proved); time (when `Wake` is answered).
--   That `step` returns is claimed (the last four claims), for the cores whose tables are short
--   (`Short`) and the events that leave room in them (`Roomy`), on a 64-bit machine.  Nothing in
--   the state is an index: a pull, a layer or a group is looked up by its number each time
--   (`pull_at`, `layer_at`, `group_at`), and a number that the core does not hold makes the step
--   do nothing; so the only things that can fail are a `push` and a counter that wraps, and
--   `Short` and `Roomy` keep them far from that.  In the model of the translator, a `push` fails
--   only on a `Vec` of 2^64 entries; the real limit is memory, see Not claimed.
--
--   To check that a claim is not trivial: (a) its hypotheses can hold: find the state in the
--   walk; (b) put in a bug the claim excludes, by hand in
--   crates/lazy-core, and `tools/verify/run lazy-core` must fail; (c) take a hypothesis out of
--   the claim, or make its conclusion stronger, and `run` must fail.
--
--   To see what `step` looks like to Lean, side by side with the Rust: run
--   `tools/verify/run lazy-core`, then read $VERIFY_CACHE/lazy-core/work/Extracted/Funs.lean
--   (the functions, `step` among them, as Aeneas wrote them) and Types.lean (the types);
--   `run` prints the directory when it ends.  Nothing generated is in the tree.
--
-- Notation:
--   - `step c now event out = ok (c', out')` reads: the Rust `step`, told
--     `event` at the time `now`, with the core `c` and the actions `out`,
--     returns, and leaves the core `c'` and the actions `out'`.  The first
--     twelve claims say nothing of a step that does not return (a panic, a loop
--     that does not end); the claims that follow the first state say that it returns.
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such
--     that P"; `∃ q ∈ l, P` is "there is an element q of l such that P";
--     `¬ P` is "not P"; `∧` is "and", `∨` is "or", `→` is "if ... then".
--   - `∃ c' out', step c now ev out = ok (c', out') ∧ P` reads: the Rust `step` RETURNS (it does
--     not panic and it ends) and what it returns satisfies `P`.
--   - `c.pulls.val` is the list of the pulls of the core `c`; `q.id` is the
--     name of the pull `q`; `t.val` is the number a time `t` (a `u64`) is.
--   - `match cl, c.cfg.retries with | ...` is a case split, the first
--     line that fits being taken.
import Proved
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_lazy_core

namespace LazyCore

-- The names the Rust gives its types (`pub type` in lib.rs), and `Actions`, a short name of this
-- file.  Aeneas does not keep the names (it writes `Std.U32` for a pull, a layer and a group
-- alike); here a statement says which one a number is.

/-- The name of a pull (`PullId`, a `u32`). -/
abbrev PullId := Std.U32

/-- The name of a layer (`LayerId`, a `u32`). -/
abbrev LayerId := Std.U32

/-- A time in milliseconds on the clock the caller keeps (`Tick`, a `u64`). -/
abbrev Tick := Std.U64

/-- The actions the core asks of the shell (`Vec<Action>`), in the order it asked them. -/
abbrev Actions := alloc.vec.Vec Action

/-- The core holds a pull named `p`. -/
def held (c : Core) (p : PullId) : Prop :=
  ∃ q ∈ c.pulls.val, q.id = p

/-- The core holds a pull named `p` that is at `ph`. -/
def phase (c : Core) (p : PullId) (ph : Phase) : Prop :=
  ∃ q ∈ c.pulls.val, q.id = p ∧ q.phase = ph

/-- No two pulls of the core have the same name. -/
def distinct (c : Core) : Prop :=
  (c.pulls.val.map (·.id)).Nodup

/-- The step asked for `a`: it is among the actions after the first `out.length` of `out'`.
That these are the actions the step added is `AStepOnlyAddsActions`, the claim below. -/
def asked (out out' : Actions) (a : Action) : Prop :=
  a ∈ out'.val.drop out.val.length

/-- **A step only adds actions.**  Whatever the event, if the step (the Rust `step`) returns, the
actions `out'` it leaves are the actions `out` it was given with more at the end.  So what
`asked out out' a` reads, "`a` is among the actions after the first ones", is "the step asked for
`a`": nothing was taken away or put in another order, and the claims below that go through `asked`
rely on this one.

Not said: that the step returns (see the index); which actions are added (the other claims say
it of some); anything of the core. -/
def AStepOnlyAddsActions : Prop :=
  ∀ (c : Core) (now : Tick) (ev : Event) (out : Actions)
    (c' : Core) (out' : Actions),
    step c now ev out = ok (c', out') → ∃ more, out'.val = out.val ++ more

/-- **A cancel is never lost.**  Take a pull `p` the core holds, which is
not being stopped already.  The step of `Cancel p` (the Rust `cancel`,
then `advance`) asks for `End p` (the pull is over, its lease goes) or
for `Abort (Pull p)` (what runs for it is stopped, and its end follows).

Not said: anything of `c'`, or of the steps after (that the end of the
stop ends the pull is `TheEndOfTheStopEndsIt`). -/
def ACancelIsNeverLost : Prop :=
  ∀ (c : Core) (now : Tick) (p : PullId) (out : Actions)
    (c' : Core) (out' : Actions),
    held c p → ¬ phase c p Phase.Cancelling →
    step c now (Event.Cancel p) out = ok (c', out') →
    asked out out' (Action.End p) ∨ asked out out' (Action.Abort (Work.Pull p))

/-- The pull `p` is over: the step recorded `s` for it and asked for its
end, and the core holds it no more. -/
def over (c' : Core) (out out' : Actions) (p : PullId) (s : State) : Prop :=
  asked out out' (Action.Record p s) ∧ asked out out' (Action.End p) ∧ ¬ held c' p

/-- The pull `p` waits until `t`: the step recorded `s` for it and asked
to be woken at `t`, and the core holds it, waiting until `t`. -/
def waits (c' : Core) (out out' : Actions) (p : PullId) (s : State)
    (t : Tick) : Prop :=
  asked out out' (Action.Record p s) ∧ asked out out' (Action.Wake t) ∧
    phase c' p (Phase.Waiting t)

/-- `t` is `wait` milliseconds after `now`, or the last time there is. -/
def after (now t : Tick) (wait : Nat) : Prop :=
  t.val = min (now.val + wait) Std.U64.max

/-- **The verdict of a failure.**  Take a core whose pulls have distinct
names and a pull `p` of it that runs (at any step of its try).  When what
ran for the pull fails with the class `cl` (the Rust `failed`, which calls
`try_failed` for the pull, then `advance`):
- for want of credentials the pull is over, recorded `NeedsCredentials`;
- on a fatal failure, or any other failure when the completion does not
  retry (`cfg.retries` is false), it is over, recorded `Failed`;
- on a full file system it waits a minute, recorded `NoSpace`;
- on a transient failure it waits, recorded `Backoff`, at most
  `retry_max` seconds and, if `retry_max` is not zero, at least a second.

Not said:
- which wait between the two bounds (that it doubles is a unit test);
- what else the step asks for or changes (the place of a pull that is over goes to another);
- anything of a failure of a group or of a layer, which reaches the pulls through `lacking`
  (not proved). -/
def TheVerdictOfAFailure : Prop :=
  ∀ (c : Core) (now : Tick) (p : PullId) (s : Step) (cl : Class)
    (out : Actions) (c' : Core) (out' : Actions),
    distinct c → phase c p (Phase.Running s) →
    step c now (Event.Done (Work.Pull p) (core.result.Result.Err cl)) out = ok (c', out') →
    match cl, c.cfg.retries with
    | Class.Credentials, _ => over c' out out' p State.NeedsCredentials
    | Class.Fatal, _ => over c' out out' p State.Failed
    | _, false => over c' out out' p State.Failed
    | Class.NoSpace, true => ∃ t, after now t 60000 ∧ waits c' out out' p (State.NoSpace t) t
    | Class.Transient, true => ∃ t wait, after now t wait ∧
        wait ≤ c.cfg.retry_max.val * 1000 ∧ (1 ≤ c.cfg.retry_max.val → 1000 ≤ wait) ∧
        waits c' out out' p (State.Backoff t) t

/-- The action says something of the pull `p`: it records a state for it, asks
for its preparation, the driver's pull or the commit of its image, stops what
runs for it, or ends it. -/
def about (a : Action) (p : PullId) : Prop :=
  match a with
  | Action.Record q _ | Action.Prepare q | Action.DriverPull q
  | Action.CommitImage q | Action.End q => q = p
  | Action.Abort (Work.Pull q) => q = p
  | _ => False

/-- **A stopping pull only ends.**  Take a core whose pulls have distinct
names and a pull `p` of it that is being stopped (`Cancelling`: `cancel`
asked `Abort (Pull p)`).  Whatever the event, the step (the Rust `step`)
asks nothing of `p` but `End p`; either the pull is still being stopped
or it is gone and `End p` was asked; and when `End p` is asked, the pull
is gone.

Not said:
- that the step returns (see the index);
- anything of the other pulls;
- that the caller ends what runs for the pull (that is its part, see the next claim);
- that the names stay distinct (`TheNamesStayDistinct`);
- anything of the actions about layers and groups (`Fetch`, `CommitLayer`, `Abort` or `Forget` of
  a layer or a group, `Wake`), nor of a group still counted as in flight for the pull. -/
def AStoppingPullOnlyEnds : Prop :=
  ∀ (c : Core) (now : Tick) (ev : Event) (out : Actions)
    (c' : Core) (out' : Actions) (p : PullId),
    distinct c → phase c p Phase.Cancelling →
    step c now ev out = ok (c', out') →
    (∀ a, asked out out' a → about a p → a = Action.End p) ∧
    (phase c' p Phase.Cancelling ∨ (¬ held c' p ∧ asked out out' (Action.End p))) ∧
    (asked out out' (Action.End p) → ¬ held c' p)

/-- **The end of the stop ends the pull.**  Take a core whose pulls have
distinct names and a pull `p` of it that is being stopped.  When what ran
for it ends, well or not (`Done (Pull p) r`), the step asks for `End p` and
the core holds `p` no more.

Not said:
- that the step returns (see the index);
- anything of the other pulls;
- that what ran for the pull ends (the caller answers `Abort` with `Done`). -/
def TheEndOfTheStopEndsIt : Prop :=
  ∀ (c : Core) (now : Tick) (r : core.result.Result Unit Class)
    (out : Actions) (c' : Core) (out' : Actions) (p : PullId),
    distinct c → phase c p Phase.Cancelling →
    step c now (Event.Done (Work.Pull p) r) out = ok (c', out') →
    asked out out' (Action.End p) ∧ ¬ held c' p

/-- **The names stay distinct.**  Take a core whose pulls have distinct names.  Whatever
the event, if the step (the Rust `step`) returns, the pulls of the core it leaves have
distinct names.  The other claims assume this of the core they start from; with
`ANewCoreHasNoPull` it holds of every core `step` is called on, by induction on the steps.

Not said:
- that the step returns (see the index);
- that the caller gives a pull a name that was never used (only that two pulls HELD at once
  differ: a name may come back after its pull ended). -/
def TheNamesStayDistinct : Prop :=
  ∀ (c : Core) (now : Tick) (ev : Event) (out : Actions)
    (c' : Core) (out' : Actions),
    distinct c → step c now ev out = ok (c', out') → distinct c'

/-- The pulls named `p` and `q` both lack some layer: a layer is among the layers of each. -/
def share (c : Core) (p q : PullId) : Prop :=
  ∃ x ∈ c.pulls.val, x.id = p ∧ ∃ y ∈ c.pulls.val, y.id = q ∧
    ∃ l, l ∈ x.layers.val ∧ l ∈ y.layers.val

/-- **A cancel makes the sharers plan again.**  Take a core whose pulls have distinct names,
a pull `p` of it that runs (at any step of its try), and another pull `q` that is working and
shares a layer with `p` (`share`).  When `p` is cancelled (the Rust `cancel`, then `advance`),
`q` prepares again: it is at `Running Preparing` afterwards, and the step asked for `Prepare q`.
What `q` held was planned for `p`, whose stagings may go.

Not said:
- that the step returns (see the index);
- that a pull that shares no layer with `p` is left alone (the unit tests check that);
- what the new plan of `q` is;
- anything for a pull that ends in another way than a cancel (a failure does not make the sharers
  plan again). -/
def ACancelMakesTheSharersPlanAgain : Prop :=
  ∀ (c : Core) (now : Tick) (p q : PullId) (s : Step) (out : Actions)
    (c' : Core) (out' : Actions),
    distinct c → phase c p (Phase.Running s) → q ≠ p →
    phase c q (Phase.Running Step.Working) → share c p q →
    step c now (Event.Cancel p) out = ok (c', out') →
    phase c' q (Phase.Running Step.Preparing) ∧ asked out out' (Action.Prepare q)

/-- The pull runs a try that was told what it lacks: it is `Working`, the storage driver pulls
its layers (`DriverPull`), or its image is committed (`Image`).  The other pulls (queued,
preparing, waiting, being stopped) have let go of their layers. -/
def PastPreparing (ph : Phase) : Prop :=
  ph = Phase.Running Step.Working ∨ ph = Phase.Running Step.DriverPull ∨
  ph = Phase.Running Step.Image

/-- The tables of the core agree.  Seven clauses, in the order of `well_formed` of
crates/lazy-core/src/walk.rs (the rule the tests check at every step), so that a reader can
check each against it: the names of the pulls, of the layers and of the groups are distinct; the
layers of a pull are distinct; a layer a pull lacks is in the table of the layers; a layer of
the table is lacked by some pull; a pull that is not past its preparation lacks nothing. -/
def WellFormed (c : Core) : Prop :=
  -- the names of the pulls are distinct
  distinct c ∧
  -- the names of the layers are distinct
  (c.layers.val.map (·.id)).Nodup ∧
  -- the names of the groups are distinct
  (c.groups.val.map (·.id)).Nodup ∧
  -- the layers a pull lacks are distinct
  (∀ p ∈ c.pulls.val, p.layers.val.Nodup) ∧
  -- a layer a pull lacks is in the table
  (∀ p ∈ c.pulls.val, ∀ l ∈ p.layers.val, ∃ x ∈ c.layers.val, x.id = l) ∧
  -- a layer of the table is lacked by some pull
  (∀ x ∈ c.layers.val, ∃ p ∈ c.pulls.val, x.id ∈ p.layers.val) ∧
  -- a pull lacks nothing unless its try is past its preparation
  (∀ p ∈ c.pulls.val, p.layers.val ≠ [] → PastPreparing p.phase)

/-- What the caller promises of an event, which the core relies on: a `Prepared` names each layer
once, and gives its groups names that differ from each other and from the names of the groups the
core holds.  (The shell does: it numbers the groups itself and removes the layer keys that come
twice.)  Every other event is told as it is. -/
def WellTold (c : Core) (ev : Event) : Prop :=
  match ev with
  | Event.Prepared _ layers groups =>
      layers.val.Nodup ∧ (groups.val.map (·.id)).Nodup ∧
      ∀ g ∈ groups.val, ∀ x ∈ c.groups.val, x.id ≠ g.id
  | _ => True

/-- **The tables stay well formed.**  Take a core whose tables agree (`WellFormed`) and an event
told as the caller promises (`WellTold`).  If the step (the Rust `step`) returns, the tables of
the core it leaves agree.  With `ANewCoreIsWellFormed`, it holds of every core `step` is called
on, when every event is `WellTold`, by induction on the steps.  In particular a layer a pull
lacks is in the table of the layers (which "an image is committed after its layers" relies on).

Not said:
- that the step returns (see the index);
- that the caller keeps its promise (`WellTold`);
- anything of the states of the layers and of the groups;
- which groups are held (the walk checks that no group is held when no pull is; that is not proved
  here: which groups `let_go` keeps is decided by `wanting`, of which only that it returns is
  proved);
- that a group names only layers of the table (it does not: a group may outlive a layer it was
  for). -/
def TheTablesStayWellFormed : Prop :=
  ∀ (c : Core) (now : Tick) (ev : Event) (out : Actions)
    (c' : Core) (out' : Actions),
    WellFormed c → WellTold c ev → step c now ev out = ok (c', out') → WellFormed c'

/-- **An image is committed after its layers.**  Take a core whose tables agree (`WellFormed`) and
an event told as the caller promises (`WellTold`).  When the step (the Rust `step`) asks for the
commit of the image of the pull `p` (`CommitImage p`), the core it leaves holds `p`, and every pull
of it named `p` (there is one: the names are distinct) is at the step `Image`, and every layer it
lacks is in the table of the layers and is `Stored`.  So an image is never asked to be named in
the store before the layers it needs.

`Stored` is what the core was told, in one of two ways: the caller answered `Done (Layer l, Ok)`
to a `CommitLayer l`; or, when the storage driver pulls the layers (`cfg.driver_pulls`), the layer
was `Ready`, a pull that lacked it was at `DriverPull`, and the caller answered
`Done (Pull p, Ok)` for it.

`WellTold` is there only because the proof uses "the tables stay well formed" for this step
(`TheTablesStayWellFormed`); of `WellFormed` it uses only "a layer a pull lacks is in the table" and
that the names of the pulls are distinct.  Without the first, "every layer of the table that the
pull lacks is stored" would be true of a layer that is missing from the table.

Not said:
- that the step returns (see the index);
- that the STORE has the layers: `Stored` is what the core was told, so the claim is as good as
  the answers of the caller (the shell drops the answers of aborted works);
- that a layer stays stored afterwards;
- that `CommitImage` is asked at most once for a pull: it may be asked again for a pull after a
  failed try (that it is at most once for each try is checked by the tests, not proved);
- the layers the pull's last `Prepared` listed are the ones the claim speaks of (a pull told it
  lacks nothing is committed at once);
- that the commit is ever asked (nothing is said about liveness);
- anything about `DriverPull` (see `ADriverPullFollowsItsLayers`). -/
def AnImageIsCommittedAfterItsLayers : Prop :=
  ∀ (c : Core) (now : Tick) (ev : Event) (out : Actions)
    (c' : Core) (out' : Actions) (p : PullId),
    WellFormed c → WellTold c ev → step c now ev out = ok (c', out') →
    asked out out' (Action.CommitImage p) →
    held c' p ∧ ∀ q ∈ c'.pulls.val, q.id = p → q.phase = Phase.Running Step.Image ∧
      ∀ l ∈ q.layers.val, ∃ x ∈ c'.layers.val, x.id = l ∧ x.state = LayerState.Stored

/-- **A driver's pull follows its layers.**  Take a core whose tables agree (`WellFormed`) and an
event told as the caller promises (`WellTold`).  When the step asks for the driver's pull of `p`
(`DriverPull p`: the storage driver pulls all the layers of the pull together), the core it leaves
holds `p`, and every pull of it named `p` is at the step `DriverPull`, and every layer it lacks is
in the table of the layers and is `Ready` (the files are there, to be pulled) or `Stored`.

Not said:
- that the step returns (see the index);
- that the driver does pull them: after `Done (Pull p, Ok)` the layers are `Stored`, which is as
  good as that answer of the caller;
- that the layers stay `Ready`;
- that `DriverPull` is asked at most once for a pull;
- that it is ever asked (nothing is said about liveness);
- anything about `CommitImage` (see `AnImageIsCommittedAfterItsLayers`);
- for `WellFormed` and `WellTold` see there. -/
def ADriverPullFollowsItsLayers : Prop :=
  ∀ (c : Core) (now : Tick) (ev : Event) (out : Actions)
    (c' : Core) (out' : Actions) (p : PullId),
    WellFormed c → WellTold c ev → step c now ev out = ok (c', out') →
    asked out out' (Action.DriverPull p) →
    held c' p ∧ ∀ q ∈ c'.pulls.val, q.id = p → q.phase = Phase.Running Step.DriverPull ∧
      ∀ l ∈ q.layers.val, ∃ x ∈ c'.layers.val, x.id = l ∧
        (x.state = LayerState.Ready ∨ x.state = LayerState.Stored)

/-- **A layer is committed after its groups.**  Whatever the event, when the step (the Rust `step`)
asks for `CommitLayer l`, the core it leaves has a layer named `l` that is `Committing`, and every
group of the core that names `l` (that has `l` in `needed_by`) is `Done`.

Not said:
- that the step returns (see the index);
- that the core holds the groups the layer waits for: a group is dropped when no pull wants it
  (the Rust `let_go`), which is not proved, so a layer whose groups were dropped is committed
  with the claim true of no group at all (the unit tests and the walk check that it does not
  happen; that `prepared` holds them is `AGroupIsHeldForTheNewLayersThatNeedIt`);
- that the groups are `Done` in the store: `Done` is what the caller answered to the fetch of the
  group (as for `Stored`, see `AnImageIsCommittedAfterItsLayers`);
- that a layer stays `Committing` or is committed once;
- that the commit is ever asked (nothing is said about liveness). -/
def ALayerIsCommittedAfterItsGroups : Prop :=
  ∀ (c : Core) (now : Tick) (ev : Event) (out : Actions)
    (c' : Core) (out' : Actions) (l : LayerId),
    step c now ev out = ok (c', out') → asked out out' (Action.CommitLayer l) →
    (∃ x ∈ c'.layers.val, x.id = l ∧ x.state = LayerState.Committing) ∧
    ∀ g ∈ c'.groups.val, l ∈ g.needed_by.val → g.state = GroupState.Done

/-- The layer `l` is new to the core `c` for a `Prepared` event that lists `layers`: the event lists
it and the table of the layers of `c` lacks it. -/
def fresh (c : Core) (layers : alloc.vec.Vec LayerId) (l : LayerId) : Prop :=
  l ∈ layers.val ∧ l ∉ c.layers.val.map (·.id)

/-- A new layer waits for the group `g` of a `Prepared` event: it is among the layers `g` is for. -/
def waitedFor (c : Core) (layers : alloc.vec.Vec LayerId) (g : GroupFact) : Prop :=
  ∃ l ∈ g.needed_by.val, fresh c layers l

/-- **A group is held for the new layers that need it.**  Take a core whose pulls have distinct
names, a pull `p` of it that is preparing, and a `Prepared` event for `p` told as the caller
promises (`WellTold`).  When the step (the Rust `step`, which calls `prepared`, then `advance`)
returns, every group `g` of the event is one of two:
- some new layer waits for it (`waitedFor`): the core the step leaves holds a group of its name,
  and the layers that group is for are those of `g` that are new;
- no new layer waits for it: the step asked for `Forget` of it, and the core holds no group of its
  name.

So a group told for a new layer is held for it, and (with `ALayerIsCommittedAfterItsGroups`, which
says the groups held for a layer are `Done` when it is committed) the layer is committed after it,
unless it was dropped in between.  A group is not dropped because some of its layers are old, and
not kept when all are.

Not said:
- that the step returns (see the index);
- that the groups the caller lists are the right ones for the layers (the plan is made outside
  the core);
- anything of a late answer (a pull that is not preparing: it tells everything back);
- that the group stays held (`let_go` drops it when no pull wants it any more);
- the state of the group, or that it is fetched. -/
def AGroupIsHeldForTheNewLayersThatNeedIt : Prop :=
  ∀ (c : Core) (now : Tick) (p : PullId) (layers : alloc.vec.Vec LayerId)
    (groups : alloc.vec.Vec GroupFact) (out : Actions)
    (c' : Core) (out' : Actions),
    distinct c → phase c p (Phase.Running Step.Preparing) →
    WellTold c (Event.Prepared p layers groups) →
    step c now (Event.Prepared p layers groups) out = ok (c', out') →
    ∀ g ∈ groups.val,
      (waitedFor c layers g → ∃ x ∈ c'.groups.val, x.id = g.id ∧
        ∀ l, l ∈ x.needed_by.val ↔ l ∈ g.needed_by.val ∧ fresh c layers l) ∧
      (¬ waitedFor c layers g →
        asked out out' (Action.Forget (Work.Group g.id)) ∧ ∀ x ∈ c'.groups.val, x.id ≠ g.id)

/-- **A new core is well formed.**  The Rust `Core::new` returns a core with no pull, no layer and
no group, so its tables agree (an empty table has no name twice and nothing to find in it).

Not said: anything of the other fields of the core. -/
def ANewCoreIsWellFormed : Prop :=
  ∀ (cfg : Cfg) (c : Core), Core.new cfg = ok c → WellFormed c

/-- **A new core has no pull.**  The Rust `Core::new` returns a core with no pull at all, so
its names are distinct (the empty list has no name twice).

Not said: anything of the other fields of the core. -/
def ANewCoreHasNoPull : Prop :=
  ∀ (cfg : Cfg) (c : Core), Core.new cfg = ok c → c.pulls.val = []

/-- The machine has 64-bit words: a `usize` has 64 bits.  Lean does not know the width of a `usize`
(it is 32 or 64), so the claims that `step` returns are for a 64-bit machine, as a hypothesis: with
32 bits a table of 2^32 entries could not be pushed to.  A hypothesis of the claims, not a claim
(`@[not_a_claim]`, ../../../Proved.lean). -/
@[not_a_claim] abbrev OnA64BitMachine : Prop :=
  System.Platform.numBits = 64

/-- The tables of the core are short: no table has more than 33 million entries (2^25 =
33 554 432), one clause for each table.  It is the one thing `step` relies on to return: it keeps
no index (a pull, a layer or a group is found by its number each time), and what could fail is a
`push` or a counter that wraps, which needs a table of the size of the address space.  A real core
is far below this (a pull takes a hundred bytes: 2^25 of them would take three gigabytes). -/
def Short (c : Core) : Prop :=
  -- there are at most 2^25 pulls
  c.pulls.val.length ≤ 2 ^ 25 ∧
  -- there are at most 2^25 layers
  c.layers.val.length ≤ 2 ^ 25 ∧
  -- there are at most 2^25 groups
  c.groups.val.length ≤ 2 ^ 25 ∧
  -- there are at most 2^25 records of the starts of containers
  c.starts.val.length ≤ 2 ^ 25

/-- After this event, every table still has at most 33 million entries (2^25).  An `Added` finds
room for one more pull; a `Prepared` finds room for the layers and the groups it lists, on top of
the ones the core holds; a start or the end of a start of a container finds room for one more
record.  The other events (`Hurry`, `Cancel`, `Done`, `Tick`) add nothing to a table. -/
def Roomy (c : Core) (ev : Event) : Prop :=
  match ev with
  | Event.Added _ _ => c.pulls.val.length + 1 ≤ 2 ^ 25
  | Event.Prepared _ layers groups =>
      c.layers.val.length + layers.val.length ≤ 2 ^ 25 ∧
      c.groups.val.length + groups.val.length ≤ 2 ^ 25
  | Event.StartBegan _ => c.starts.val.length + 1 ≤ 2 ^ 25
  | Event.StartEnded _ => c.starts.val.length + 1 ≤ 2 ^ 25
  | _ => True

/-- **A new core is short.**  The Rust `Core::new` returns a core with no pull, no layer, no group
and no record of a start, so its tables are short.  It is the first state of every run, and
`AStepAlwaysReturns` keeps the tables short.

Not said: anything of the other fields of the core. -/
def ANewCoreIsShort : Prop :=
  ∀ (cfg : Cfg) (c : Core), Core.new cfg = ok c → Short c

/-- **`step` always returns on a short core.**  Take a 64-bit machine, a core whose tables are short
(`Short`), any event that leaves room in them (`Roomy`) and an action list `out` that is not huge
(fewer than 2^62 actions: the shell passes a list it has just emptied).  The Rust `step` returns:
it does not panic (no index of a `Vec` out of range, no `push` to a full `Vec`, no overflow of a
counter, no removal of a place that is not there), and it ends.  It leaves a core whose tables are
short again, and it pushes at most 2^54 actions.

The event may name a pull, a layer or a group the core does not hold, or a pull in a state the
event does not fit (a late answer): `step` then does nothing, or tells the answer back (it never
indexes with a number of the event: it looks the number up first).  The proof follows the Rust
function by function (ReturnsStep.lean and the files it rests on), each loop with a number that
goes down.

Not said:
- that the event is told as the caller promises (`WellTold`: not needed to return);
- what `step` does (the other claims say it of some of what it does);
- that the tables of the core `step` leaves leave room for the next event (that is the
  hypothesis `Roomy` of `StepReturnsOnEveryReachableCore`, about the events of a run);
- time: the number of steps it takes is not claimed, only that it ends. -/
def AStepAlwaysReturns : Prop :=
  ∀ (c : Core) (now : Tick) (ev : Event) (out : Actions),
    OnA64BitMachine → Short c → Roomy c ev → out.val.length ≤ 2 ^ 62 →
    ∃ (c' : Core) (out' : Actions), step c now ev out = ok (c', out') ∧ Short c' ∧
      out'.val.length ≤ out.val.length + 2 ^ 54

/-- A state a run can get to, if every event left room: the first core (what `Core::new` returns),
and the core a `step` returns when it is given a core that is reached, an event that leaves room
(`Roomy`) and an action list that is not huge (as in `AStepAlwaysReturns`).

The constructor `next` takes `Roomy c ev` as a premise, so "reachable" means reachable by events
that leave room.  `Roomy` is assumed for every event, not checked by the shell.  It holds in
practice because the tables hold only live pulls, their layers and groups, and recent starts:
entries are removed when a pull leaves (`leave`), when its layers and groups are let go
(`let_go`) and when start records are dropped (`start_at`); nothing piles up over the life of the
service.  2^25 live entries would take gigabytes of memory first. -/
inductive Reachable : Core → Prop
  | first (cfg : Cfg) (c : Core) (made : Core.new cfg = ok c) : Reachable c
  | next (c : Core) (now : Tick) (ev : Event) (out : Actions) (c' : Core) (out' : Actions)
      (reached : Reachable c) (leaves_room : Roomy c ev) (not_huge : out.val.length ≤ 2 ^ 62)
      (returned : step c now ev out = ok (c', out')) : Reachable c'

/-- **`step` always returns on the states the machine can reach.**  Take a 64-bit machine, a core
that is reached from the first one by steps that returned, an event that leaves room in its tables
and an action list that is not huge.  The Rust `step` returns.  This is `AStepAlwaysReturns` by
induction on the steps: the first core is short (`ANewCoreIsShort`), and a core `step` returns is
short again.  With it, the claims above that read "if the step returns" hold of every step of a
run, without the "if".

Not said: that the shell leaves room (`Roomy`) for each event, or that it keeps the list of actions
short: they are what the run is (a table of 33 million entries, or a list of 4 billion billion
actions, does not occur); that anything is asked; the shell. -/
def StepReturnsOnEveryReachableCore : Prop :=
  ∀ (c : Core), Reachable c → ∀ (now : Tick) (ev : Event) (out : Actions),
    OnA64BitMachine → Roomy c ev → out.val.length ≤ 2 ^ 62 →
    ∃ (c' : Core) (out' : Actions), step c now ev out = ok (c', out')

/-- **A step returns and keeps the tables well formed.**  Take a 64-bit machine, a core whose
tables agree (`WellFormed`) and are short, an event told as the caller promises (`WellTold`) that
leaves room, and an action list that is not huge.  The Rust `step` returns, the tables of the core
it leaves agree and are short, and the actions it leaves are the ones it was given with more at the
end.  It is `TheTablesStayWellFormed` and `AStepOnlyAddsActions` without their "if the step
returns".

Not said: what the actions are; that the caller keeps its promise (`WellTold`). -/
def AStepReturnsAndKeepsTheTablesWellFormed : Prop :=
  ∀ (c : Core) (now : Tick) (ev : Event) (out : Actions),
    OnA64BitMachine → WellFormed c → Short c → WellTold c ev → Roomy c ev →
    out.val.length ≤ 2 ^ 62 →
    ∃ (c' : Core) (out' : Actions), step c now ev out = ok (c', out') ∧ WellFormed c' ∧
      Short c' ∧ ∃ more, out'.val = out.val ++ more

/-- **A claim that holds "if the step returns" holds without the "if".**  The schema of the index,
for any `P`: on a reachable core, with an event that leaves room, if every step that returns
satisfies `P`, then the step returns and satisfies `P`.  The hypotheses of a claim of the form
`step ... = ok (c', o') -> P` come with it (and `WellTold` where the claim needs it).

Not said: that `P` holds (it is the claim's own); anything of a core that is not reachable. -/
def TheOtherClaimsHoldWithoutTheIf : Prop :=
  ∀ (P : Core → Actions → Prop) (c : Core) (now : Tick) (ev : Event) (out : Actions),
    OnA64BitMachine → Reachable c → Roomy c ev → out.val.length ≤ 2 ^ 62 →
    (∀ (c' : Core) (out' : Actions), step c now ev out = ok (c', out') → P c' out') →
    ∃ (c' : Core) (out' : Actions), step c now ev out = ok (c', out') ∧ P c' out'

end LazyCore
