-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what each function of lib.rs that gets the list of actions `out` pushes to
-- it, and that it only pushes: whatever is in `out` before a call is still there, at the front,
-- after it, and what comes after is of the kinds the function is known to push.
--
-- Why it is needed: four proofs ask it.  A cancel is not lost (Cancel.lean) finds `End p` or
-- `Abort (Pull p)` in `out` after `cancel`, and `step` then calls `advance`, which cannot take it
-- away.  A stopping pull only ends (Stopping.lean) needs that what `let_go` and the loops of
-- `advance` and `prepared` push says nothing of a pull.  An image is committed after its layers
-- (Image.lean) needs that no function but `advance` pushes `CommitImage` or `DriverPull`.  Each
-- function calls others, so each one needs the fact.
--
-- The fact, once for each function.  The Rust function pushes actions of a few KINDS only:
-- `begin_try` pushes `Record` and `Prepare`, `let_go` pushes `Abort` of a layer or of a group and
-- `Forget`, and so on.  A kind is the constructor of the action, but `Abort` of a pull and `Abort`
-- of anything else are two kinds, because `about` (Spec.lean) tells them apart.  For each function
-- `f` there is one lemma `f_kinds`: if `f` returns, the actions in the `out` it returns are those
-- of the `out` it was given, with actions of these kinds added at the end:
--
--     AppendsKinds (f ... out) (the out in the result) [kinds] out
--
-- (`Ok` is explained in Ok.lean; `AppendsKinds` below says it in full.)  Every other fact is a
-- corollary, by one line: `AppendsOnly.noPull` ("what is pushed says nothing of a pull", `about` of
-- Spec.lean), `AppendsOnly.notPullStep` ("none of it is `CommitImage` or `DriverPull`") and
-- `AppendsOnly.grows` ("`out` only grows").  The lemmas are in order: a function after those it
-- calls.  (Aeneas extracts a loop as a function of its own: `let_go_loop0` is the first loop of
-- `let_go`, `advance_loop4_loop0` the first loop in the third loop of `advance`.)
--
-- How a lemma is proved: by the tactic `appends_only`, which follows the body of the Rust function
-- line by line.  After `unfold f` the goal is the body.  `appends_only` repeats these steps until
-- the goal is closed:
--   - the body ends with `ok x`: the claim holds because the `out` in `x` is the one known so far
--     (`assumption`);
--   - the body panics: nothing to show (`Ok.fail`);
--   - the line is a `Vec::push` of an action: its kind must be among those of the lemma
--     (`push_appends_only`), and the new `out` has its own fact `hx`;
--   - the line is a branch (`if`, `match`): the cases are taken one by one;
--   - the line is a call of a function that has its `f_kinds` lemma: Lean finds the lemma by
--     itself (the lemmas are registered as instances of `AppendsKinds`, `attribute [instance]`
--     after each) and the kinds of the call must be among those of the lemma;
--   - any other line (a call that does not get `out`, a test): its result is unknown and does
--     not matter (`Ok.any`).
-- For a loop the proof starts with `Ok.loop`, with the invariant "what is in the `out` of the
-- loop so far is `out` with actions of these kinds added", then runs `appends_only` on the body.
--
-- The base of them all is `push_appends`: what `Vec::push` does.
--
-- Read before this file: Ok.lean, and `about` in Spec.lean.
--
-- Notation: `old <+: l` is "`old` is the beginning of `l`"; `l.drop n` is `l` without its first
-- `n` elements; `v.val` is the list inside a Rust `Vec`; `[.record, .prepare]` is the list of
-- the two kinds `Kind.record` and `Kind.prepare`; `(·.2)` is "the second element of the result".
import Ok
import LazyCore.Spec
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_lazy_core

namespace LazyCore

-- (the proofs unfold these one at a time: the unifier is not to; nor is it to unfold `Ok`, which
-- makes a call that is not the one looked for fail at once)
attribute [local irreducible] Ok begin_try let_go_loop0 let_go_loop1 let_go leave_loop
  leave cancel_loop cancel advance_loop2 advance_loop3 advance_loop4_loop0
  advance_loop4 advance Core.pull_at Core.lacking slots_held goes wanting in_flight
  Core.starting Pull.has_all Pull.working Pull.wants Pull.lacks

/-- `Vec::push` returns the vector with `x` added at the end. -/
theorem push_appends {α : Type} (v : alloc.vec.Vec α) (x : α) :
    Ok (v.push x) (fun v1 => v1.val = v.val ++ [x]) := by
  unfold alloc.vec.Vec.push
  dsimp only
  split
  · apply Ok.ok.mpr; simp
  · exact Ok.fail

/-- Aeneas writes a call on a pair as `uncurry f x`; this says it is `f x.1 x.2`,
    so that `appends_only` can read it. -/
theorem uncurry_eq {α β γ : Type} (f : α → β → γ) (x : α × β) :
    uncurry f x = f x.1 x.2 := by
  cases x; rfl

/-- The kinds of action.  There is one for each constructor of `Action`, but `Abort` of a pull and
`Abort` of a layer or of a group are two (`about` says which pull the first is for). -/
inductive Kind where
  | record | prepare | driverPull | commitImage | commitLayer | fetch | abortPull | abortOther
  | forget | endPull | wake
  deriving DecidableEq

/-- The kind of an action. -/
def kindOf : Action → Kind
  | Action.Record _ _ => Kind.record
  | Action.Prepare _ => Kind.prepare
  | Action.DriverPull _ => Kind.driverPull
  | Action.CommitImage _ => Kind.commitImage
  | Action.CommitLayer _ => Kind.commitLayer
  | Action.Fetch _ => Kind.fetch
  | Action.Abort (Work.Pull _) => Kind.abortPull
  | Action.Abort (Work.Layer _) => Kind.abortOther
  | Action.Abort (Work.Group _) => Kind.abortOther
  | Action.Forget _ => Kind.forget
  | Action.End _ => Kind.endPull
  | Action.Wake _ => Kind.wake

/-- The action is of one of the kinds `ks`. -/
def OfKinds (ks : List Kind) (a : Action) : Prop := kindOf a ∈ ks

/-- Kinds that are among fewer kinds are among more. -/
theorem OfKinds.mono {ks ks' : List Kind} (sub : ks ⊆ ks') (a : Action) :
    OfKinds ks a → OfKinds ks' a :=
  fun h => sub h

/-- The action says nothing of any pull. -/
def AboutNoPull (a : Action) : Prop := ∀ p, ¬ about a p

/-- The action is neither the commit of an image (`CommitImage`) nor the driver's pull
(`DriverPull`), whatever the pull: the two actions that `advance` asks for a working pull, which then
goes on to its next step. -/
def NotPullStep (a : Action) : Prop := ∀ p, a ≠ Action.CommitImage p ∧ a ≠ Action.DriverPull p

/-- The kinds that say nothing of a pull. -/
abbrev noPullKinds : List Kind := [.commitLayer, .fetch, .abortOther, .forget, .wake]

/-- The kinds that are neither `CommitImage` nor `DriverPull`. -/
abbrev notPullStepKinds : List Kind :=
  [.record, .prepare, .commitLayer, .fetch, .abortPull, .abortOther, .forget, .endPull, .wake]

/-- An action of a kind that says nothing of a pull says nothing of a pull. -/
theorem AboutNoPull.of_kind {a : Action} (h : OfKinds noPullKinds a) : AboutNoPull a := by
  intro p
  cases a with
  | Abort w => cases w <;> simp_all [OfKinds, kindOf, about]
  | _ => simp_all [OfKinds, kindOf, about]

/-- An action of a kind that is neither `CommitImage` nor `DriverPull` is none of them. -/
theorem NotPullStep.of_kind {a : Action} (h : OfKinds notPullStepKinds a) : NotPullStep a := by
  intro p
  cases a <;> simp_all [OfKinds, kindOf]

/-- `AppendsOnly P old l`: `old` is the beginning of `l`, and every action after it satisfies
`P`. -/
def AppendsOnly (P : Action → Prop) (old l : List Action) : Prop :=
  old <+: l ∧ ∀ a ∈ l.drop old.length, P a

/-- `AppendsAboutNoPull old l`: `old` is the beginning of `l`, and every action after it says
nothing of any pull. -/
abbrev AppendsAboutNoPull (old l : List Action) : Prop := AppendsOnly AboutNoPull old l

/-- Nothing appended satisfies every `P`. -/
theorem AppendsOnly.refl {P : Action → Prop} (l : List Action) : AppendsOnly P l l :=
  ⟨List.prefix_refl _, by simp⟩

/-- A list that `AppendsOnly P` is the old one with actions that satisfy `P` appended. -/
theorem AppendsOnly.appended {P : Action → Prop} {old l : List Action}
    (appends : AppendsOnly P old l) : ∃ t, l = old ++ t ∧ ∀ a ∈ t, P a := by
  obtain ⟨⟨t, rfl⟩, after⟩ := appends
  exact ⟨t, rfl, by simpa using after⟩

/-- What is appended may be said with a weaker `P`. -/
theorem AppendsOnly.mono {P Q : Action → Prop} {old l : List Action}
    (appends : AppendsOnly P old l) (weaker : ∀ a, P a → Q a) : AppendsOnly Q old l :=
  ⟨appends.1, fun a ha => weaker a (appends.2 a ha)⟩

/-- What is appended after something that is appended is appended. -/
theorem AppendsOnly.trans {P : Action → Prop} {old mid l : List Action}
    (first : AppendsOnly P old mid) (second : AppendsOnly P mid l) : AppendsOnly P old l := by
  obtain ⟨t, rfl, in_t⟩ := first.appended
  obtain ⟨u, rfl, in_u⟩ := second.appended
  refine ⟨⟨t ++ u, by simp⟩, fun a ha => ?_⟩
  have drop_is : (old ++ t ++ u).drop old.length = t ++ u := by simp
  rw [drop_is] at ha
  rcases List.mem_append.mp ha with h | h
  exacts [in_t a h, in_u a h]

/-- `out` only grows: what was in it is still there, at the front. -/
theorem AppendsOnly.grows {P : Action → Prop} {old l : List Action}
    (appends : AppendsOnly P old l) : old <+: l :=
  appends.1

/-- What is appended is of the kinds `ks`, and `ks` is among the kinds that say nothing of a pull:
it says nothing of a pull (the proof of the inclusion is `by decide`). -/
theorem AppendsOnly.noPull {ks : List Kind} {old l : List Action}
    (appends : AppendsOnly (OfKinds ks) old l) (sub : ks ⊆ noPullKinds := by decide) :
    AppendsAboutNoPull old l :=
  appends.mono fun _ h => AboutNoPull.of_kind (OfKinds.mono sub _ h)

/-- What is appended is of the kinds `ks`, and `ks` is among the kinds that are neither
`CommitImage` nor `DriverPull`: it is neither. -/
theorem AppendsOnly.notPullStep {ks : List Kind} {old l : List Action}
    (appends : AppendsOnly (OfKinds ks) old l) (sub : ks ⊆ notPullStepKinds := by decide) :
    AppendsOnly NotPullStep old l :=
  appends.mono fun _ h => NotPullStep.of_kind (OfKinds.mono sub _ h)

/-- `Vec::push` of an action that satisfies `P` keeps a list `AppendsOnly P`. -/
theorem push_appends_only {P : Action → Prop} (v : alloc.vec.Vec Action) (x : Action)
    (old : List Action) (appends : AppendsOnly P old v.val) (is_p : P x) :
    Ok (v.push x) (fun v1 => AppendsOnly P old v1.val) := by
  obtain ⟨old_first, after⟩ := appends
  refine (push_appends v x).mono fun v1 appended => ?_
  rw [appended]
  refine ⟨old_first.trans (List.prefix_append _ _), fun a ha => ?_⟩
  rw [List.drop_append_of_le_length old_first.length_le] at ha
  simp only [List.mem_append, List.mem_singleton] at ha
  rcases ha with ha | rfl
  exacts [after a ha, is_p]

/-- `AppendsKinds m out ks before`: if the call `m` returns `r`, the actions `out r` are those of
`before` (the `out` the call was given) with actions of the kinds `ks` added at the end.  It is
what each lemma `f_kinds` says of a function `f`, and Lean finds the lemma of a function by
looking for an instance of this class (the lemmas are registered with `attribute [instance]`). -/
class AppendsKinds {β : Type} (m : Result β) (out : outParam (β → alloc.vec.Vec Action))
    (ks : outParam (List Kind)) (before : outParam (alloc.vec.Vec Action)) : Prop where
  appends : Ok m (fun r => AppendsOnly (OfKinds ks) before.val (out r).val)

/-- A call of a function of known kinds, made when `out` was appended with actions of the kinds
`ks'` since `old`, leaves `out` appended with actions of the kinds `ks'` since `old`, if the kinds
of the function are among them. -/
theorem AppendsKinds.after {β : Type} {m : Result β} {out : β → alloc.vec.Vec Action}
    {ks : List Kind} {before : alloc.vec.Vec Action} [callee : AppendsKinds m out ks before]
    {ks' : List Kind} {old : List Action} (earlier : AppendsOnly (OfKinds ks') old before.val)
    (sub : ks ⊆ ks') : Ok m (fun r => AppendsOnly (OfKinds ks') old (out r).val) :=
  callee.appends.mono fun _ appended => earlier.trans (appended.mono (OfKinds.mono sub))

/-- `appends_only`: prove "`out` stays `AppendsOnly (OfKinds ks)`" for the body of a Rust function,
line by line, as explained at the top of this file. -/
macro "appends_only" : tactic => `(tactic| repeat (first
  | (apply Ok.ok.mpr; (try simp only [uncurry_eq, bind_tc_ok, bind_ok, bind_assoc_eq,
      Std.bind_assoc] at *); assumption)
  | exact Ok.fail
  | (refine Ok.bind (push_appends_only _ _ _ (by assumption) (by simp [OfKinds, kindOf])) ?_;
      intro x hx;
      try simp only [uncurry_eq, bind_tc_ok, bind_ok, bind_assoc_eq, Std.bind_assoc] at hx ⊢)
  | simp only [uncurry_eq, bind_tc_ok, bind_ok, bind_assoc_eq, Std.bind_assoc]
  | split
  | exact AppendsKinds.after (by assumption) (by decide)
  | (refine Ok.bind (AppendsKinds.after (by assumption) (by decide)) ?_; intro x hx;
      try simp only [uncurry_eq, bind_tc_ok, bind_ok, bind_assoc_eq, Std.bind_assoc] at hx ⊢)
  | (refine Ok.bind (Ok.any _) ?_; intro x _)))

/-- `begin_try` pushes `Record` and `Prepare`. -/
theorem begin_try_kinds (c : Core) (at_ : Std.Usize) (out : alloc.vec.Vec Action) :
    AppendsKinds (begin_try c at_ out) (·.2) [.record, .prepare] out := by
  refine ⟨?_⟩
  unfold begin_try
  have appended : AppendsOnly (OfKinds [.record, .prepare]) out.val out.val := AppendsOnly.refl _
  appends_only

attribute [instance] begin_try_kinds

/-- The first loop of `let_go`, over the layers, pushes `Abort` of a layer's commit and `Forget`. -/
theorem let_go_loop0_kinds (iter : core.slice.iter.Iter Layer) (out : alloc.vec.Vec Action)
    (mine : alloc.vec.Vec Std.U32) (pulls : alloc.vec.Vec Pull) :
    AppendsKinds (let_go_loop0 iter out mine pulls) (·) [.abortOther, .forget] out := by
  refine ⟨?_⟩
  unfold let_go_loop0
  refine Ok.loop (I := fun x => AppendsOnly (OfKinds [.abortOther, .forget]) out.val (x.2.val)) ?_ (AppendsOnly.refl _)
  rintro ⟨iter, out⟩ appended
  dsimp only at appended
  unfold let_go_loop0.body
  appends_only

attribute [instance] let_go_loop0_kinds

/-- The second loop of `let_go`, over the groups, pushes `Abort` of a group and `Forget`. -/
theorem let_go_loop1_kinds (iter : core.slice.iter.IterMut Group)
    (back : core.slice.iter.IterMut Group → core.slice.iter.IterMut Group)
    (out : alloc.vec.Vec Action) (me : Std.U32) (pulls : alloc.vec.Vec Pull) :
    AppendsKinds (let_go_loop1 iter back out me pulls) (·.1) [.abortOther, .forget] out := by
  refine ⟨?_⟩
  unfold let_go_loop1
  refine Ok.loop (I := fun x => AppendsOnly (OfKinds [.abortOther, .forget]) out.val (x.2.2.val)) ?_ (AppendsOnly.refl _)
  rintro ⟨iter, back, out⟩ appended
  dsimp only at appended
  unfold let_go_loop1.body
  appends_only

attribute [instance] let_go_loop1_kinds

/-- `let_go` pushes `Abort` and `Forget` of layers and groups, through its two loops. -/
theorem let_go_kinds (c : Core) (at_ : Std.Usize) (out : alloc.vec.Vec Action) :
    AppendsKinds (let_go c at_ out) (·.2) [.abortOther, .forget] out := by
  refine ⟨?_⟩
  unfold let_go
  have appended : AppendsOnly (OfKinds [.abortOther, .forget]) out.val out.val := AppendsOnly.refl _
  appends_only

attribute [instance] let_go_kinds

/-- The loop of `leave` that gives the freed place to the pulls that wait pushes what `begin_try` pushes. -/
theorem leave_loop_kinds (iter : core.ops.range.Range Std.Usize) (c : Core) (out : alloc.vec.Vec Action) :
    AppendsKinds (leave_loop iter c out) (·.2) [.record, .prepare] out := by
  refine ⟨?_⟩
  unfold leave_loop
  refine Ok.loop (I := fun x => AppendsOnly (OfKinds [.record, .prepare]) out.val (x.2.2.val)) ?_ (AppendsOnly.refl _)
  rintro ⟨iter, c, out⟩ appended
  dsimp only at appended
  unfold leave_loop.body
  appends_only

attribute [instance] leave_loop_kinds

/-- `leave` pushes what `let_go` pushes, `End`, and what the loop that gives the place away pushes. -/
theorem leave_kinds (c : Core) (at_ : Std.Usize) (out : alloc.vec.Vec Action) :
    AppendsKinds (leave c at_ out) (·.2) [.abortOther, .forget, .endPull, .record, .prepare] out := by
  refine ⟨?_⟩
  unfold leave
  have appended : AppendsOnly (OfKinds [.abortOther, .forget, .endPull, .record, .prepare]) out.val out.val := AppendsOnly.refl _
  appends_only

attribute [instance] leave_kinds

/-- The loop of `cancel` over the pulls that shared a layer pushes what `let_go` and `begin_try` push. -/
theorem cancel_loop_kinds (iter : alloc.vec.into_iter.IntoIter Std.U32) (c : Core) (out : alloc.vec.Vec Action) :
    AppendsKinds (cancel_loop iter c out) (·.2) [.abortOther, .forget, .record, .prepare] out := by
  refine ⟨?_⟩
  unfold cancel_loop
  refine Ok.loop (I := fun x => AppendsOnly (OfKinds [.abortOther, .forget, .record, .prepare]) out.val (x.2.2.val)) ?_ (AppendsOnly.refl _)
  rintro ⟨iter, c, out⟩ appended
  dsimp only at appended
  unfold cancel_loop.body
  appends_only

attribute [instance] cancel_loop_kinds

/-- `cancel` pushes what `leave` pushes, or what `let_go` pushes, `Abort` of the pull, and what its loop pushes. -/
theorem cancel_kinds (c : Core) (pull : Std.U32) (out : alloc.vec.Vec Action) :
    AppendsKinds (cancel c pull out) (·.2) [.abortOther, .forget, .endPull, .record, .prepare, .abortPull] out := by
  refine ⟨?_⟩
  unfold cancel
  have appended : AppendsOnly (OfKinds [.abortOther, .forget, .endPull, .record, .prepare, .abortPull]) out.val out.val := AppendsOnly.refl _
  appends_only

attribute [instance] cancel_kinds

/-- The loop of `advance` over the layers pushes `CommitLayer`. -/
theorem advance_loop2_kinds (iter : core.slice.iter.IterMut Layer)
    (back : core.slice.iter.IterMut Layer → core.slice.iter.IterMut Layer)
    (cfg : Cfg) (out : alloc.vec.Vec Action) (working committing : Std.Usize)
    (groups : alloc.vec.Vec Group) :
    AppendsKinds (advance_loop2 iter back cfg out working committing groups) (·.2.1) [.commitLayer] out := by
  refine ⟨?_⟩
  unfold advance_loop2
  refine Ok.loop (I := fun x => AppendsOnly (OfKinds [.commitLayer]) out.val (x.2.2.1.val)) ?_ (AppendsOnly.refl _)
  rintro ⟨iter, back, out, committing⟩ appended
  dsimp only at appended
  unfold advance_loop2.body
  appends_only

attribute [instance] advance_loop2_kinds

/-- The loop of `advance` over the pulls pushes `CommitImage` and `DriverPull`. -/
theorem advance_loop3_kinds (iter : core.slice.iter.IterMut Pull)
    (back : core.slice.iter.IterMut Pull → core.slice.iter.IterMut Pull)
    (out : alloc.vec.Vec Action) (layers : alloc.vec.Vec Layer) :
    AppendsKinds (advance_loop3 iter back out layers) (·.1) [.commitImage, .driverPull] out := by
  refine ⟨?_⟩
  unfold advance_loop3
  refine Ok.loop (I := fun x => AppendsOnly (OfKinds [.commitImage, .driverPull]) out.val (x.2.2.val)) ?_ (AppendsOnly.refl _)
  rintro ⟨iter, back, out⟩ appended
  dsimp only at appended
  unfold advance_loop3.body
  appends_only

attribute [instance] advance_loop3_kinds

/-- The inner loop of the third loop of `advance`, over the groups of a pull, pushes `Fetch`. -/
theorem advance_loop4_loop0_kinds (iter : core.ops.range.Range Std.Usize)
    (pulls : alloc.vec.Vec Pull) (v : alloc.vec.Vec Group) (out : alloc.vec.Vec Action)
    (p : Std.Usize) (limit id sent : Std.U32) :
    AppendsKinds (advance_loop4_loop0 iter pulls v out p limit id sent) (·.2) [.fetch] out := by
  refine ⟨?_⟩
  unfold advance_loop4_loop0
  refine Ok.loop (I := fun x => AppendsOnly (OfKinds [.fetch]) out.val (x.2.2.1.val)) ?_ (AppendsOnly.refl _)
  rintro ⟨iter, v, out, sent⟩ appended
  dsimp only at appended
  unfold advance_loop4_loop0.body
  appends_only

attribute [instance] advance_loop4_loop0_kinds

/-- The third loop of `advance`, over the pulls and their groups, pushes `Fetch`. -/
theorem advance_loop4_kinds (iter : core.ops.range.Range Std.Usize) (cfg : Cfg)
    (pulls : alloc.vec.Vec Pull) (layers : alloc.vec.Vec Layer)
    (groups : alloc.vec.Vec Group) (starts : alloc.vec.Vec ContainerStart)
    (now : Std.U64) (out : alloc.vec.Vec Action) :
    AppendsKinds (advance_loop4 iter cfg pulls layers groups starts now out) (·.2.2) [.fetch] out := by
  refine ⟨?_⟩
  unfold advance_loop4
  refine Ok.loop (I := fun x => AppendsOnly (OfKinds [.fetch]) out.val (x.2.2.val)) ?_ (AppendsOnly.refl _)
  rintro ⟨iter, groups, out⟩ appended
  dsimp only at appended
  unfold advance_loop4.body
  appends_only

attribute [instance] advance_loop4_kinds

/-- `advance` pushes `CommitLayer`, `CommitImage`, `DriverPull` and `Fetch`, through its loops. -/
theorem advance_kinds (c : Core) (now : Std.U64) (out : alloc.vec.Vec Action) :
    AppendsKinds (advance c now out) (·.2) [.commitLayer, .commitImage, .driverPull, .fetch] out := by
  refine ⟨?_⟩
  unfold advance
  have appended : AppendsOnly (OfKinds [.commitLayer, .commitImage, .driverPull, .fetch]) out.val out.val := AppendsOnly.refl _
  appends_only

attribute [instance] advance_kinds

/-- The loop of `prepared` that tells back the layers of a late answer pushes `Forget`. -/
theorem prepared_loop0_kinds (iter : alloc.vec.into_iter.IntoIter Std.U32)
    (out : alloc.vec.Vec Action) :
    AppendsKinds (prepared_loop0 iter out) (·) [.forget] out := by
  refine ⟨?_⟩
  unfold prepared_loop0
  refine Ok.loop (I := fun x => AppendsOnly (OfKinds [.forget]) out.val (x.2.val)) ?_ (AppendsOnly.refl _)
  rintro ⟨iter, out⟩ appended
  dsimp only at appended
  unfold prepared_loop0.body
  appends_only

attribute [instance] prepared_loop0_kinds

/-- The loop of `prepared` that tells back the groups of a late answer pushes `Forget`. -/
theorem prepared_loop1_kinds (iter : alloc.vec.into_iter.IntoIter GroupFact)
    (out : alloc.vec.Vec Action) :
    AppendsKinds (prepared_loop1 iter out) (·) [.forget] out := by
  refine ⟨?_⟩
  unfold prepared_loop1
  refine Ok.loop (I := fun x => AppendsOnly (OfKinds [.forget]) out.val (x.2.val)) ?_ (AppendsOnly.refl _)
  rintro ⟨iter, out⟩ appended
  dsimp only at appended
  unfold prepared_loop1.body
  appends_only

attribute [instance] prepared_loop1_kinds

/-- The loop of `prepared` over the groups of an answer in time (it keeps a group for the new layers that wait for it, or tells it back) pushes `Forget`. -/
theorem prepared_loop2_kinds (iter : alloc.vec.into_iter.IntoIter GroupFact)
    (v : alloc.vec.Vec Group) (out : alloc.vec.Vec Action) (fresh : alloc.vec.Vec Std.U32) :
    AppendsKinds (prepared_loop2 iter v out fresh) (·.2) [.forget] out := by
  refine ⟨?_⟩
  unfold prepared_loop2
  refine Ok.loop (I := fun x => AppendsOnly (OfKinds [.forget]) out.val (x.2.2.val)) ?_ (AppendsOnly.refl _)
  rintro ⟨iter, v, out⟩ appended
  dsimp only at appended
  unfold prepared_loop2.body
  appends_only

attribute [instance] prepared_loop2_kinds

/-- `add` pushes what `begin_try` pushes, and `Record`. -/
theorem add_kinds (c : Core) (pull : Std.U32) (containers : Bool)
    (out : alloc.vec.Vec Action) :
    AppendsKinds (add c pull containers out) (·.2) [.record, .prepare] out := by
  refine ⟨?_⟩
  unfold add
  have appended : AppendsOnly (OfKinds [.record, .prepare]) out.val out.val := AppendsOnly.refl _
  appends_only

attribute [instance] add_kinds

/-- `try_failed` pushes `Record` and `Wake`, and what `let_go` and `leave` push. -/
theorem try_failed_kinds (c : Core) (now : Std.U64) (at_ : Std.Usize) (cl : Class)
    (out : alloc.vec.Vec Action) :
    AppendsKinds (try_failed c now at_ cl out) (·.2) [.record, .abortOther, .forget, .wake, .endPull, .prepare] out := by
  refine ⟨?_⟩
  unfold try_failed
  have appended : AppendsOnly (OfKinds [.record, .abortOther, .forget, .wake, .endPull, .prepare]) out.val out.val := AppendsOnly.refl _
  appends_only

attribute [instance] try_failed_kinds

/-- The loop of `failed` over the pulls whose try fails pushes what `try_failed` pushes. -/
theorem failed_loop0_kinds (iter : alloc.vec.into_iter.IntoIter Std.U32) (c : Core)
    (now : Std.U64) (cl : Class) (out : alloc.vec.Vec Action) :
    AppendsKinds (failed_loop0 iter c now cl out) (·.2) [.record, .abortOther, .forget, .wake, .endPull, .prepare] out := by
  refine ⟨?_⟩
  unfold failed_loop0
  refine Ok.loop (I := fun x => AppendsOnly (OfKinds [.record, .abortOther, .forget, .wake, .endPull, .prepare]) out.val (x.2.2.val)) ?_ (AppendsOnly.refl _)
  rintro ⟨iter, c, out⟩ appended
  dsimp only at appended
  unfold failed_loop0.body
  appends_only

attribute [instance] failed_loop0_kinds

/-- The same loop of `failed`, for the layer that failed (Aeneas extracts it three times). -/
theorem failed_loop1_kinds (iter : alloc.vec.into_iter.IntoIter Std.U32) (c : Core)
    (now : Std.U64) (cl : Class) (out : alloc.vec.Vec Action) :
    AppendsKinds (failed_loop1 iter c now cl out) (·.2) [.record, .abortOther, .forget, .wake, .endPull, .prepare] out := by
  refine ⟨?_⟩
  unfold failed_loop1
  refine Ok.loop (I := fun x => AppendsOnly (OfKinds [.record, .abortOther, .forget, .wake, .endPull, .prepare]) out.val (x.2.2.val)) ?_ (AppendsOnly.refl _)
  rintro ⟨iter, c, out⟩ appended
  dsimp only at appended
  unfold failed_loop1.body
  appends_only

attribute [instance] failed_loop1_kinds

/-- The same loop of `failed`, for the group that failed. -/
theorem failed_loop2_kinds (iter : alloc.vec.into_iter.IntoIter Std.U32) (c : Core)
    (now : Std.U64) (cl : Class) (out : alloc.vec.Vec Action) :
    AppendsKinds (failed_loop2 iter c now cl out) (·.2) [.record, .abortOther, .forget, .wake, .endPull, .prepare] out := by
  refine ⟨?_⟩
  unfold failed_loop2
  refine Ok.loop (I := fun x => AppendsOnly (OfKinds [.record, .abortOther, .forget, .wake, .endPull, .prepare]) out.val (x.2.2.val)) ?_ (AppendsOnly.refl _)
  rintro ⟨iter, c, out⟩ appended
  dsimp only at appended
  unfold failed_loop2.body
  appends_only

attribute [instance] failed_loop2_kinds

/-- `failed` pushes what `try_failed` pushes for the tries that fail, or what `leave` pushes. -/
theorem failed_kinds (c : Core) (now : Std.U64) (work : Work) (cl : Class)
    (out : alloc.vec.Vec Action) :
    AppendsKinds (failed c now work cl out) (·.2) [.record, .abortOther, .forget, .wake, .endPull, .prepare] out := by
  refine ⟨?_⟩
  unfold failed
  have appended : AppendsOnly (OfKinds [.record, .abortOther, .forget, .wake, .endPull, .prepare]) out.val out.val := AppendsOnly.refl _
  appends_only

attribute [instance] failed_kinds

/-- `succeeded` pushes what `leave` pushes, for a pull that ends. -/
theorem succeeded_kinds (c : Core) (work : Work) (out : alloc.vec.Vec Action) :
    AppendsKinds (succeeded c work out) (·.2) [.abortOther, .forget, .endPull, .record, .prepare] out := by
  refine ⟨?_⟩
  unfold succeeded
  have appended : AppendsOnly (OfKinds [.abortOther, .forget, .endPull, .record, .prepare]) out.val out.val := AppendsOnly.refl _
  appends_only

attribute [instance] succeeded_kinds

/-- `prepared` pushes `Forget` only. -/
theorem prepared_kinds (c : Core) (pull : Std.U32) (layers : alloc.vec.Vec Std.U32)
    (groups : alloc.vec.Vec GroupFact) (out : alloc.vec.Vec Action) :
    AppendsKinds (prepared c pull layers groups out) (·.2) [.forget] out := by
  refine ⟨?_⟩
  unfold prepared
  have appended : AppendsOnly (OfKinds [.forget]) out.val out.val := AppendsOnly.refl _
  appends_only

attribute [instance] prepared_kinds

/-- The loop of a `Tick` over the pulls pushes what `begin_try` pushes, for those whose wait is over. -/
theorem step_loop_kinds (iter : core.ops.range.Range Std.Usize) (c : Core)
    (now : Std.U64) (out : alloc.vec.Vec Action) :
    AppendsKinds (step_loop iter c now out) (·.2) [.record, .prepare] out := by
  refine ⟨?_⟩
  unfold step_loop
  refine Ok.loop (I := fun x => AppendsOnly (OfKinds [.record, .prepare]) out.val (x.2.2.val)) ?_ (AppendsOnly.refl _)
  rintro ⟨iter, c, out⟩ appended
  dsimp only at appended
  unfold step_loop.body
  appends_only

attribute [instance] step_loop_kinds

end LazyCore
