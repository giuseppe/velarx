-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the shape of `step` of crates/lazy-core, proved once.  `step` is a `match`
-- on the event.  `Added`, `Cancel`, `Prepared` and `Done` call a function (`add`, `cancel`,
-- `prepared`, `succeeded` or `failed`) and then `advance`; `Hurry`, `StartBegan`, `StartEnded` and
-- `Tick` are code of `step` itself.  `StepFacts` lists, one field per piece of that code, what a
-- proof about `step` has to show; `StepFacts.holds` says that then `step` does what is claimed.
-- It is used once here too: for `AStepOnlyAddsActions` of Spec.lean.
--
-- Why it is needed: Names.lean, Stopping.lean, Tables.lean and Image.lean each prove a claim about
-- `step` by the same walk of the `match`, and only the facts about the pieces differ.  The walk is
-- here once; each of those files gives its facts, one line for each event, and applies `StepFacts.holds`.
--
-- How to read a use.  A claim about `step c now ev out` is `Ok (step c now ev out) Q`: if `step`
-- returns, `(c', out')` satisfies `Q`.  The calls before `advance` are shown to satisfy a weaker
-- `A`, and `advance` takes `A` to `Q`:
--
--     add, cancel, prepared, succeeded, failed, ...   satisfy `A`
--     advance                                         takes `A` to `Q`
--
-- (for most claims `A` and `Q` are the same).  `told` is what the caller promises of the event:
-- `prepared` needs it, and the others do not.
--
-- Read before this file: Ok.lean, Grows.lean and Pulls.lean.
--
-- Notation: `Ok m P` is "if `m` returns, its result satisfies `P`"; `r.1`, `r.2` are the first and
-- second element of a pair; `∀ r, A r → ...` is "for every result `r` that satisfies `A`, ...".
import LazyCore.Pulls

open Aeneas Aeneas.Std Result velarx_lazy_core

namespace LazyCore

attribute [local irreducible] begin_try let_go leave_loop cancel_loop cancel advance_loop2
  advance_loop3 advance_loop4_loop0 advance_loop4 advance Core.pull_at

/-- The core `c` after `Hurry` boosted the pull at `at_` (the Rust `c.pulls[at].boosted = true`):
the pull is written back with the one field changed. -/
def hurried (c : Core) (at_ : Std.Usize) (in_range : at_.val < c.pulls.val.length) : Core :=
  { c with pulls := alloc.vec.Vec.set c.pulls at_ { c.pulls.val[at_.val] with boosted := true } }

/-- The pull waits for its turn or for a time: `Hurry` begins its try. -/
def Idle (p : Pull) : Prop :=
  p.phase = Phase.Queued ∨ ∃ t, p.phase = Phase.Waiting t

/-- `StepFacts c now out told A Q`: what is to be shown, of the core `c` and the actions `out` that
`step` is called with, for `Ok (step c now ev out) Q` to hold for every event `ev` that is `told`.
`A` is what each function that `step` calls before `advance` leaves, and `Q` what `step` leaves. -/
structure StepFacts (c : Core) (now : Std.U64) (out : alloc.vec.Vec Action)
    (told : Event → Prop) (A Q : Core × alloc.vec.Vec Action → Prop) : Prop where
  /-- `advance` takes what the call before it left (`A`) to what `step` leaves (`Q`). -/
  advance_ok : ∀ r, A r → Ok (advance r.1 now r.2) Q
  /-- `add` leaves `A`. -/
  add_ok : ∀ pull containers, Ok (add c pull containers out) A
  /-- `cancel` leaves `A`. -/
  cancel_ok : ∀ pull, Ok (cancel c pull out) A
  /-- `prepared` leaves `A`, for what the caller promises of the event. -/
  prepared_ok : ∀ pull layers groups, told (Event.Prepared pull layers groups) →
    Ok (prepared c pull layers groups out) A
  /-- `succeeded` leaves `A`. -/
  succeeded_ok : ∀ work, Ok (succeeded c work out) A
  /-- `failed` leaves `A`. -/
  failed_ok : ∀ work cl, Ok (failed c now work cl out) A
  /-- `Hurry` of a name no pull has: `step` returns `(c, out)`, and it is `Q`. -/
  hurry_of_none : Q (c, out)
  /-- `Hurry` of a pull: it is boosted, and that leaves `A`. -/
  hurry_boosts : ∀ at_ (in_range : at_.val < c.pulls.val.length), A (hurried c at_ in_range, out)
  /-- `Hurry` of a pull that is queued or waits: the boosted pull begins its try, which leaves `A`. -/
  hurry_begins : ∀ at_ (in_range : at_.val < c.pulls.val.length), Idle c.pulls.val[at_.val] →
    Ok (begin_try (hurried c at_ in_range) at_ out) A
  /-- The record of the starts of a layer is changed (`start_at`), whatever is written back: it is
  `Q` with the same `out`. -/
  start_of_a_layer : ∀ layer, Ok (start_at c layer now) (fun r => ∀ cs, Q (r.2 cs, out))
  /-- A `Wake` pushed to the actions of something that is `Q` is `Q`. -/
  wake : ∀ r, Q r → ∀ t out1, out1.val = r.2.val ++ [Action.Wake t] → Q (r.1, out1)
  /-- The loop of a `Tick` over the pulls leaves `A`. -/
  tick_loop : ∀ iter, Ok (step_loop iter c now out) A

/-- **The shape of `step`.**  When the facts of `StepFacts` hold, `step` of an event that is `told`
leaves `Q`: one case for each event of the `match` of `step`. -/
theorem StepFacts.holds {c : Core} {now : Std.U64} {out : alloc.vec.Vec Action}
    {told : Event → Prop} {A Q : Core × alloc.vec.Vec Action → Prop}
    (facts : StepFacts c now out told A Q) (ev : Event) (is_told : told ev) :
    Ok (step c now ev out) Q := by
  -- a call of a function that leaves `A`, then `advance`
  have then_advance : ∀ {m : Result (Core × alloc.vec.Vec Action)}, Ok m A →
      Ok (do let (c1, out1) ← m; advance c1 now out1) Q :=
    fun first => Ok.bind first fun r a => facts.advance_ok r a
  unfold velarx_lazy_core.step
  cases ev with
  | Added pull containers => exact then_advance (facts.add_ok pull containers)
  | Hurry pull =>
    -- the pull is looked up, boosted, and begins its try if it is queued or waits
    refine Ok.bind (pull_at_sound c pull) ?_
    intro o found
    cases o with
    | none => exact Ok.ok.mpr facts.hurry_of_none
    | some at_ =>
      obtain ⟨in_range, _⟩ := found at_ rfl
      simp only []
      refine Ok.bind (index_mut_result _ _) ?_
      rintro _ ⟨in_range', rfl⟩
      simp only [uncurry_eq]
      refine Ok.bind (index_result _ _) ?_
      rintro p1 ⟨_, is_p1⟩
      have same_phase : p1.phase = c.pulls.val[at_.val].phase := by
        rw [is_p1]; simp [alloc.vec.Vec.set]
      have boosted := facts.hurry_boosts at_ in_range
      -- (the test on the phase of the pull as it is: `Queued` or `Waiting` begin the try)
      rcases hph : p1.phase with _ | s | t | _ <;>
        simp only [bind_ok, Bool.false_eq_true, ↓reduceIte]
      · exact then_advance (facts.hurry_begins at_ in_range (Or.inl (same_phase ▸ hph)))
      · exact facts.advance_ok _ boosted
      · exact then_advance (facts.hurry_begins at_ in_range (Or.inr ⟨t, same_phase ▸ hph⟩))
      · exact facts.advance_ok _ boosted
  | Cancel pull => exact then_advance (facts.cancel_ok pull)
  | Prepared pull layers groups => exact then_advance (facts.prepared_ok pull layers groups is_told)
  | Done work r =>
    cases r with
    | Ok done => exact then_advance (facts.succeeded_ok work)
    | Err cl => exact then_advance (facts.failed_ok work cl)
  | StartBegan layer =>
    refine Ok.bind (facts.start_of_a_layer layer) ?_
    rintro ⟨start, back⟩ starts
    refine Ok.bind (Ok.any _) ?_; intro i _
    exact Ok.ok.mpr (starts _)
  | StartEnded layer =>
    refine Ok.bind (facts.start_of_a_layer layer) ?_
    rintro ⟨start, back⟩ starts
    refine Ok.bind (Ok.any _) ?_; intro i _
    refine Ok.bind (Ok.any _) ?_; intro i1 _
    refine Ok.bind (push_appends _ _) ?_; intro out1 pushed
    exact Ok.ok.mpr (facts.wake _ (starts _) i1 out1 pushed)
  | Tick =>
    refine Ok.bind (facts.tick_loop _) ?_
    rintro ⟨c1, out1⟩ looped
    refine Ok.bind (facts.advance_ok _ looped) ?_
    rintro ⟨c2, out2⟩ advanced
    refine Ok.bind (Ok.any _) ?_; intro o _
    cases o with
    | none => exact Ok.ok.mpr advanced
    | some t =>
      simp only []
      refine Ok.bind (push_appends _ _) ?_; intro out3 pushed
      exact Ok.ok.mpr (facts.wake _ advanced t out3 pushed)

/-- **`step` only adds actions.**  Whatever the event, if `step` returns, the actions it leaves are
the `out` it was given with more at the end: each function it calls only pushes (`Grows.lean`), and
the events that call none push at most a `Wake`. -/
theorem step_only_adds (c : Core) (now : Std.U64) (ev : Event) (out : alloc.vec.Vec Action) :
    Ok (step c now ev out) (fun r => out.val <+: r.2.val) :=
  have nothing : out.val <+: out.val := List.prefix_refl _
  StepFacts.holds (told := fun _ => True) (A := fun r => out.val <+: r.2.val)
    (Q := fun r => out.val <+: r.2.val)
    { advance_ok := fun r grown =>
        (advance_kinds r.1 now r.2).appends.mono fun _ h => grown.trans h.grows
      add_ok := fun pull containers => (add_kinds c pull containers out).appends.mono fun _ h => h.grows
      cancel_ok := fun pull => (cancel_kinds c pull out).appends.mono fun _ h => h.grows
      prepared_ok := fun pull layers groups _ =>
        (prepared_kinds c pull layers groups out).appends.mono fun _ h => h.grows
      succeeded_ok := fun work => (succeeded_kinds c work out).appends.mono fun _ h => h.grows
      failed_ok := fun work cl => (failed_kinds c now work cl out).appends.mono fun _ h => h.grows
      hurry_of_none := nothing
      hurry_boosts := fun _ _ => nothing
      hurry_begins := fun at_ _ _ => (begin_try_kinds _ at_ out).appends.mono fun _ h => h.grows
      start_of_a_layer := fun layer => (Ok.any (start_at c layer now)).mono fun _ _ _cs => nothing
      wake := fun _ grown _ _ pushed =>
        grown.trans (pushed ▸ List.prefix_append _ _)
      tick_loop := fun iter => (step_loop_kinds iter c now out).appends.mono fun _ h => h.grows }
    ev trivial

/-- **`step` only adds actions** (the statement of Spec.lean): `step_only_adds`, with the
beginning of a list as "the list with more at its end". -/
theorem a_step_only_adds_actions : AStepOnlyAddsActions := by
  intro c now ev out c' out' returns
  obtain ⟨t, rest⟩ := (step_only_adds c now ev out).eq returns
  exact ⟨t, rest.symm⟩

end LazyCore
