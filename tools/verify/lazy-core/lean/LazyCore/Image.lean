-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of `AnImageIsCommittedAfterItsLayers` and of
-- `ADriverPullFollowsItsLayers` (Spec.lean).  When the step asks for the commit of the image of a
-- pull (`CommitImage p`), the core holds the pull at the step `Image`, and every layer the pull
-- lacks is in the table of the layers, in the state `Stored`.  When it asks for the driver's pull
-- (`DriverPull p`), the core holds the pull at the step `DriverPull`, and every layer the pull
-- lacks is in the table, `Ready` or `Stored`.
--
-- Why it is needed: an image named in the store before its layers are is the bug "named before
-- durable".  This is the claim that `advance` does not make it, whatever the events before.
--
-- The argument follows the Rust, from the inside out:
--   1. Only `advance` asks for `CommitImage` and `DriverPull`.  Every other function of lib.rs that
--      `step` calls before `advance` (`add`, `begin_try`, `cancel`, `prepared`, `succeeded`,
--      `failed`, `leave`, `let_go`, the loops of them and of `Tick`) pushes actions of kinds that
--      are neither: the lemma `f_kinds` of each function (Grows.lean) says which kinds it pushes,
--      and `AppendsOnly.notPullStep` takes "neither" from it.
--   2. `advance` asks for the commit of a pull in its loop over the pulls, when
--      `p.has_all(layers, |s| s == Stored)` says yes, and then sets the phase to `Image`; it asks for
--      the driver's pull when that says no and `p.has_all(layers, |s| matches!(s, Ready | Stored))`
--      says yes, and sets the phase to `DriverPull`.  From the loop form of `has_all`, "yes" means
--      that every layer of the table that the pull lacks is in that state (`has_all_iff`,
--      Pulls.lean); `advance_loop3_keeps_pulls` and `advance_keeps_pulls` (Verdict.lean) carry it to
--      the core `advance` leaves (`AllStored`, `AllReady`).
--   3. `step_follows` puts the two together for every event (`Follows`; the walk of the events
--      of `step` is Step.lean), and the claims follow with
--      `the_tables_stay_well_formed` (Tables.lean): a layer a pull lacks is in the table, and
--      the names of the pulls are distinct.
--
-- Read before this file: Grows.lean (`AppendsKinds`, `appends_only`), Verdict.lean (`AllStored`,
-- `AllReady`, `advance_keeps_pulls`), Step.lean, Tables.lean, and the statements in Spec.lean.
--
-- A "pull step" is `CommitImage` or `DriverPull`, the two actions that move a working pull on.
--
-- Notation: besides the notations of the files above, `AppendsOnly NotPullStep old l` is "`l` is
-- `old` with actions added at the end, none of them `CommitImage _` or `DriverPull _`", `Ok m P` is
-- "if `m` returns, its result satisfies `P`" and `r.1`, `r.2` are the first and second element of a
-- pair.
import LazyCore.Tables

open Aeneas Aeneas.Std Result velarx_lazy_core

namespace LazyCore

/-- `ReadyForImage c p`: the core holds the pull `p` at the step `Image`, and every layer of the
table that `p` lacks is `Stored` (this is what `advance` leaves when it asks for the commit of the
image of `p`). -/
def ReadyForImage (c : Core) (p : Std.U32) : Prop :=
  ∃ q ∈ c.pulls.val, q.id = p ∧ q.phase = Phase.Running Step.Image ∧
    AllStored c.layers.val q

/-- `ReadyForDriver c p`: the core holds the pull `p` at the step `DriverPull`, and every layer of
the table that `p` lacks is `Ready` or `Stored` (this is what `advance` leaves when it asks for the
driver's pull of `p`). -/
def ReadyForDriver (c : Core) (p : Std.U32) : Prop :=
  ∃ q ∈ c.pulls.val, q.id = p ∧ q.phase = Phase.Running Step.DriverPull ∧
    AllReady c.layers.val q

/-- `Follows c new`: of the actions `new` that a step added, a commit of the image of `p` is only
there if the core `c` the step leaves is `ReadyForImage` for `p`, and a driver's pull of `p` only
if it is `ReadyForDriver` for `p`. -/
def Follows (c : Core) (new : List Action) : Prop :=
  ∀ p, (Action.CommitImage p ∈ new → ReadyForImage c p) ∧
    (Action.DriverPull p ∈ new → ReadyForDriver c p)

/-- Actions that are neither a commit of an image nor a driver's pull follow trivially. -/
theorem Follows.of_none {c : Core} {new : List Action} (none : ∀ a ∈ new, NotPullStep a) :
    Follows c new :=
  fun p => ⟨fun h => absurd rfl (none _ h p).1, fun h => absurd rfl (none _ h p).2⟩

/-- If every action of `new'` is one of `new` or neither a commit of an image nor a driver's pull,
`new'` follows when `new` does. -/
theorem Follows.extend {c : Core} {new new' : List Action} (follows : Follows c new)
    (sub : ∀ a ∈ new', a ∈ new ∨ NotPullStep a) : Follows c new' :=
  fun p => ⟨fun h => (sub _ h).elim (fun in_new => (follows p).1 in_new)
      fun not_step => absurd rfl (not_step p).1,
    fun h => (sub _ h).elim (fun in_new => (follows p).2 in_new)
      fun not_step => absurd rfl (not_step p).2⟩

/-- `advance`, called after something that pushed no commit and no driver's pull since `out`, leaves
a core that `Follows` what was pushed since `out`: `advance_keeps_pulls` says it of what `advance`
itself pushed, and what was pushed before is neither. -/
theorem advance_follows (c : Core) (now : Std.U64) (out1 : alloc.vec.Vec Action)
    (out : List Action) (no_pull_step : AppendsOnly NotPullStep out out1.val) :
    Ok (advance c now out1) (fun r => Follows r.1 (r.2.val.drop out.length)) := by
  refine (advance_keeps_pulls c now out1).mono ?_
  rintro r ⟨⟨t, pushed, _⟩, _, _, _, commits, drivers⟩
  obtain ⟨t0, is_out1, not_steps⟩ := no_pull_step.appended
  have drop_is : r.2.val.drop out.length = t0 ++ t := by
    rw [pushed, is_out1]; simp
  refine fun p => ⟨fun asked => ?_, fun asked => ?_⟩
  · rw [drop_is] at asked
    rcases List.mem_append.mp asked with in_t0 | in_new
    · exact absurd rfl (not_steps _ in_t0 p).1
    · exact commits p (by simpa [pushed] using in_new)
  · rw [drop_is] at asked
    rcases List.mem_append.mp asked with in_t0 | in_new
    · exact absurd rfl (not_steps _ in_t0 p).2
    · exact drivers p (by simpa [pushed] using in_new)

/-- A `Wake` pushed after something that `Follows` still does: a `Wake` is neither a commit of an
image nor a driver's pull. -/
theorem Follows.wake {c : Core} {out out1 : alloc.vec.Vec Action} {old : List Action}
    (follows : Follows c (out.val.drop old.length)) {t : Std.U64}
    (pushed : out1.val = out.val ++ [Action.Wake t]) : Follows c (out1.val.drop old.length) := by
  refine follows.extend fun a h => ?_
  rw [pushed, List.drop_append] at h
  rcases List.mem_append.mp h with before | wake
  · exact Or.inl before
  · have := List.mem_of_mem_drop wake
    simp at this
    subst this
    exact Or.inr fun p => by simp

/-- **Every event.**  Whatever the event, what the step asks for `Follows` in the core it leaves:
each event is a call of one function of lib.rs (then `advance`), or code of `step` itself
(`Step.lean`); the functions called before `advance` push no commit and no driver's pull
(`AppendsOnly NotPullStep`), `advance` leaves a core that `Follows` what it pushed
(`advance_follows`), and the events that do not call `advance` push neither at all. -/
theorem step_follows (c : Core) (now : Std.U64) (ev : Event) (out : alloc.vec.Vec Action) :
    Ok (step c now ev out) (fun r => Follows r.1 (r.2.val.drop out.val.length)) :=
  have nothing : AppendsOnly NotPullStep out.val out.val := AppendsOnly.refl _
  have none_asked : ∀ c' : Core, Follows c' (out.val.drop out.val.length) :=
    fun _ => Follows.of_none (by simp)
  StepFacts.holds (told := fun _ => True) (A := fun r => AppendsOnly NotPullStep out.val r.2.val)
    (Q := fun r => Follows r.1 (r.2.val.drop out.val.length))
    { advance_ok := fun r no_pull_step => advance_follows r.1 now r.2 out.val no_pull_step
      add_ok := fun pull containers =>
        (add_kinds c pull containers out).appends.mono fun _ h => h.notPullStep
      cancel_ok := fun pull => (cancel_kinds c pull out).appends.mono fun _ h => h.notPullStep
      prepared_ok := fun pull layers groups _ =>
        (prepared_kinds c pull layers groups out).appends.mono fun _ h => h.notPullStep
      succeeded_ok := fun work =>
        (succeeded_kinds c work out).appends.mono fun _ h => h.notPullStep
      failed_ok := fun work cl =>
        (failed_kinds c now work cl out).appends.mono fun _ h => h.notPullStep
      hurry_of_none := none_asked c
      hurry_boosts := fun _ _ => nothing
      hurry_begins := fun at_ in_range _ =>
        (begin_try_kinds _ at_ out).appends.mono fun _ h => h.notPullStep
      start_of_a_layer := fun layer => (Ok.any (start_at c layer now)).mono fun _ _ cs => none_asked _
      wake := fun _ follows _ _ pushed => follows.wake pushed
      tick_loop := fun iter =>
        (step_loop_kinds iter c now out).appends.mono fun _ h => h.notPullStep } ev trivial

/-- **An image is committed after its layers** (the statement of Spec.lean): the step asks for the
commit of the image of `p` only if `advance` did (`step_follows`), so the core holds `p` at `Image`
with every layer of the table that it lacks `Stored`; and a layer `p` lacks is in the table (the tables
are well formed, `the_tables_stay_well_formed`), so each layer `p` lacks is there and `Stored`.  The
names are distinct, so the pull is the only one named `p`. -/
theorem an_image_is_committed_after_its_layers : AnImageIsCommittedAfterItsLayers := by
  intro c now ev out c' out' p wf told returns asked_p
  obtain ⟨q, in_q, named, image, stored⟩ := (((step_follows c now ev out).eq returns) p).1 asked_p
  have wf' := the_tables_stay_well_formed c now ev out c' out' wf told returns
  refine ⟨⟨q, in_q, named⟩, fun q' in_q' named' => ?_⟩
  obtain rfl : q' = q := List.inj_on_of_nodup_map wf'.1 in_q' in_q (named'.trans named.symm)
  refine ⟨image, fun l in_l => ?_⟩
  obtain ⟨x, in_x, same⟩ := wf'.2.2.2.2.1 q' in_q l in_l
  exact ⟨x, in_x, same, stored x in_x (same ▸ in_l)⟩

/-- **A driver's pull follows its layers** (the statement of Spec.lean): the step asks for the driver's
pull of `p` only if `advance` did (`step_follows`), so the core holds `p` at `DriverPull` with every
layer of the table that it lacks `Ready` or `Stored`; the rest is as for
`an_image_is_committed_after_its_layers`. -/
theorem a_driver_pull_follows_its_layers : ADriverPullFollowsItsLayers := by
  intro c now ev out c' out' p wf told returns asked_p
  obtain ⟨q, in_q, named, driver, ready⟩ := (((step_follows c now ev out).eq returns) p).2 asked_p
  have wf' := the_tables_stay_well_formed c now ev out c' out' wf told returns
  refine ⟨⟨q, in_q, named⟩, fun q' in_q' named' => ?_⟩
  obtain rfl : q' = q := List.inj_on_of_nodup_map wf'.1 in_q' in_q (named'.trans named.symm)
  refine ⟨driver, fun l in_l => ?_⟩
  obtain ⟨x, in_x, same⟩ := wf'.2.2.2.2.1 q' in_q l in_l
  exact ⟨x, in_x, same, ready x in_x (same ▸ in_l)⟩
end LazyCore
