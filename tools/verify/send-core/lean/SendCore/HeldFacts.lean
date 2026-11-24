-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that the state remembers the `Authorization` of the pass the way the
-- shell told it (`HeldFacts`): when the last action is a send, the `held` of the state is the
-- `held` of the last `Authed` of the run, and every run keeps it so.
--
-- Why it is needed: a send to the registry's origin carries the `held` of the state.  The claim
-- AHomeSendCarriesItsPassesAuthorization says it is the one the shell told for the pass.
--
-- Read before this file: Spec.lean, StepCases.lean, RunLemmas.lean.
--
-- Notation: `passHeld tr` is the `held` of the last `Authed` of `tr` that was not refused;
-- `some h` is "it is `h`", and `none` "there is none"; `Run b tr s a` is a run of the request `b`
-- with turns `tr`, ending in state `s` and action `a`.
import SendCore.FreshFacts
open Aeneas Aeneas.Std Result velarx_send_core
namespace SendCore

/-- An answer (not an `Authed`) leaves the `held` of the pass as it was. -/
theorem pass_held_after_an_answer (tr : List Turn) (answer : Answer) (a' : Action) :
    passHeld (tr ++ [⟨.Got answer, a'⟩]) = passHeld tr := by
  simp [passHeld]

/-- A `V2` leaves the `held` of the pass as it was. -/
theorem pass_held_after_a_challenge (tr : List Turn) (learned : Bool) (a' : Action) :
    passHeld (tr ++ [⟨.V2 learned, a'⟩]) = passHeld tr := by
  simp [passHeld]

/-- An `Authed` that the core did not refuse as out of turn makes the pass hold what it said. -/
theorem pass_held_after_a_pass (tr : List Turn) (probe held : Bool) (a' : Action)
    (in_turn : a' ≠ .Refuse .OutOfTurn) :
    passHeld (tr ++ [⟨.Authed probe held, a'⟩]) = some held := by
  cases a' <;> simp_all [passHeld, isOutOfTurn]

/-- When the last action is a send, the state holds what the last pass of the run said. -/
structure HeldFacts (tr : List Turn) (s : State) (a : Action) : Prop where
  held_is_the_pass : ∀ r, a = .Send r → passHeld tr = some s.held

attribute [local simp] pass_held_after_an_answer pass_held_after_a_challenge moved newPass
  redirected

/-- One step keeps the facts, in every case of `Moves`. -/
theorem held_facts_after_a_step {tr : List Turn} {s : State} {a : Action} {e : Event} {n : State}
    {a' : Action} (facts : HeldFacts tr s a) (fits : Fits a e) (moves : Moves s e n a') :
    HeldFacts (tr ++ [⟨e, a'⟩]) n a' := by
  obtain ⟨held⟩ := facts
  cases moves with
  | authed probe held' n a' sends =>
    cases sends <;> refine ⟨fun r same => ?_⟩ <;> simp_all
    all_goals exact pass_held_after_a_pass tr probe held' _ (by simp)
  | redirect keeps next n a' redirects =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    cases redirects with
    | too_many => exact ⟨by simp⟩
    | body_refused => exact ⟨by simp⟩
    | sent hops n a' _ _ _ sends =>
      cases sends <;> refine ⟨fun r same => ?_⟩ <;> simp_all
  | hinted n a' _ _ retry => cases retry <;> exact ⟨by simp⟩
  | challenged n a' _ _ _ retry => cases retry <;> exact ⟨by simp⟩
  | refused c n a' _ _ _ retry => cases retry <;> exact ⟨by simp⟩
  | v2_learned n a' _ retry => cases retry <;> exact ⟨by simp⟩
  | _ => exact ⟨by simp⟩

/-- An event out of turn is refused and the request is over: nothing is sent. -/
theorem held_facts_after_a_refusal {tr : List Turn} {s : State} {e : Event} :
    HeldFacts (tr ++ [⟨e, .Refuse .OutOfTurn⟩]) s (.Refuse .OutOfTurn) :=
  ⟨by simp⟩

/-- The facts do not depend on what the core waits for. -/
theorem held_facts_rewait {tr : List Turn} {s : State} {a : Action} (w : Wait)
    (facts : HeldFacts tr s a) : HeldFacts tr { s with wait := w } a :=
  ⟨facts.held_is_the_pass⟩

/-- Every run has the facts. -/
theorem held_facts {b : Begin} {tr : List Turn} {s : State} {a : Action}
    (run : Run b tr s a) : HeldFacts tr s a := by
  refine run_induction (P := fun tr s a => HeldFacts tr s a) ?_ ?_ ?_
    (fun _ _ _ w facts => held_facts_rewait w facts) run
  · intro s a started
    obtain ⟨_, _, _, _, _, _, rfl, _⟩ := begin_state b s a started
    exact ⟨by simp⟩
  · intro tr s a e n a' run facts fits moves
    exact held_facts_after_a_step facts fits moves
  · intro tr s a e run facts
    exact held_facts_after_a_refusal
