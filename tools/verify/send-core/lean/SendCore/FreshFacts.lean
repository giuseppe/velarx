-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that the state remembers when a fresh token was asked (`FreshFacts`):
-- at most one turn of a run is a `Pass` with `refresh` (a token other than the one that was
-- refused), and once it was the state says `refreshed`.
--
-- Why it is needed: it is the proof of AFreshTokenIsAskedAtMostOnce.
--
-- Read before this file: Spec.lean, StepCases.lean, RunLemmas.lean.
--
-- Notation: `Run b tr s a` is a run of the request `b` with turns `tr`, ending in state `s` and
-- action `a`; `step s e = ok (n, a)` is "`step` returns `n` and `a`"; `∀`, `∃`, `∧`, `∨`, `→`,
-- `↔` are "for every", "there is", "and", "or", "if ... then", "exactly when".
import SendCore.BudgetFacts
open Aeneas Aeneas.Std Result velarx_send_core
namespace SendCore

/-- The number of turns of the run that asked for a fresh token. -/
def freshCount (tr : List Turn) : Nat :=
  tr.countP asksAFreshToken

/-- One more turn adds one to the count exactly when it is a turn that asks for a fresh token. -/
theorem fresh_count_after_a_turn (tr : List Turn) (e : Event) (a' : Action) :
    freshCount (tr ++ [⟨e, a'⟩]) = freshCount tr + (if asksAFreshToken ⟨e, a'⟩ then 1 else 0) := by
  simp [freshCount, List.countP_append]

/-- The turns that asked for a fresh token are at most one, and the state has remembered it. -/
structure FreshFacts (tr : List Turn) (s : State) : Prop where
  at_most_once : freshCount tr ≤ 1
  recorded : freshCount tr = 1 → s.refreshed = true

attribute [local simp] fresh_count_after_a_turn asksAFreshToken moved newPass redirected

/-- One step keeps the facts, in every case of `Moves`: only `refused` asks for a fresh token, and
it does so when the state says nothing was refreshed, so the count was zero. -/
theorem fresh_facts_after_a_step {tr : List Turn} {s : State} {e : Event} {n : State}
    {a' : Action} (facts : FreshFacts tr s) (moves : Moves s e n a') :
    FreshFacts (tr ++ [⟨e, a'⟩]) n := by
  obtain ⟨once, recorded⟩ := facts
  cases moves with
  | authed probe held n a' sends => cases sends <;> refine ⟨?_, ?_⟩ <;> simp_all
  | hinted n a' _ _ retry => cases retry <;> refine ⟨?_, ?_⟩ <;> simp_all
  | challenged n a' _ unrefreshed _ retry => cases retry <;> refine ⟨?_, ?_⟩ <;> simp_all
  | refused c n a' _ unrefreshed _ retry =>
    -- no fresh token was asked before, since the state says it was not refreshed
    have none_before : freshCount tr = 0 := by
      by_cases one : freshCount tr = 1
      · simp_all
      · omega
    cases retry <;> refine ⟨?_, ?_⟩ <;> simp_all
  | probe_missing => refine ⟨?_, ?_⟩ <;> simp_all
  | redirect keeps next n a' redirects =>
    cases redirects with
    | too_many => refine ⟨?_, ?_⟩ <;> simp_all
    | body_refused => refine ⟨?_, ?_⟩ <;> simp_all
    | sent hops' n a' _ _ _ sends => cases sends <;> refine ⟨?_, ?_⟩ <;> simp_all
  | unusable_too_many => refine ⟨?_, ?_⟩ <;> simp_all
  | unusable_location => refine ⟨?_, ?_⟩ <;> simp_all
  | v2_learned n a' _ retry => cases retry <;> refine ⟨?_, ?_⟩ <;> simp_all
  | hinted_refreshed _ _ => refine ⟨?_, ?_⟩ <;> simp_all
  | v2_refreshed _ => refine ⟨?_, ?_⟩ <;> simp_all
  | served => refine ⟨?_, ?_⟩ <;> simp_all
  | v2_unknown => refine ⟨?_, ?_⟩ <;> simp_all
  | hinted_away => refine ⟨?_, ?_⟩ <;> simp_all
  | unauthorized_closed => refine ⟨?_, ?_⟩ <;> simp_all
  | missing_closed => refine ⟨?_, ?_⟩ <;> simp_all

/-- An event out of turn is refused and the request is over: the facts hold, since the turn is
not a pass. -/
theorem fresh_facts_after_a_refusal {tr : List Turn} {s : State} {e : Event}
    (facts : FreshFacts tr s) : FreshFacts (tr ++ [⟨e, .Refuse .OutOfTurn⟩]) s := by
  obtain ⟨once, recorded⟩ := facts
  refine ⟨?_, ?_⟩ <;> simp_all

/-- The facts do not depend on what the core waits for. -/
theorem fresh_facts_rewait {tr : List Turn} {s : State} (w : Wait) (facts : FreshFacts tr s) :
    FreshFacts tr { s with wait := w } :=
  ⟨facts.at_most_once, facts.recorded⟩

/-- Every run has the facts. -/
theorem fresh_facts {b : Begin} {tr : List Turn} {s : State} {a : Action}
    (run : Run b tr s a) : FreshFacts tr s := by
  refine run_induction (P := fun tr s _ => FreshFacts tr s) ?_ ?_ ?_
    (fun _ _ _ w facts => fresh_facts_rewait w facts) run
  · intro s a started
    refine ⟨?_, ?_⟩ <;> simp [freshCount]
  · intro tr s a e n a' run facts fits moves
    exact fresh_facts_after_a_step facts moves
  · intro tr s a e run facts
    exact fresh_facts_after_a_refusal facts
