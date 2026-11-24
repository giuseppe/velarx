-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that the counters of the state bound what a run has done (`BudgetFacts`):
-- the number of sends and of turns so far is at most what the retries and the hops say.  A pass
-- has at most 11 sends (the first, and one for each of at most 10 redirects) and at most 13 turns
-- (its `Authed`, an answer to each send, a `V2`), and a request has at most 4 passes.
--
-- Why it is needed: it is the proof that the loop ends (AtMostSoManySends, AtMostSoManyTurns).
--
-- Read before this file: Spec.lean, StepCases.lean, RunLemmas.lean.
--
-- Notation: `tr.countP p` is the number of turns of `tr` that `p` accepts; `omega` is the
-- tactic that adds up bounds on numbers; `simp_all` rewrites everything it knows.
import SendCore.SendTurns
open Aeneas Aeneas.Std Result velarx_send_core
namespace SendCore

/-- The constant `MAX_RETRIES` is 3. -/
theorem max_retries_val : MAX_RETRIES.val = 3 := by simp [MAX_RETRIES]

/-- The constant `MAX_REDIRECTS` is 10. -/
theorem max_redirects_val : MAX_REDIRECTS.val = 10 := by simp [MAX_REDIRECTS]

/-- The sends a request may have made, beyond those of its earlier passes (11 each, one more than
the redirects of a pass): none while a new pass is being asked, then one for each hop and the
first send. -/
def sendSlack : Action → Nat → Nat
  | .Pass _, _ => 0
  | _, hops => hops + 1

/-- The turns a request may have had, beyond those of its earlier passes (13 each: the `Authed`,
at most 11 answers to its sends, and a `V2`): the `Authed` and an answer for each hop, then one
more for each kind of ending. -/
def turnSlack : Action → Nat → Nat
  | .Pass _, _ => 0
  | .Send _, hops => hops + 1
  | .AskV2, hops => hops + 2
  | _, hops => hops + 3

/-- The counters of the state bound the length of the run: what it has sent and the turns it has
taken. -/
structure BudgetFacts (tr : List Turn) (s : State) (a : Action) : Prop where
  sends_bounded : tr.countP (fun x => isSend x.action) ≤ 11 * s.retries.val + sendSlack a s.hops.val
  turns_bounded : tr.countP (fun x => !isOutOfTurn x) ≤ 13 * s.retries.val + turnSlack a s.hops.val

/-- A request that has just begun has the facts: it has done nothing. -/
theorem budget_facts_at_the_start {b : Begin} {s : State} {a : Action}
    (started : begin b = ok (s, a)) : BudgetFacts [] s a := by
  obtain ⟨_, _, _, _, _, _, rfl, _⟩ := begin_state b s a started
  exact ⟨by simp [sendSlack], by simp [turnSlack]⟩

attribute [local simp] sendSlack turnSlack isSend isOutOfTurn moved newPass redirected
  List.countP_append

set_option linter.unnecessarySeqFocus false in
set_option linter.unusedTactic false in
/-- One step keeps the facts, in every case of `Moves`.  Every case is closed by the same two
steps: `simp_all` writes the counters of the state the case gives, and `omega` adds up the
bounds (in some cases `simp_all` already closes the goal, which is why the two linters that
ask for `;` are off for this proof). -/
theorem budget_facts_after_a_step {b : Begin} {tr : List Turn} {s : State} {a : Action}
    {e : Event} {n : State} {a' : Action} (facts : BudgetFacts tr s a) (counters : Counters b s)
    (fits : Fits a e) (moves : Moves s e n a') : BudgetFacts (tr ++ [⟨e, a'⟩]) n a' := by
  obtain ⟨sent, taken⟩ := facts
  obtain ⟨_, retries, hops⟩ := counters
  cases moves with
  | authed probe held n a' sends =>
    obtain ⟨refresh, rfl⟩ := fits_authed fits
    cases sends <;> refine ⟨?_, ?_⟩ <;> simp_all <;> omega
  | hinted n a' _ _ retry =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    cases retry <;> refine ⟨?_, ?_⟩ <;> simp_all <;> omega
  | challenged n a' _ _ _ retry =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    cases retry <;> refine ⟨?_, ?_⟩ <;> simp_all <;> omega
  | refused c n a' _ _ _ retry =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    cases retry <;> refine ⟨?_, ?_⟩ <;> simp_all <;> omega
  | probe_missing =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    refine ⟨?_, ?_⟩ <;> simp_all <;> omega
  | redirect keeps next n a' redirects =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    cases redirects with
    | too_many => refine ⟨?_, ?_⟩ <;> simp_all <;> omega
    | body_refused => refine ⟨?_, ?_⟩ <;> simp_all <;> omega
    | sent hops' n a' below _ val_hops sends =>
      cases sends <;> refine ⟨?_, ?_⟩ <;> simp_all <;> omega
  | unusable_too_many =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    refine ⟨?_, ?_⟩ <;> simp_all <;> omega
  | unusable_location =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    refine ⟨?_, ?_⟩ <;> simp_all <;> omega
  | v2_learned n a' _ retry =>
    have asking := fits_v2 fits
    subst asking
    cases retry <;> refine ⟨?_, ?_⟩ <;> simp_all <;> omega
  | hinted_refreshed _ _ =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    refine ⟨?_, ?_⟩ <;> simp_all <;> omega
  | v2_refreshed _ =>
    have asking := fits_v2 fits
    subst asking
    refine ⟨?_, ?_⟩ <;> simp_all <;> omega
  | served =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    refine ⟨?_, ?_⟩ <;> simp_all <;> omega
  | v2_unknown =>
    have asking := fits_v2 fits
    subst asking
    refine ⟨?_, ?_⟩ <;> simp_all <;> omega
  | hinted_away =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    refine ⟨?_, ?_⟩ <;> simp_all <;> omega
  | unauthorized_closed =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    refine ⟨?_, ?_⟩ <;> simp_all <;> omega
  | missing_closed =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    refine ⟨?_, ?_⟩ <;> simp_all <;> omega

/-- An event out of turn is refused and the request is over: the facts hold, since the turn is not
counted and the slack of an ending is the largest. -/
theorem budget_facts_after_a_refusal {tr : List Turn} {s : State} {a : Action} {e : Event}
    (facts : BudgetFacts tr s a) :
    BudgetFacts (tr ++ [⟨e, .Refuse .OutOfTurn⟩]) s (.Refuse .OutOfTurn) := by
  obtain ⟨sent, taken⟩ := facts
  cases a <;> refine ⟨?_, ?_⟩ <;> simp_all <;> omega

/-- The facts do not depend on what the core waits for. -/
theorem budget_facts_rewait {tr : List Turn} {s : State} {a : Action} (w : Wait)
    (facts : BudgetFacts tr s a) : BudgetFacts tr { s with wait := w } a :=
  ⟨facts.sends_bounded, facts.turns_bounded⟩

/-- Every run has the facts. -/
theorem budget_facts {b : Begin} {tr : List Turn} {s : State} {a : Action}
    (run : Run b tr s a) : BudgetFacts tr s a := by
  refine run_induction (P := fun tr s a => BudgetFacts tr s a)
    (fun _ _ started => budget_facts_at_the_start started) ?_ ?_
    (fun _ _ _ w facts => budget_facts_rewait w facts) run
  · intro tr s a e n a' run facts fits moves
    exact budget_facts_after_a_step facts (run_counters run) fits moves
  · intro tr s a e run facts
    exact budget_facts_after_a_refusal facts
