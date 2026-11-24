-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of AtMostSoManySends and AtMostSoManyTurns.
--
-- Why it is needed: they say that the loop ends: the number of sends and of answers is bounded
-- by the constants of the crate, and a run with that many turns is over.
--
-- Read before this file: Spec.lean, and the files of what a run keeps true (HomeFacts.lean,
-- RequestFacts.lean, BudgetFacts.lean, FreshFacts.lean, HeldFacts.lean) that it uses.
--
-- Both proofs read the bound that `BudgetFacts` keeps over the whole run, with the counters in
-- range (`run_counters`), and finish by arithmetic on each kind of last action.
--
-- Notation: `Run b tr s a` is a run of the request `b` with turns `tr`, ending in state `s` and
-- action `a`; `step s e = ok (n, a)` is "`step` returns `n` and `a`"; `∀`, `∃`, `∧`, `∨`, `→`,
-- `↔` are "for every", "there is", "and", "or", "if ... then", "exactly when".
import SendCore.HeldFacts
open Aeneas Aeneas.Std Result velarx_send_core
namespace SendCore

/-- The sends so far are at most 11 for each retry and what the pass has done (`BudgetFacts`), and
the counters are in range, so at most 44. -/
theorem at_most_so_many_sends : AtMostSoManySends := by
  intro b tr s a run
  have budget := (budget_facts run).sends_bounded
  obtain ⟨_, retries, hops⟩ := run_counters run
  rw [max_retries_val, max_redirects_val]
  cases a <;> simp [sendSlack] at budget <;> omega

/-- The turns so far are at most 13 for each retry and what the pass has done (`BudgetFacts`), so
at most 52, and at 52 the last action is not a `Pass`, a `Send` or an `AskV2`. -/
theorem at_most_so_many_turns : AtMostSoManyTurns := by
  intro b tr s a run
  have budget := (budget_facts run).turns_bounded
  obtain ⟨_, retries, hops⟩ := run_counters run
  rw [max_retries_val, max_redirects_val]
  constructor
  · cases a <;> simp [turnSlack] at budget <;> omega
  · intro long
    cases a <;> simp [turnSlack, Finished] at budget ⊢ <;> omega
