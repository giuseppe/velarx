-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of AsksOnlyAfterAHomeAnswer and
-- AFreshTokenIsAskedAtMostOnce.
--
-- Why it is needed: they say when a token (a new pass) and the `/v2/` challenge are asked, and
-- that a fresh token is asked once.
--
-- Read before this file: Spec.lean, and the files of what a run keeps true (HomeFacts.lean,
-- RequestFacts.lean, BudgetFacts.lean, FreshFacts.lean, HeldFacts.lean) that it uses.
--
-- Every proof here has the same shape: cut the run at the turn the claim is about
-- (`moves_of_a_turn`), read what the step did from the cases of `Moves`, and use what the run
-- before it kept true.
--
-- Notation: `Run b tr s a` is a run of the request `b` with turns `tr`, ending in state `s` and
-- action `a`; `step s e = ok (n, a)` is "`step` returns `n` and `a`"; `∀`, `∃`, `∧`, `∨`, `→`,
-- `↔` are "for every", "there is", "and", "or", "if ... then", "exactly when".
import SendCore.ClaimsOfTheLimits
open Aeneas Aeneas.Std Result velarx_send_core
namespace SendCore

/-- A new pass is asked in answer to a 401 or 403 (`Hinted`, `Unauthorized`) to a request that is
at home, or in answer to the learned `/v2/` challenge. -/
theorem what_a_new_pass_answers {s n : State} {e : Event} {refresh : Bool}
    (moves : Moves s e n (.Pass refresh)) :
    e = .V2 true ∨
      (s.at_home = true ∧ (e = .Got .Hinted ∨ ∃ c, e = .Got (.Unauthorized c))) := by
  cases moves with
  | authed _ _ _ _ sends => cases sends
  | hinted _ _ at_home _ retry => (cases retry; simp_all)
  | challenged _ _ at_home _ _ retry => (cases retry; simp_all)
  | refused c _ _ at_home _ _ retry => (cases retry; simp_all)
  | redirect _ _ _ _ redirects =>
    cases redirects with
    | sent _ _ _ _ _ _ sends => cases sends
  | v2_learned => exact .inl rfl

/-- The `/v2/` challenge is asked in answer to a 403 or 404 to a request that is at home. -/
theorem what_a_v2_challenge_answers {s n : State} {e : Event} (moves : Moves s e n .AskV2) :
    s.at_home = true ∧ e = .Got .Missing := by
  cases moves with
  | probe_missing at_home => exact ⟨at_home, rfl⟩
  | hinted _ _ _ _ retry => cases retry
  | challenged _ _ _ _ _ retry => cases retry
  | refused _ _ _ _ _ _ retry => cases retry
  | v2_learned _ _ _ retry => cases retry
  | authed _ _ _ _ sends => cases sends
  | redirect _ _ _ _ redirects =>
    cases redirects with
    | sent _ _ _ _ _ _ sends => cases sends

/-- What the step answers, and `HomeFacts` for a request that is at home with something to
answer (a send, or a `/v2/` challenge): it never left, and has been sent to the registry. -/
theorem asks_only_after_a_home_answer : AsksOnlyAfterAHomeAnswer := by
  intro b tr s a run pre x post split
  obtain ⟨e, act⟩ := x
  constructor
  -- a new pass, in answer to the registry or to the learned `/v2/` challenge
  · rintro ⟨refresh, rfl⟩
    obtain ⟨s0, a0, n, before, fits, moves⟩ := moves_of_a_turn run pre e _ post split (by simp)
    have facts := home_facts before
    rcases what_a_new_pass_answers moves with rfl | ⟨at_home, kind⟩
    · have asking := fits_v2 fits
      subst asking
      exact ⟨.inr (.inr rfl), facts.answers_at_home (.inr rfl) (facts.v2_is_home rfl)⟩
    · rcases kind with rfl | ⟨c, rfl⟩
      · obtain ⟨r, rfl⟩ := fits_answer fits
        exact ⟨.inl rfl, facts.answers_at_home (.inl rfl) at_home⟩
      · obtain ⟨r, rfl⟩ := fits_answer fits
        exact ⟨.inr (.inl ⟨c, rfl⟩), facts.answers_at_home (.inl rfl) at_home⟩
  -- the `/v2/` challenge, in answer to a 403 or 404
  · rintro rfl
    obtain ⟨s0, a0, n, before, fits, moves⟩ := moves_of_a_turn run pre e _ post split (by simp)
    have facts := home_facts before
    obtain ⟨at_home, e_is⟩ := what_a_v2_challenge_answers moves
    rw [e_is] at fits
    obtain ⟨r, rfl⟩ := fits_answer fits
    exact ⟨e_is, facts.answers_at_home (.inl rfl) at_home⟩

/-- This is what `FreshFacts` says. -/
theorem a_fresh_token_is_asked_at_most_once : AFreshTokenIsAskedAtMostOnce :=
  fun _ _ _ _ run => (fresh_facts run).at_most_once
