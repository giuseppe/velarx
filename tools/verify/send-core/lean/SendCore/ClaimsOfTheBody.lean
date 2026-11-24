-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of BodyOnlyToTheStartOrigin, RedirectsRewriteTheRequest and
-- APassStartsFromTheRequest.
--
-- Why it is needed: they say where a body goes, and what a redirect does to the method and the
-- body of the request.
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
import SendCore.ClaimsOfTheTarget
open Aeneas Aeneas.Std Result velarx_send_core
namespace SendCore

/-- A pass goes to the start origin, a redirect keeps the body only if the target is the start
origin (else `redirect` refuses). -/
theorem body_only_to_the_start_origin : BodyOnlyToTheStartOrigin := by
  intro b tr s a run starts x member r t sends has_body
  obtain ⟨pre, post, split⟩ := List.append_of_mem member
  obtain ⟨e, action⟩ := x
  obtain ⟨sent, target⟩ := sends
  simp only at sent target
  subst sent
  obtain ⟨s0, a0, n, before, fits, moves⟩ := moves_of_a_turn run pre e _ post split (by simp)
  rcases only_passes_and_redirects_send moves with ⟨probe, held, rfl⟩ | ⟨keeps, next, rfl⟩
  · simp only [targetOf, Option.some.injEq] at target
    subst target
    exact starts
  · obtain ⟨_, keeps_the_body, _, _, kind, _⟩ := what_a_redirect_sends moves
    simp only [targetOf, Option.some.injEq] at target
    subst target
    rcases kind with ⟨_, _, rfl⟩ | ⟨_, rfl⟩ <;>
      simp only [bodyOf, Bool.and_eq_true] at has_body <;>
      exact keeps_the_body has_body.1 has_body.2

/-- The request sent after a redirect has the method and the body that `redirect` computes from
the state, which holds the method and the body of the send before it (`RequestFacts`). -/
theorem redirects_rewrite_the_request : RedirectsRewriteTheRequest := by
  intro b tr s a run pre p x post split rp r keeps next sent_before redirect sent_after
  obtain ⟨e, act⟩ := x
  simp only at redirect sent_after
  subst redirect sent_after
  have prefix_split : tr = (pre ++ [p]) ++ ⟨.Got (.Redirect keeps next), .Send r⟩ :: post := by
    simp [split]
  obtain ⟨s0, a0, n, before, fits, moves⟩ :=
    moves_of_a_turn run (pre ++ [p]) (.Got (.Redirect keeps next)) (.Send r) post
    prefix_split (by simp)
  -- the send before the redirect is the last action of the run before, which says its method
  -- and its body are those of the state
  obtain ⟨r', rfl⟩ := fits_answer fits
  have last := run_ends_on_its_last_turn before pre p rfl
  rw [sent_before] at last
  cases last
  obtain ⟨same_method, same_body⟩ := (request_facts before).request_is_the_state rp rfl
  obtain ⟨_, _, _, _, kind, _⟩ := what_a_redirect_sends moves
  -- the redirect gives the method and the body that `redirect` computes from the state
  rw [same_method, same_body]
  rcases kind with ⟨_, _, rfl⟩ | ⟨_, rfl⟩ <;> simp [methodOf, bodyOf] <;>
    intro no_keep keeps_it <;> simp [no_keep] at keeps_it

/-- A pass starts from the method and the body of the request as it began. -/
theorem a_pass_starts_from_the_request : APassStartsFromTheRequest := by
  intro b tr s a run x member probe held r authed action
  obtain ⟨pre, post, split⟩ := List.append_of_mem member
  obtain ⟨e, act⟩ := x
  simp only at authed action
  subst authed action
  obtain ⟨s0, a0, n, before, fits, moves⟩ := moves_of_a_turn run pre _ _ post split (by simp)
  have begun := (run_counters before).1
  obtain ⟨_, _, kind, _⟩ := what_a_pass_sends moves
  rw [begun] at kind
  rcases kind with ⟨_, _, rfl⟩ | ⟨_, rfl⟩ <;> simp [methodOf, bodyOf]
