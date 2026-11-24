-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of NoDowngrade, NoDowngradeAfterHttps, EverySendIsAllowed and
-- OnlyAnAllowedRedirectIsRemembered.
--
-- Why it is needed: they say that nothing is sent to http after https, that the address policy
-- allowed every send before it was made, and what the shell is allowed to remember.
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
import SendCore.RequestFacts
open Aeneas Aeneas.Std Result velarx_send_core
namespace SendCore

/-- A pass goes to the URL of the request, which is https if the registry is (else the send is
refused), or is https itself; a redirect goes to an https target if the state says the last send
was https (`RequestFacts`) or the registry is https. -/
theorem no_downgrade : NoDowngrade := by
  intro b tr s a run began_on_https x member r t sends
  -- the turn, the run before it, and what the step did
  obtain ⟨pre, post, split⟩ := List.append_of_mem member
  obtain ⟨e, action⟩ := x
  obtain ⟨sent, target⟩ := sends
  simp only at sent target
  subst sent
  obtain ⟨s0, a0, n, before, fits, moves⟩ := moves_of_a_turn run pre e _ post split (by simp)
  have begun := (run_counters before).1
  rcases only_passes_and_redirects_send moves with ⟨probe, held, rfl⟩ | ⟨keeps, next, rfl⟩
  -- a pass: the target is the start URL, https if the registry is, or https itself
  · obtain ⟨_, https, _, _⟩ := what_a_pass_sends moves
    simp only [targetOf, Option.some.injEq] at target
    subst target
    rw [begun] at https
    rcases began_on_https with home_https | start_https
    · exact https home_https
    · exact start_https
  -- a redirect: not a downgrade from an https send or an https registry
  · obtain ⟨r', rfl⟩ := fits_answer fits
    obtain ⟨_, _, _, scheme, _⟩ := what_a_redirect_sends moves
    simp only [targetOf, Option.some.injEq] at target
    subst target
    rw [begun] at scheme
    rcases began_on_https with home_https | start_https
    · exact scheme (.inr home_https)
    · exact scheme (.inl ((request_facts before).https_is_kept start_https r' rfl))

/-- A redirect that follows a send to an https target: the run before it says the state's last
send was https (`RequestFacts`, `last_scheme`), and `redirect` refuses a redirect to http from
there. -/
theorem no_downgrade_after_https : NoDowngradeAfterHttps := by
  intro b tr s a run pre p x post split rp r tp next keeps sends_p https_p event action
  obtain ⟨e, act⟩ := x
  simp only at event action
  subst event action
  -- the redirect, seen from the run that ends with the send before it
  have prefix_split : tr = (pre ++ [p]) ++ ⟨.Got (.Redirect keeps next), .Send r⟩ :: post := by
    simp [split]
  obtain ⟨s0, a0, n, before, fits, moves⟩ :=
    moves_of_a_turn run (pre ++ [p]) (.Got (.Redirect keeps next)) (.Send r) post
    prefix_split (by simp)
  obtain ⟨r', rfl⟩ := fits_answer fits
  -- that send was to an https target, and the state remembers its scheme
  obtain ⟨pre', p', t, same_turns, target, scheme⟩ :=
    (request_facts before).last_scheme r' rfl
  have same := List.append_inj' same_turns (by simp)
  simp only [List.cons.injEq, and_true] at same
  obtain ⟨_, rfl⟩ := same
  have same_target : t = tp := by
    rw [sends_p.2] at target
    exact (Option.some.inj target).symm
  subst same_target
  obtain ⟨_, _, _, scheme_kept, _⟩ := what_a_redirect_sends moves
  exact scheme_kept (.inl (by rw [scheme]; exact https_p))

/-- A pass and a redirect refuse a target the policy did not allow, so a send has an allowed
target. -/
theorem every_send_is_allowed : EverySendIsAllowed := by
  intro b tr s a run x member r action
  obtain ⟨pre, post, split⟩ := List.append_of_mem member
  obtain ⟨e, act⟩ := x
  simp only at action
  subst action
  obtain ⟨s0, a0, n, before, fits, moves⟩ := moves_of_a_turn run pre e _ post split (by simp)
  rcases only_passes_and_redirects_send moves with ⟨probe, held, rfl⟩ | ⟨keeps, next, rfl⟩
  · obtain ⟨allowed, _⟩ := what_a_pass_sends moves
    rw [(run_counters before).1] at allowed
    exact ⟨b.start, ⟨rfl, rfl⟩, allowed⟩
  · obtain ⟨_, _, allowed, _⟩ := what_a_redirect_sends moves
    exact ⟨next, ⟨rfl, rfl⟩, allowed⟩

/-- A send is `Away` with `remember` only for a redirect (a pass remembers nothing), and `remembers`
says the target is allowed and not the start origin, the request is cacheable, and the state has
no hops, which `RequestFacts` turns into "the turn before is the `Authed`". -/
theorem only_an_allowed_redirect_is_remembered : OnlyAnAllowedRedirectIsRemembered := by
  intro b tr s a run pre x post split m body remembered
  obtain ⟨e, act⟩ := x
  simp only at remembered
  subst remembered
  obtain ⟨s0, a0, n, before, fits, moves⟩ := moves_of_a_turn run pre e _ post split (by simp)
  rcases only_passes_and_redirects_send moves with ⟨probe, held, rfl⟩ | ⟨keeps, next, rfl⟩
  -- a pass remembers nothing
  · obtain ⟨_, _, kind, _⟩ := what_a_pass_sends moves
    simp at kind
  -- a redirect: what `remembers` says, and the turn before is the `Authed` of the pass
  · obtain ⟨r', rfl⟩ := fits_answer fits
    obtain ⟨_, _, allowed, _, kind, _⟩ := what_a_redirect_sends moves
    have begun := (run_counters before).1
    rcases kind with ⟨_, _, wrong⟩ | ⟨_, same_request⟩
    · simp at wrong
    · simp only [Request.Away.injEq] at same_request
      obtain ⟨_, _, remembered⟩ := same_request
      simp [remembers] at remembered
      obtain ⟨not_start, hops_zero, cacheable, _⟩ := remembered
      obtain ⟨pre', p', same_turns, probe, held, authed⟩ :=
        (request_facts before).first_hop r' rfl hops_zero
      exact ⟨⟨pre', p', probe, held, same_turns, authed⟩, ⟨keeps, next, rfl, allowed, not_start⟩,
        by rw [← begun]; exact cacheable⟩
