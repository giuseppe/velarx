-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what a turn that is a send tells, read from the cases of `Moves`: it
-- follows a pass or a redirect, and what the target and the request are in each (the target is
-- allowed, the scheme is not a downgrade, a `Home` request is to the registry's origin of a
-- request that never left it, a body is kept only to the start origin).
--
-- Why it is needed: the claims about the sends (authorization, https, policy, body) all begin
-- with "a send is made by one of two events".  This is the one place that opens the cases.
--
-- Read before this file: Spec.lean, StepCases.lean.
--
-- Notation: `Moves s e n a` is "`step` from the state `s` for the event `e` gives the state `n`
-- and the action `a`" (one of the cases of StepCases.lean); `∧`, `∨`, `→` are "and", "or",
-- "if ... then".
import SendCore.HomeFacts
open Aeneas Aeneas.Std Result velarx_send_core
namespace SendCore

/-- Only a pass and a redirect make a send. -/
theorem only_passes_and_redirects_send {s n : State} {e : Event} {r : Request}
    (moves : Moves s e n (.Send r)) :
    (∃ probe held, e = .Authed probe held) ∨ ∃ keeps next, e = .Got (.Redirect keeps next) := by
  cases moves with
  | authed probe held => exact .inl ⟨probe, held, rfl⟩
  | redirect keeps next => exact .inr ⟨keeps, next, rfl⟩
  | hinted _ _ _ _ retry => cases retry
  | challenged _ _ _ _ _ retry => cases retry
  | refused _ _ _ _ _ _ retry => cases retry
  | v2_learned _ _ _ retry => cases retry

/-- A pass that sends goes to the URL the request started at; that URL is allowed, and not a
downgrade for an https registry; the request is `Home` with the pass's own `Authorization` if the
URL is the registry's and the request never left it, and `Away`, with no remembering, if not; the
next state has no hops and the scheme of the URL. -/
theorem what_a_pass_sends {s n : State} {probe held : Bool} {r : Request}
    (moves : Moves s (.Authed probe held) n (.Send r)) :
    s.begin.start.allowed = true ∧ (s.begin.home_https = true → s.begin.start.https = true) ∧
    ((s.begin.start.home = true ∧ s.left_home = false ∧
        r = .Home held s.begin.method s.begin.body) ∨
      ((s.begin.start.home = false ∨ s.left_home = true) ∧
        r = .Away s.begin.method s.begin.body false)) ∧
    n.hops.val = 0 ∧ n.https = s.begin.start.https := by
  cases moves with
  | authed _ _ _ _ sends =>
    cases sends <;> simp_all [moved, newPass]
    cases left : s.left_home <;> simp_all

/-- A redirect that sends has hops left; keeps a body only to the origin of the start; goes to an
allowed target that is not a downgrade; is `Home` only to the registry's origin of a request that
never left it, else `Away` (remembered as `remembers` says); the method and the body are those
after the redirect; and the next state counts the hop and has the scheme of the target. -/
theorem what_a_redirect_sends {s n : State} {keeps : Bool} {next : Target} {r : Request}
    (moves : Moves s (.Got (.Redirect keeps next)) n (.Send r)) :
    s.hops.val < 10 ∧ (keeps = true → s.body = true → next.start = true) ∧
    next.allowed = true ∧ ((s.https = true ∨ s.begin.home_https = true) → next.https = true) ∧
    ((next.home = true ∧ s.left_home = false ∧
        r = .Home s.held (methodAfter keeps s.method) (keeps && s.body)) ∨
      ((next.home = false ∨ s.left_home = true) ∧
        r = .Away (methodAfter keeps s.method) (keeps && s.body) (remembers s next))) ∧
    n.hops.val = s.hops.val + 1 ∧ n.https = next.https := by
  cases moves with
  | redirect _ _ _ _ redirects =>
    cases redirects with
    | sent hops _ _ below no_body_refusal val_hops sends =>
      cases sends <;> simp_all [moved, redirected]
      cases left : s.left_home <;> simp_all
