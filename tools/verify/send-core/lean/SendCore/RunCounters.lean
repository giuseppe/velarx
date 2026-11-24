-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that every state of a run has the request's own facts and counters in
-- range (`Counters`: the retries are at most 3, the hops at most 10), and what the state is when a
-- request begins.
--
-- Why it is needed: `step` adds one to `retries` and `hops`.  It returns (no overflow) only
-- while they are in range, and the claims of Spec.lean say it returns in every run: this file is
-- why.  It is also where the state is known to be the request's (`begin = b`) at every step.
--
-- Read before this file: Spec.lean, StepCases.lean.
--
-- Notation: `Run b tr s a` is a run of the request `b` with turns `tr`, ending in state `s` and
-- action `a`; `step s e = ok (n, a)` is "`step` returns `n` and `a`"; `∀`, `∃`, `∧`, `∨`, `→`,
-- `↔` are "for every", "there is", "and", "or", "if ... then", "exactly when".
import SendCore.StepCases
open Aeneas Aeneas.Std Result velarx_send_core
namespace SendCore

/-- The state has the request's own facts, and its counters are in range. -/
def Counters (b : Begin) (s : State) : Prop :=
  s.begin = b ∧ s.retries.val ≤ 3 ∧ s.hops.val ≤ 10

/-- What `begin` gives: the request, counters at zero, not at home, nothing refreshed, the `Pass`
that begins the first pass, and the scheme, method and body the request has. -/
theorem begin_state (b : Begin) (s : State) (a : Action) (started : begin b = ok (s, a)) :
    s.begin = b ∧ s.retries.val = 0 ∧ s.hops.val = 0 ∧ s.at_home = false ∧
      s.left_home = false ∧ s.refreshed = false ∧ a = .Pass false ∧
      s.https = b.start.https ∧ s.method = b.method ∧ s.body = b.body ∧ s.wait = .Pass := by
  unfold begin at started
  simp at started
  obtain ⟨rfl, rfl⟩ := started
  simp

/-- A send leaves in the state the request, the counters, the token facts, the method and the
body: it changes only what the origin of the target says. -/
theorem send_keeps_the_counters {s : State} {t : Target} {remember : Bool} {n : State}
    {a : Action} (moves : SendMoves s t remember n a) :
    n.begin = s.begin ∧ n.retries = s.retries ∧ n.hops = s.hops ∧ n.refreshed = s.refreshed ∧
      n.probe = s.probe ∧ n.held = s.held ∧ n.method = s.method ∧ n.body = s.body := by
  cases moves <;> simp [moved]

/-- A retry keeps the counters in range: it adds one only below the limit. -/
theorem counters_after_a_retry {b : Begin} {s n : State} {a : Action}
    (counters : Counters b s) (retry : RetryMoves s n a) : Counters b n := by
  cases retry with
  | exhausted => exact counters
  | again i below val_i => exact ⟨counters.1, by simp; omega, counters.2.2⟩

/-- One step keeps the request and the counters in range, in every case of `Moves`. -/
theorem counters_after_a_step {b : Begin} {s : State} {e : Event} {n : State} {a : Action}
    (counters : Counters b s) (moves : Moves s e n a) : Counters b n := by
  have unchanged := counters
  obtain ⟨begun, retries, hops⟩ := counters
  cases moves with
  | authed probe held n a sends =>
    obtain ⟨b', r', h', _⟩ := send_keeps_the_counters sends
    simp [newPass] at b' r' h'
    exact ⟨by rw [b', begun], by rw [r']; exact retries, by rw [h']; simp⟩
  | hinted n a _ _ retry => exact counters_after_a_retry unchanged retry
  | hinted_refreshed _ _ => exact unchanged
  | challenged n a _ _ _ retry => exact counters_after_a_retry unchanged retry
  | refused c n a _ _ _ retry =>
    exact counters_after_a_retry (s := { s with refreshed := true }) unchanged retry
  | probe_missing _ _ => exact unchanged
  | redirect keeps next n a redirects =>
    cases redirects with
    | too_many _ => exact unchanged
    | body_refused _ _ => exact unchanged
    | sent hops' n a below _ val_hops sends =>
      obtain ⟨b', r', h', _⟩ := send_keeps_the_counters sends
      simp [redirected] at b' r' h'
      exact ⟨by rw [b', begun], by rw [r']; exact retries, by rw [h']; omega⟩
  | unusable_too_many _ => exact unchanged
  | unusable_location _ => exact unchanged
  | v2_learned n a _ retry => exact counters_after_a_retry unchanged retry
  | v2_refreshed _ => exact unchanged
  | served => exact unchanged
  | v2_unknown => exact unchanged
  | hinted_away _ => exact unchanged
  | unauthorized_closed _ _ => exact unchanged
  | missing_closed _ => exact unchanged

/-- One step of a run keeps the request and the counters in range, for any event. -/
theorem counters_after_any_step {b : Begin} {s : State} {e : Event} {n : State} {a : Action}
    (counters : Counters b s) (moves : StepMoves s e n a) : Counters b n := by
  cases moves with
  | in_turn n0 a _ inner =>
    -- only the field `wait` differs from the state `advance` gives
    obtain ⟨begun, retries, hops⟩ := counters_after_a_step counters inner
    exact ⟨begun, retries, hops⟩
  | out_of_turn _ => exact counters
