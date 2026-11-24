-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is true of every run, whatever it is about: its states have their
-- counters in range, the step that made each turn is one of the cases of `Moves`, a run can be
-- cut at any of its turns, and a fact kept by every step is kept by the whole run
-- (`run_induction`).
--
-- Why it is needed: each claim of Spec.lean is about a turn in the middle of a run, or about the
-- whole run.  These are the tools that bring a claim back to one step.
--
-- Read before this file: Spec.lean, StepCases.lean, RunCounters.lean.
--
-- Notation: `Run b tr s a` is a run of the request `b` with turns `tr`, ending in state `s` and
-- action `a`; `step s e = ok (n, a)` is "`step` returns `n` and `a`"; `∀`, `∃`, `∧`, `∨`, `→`,
-- `↔` are "for every", "there is", "and", "or", "if ... then", "exactly when".
import SendCore.RunCounters
open Aeneas Aeneas.Std Result velarx_send_core
namespace SendCore

/-- Every state of a run has the request's own facts and its counters in range. -/
theorem run_counters {b : Begin} {tr : List Turn} {s : State} {a : Action}
    (run : Run b tr s a) : Counters b s := by
  induction run with
  | begins started =>
    obtain ⟨begun, no_retries, no_hops, _⟩ := begin_state b _ _ started
    exact ⟨begun, by omega, by omega⟩
  | answers run stepped counters =>
    obtain ⟨n, a, stepped', moves⟩ := step_moves _ _ counters.2.1 counters.2.2
    rw [stepped] at stepped'
    simp only [ok.injEq, Prod.mk.injEq] at stepped'
    obtain ⟨rfl, rfl⟩ := stepped'
    exact counters_after_any_step counters moves

/-- The step of a turn of a run is one of the two cases of `StepMoves`. -/
theorem run_moves {b : Begin} {tr : List Turn} {s : State} {a : Action} {e : Event} {n : State}
    {a' : Action} (run : Run b tr s a) (stepped : step s e = ok (n, a')) :
    StepMoves s e n a' := by
  have counters := run_counters run
  obtain ⟨n', a'', stepped', moves⟩ := step_moves s e counters.2.1 counters.2.2
  rw [stepped] at stepped'
  simp only [ok.injEq, Prod.mk.injEq] at stepped'
  obtain ⟨rfl, rfl⟩ := stepped'
  exact moves

/-- What the core waits for at the end of a run is what the last action asked. -/
theorem run_waits {b : Begin} {tr : List Turn} {s : State} {a : Action}
    (run : Run b tr s a) : s.wait = waitAfter a := by
  induction run with
  | begins started =>
    obtain ⟨_, _, _, _, _, _, rfl, _, _, _, waits⟩ := begin_state b _ _ started
    simp [waits, waitAfter]
  | answers run stepped _ =>
    cases run_moves run stepped with
    | in_turn _ _ _ _ => rfl
    | out_of_turn _ => rfl

/-- To show that a fact holds in every run: it holds at the start; it holds after a step that
answers the last action (one of the cases of `Moves`) if it held before; it holds after an
event out of turn, which the core refuses and leaves the state as it was; and it does not depend
on what the core waits for. -/
theorem run_induction {b : Begin} {P : List Turn → State → Action → Prop}
    (base : ∀ s a, begin b = ok (s, a) → P [] s a)
    (answer : ∀ tr s a e n a', Run b tr s a → P tr s a → Fits a e → Moves s e n a' →
      P (tr ++ [⟨e, a'⟩]) n a')
    (refusal : ∀ tr s a e, Run b tr s a → P tr s a →
      P (tr ++ [⟨e, .Refuse .OutOfTurn⟩]) s (.Refuse .OutOfTurn))
    (rewait : ∀ tr s a w, P tr s a → P tr { s with wait := w } a)
    {tr : List Turn} {s : State} {a : Action} (run : Run b tr s a) : P tr s a := by
  induction run with
  | begins started => exact base _ _ started
  | answers run stepped ih =>
    cases run_moves run stepped with
    | in_turn n a' answers inner =>
      have fits : Fits _ _ := (fits_is_answers _ _).mpr (run_waits run ▸ answers)
      exact rewait _ _ _ _ (answer _ _ _ _ _ _ run ih fits inner)
    | out_of_turn _ => exact rewait _ _ _ _ (refusal _ _ _ _ run ih)

/-- A turn of a run, with the turns before it: those turns are a run that ends at the state the
turn was answered from, the event answers its last action, `step` gives the turn's action, and
the turns up to and including it are a run (any event is a turn). -/
theorem run_split {b : Begin} {tr : List Turn} {s : State} {a : Action} (run : Run b tr s a)
    (pre : List Turn) (x : Turn) (post : List Turn) (split : tr = pre ++ x :: post) :
    ∃ s0 a0 n, Run b pre s0 a0 ∧ step s0 x.event = ok (n, x.action) ∧
      Run b (pre ++ [x]) n x.action := by
  induction run generalizing post with
  -- no turn is in an empty run
  | begins started => simp at split
  | @answers tr s a e n a' run stepped ih =>
    -- the turn is the last one: the run before it is `pre`
    rcases List.eq_nil_or_concat post with rfl | ⟨post', last, rfl⟩
    · have same : tr = pre ∧ (⟨e, a'⟩ : Turn) = x := by
        have := List.append_inj' (s₁ := tr) (t₁ := [⟨e, a'⟩]) (s₂ := pre) (t₂ := [x])
          (by simpa using split) (by simp)
        simpa using this
      obtain ⟨rfl, rfl⟩ := same
      exact ⟨s, a, n, run, stepped, Run.answers run stepped⟩
    -- the turn is before the last one: the same, for the run without the last turn
    · have regrouped : pre ++ x :: post'.concat last = (pre ++ x :: post') ++ [last] := by simp
      rw [regrouped] at split
      have same := List.append_inj' split (by simp)
      exact ih post' same.1

/-- A turn of a run that the core did not refuse as out of turn, seen from the state before it:
the run before it, that the event answers the action it ended on, and what `advance` does for it
(one of the cases of `Moves`). -/
theorem moves_of_a_turn {b : Begin} {tr : List Turn} {s : State} {a : Action} (run : Run b tr s a)
    (pre : List Turn) (e : Event) (a' : Action) (post : List Turn)
    (split : tr = pre ++ ⟨e, a'⟩ :: post) (in_turn : a' ≠ .Refuse .OutOfTurn) :
    ∃ s0 a0 n, Run b pre s0 a0 ∧ Fits a0 e ∧ Moves s0 e n a' := by
  obtain ⟨s0, a0, n, before, stepped, _⟩ := run_split run pre ⟨e, a'⟩ post split
  cases run_moves before stepped with
  | in_turn n0 a0' answers inner =>
    exact ⟨s0, a0, _, before, (fits_is_answers _ _).mpr (run_waits before ▸ answers), inner⟩
  | out_of_turn _ => exact absurd rfl in_turn

/-- `begin` returns. -/
theorem begin_returns (b : Begin) : ∃ s a, begin b = ok (s, a) := by
  unfold begin
  exact ⟨_, _, rfl⟩

/-- `step` returns, at every state of every run, whatever the event. -/
theorem step_returns {b : Begin} {tr : List Turn} {s : State} {a : Action} {e : Event}
    (run : Run b tr s a) : ∃ n a', step s e = ok (n, a') := by
  have counters := run_counters run
  obtain ⟨n, a', stepped, _⟩ := step_moves s e counters.2.1 counters.2.2
  exact ⟨n, a', stepped⟩

/-- The action a run ends on is the action of its last turn. -/
theorem run_ends_on_its_last_turn {b : Begin} {tr : List Turn} {s : State} {a : Action}
    (run : Run b tr s a) (pre : List Turn) (y : Turn) (split : tr = pre ++ [y]) : a = y.action := by
  induction run generalizing pre with
  | begins => simp at split
  | answers run stepped =>
    have same := List.append_inj' split (by simp)
    obtain ⟨_, single⟩ := same
    cases single
    rfl
