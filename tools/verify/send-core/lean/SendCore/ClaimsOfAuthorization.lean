-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims that the functions return, that an event out
-- of turn is refused, and that the `Authorization` stays at home: BeginAndStepAlwaysReturn,
-- EventsOutOfTurnAreRefused, AnAwayRequestHasNoAuthorization,
-- AuthorizationOnlyBeforeLeavingHome, NoAuthorizationAfterLeavingHome and
-- AHomeSendCarriesItsPassesAuthorization.
--
-- Why it is needed: these are the first two groups of the claims of Spec.lean, the ones that
-- say the registry's credentials are not sent to another origin.
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
import SendCore.HeldFacts
open Aeneas Aeneas.Std Result velarx_send_core
namespace SendCore

/-- `begin` returns, and `step` returns at every turn of every run (the counters are in range). -/
theorem begin_and_step_always_return : BeginAndStepAlwaysReturn :=
  ⟨begin_returns, fun _ _ _ _ _ run => step_returns run⟩

/-- `advance` never refuses an event as out of turn: only `step` does, before it. -/
theorem advance_does_not_refuse_out_of_turn {s : State} {e : Event} {n : State} {a : Action}
    (moves : Moves s e n a) : a ≠ .Refuse .OutOfTurn := by
  cases moves with
  | authed _ _ _ _ sends => cases sends <;> simp
  | hinted _ _ _ _ retry => cases retry <;> simp
  | challenged _ _ _ _ _ retry => cases retry <;> simp
  | refused _ _ _ _ _ _ retry => cases retry <;> simp
  | redirect _ _ _ _ redirects =>
    cases redirects with
    | sent _ _ _ _ _ _ sends => cases sends <;> simp
    | _ => simp
  | v2_learned _ _ _ retry => cases retry <;> simp
  | _ => simp

/-- A step that is in turn is one of the cases of `Moves`, and one that is not is refused as out
of turn and does nothing else (the state only waits for nothing). -/
theorem events_out_of_turn_are_refused : EventsOutOfTurnAreRefused := by
  intro b tr s a e run
  have counters := run_counters run
  obtain ⟨n, a', stepped, moves⟩ := step_moves s e counters.2.1 counters.2.2
  refine ⟨n, a', stepped, ?_⟩
  cases moves with
  | in_turn n0 a0 answers inner =>
    exact .inl ⟨(fits_is_answers _ _).mpr (run_waits run ▸ answers),
      advance_does_not_refuse_out_of_turn inner⟩
  | out_of_turn not_answers =>
    exact .inr ⟨fun fits => not_answers (run_waits run ▸ (fits_is_answers _ _).mp fits), rfl⟩

/-- A request `Away` is not a request `Home` with an `Authorization`: the types differ. -/
theorem an_away_request_has_no_authorization : AnAwayRequestHasNoAuthorization := by
  rintro m body remember ⟨m', body', away_is_home⟩
  cases away_is_home

/-- A send with an `Authorization` is a `Home` send; a `Home` send is made only to the registry's
origin and, in the case of a redirect, only if the state says the request never left (which the
run says too, `HomeFacts`); in the case of a pass, the pass is asked only before the request
left. -/
theorem authorization_only_before_leaving_home : AuthorizationOnlyBeforeLeavingHome := by
  intro b tr s a run pre x post split r t sends carries
  obtain ⟨e, action⟩ := x
  obtain ⟨sent, target⟩ := sends
  simp only at sent target
  subst sent
  -- the run before the send, and what the step did
  obtain ⟨s0, a0, n, before, fits, moves⟩ := moves_of_a_turn run pre e _ post split (by simp)
  have facts := home_facts before
  have begun := (run_counters before).1
  obtain ⟨m, body, rfl⟩ := carries
  rcases only_passes_and_redirects_send moves with ⟨probe, held, rfl⟩ | ⟨keeps, next, rfl⟩
  -- a pass: it follows a `Pass`, which is asked only before the request left home
  · obtain ⟨refresh, rfl⟩ := fits_authed fits
    obtain ⟨_, _, kind, _⟩ := what_a_pass_sends moves
    simp only [targetOf, Option.some.injEq] at target
    subst target
    rcases kind with ⟨home, _, _⟩ | ⟨_, away⟩
    · rw [begun] at home
      exact ⟨home, facts.pass_is_home refresh rfl⟩
    · cases away
  -- a redirect: a `Home` send needs a state that never left home, and then the run did not
  · obtain ⟨refresh, rfl⟩ := fits_answer fits
    obtain ⟨_, _, _, _, kind, _⟩ := what_a_redirect_sends moves
    simp only [targetOf, Option.some.injEq] at target
    subst target
    rcases kind with ⟨home, at_the_registry, _⟩ | ⟨_, away⟩
    · exact ⟨home, fun left => by simp [facts.left_is_kept left] at at_the_registry⟩
    · cases away

/-- The same claim read the other way round. -/
theorem no_authorization_after_leaving_home : NoAuthorizationAfterLeavingHome := by
  intro b tr s a run pre x post split left r t sends carries
  obtain ⟨_, not_left⟩ := authorization_only_before_leaving_home b tr s a run pre x post split r t
    sends carries
  exact not_left left

theorem a_home_send_carries_its_passes_authorization : AHomeSendCarriesItsPassesAuthorization := by
  intro b tr s a run pre x post split auth m body sent
  obtain ⟨e, act⟩ := x
  simp only at sent
  subst sent
  obtain ⟨s0, a0, n, before, fits, moves⟩ := moves_of_a_turn run pre e _ post split (by simp)
  rcases only_passes_and_redirects_send moves with ⟨probe, held, rfl⟩ | ⟨keeps, next, rfl⟩
  -- a pass: the `Authed` says the `held` of the request, and it is the last one
  · obtain ⟨_, _, kind, _⟩ := what_a_pass_sends moves
    rcases kind with ⟨_, _, same⟩ | ⟨_, away⟩
    · simp only [Request.Home.injEq] at same
      rw [same.1]
      exact pass_held_after_a_pass pre probe held (.Send (.Home held m body)) (by simp)
    · cases away
  -- a redirect: the state holds the `held` of the last pass, which a redirect does not change
  · obtain ⟨r', rfl⟩ := fits_answer fits
    obtain ⟨_, _, _, _, kind, _⟩ := what_a_redirect_sends moves
    rcases kind with ⟨_, _, same⟩ | ⟨_, away⟩
    · simp only [Request.Home.injEq] at same
      rw [same.1, pass_held_after_an_answer]
      exact (held_facts before).held_is_the_pass r' rfl
    · cases away
