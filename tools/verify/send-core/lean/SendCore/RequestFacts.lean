-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that the state remembers what was sent (`RequestFacts`): the scheme of
-- the last send, its method and body, and that a send with no redirect before it is the first of
-- its pass, and that every run keeps it so.
--
-- Why it is needed: a redirect is a send of the request as the last send left it.  The claims
-- about no downgrade after https, about the method and the body after a redirect, and about
-- remembering only the first redirect of a pass, need to know what the last send was.
--
-- Read before this file: Spec.lean, StepCases.lean, RunLemmas.lean.
--
-- Notation: `Run b tr s a` is a run of the request `b` with turns `tr`, ending in state `s` and
-- action `a`; `step s e = ok (n, a)` is "`step` returns `n` and `a`"; `∀`, `∃`, `∧`, `∨`, `→`,
-- `↔` are "for every", "there is", "and", "or", "if ... then", "exactly when".
import SendCore.SendTurns
open Aeneas Aeneas.Std Result velarx_send_core
namespace SendCore

/-- What the state remembers of the last send, when the last action is a send: an https start
means the scheme of the send is https (`https_is_kept`); its method and its body are those of the
state (`request_is_the_state`); and if the state has no hops, the turn before is the `Authed`
that began the pass (`first_hop`). -/
structure RequestFacts (b : Begin) (tr : List Turn) (s : State) (a : Action) : Prop where
  https_is_kept : b.start.https = true → ∀ r, a = .Send r → s.https = true
  request_is_the_state : ∀ r, a = .Send r → methodOf r = s.method ∧ bodyOf r = s.body
  first_hop : ∀ r, a = .Send r → s.hops.val = 0 →
    ∃ pre p, tr = pre ++ [p] ∧ ∃ probe held, p.event = .Authed probe held
  last_scheme : ∀ r, a = .Send r →
    ∃ pre p t, tr = pre ++ [p] ∧ targetOf b p.event = some t ∧ s.https = t.https

/-- A request that has just begun has the facts: it has sent nothing. -/
theorem request_facts_at_the_start {b : Begin} {s : State} {a : Action}
    (started : begin b = ok (s, a)) : RequestFacts b [] s a := by
  obtain ⟨_, _, _, _, _, _, rfl, _⟩ := begin_state b s a started
  exact ⟨by simp, by simp, by simp, by simp⟩

/-- One step keeps the facts, in every case of `Moves`. -/
theorem request_facts_after_a_step {b : Begin} {tr : List Turn} {s : State} {a : Action}
    {e : Event} {n : State} {a' : Action} (facts : RequestFacts b tr s a) (begun : s.begin = b)
    (fits : Fits a e) (moves : Moves s e n a') :
    RequestFacts b (tr ++ [⟨e, a'⟩]) n a' := by
  obtain ⟨kept, request, first⟩ := facts
  cases moves with
  | authed probe held n a' sends =>
    subst begun
    cases sends <;>
      refine ⟨?_, ?_, fun _ _ _ => ⟨tr, _, rfl, probe, held, rfl⟩,
        fun _ _ => ⟨tr, _, s.begin.start, rfl, rfl, ?_⟩⟩ <;>
      simp [moved, newPass, methodOf, bodyOf]
  | hinted n a' _ _ retry => cases retry <;> refine ⟨?_, ?_, ?_, ?_⟩ <;> simp
  | challenged n a' _ _ _ retry => cases retry <;> refine ⟨?_, ?_, ?_, ?_⟩ <;> simp
  | refused c n a' _ _ _ retry => cases retry <;> refine ⟨?_, ?_, ?_, ?_⟩ <;> simp
  | probe_missing => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp
  | redirect keeps next n a' redirects =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    cases redirects with
    | too_many => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp
    | body_refused => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp
    | sent hops n a' _ _ val_hops sends =>
      have scheme := kept
      cases sends <;> refine ⟨?_, ?_, ?_, ?_⟩ <;>
        simp_all [moved, redirected, methodOf, bodyOf, targetOf]
  | unusable_too_many => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp
  | unusable_location => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp
  | v2_learned n a' _ retry => cases retry <;> refine ⟨?_, ?_, ?_, ?_⟩ <;> simp
  | hinted_refreshed => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp
  | v2_refreshed => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp
  | served => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp
  | v2_unknown => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp
  | hinted_away => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp
  | unauthorized_closed => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp
  | missing_closed => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp

/-- An event out of turn is refused and the request is over: the facts hold, since nothing was
sent. -/
theorem request_facts_after_a_refusal {b : Begin} {tr : List Turn} {s : State} {e : Event} :
    RequestFacts b (tr ++ [⟨e, .Refuse .OutOfTurn⟩]) s (.Refuse .OutOfTurn) :=
  ⟨by simp, by simp, by simp, by simp⟩

/-- The facts do not depend on what the core waits for. -/
theorem request_facts_rewait {b : Begin} {tr : List Turn} {s : State} {a : Action} (w : Wait)
    (facts : RequestFacts b tr s a) : RequestFacts b tr { s with wait := w } a :=
  ⟨facts.https_is_kept, facts.request_is_the_state, facts.first_hop, facts.last_scheme⟩

/-- Every run has the facts. -/
theorem request_facts {b : Begin} {tr : List Turn} {s : State} {a : Action}
    (run : Run b tr s a) : RequestFacts b tr s a := by
  refine run_induction (P := RequestFacts b)
    (fun _ _ started => request_facts_at_the_start started) ?_ ?_
    (fun _ _ _ w facts => request_facts_rewait w facts) run
  · intro tr s a e n a' run facts fits moves
    exact request_facts_after_a_step facts (run_counters run).1 fits moves
  · intro tr s a e run facts
    exact request_facts_after_a_refusal
