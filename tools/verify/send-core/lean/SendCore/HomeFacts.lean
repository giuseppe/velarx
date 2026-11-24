-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that the flags of the state that say where the request is (`at_home`,
-- `left_home`) match what the shell reported in the run (`HomeFacts`), and that every run keeps
-- it so.  It is why a send that carries the `Authorization` is a send to the registry's own
-- origin of a request that never left it, and why a new pass is asked only at home.
--
-- Why it is needed: Spec.lean says "left home" from the run (`Left`), not from the flag
-- `left_home` of the core.  The two agree; this is the proof.
--
-- Read before this file: Spec.lean, StepCases.lean, RunLemmas.lean.
--
-- Notation: `Run b tr s a` is a run of the request `b` with turns `tr`, ending in state `s` and
-- action `a`; `step s e = ok (n, a)` is "`step` returns `n` and `a`"; `∀`, `∃`, `∧`, `∨`, `→`,
-- `↔` are "for every", "there is", "and", "or", "if ... then", "exactly when".
import SendCore.RunLemmas
open Aeneas Aeneas.Std Result velarx_send_core
namespace SendCore

/-- An `Authed` answers a `Pass`. -/
theorem fits_authed {a : Action} {probe held : Bool} (fits : Fits a (.Authed probe held)) :
    ∃ refresh, a = .Pass refresh := by
  cases a <;> simp [Fits] at fits ⊢

/-- An answer (`Got`) answers a `Send`. -/
theorem fits_answer {a : Action} {answer : Answer} (fits : Fits a (.Got answer)) :
    ∃ r, a = .Send r := by
  cases a <;> simp [Fits] at fits ⊢

/-- A `V2` answers an `AskV2`. -/
theorem fits_v2 {a : Action} {learned : Bool} (fits : Fits a (.V2 learned)) : a = .AskV2 := by
  cases a <;> simp [Fits] at fits ⊢

/-- The request has left home after one more turn exactly when it had, or the turn is a send to a
target that is not the registry's. -/
theorem left_after_a_turn (b : Begin) (tr : List Turn) (e : Event) (a' : Action) :
    Left b (tr ++ [⟨e, a'⟩]) ↔
      Left b tr ∨ ∃ r t, a' = .Send r ∧ targetOf b e = some t ∧ t.home = false := by
  simp only [Left, SendsTo, List.mem_append, List.mem_singleton]
  constructor
  · rintro ⟨x, (member | rfl), r, t, ⟨action, target⟩, away⟩
    · exact .inl ⟨x, member, r, t, ⟨action, target⟩, away⟩
    · exact .inr ⟨r, t, action, target, away⟩
  · rintro (⟨x, member, r, t, sends, away⟩ | ⟨r, t, action, target, away⟩)
    · exact ⟨x, .inl member, r, t, sends, away⟩
    · exact ⟨⟨e, a'⟩, .inr rfl, r, t, ⟨action, target⟩, away⟩

/-- The request was at home after one more turn exactly when it had been, or the turn is a send to
the registry's own origin. -/
theorem was_at_home_after_a_turn (b : Begin) (tr : List Turn) (e : Event) (a' : Action) :
    WasAtHome b (tr ++ [⟨e, a'⟩]) ↔
      WasAtHome b tr ∨ ∃ r t, a' = .Send r ∧ targetOf b e = some t ∧ t.home = true := by
  simp only [WasAtHome, SendsTo, List.mem_append, List.mem_singleton]
  constructor
  · rintro ⟨x, (member | rfl), r, t, ⟨action, target⟩, home⟩
    · exact .inl ⟨x, member, r, t, ⟨action, target⟩, home⟩
    · exact .inr ⟨r, t, action, target, home⟩
  · rintro (⟨x, member, r, t, sends, home⟩ | ⟨r, t, action, target, home⟩)
    · exact ⟨x, .inl member, r, t, sends, home⟩
    · exact ⟨⟨e, a'⟩, .inr rfl, r, t, ⟨action, target⟩, home⟩

/-- What the state says of where the request is matches the run: if the request left home the
state says so (`left_is_kept`); a new pass is asked only before it left (`pass_is_home`); the
`/v2/` challenge is asked only at home (`v2_is_home`); and a request that is at home, with a
send or a challenge to answer, never left and has been sent to the registry
(`answers_at_home`). -/
structure HomeFacts (b : Begin) (tr : List Turn) (s : State) (a : Action) : Prop where
  left_is_kept : Left b tr → s.left_home = true
  pass_is_home : ∀ r, a = .Pass r → ¬ Left b tr
  v2_is_home : a = .AskV2 → s.at_home = true
  answers_at_home : (isSend a = true ∨ a = .AskV2) → s.at_home = true →
    ¬ Left b tr ∧ WasAtHome b tr

/-- A request that has just begun has the facts: it has sent nothing. -/
theorem home_facts_at_the_start {b : Begin} {s : State} {a : Action}
    (started : begin b = ok (s, a)) : HomeFacts b [] s a := by
  obtain ⟨_, _, _, at_home, left_home, _, rfl, _⟩ := begin_state b s a started
  refine ⟨?_, ?_, ?_, ?_⟩ <;> simp [Left, at_home, left_home, isSend]

attribute [local simp] left_after_a_turn was_at_home_after_a_turn targetOf moved newPass redirected
  isSend

/-- One step keeps the facts, in every case of `Moves`. -/
theorem home_facts_after_a_step {b : Begin} {tr : List Turn} {s : State} {a : Action} {e : Event}
    {n : State} {a' : Action} (facts : HomeFacts b tr s a) (begun : s.begin = b) (fits : Fits a e)
    (moves : Moves s e n a') : HomeFacts b (tr ++ [⟨e, a'⟩]) n a' := by
  obtain ⟨kept, pass, v2, home⟩ := facts
  cases moves with
  | authed probe held n a' sends =>
    obtain ⟨refresh, rfl⟩ := fits_authed fits
    have at_the_registry := pass refresh rfl
    cases sends <;> refine ⟨?_, ?_, ?_, ?_⟩ <;>
      simp_all
  | hinted n a' at_home _ retry =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    have at_the_registry := home (.inl rfl) at_home
    cases retry <;> refine ⟨?_, ?_, ?_, ?_⟩ <;>
      simp_all
  | challenged n a' at_home _ _ retry =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    have at_the_registry := home (.inl rfl) at_home
    cases retry <;> refine ⟨?_, ?_, ?_, ?_⟩ <;>
      simp_all
  | refused c n a' at_home _ _ retry =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    have at_the_registry := home (.inl rfl) at_home
    cases retry <;> refine ⟨?_, ?_, ?_, ?_⟩ <;>
      simp_all
  | probe_missing at_home _ =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    have at_the_registry := home (.inl rfl) at_home
    refine ⟨?_, ?_, ?_, ?_⟩ <;>
      simp_all
  | redirect keeps next n a' redirects =>
    obtain ⟨r, rfl⟩ := fits_answer fits
    cases redirects with
    | too_many _ => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp_all
    | body_refused _ _ => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp_all
    | sent hops n a' _ _ _ sends =>
      cases sends <;> refine ⟨?_, ?_, ?_, ?_⟩ <;> simp_all
      -- (the only goal left: a send away from home keeps what `Left` says in `left_home`)
      tauto
  | unusable_too_many _ => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp_all
  | unusable_location _ => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp_all
  | v2_learned n a' _ retry =>
    have asking := fits_v2 fits
    subst asking
    have at_home := v2 rfl
    have at_the_registry := home (.inr rfl) at_home
    cases retry <;> refine ⟨?_, ?_, ?_, ?_⟩ <;> simp_all
  | hinted_refreshed _ _ => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp_all
  | v2_refreshed _ => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp_all
  | served => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp_all
  | v2_unknown => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp_all
  | hinted_away _ => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp_all
  | unauthorized_closed _ _ => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp_all
  | missing_closed _ => refine ⟨?_, ?_, ?_, ?_⟩ <;> simp_all

/-- An event out of turn is refused and the request is over: the facts hold, since nothing was
sent. -/
theorem home_facts_after_a_refusal {b : Begin} {tr : List Turn} {s : State} {a : Action}
    {e : Event} (facts : HomeFacts b tr s a) :
    HomeFacts b (tr ++ [⟨e, .Refuse .OutOfTurn⟩]) s (.Refuse .OutOfTurn) := by
  obtain ⟨kept, pass, v2, home⟩ := facts
  refine ⟨?_, ?_, ?_, ?_⟩ <;> simp_all

/-- The facts do not depend on what the core waits for. -/
theorem home_facts_rewait {b : Begin} {tr : List Turn} {s : State} {a : Action} (w : Wait)
    (facts : HomeFacts b tr s a) : HomeFacts b tr { s with wait := w } a :=
  ⟨facts.left_is_kept, facts.pass_is_home, facts.v2_is_home, facts.answers_at_home⟩

/-- Every run has the facts. -/
theorem home_facts {b : Begin} {tr : List Turn} {s : State} {a : Action} (run : Run b tr s a) :
    HomeFacts b tr s a := by
  refine run_induction (P := HomeFacts b) (fun _ _ started => home_facts_at_the_start started)
    ?_ ?_ (fun _ _ _ w facts => home_facts_rewait w facts) run
  · intro tr s a e n a' run facts fits moves
    exact home_facts_after_a_step facts (run_counters run).1 fits moves
  · intro tr s a e run facts
    exact home_facts_after_a_refusal facts
