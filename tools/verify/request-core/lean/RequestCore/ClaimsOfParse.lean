-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about `parse`, `alg_len` and `most`:
-- `parse_always_returns`, `done_is_said_when_a_head_begins`,
-- `a_done_head_is_as_long_as_its_fields_say`, `need_is_said_when_a_head_can_still_begin`,
-- `need_asks_for_more_but_no_more_than_a_head_takes`, `bad_is_said_when_no_head_can_begin`,
-- `an_unknown_algorithm_is_refused` and `most_is_the_longest_head`.
-- Why it is needed: Theorems.lean ties each claim of Spec.lean to a proof, and these are the
-- proofs: each reads the answer of `parse` as `answer` (TheAnswer.lean) and then uses what
-- WhatTheAnswerSays.lean and WhatNeedAsksFor.lean show of it.
-- Read before this file: Spec.lean, TheAnswer.lean, WhatTheAnswerSays.lean, WhatNeedAsksFor.lean.
-- Notation: `WP.spec_mono h ?_` is "use the result `h` about the function, and show that what it
-- says is enough"; `cases r` takes the answer `r` apart into its three kinds.
import RequestCore.WhatNeedAsksFor

open Aeneas Aeneas.Std Result velarx_request_core

open Classical

namespace RequestCore

/-- The answer of `parse` is `Done count used` exactly when `answer` says `done` with their
numbers. -/
theorem is_done_when (r : Parse) (a : Answer) (agrees : Says r a) (count used : Std.Usize) :
    r = Parse.Done count used ↔ a = .done count.val used.val := by
  cases r <;> cases a <;> simp only [Says] at agrees <;> simp
  obtain ⟨is_count, is_used⟩ := agrees
  subst is_count is_used
  exact ⟨fun ⟨same_count, same_used⟩ => ⟨by rw [same_count], by rw [same_used]⟩,
    fun ⟨same_count, same_used⟩ =>
      ⟨UScalar.eq_of_val_eq same_count, UScalar.eq_of_val_eq same_used⟩⟩

/-- The answer of `parse` is `Bad` exactly when `answer` says `bad`. -/
theorem is_bad_when (r : Parse) (a : Answer) (agrees : Says r a) : r = Parse.Bad ↔ a = .bad := by
  cases r <;> cases a <;> simp only [Says] at agrees <;> simp

/-- The answer of `parse` is a `Need` exactly when `answer` says `need`, with the same total. -/
theorem is_need_when (r : Parse) (a : Answer) (agrees : Says r a) :
    (∃ n, r = Parse.Need n) ↔ ∃ m, a = .need m := by
  cases r <;> cases a <;> simp only [Says] at agrees <;> simp

/-- When `parse` says `Need n`, `answer` says `need` with the number of `n`. -/
theorem need_has_the_total (r : Parse) (a : Answer) (agrees : Says r a) (n : Std.Usize)
    (is_need : r = Parse.Need n) : a = .need n.val := by
  subst is_need
  cases a <;> simp only [Says] at agrees
  rw [agrees]

theorem parse_always_returns : ParseAlwaysReturns :=
  fun bytes max => WP.spec_mono (parse_answers_as_described bytes max) fun _ _ => trivial

theorem done_is_said_when_a_head_begins : DoneIsSaidWhenAHeadBegins := by
  intro bytes max
  refine WP.spec_mono (parse_answers_as_described bytes max) ?_
  intro r agrees count used
  rw [is_done_when r _ agrees]
  exact done_exactly_when_a_head_begins bytes.val max.val count.val used.val

theorem a_done_head_is_as_long_as_its_fields_say : ADoneHeadIsAsLongAsItsFieldsSay := by
  intro bytes max count used
  refine WP.spec_mono (parse_answers_as_described bytes max) ?_
  intro r agrees is_done
  have begins := (done_exactly_when_a_head_begins bytes.val max.val count.val used.val).mp
    ((is_done_when r _ agrees count used).mp is_done)
  -- the bytes are the four first, then the rest
  have shape : ∃ operation urgency high low tail,
      bytes.val = operation :: urgency :: high :: low :: tail := by
    have ⟨head, rest, split, ⟨operation, urgency, high, low, algorithms, raw, is_head, _⟩, _⟩ :=
      begins
    rw [split, is_head]
    exact ⟨operation, urgency, high, low, _, rfl⟩
  obtain ⟨operation, urgency, high, low, tail, is_bytes⟩ := shape
  rw [is_bytes] at begins
  obtain ⟨is_count, at_least, at_most, known, enough, is_used, fits⟩ :=
    (begins_with_a_head_when max.val count.val used.val operation urgency high low tail).mp begins
  have bytes_length : bytes.length = tail.length + 4 := by
    show bytes.val.length = _
    rw [is_bytes]; simp
  refine ⟨high, low, by simp [is_bytes], by simp [is_bytes], is_count.symm, at_least, at_most,
    ?_, ?_, ?_, ?_⟩
  · simpa [is_bytes] using known
  · simp [is_bytes]; omega
  · simpa [is_bytes] using is_used
  · omega

theorem need_is_said_when_a_head_can_still_begin : NeedIsSaidWhenAHeadCanStillBegin := by
  intro bytes max
  refine WP.spec_mono (parse_answers_as_described bytes max) ?_
  intro r agrees
  rw [is_need_when r _ agrees]
  exact need_exactly_when_a_head_can_still_begin bytes.val max.val

theorem need_asks_for_more_but_no_more_than_a_head_takes :
    NeedAsksForMoreButNoMoreThanAHeadTakes := by
  intro bytes max n
  refine WP.spec_mono (parse_answers_as_described bytes max) ?_
  intro r agrees is_need
  exact need_answer_asks_for_what_a_head_takes bytes.val max.val n.val
    (need_has_the_total r _ agrees n is_need)

theorem bad_is_said_when_no_head_can_begin : BadIsSaidWhenNoHeadCanBegin := by
  intro bytes max
  refine WP.spec_mono (parse_answers_as_described bytes max) ?_
  intro r agrees
  rw [is_bad_when r _ agrees]
  exact bad_exactly_when_no_head_can_begin bytes.val max.val

theorem an_unknown_algorithm_is_refused : AnUnknownAlgorithmIsRefused := by
  intro bytes max high low algorithm k at_high at_low at_least at_most below at_algorithm unknown
  refine WP.spec_mono (parse_answers_as_described bytes max) ?_
  intro r agrees
  rw [is_bad_when r _ agrees, bad_exactly_when_no_head_can_begin]
  -- the bytes are the four first, then the rest
  obtain ⟨operation, urgency, tail, is_bytes⟩ : ∃ operation urgency tail,
      bytes.val = operation :: urgency :: high :: low :: tail := by
    rcases is_bytes : bytes.val with _ | ⟨operation, _ | ⟨urgency, _ | ⟨high', _ | ⟨low', tail⟩⟩⟩⟩
    · rw [is_bytes] at at_high; simp at at_high
    · rw [is_bytes] at at_high; simp at at_high
    · rw [is_bytes] at at_high; simp at at_high
    · rw [is_bytes] at at_low; simp at at_low
    · rw [is_bytes] at at_high at_low
      simp only [List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq]
        at at_high at_low
      subst at_high at_low
      exact ⟨operation, urgency, tail, rfl⟩
  rw [is_bytes] at at_algorithm ⊢
  refine ⟨by simp, ?_⟩
  rw [can_become_a_head_when]
  rintro ⟨_, _, known⟩
  apply known algorithm _ unknown
  have : (tail.take (high.val * 256 + low.val))[k]? = some algorithm := by
    rw [List.getElem?_take_of_lt below]
    simpa using at_algorithm
  exact List.mem_of_getElem? this

theorem most_is_the_longest_head : MostIsTheLongestHead := by
  refine ⟨a_head_is_at_most_as_long_as_most, ?_⟩
  intro max fits
  unfold most
  have header : HEADER.val = 4 := by rw [header_is_four]; rfl
  step as ⟨ i, is_i ⟩
  step as ⟨ i1, is_i1 ⟩
  step as ⟨ r, is_r ⟩
  omega

end RequestCore
