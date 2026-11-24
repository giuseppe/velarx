-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the claims of Spec.lean about `parse`, proved of `answer` (the plain
-- description of what `parse` answers, TheAnswer.lean): when it says `Done`, `Need` and `Bad`,
-- and what `Need` asks for.  They are about lists of bytes; ClaimsOfParse.lean turns them into
-- the claims about `parse`.
-- Why it is needed: this is where the code is compared with what a head is.  A head is read
-- as `BeginsWithAHead` and `CanBecomeAHead` (BeginningsOfHeads.lean) say, and `answer` decides
-- with the same facts: the count is valid, the algorithm bytes that are there are known, the
-- algorithm bytes are all there, the head is all there.
-- Read before this file: Spec.lean, TheAnswer.lean, BeginningsOfHeads.lean.
-- Notation: `rcases b with _ | ⟨x, rest⟩` splits a list into the empty one and `x :: rest`;
-- `split_ifs` splits the cases of the `if`s of a definition.
import RequestCore.TheAnswer
import RequestCore.BeginningsOfHeads

open Aeneas Aeneas.Std Result velarx_request_core

open Classical

namespace RequestCore

noncomputable section

/-- Fewer than four bytes begin with no head, and `answer` asks for four. -/
theorem short_bytes (bytes : List Std.U8) (max : Nat) (short : bytes.length < 4) :
    answer bytes max = .need 4 ∧ ¬ ∃ count used, BeginsWithAHead max bytes count used := by
  constructor
  · rcases bytes with _ | ⟨_, _ | ⟨_, _ | ⟨_, _ | ⟨_, _⟩⟩⟩⟩
    · simp [answer]
    · simp [answer]
    · simp [answer]
    · simp [answer]
    · simp only [List.length_cons] at short; omega
  · rintro ⟨count, used, head, rest, split,
      ⟨operation, urgency, high, low, algorithms, raw, is_head, _⟩, _⟩
    rw [split, is_head] at short
    simp only [List.length_append, List.length_cons] at short
    omega

/-- **`Done`**: `answer` says `done count used` exactly when the bytes begin with a head of `count`
digests that is `used` bytes long. -/
theorem done_exactly_when_a_head_begins (bytes : List Std.U8) (max count used : Nat) :
    answer bytes max = .done count used ↔ BeginsWithAHead max bytes count used := by
  by_cases short : bytes.length < 4
  · obtain ⟨is_need, no_head⟩ := short_bytes bytes max short
    rw [is_need]
    exact ⟨fun h => Answer.noConfusion h, fun h => absurd ⟨count, used, h⟩ no_head⟩
  · rcases bytes with _ | ⟨operation, _ | ⟨urgency, _ | ⟨high, _ | ⟨low, tail⟩⟩⟩⟩
    all_goals try (simp only [List.length_cons, List.length_nil] at short; omega)
    rw [begins_with_a_head_when]
    simp only [answer]
    generalize high.val * 256 + low.val = c
    simp only [List.length_cons]
    split_ifs
    · -- the count is not valid
      rename_i invalid
      refine ⟨False.elim, ?_⟩
      rintro ⟨rfl, at_least, at_most, _⟩
      omega
    · -- some algorithm bytes are missing
      rename_i valid known missing
      refine ⟨False.elim, ?_⟩
      rintro ⟨rfl, _, _, _, enough, _⟩
      omega
    · -- the digests are not all there
      rename_i valid known there waiting
      refine ⟨False.elim, ?_⟩
      rintro ⟨rfl, _, _, _, _, is_used, fits⟩
      omega
    · -- the whole head is there
      rename_i valid known there whole
      constructor
      · intro is_done
        injection is_done with is_count is_used
        subst is_count
        refine ⟨rfl, by omega, by omega, known, by omega, is_used.symm, by omega⟩
      · rintro ⟨rfl, _, _, _, _, is_used, _⟩
        rw [is_used]
    · -- an algorithm byte that is there is not known
      rename_i valid unknown
      refine ⟨False.elim, ?_⟩
      rintro ⟨rfl, _, _, known, _⟩
      exact unknown known

/-- **`Bad`**: `answer` says `bad` exactly when the bytes are four or more and no bytes appended to
them begin with a head. -/
theorem bad_exactly_when_no_head_can_begin (bytes : List Std.U8) (max : Nat) :
    answer bytes max = .bad ↔ 4 ≤ bytes.length ∧ ¬ CanBecomeAHead max bytes := by
  by_cases short : bytes.length < 4
  · rw [(short_bytes bytes max short).1]
    exact ⟨fun h => Answer.noConfusion h, fun ⟨long, _⟩ => absurd short (by omega)⟩
  · rcases bytes with _ | ⟨operation, _ | ⟨urgency, _ | ⟨high, _ | ⟨low, tail⟩⟩⟩⟩
    all_goals try (simp only [List.length_cons, List.length_nil] at short; omega)
    rw [can_become_a_head_when]
    simp only [answer, List.length_cons]
    generalize high.val * 256 + low.val = c
    split_ifs
    · rename_i invalid
      refine ⟨fun _ => ⟨by omega, ?_⟩, fun _ => rfl⟩
      rintro ⟨at_least, at_most, _⟩
      omega
    · rename_i valid known missing
      exact ⟨False.elim, fun ⟨_, no⟩ => absurd ⟨by omega, by omega, known⟩ no⟩
    · rename_i valid known there waiting
      exact ⟨False.elim, fun ⟨_, no⟩ => absurd ⟨by omega, by omega, known⟩ no⟩
    · rename_i valid known there whole
      exact ⟨False.elim, fun ⟨_, no⟩ => absurd ⟨by omega, by omega, known⟩ no⟩
    · rename_i valid unknown
      refine ⟨fun _ => ⟨by omega, ?_⟩, fun _ => rfl⟩
      rintro ⟨_, _, known⟩
      exact unknown known

/-- **`Need`**: `answer` says `need`, with some total, exactly when the bytes do not begin with a
head and either they are fewer than four or they can become one. -/
theorem need_exactly_when_a_head_can_still_begin (bytes : List Std.U8) (max : Nat) :
    (∃ n, answer bytes max = .need n) ↔
      (¬ ∃ count used, BeginsWithAHead max bytes count used) ∧
        (bytes.length < 4 ∨ CanBecomeAHead max bytes) := by
  have bad := bad_exactly_when_no_head_can_begin bytes max
  have done := fun count used => done_exactly_when_a_head_begins bytes max count used
  constructor
  · rintro ⟨n, is_need⟩
    refine ⟨?_, ?_⟩
    · rintro ⟨count, used, begins⟩
      rw [← done] at begins
      rw [is_need] at begins
      exact Answer.noConfusion begins
    · by_contra neither
      obtain ⟨not_short, no_can⟩ := not_or.mp neither
      have := bad.mpr ⟨Nat.not_lt.mp not_short, no_can⟩
      rw [is_need] at this
      exact Answer.noConfusion this
  · rintro ⟨no_head, short_or_can⟩
    have not_bad : ¬ (4 ≤ bytes.length ∧ ¬ CanBecomeAHead max bytes) := by
      rintro ⟨long, no_can⟩
      rcases short_or_can with short | can
      · omega
      · exact no_can can
    rcases is_answer : answer bytes max with n | _ | ⟨count, used⟩
    · exact ⟨n, rfl⟩
    · exact absurd (bad.mp is_answer) not_bad
    · exact absurd ⟨count, used, (done count used).mp is_answer⟩ no_head

end

end RequestCore
