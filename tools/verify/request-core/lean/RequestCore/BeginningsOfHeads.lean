-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what it takes for bytes to BEGIN with a head and to CAN BECOME one, in the
-- terms `parse` looks at them with.  The bytes are an operation, an urgency, the two bytes of the
-- count, and the rest (`tail`).  Let `count` be the number of the two bytes.
--   - they begin with a head of `count` digests that is `used` bytes long exactly when the count is
--     at least 1 and at most the bound, the `count` first bytes of the rest are known algorithms,
--     there are that many of them, `used` is the four bytes, the `count` algorithm bytes and the
--     lengths the algorithms say, and the bytes are at least `used` long;
--   - they can become a head exactly when the count is valid and the algorithm bytes that are
--     already there (at most `count`) are known.
-- Why it is needed: `parse` looks at the bytes in the second way, and the claims of Spec.lean are
-- stated in the first; this is the step between them.
-- Read before this file: Spec.lean, AlgorithmLengths.lean.
-- Notation: `tail.take count` is the first `count` bytes of the rest (the algorithm bytes that are
-- there, when the rest is shorter, all of it); `l.drop n` is `l` without its first `n`.
import RequestCore.AlgorithmLengths

open Aeneas Aeneas.Std Result velarx_request_core

namespace RequestCore

/-- **What it takes to begin with a head.**  The bytes `op :: urg :: high :: low :: tail` begin
with a head of `count` digests that is `used` bytes long exactly when the number of `high` and
`low` is `count`, valid for the bound `max`, the algorithm bytes are all known and all there,
`used` is the length they say, and the bytes are that long. -/
theorem begins_with_a_head_when (max count used : Nat) (operation urgency high low : Std.U8)
    (tail : List Std.U8) :
    BeginsWithAHead max (operation :: urgency :: high :: low :: tail) count used ↔
      high.val * 256 + low.val = count ∧ 1 ≤ count ∧ count ≤ max ∧
      (∀ a ∈ tail.take count, AlgorithmLength a ≠ 0) ∧ count ≤ tail.length ∧
      used = 4 + count + ((tail.take count).map AlgorithmLength).sum ∧
      used ≤ tail.length + 4 := by
  constructor
  · rintro ⟨head, rest, split, ⟨operation', urgency', high', low', algorithms, raw, is_head,
      is_count, at_least, at_most, count_algorithms, known, raw_length⟩, head_length⟩
    rw [is_head] at split
    simp only [List.cons_append, List.cons.injEq, List.append_assoc] at split
    obtain ⟨rfl, rfl, rfl, rfl, is_tail⟩ := split
    have taken : tail.take count = algorithms := by
      rw [is_tail, ← count_algorithms]
      exact List.take_left
    rw [is_head] at head_length
    simp only [List.length_cons, List.length_append] at head_length
    have tail_length : tail.length = algorithms.length + (raw.length + rest.length) := by
      rw [is_tail]; simp
    refine ⟨is_count.symm, at_least, at_most, ?_, ?_, ?_, ?_⟩
    · rw [taken]; exact known
    · omega
    · rw [taken]; omega
    · omega
  · rintro ⟨is_count, at_least, at_most, known, enough, is_used, fits⟩
    refine ⟨operation :: urgency :: high :: low :: (tail.take count ++
        (tail.drop count).take (((tail.take count).map AlgorithmLength).sum)),
      (tail.drop count).drop (((tail.take count).map AlgorithmLength).sum), ?_, ?_, ?_⟩
    · simp only [List.cons_append, List.append_assoc, List.take_append_drop]
    · refine ⟨operation, urgency, high, low, tail.take count,
        (tail.drop count).take (((tail.take count).map AlgorithmLength).sum), rfl,
        is_count.symm, at_least, at_most, by simp; omega, known, ?_⟩
      have : (tail.drop count).length ≥ ((tail.take count).map AlgorithmLength).sum := by
        simp only [List.length_drop]; omega
      simp only [List.length_take, List.length_drop]
      omega
    · simp only [List.length_cons, List.length_append, List.length_take, List.length_drop]
      have : (tail.drop count).length ≥ ((tail.take count).map AlgorithmLength).sum := by
        simp only [List.length_drop]; omega
      simp only [List.length_drop] at this
      omega

/-- **What it takes to be able to become a head.**  The bytes `op :: urg :: high :: low :: tail`
can become a head exactly when the number of `high` and `low` is a valid count and the algorithm
bytes that are already there (the first `count` of the rest) are all known: the bytes that are
missing can be chosen to be the algorithm 1, and the digests anything. -/
theorem can_become_a_head_when (max : Nat) (operation urgency high low : Std.U8)
    (tail : List Std.U8) :
    CanBecomeAHead max (operation :: urgency :: high :: low :: tail) ↔
      1 ≤ high.val * 256 + low.val ∧ high.val * 256 + low.val ≤ max ∧
        ∀ a ∈ tail.take (high.val * 256 + low.val), AlgorithmLength a ≠ 0 := by
  constructor
  · rintro ⟨more, count, used, begins⟩
    rw [List.cons_append, List.cons_append, List.cons_append, List.cons_append] at begins
    obtain ⟨is_count, at_least, at_most, known, _⟩ := (begins_with_a_head_when max count used
      operation urgency high low (tail ++ more)).mp begins
    refine ⟨by omega, by omega, ?_⟩
    intro a member
    apply known a
    rw [← is_count, List.take_append]
    exact List.mem_append_left _ member
  · rintro ⟨at_least, at_most, known⟩
    -- the missing algorithm bytes are the algorithm 1, then room for the longest digests
    let count := high.val * 256 + low.val
    let more := List.replicate (count - tail.length) (1#u8) ++ List.replicate (64 * count) (0#u8)
    have taken : (tail ++ more).take count = tail.take count ++
        List.replicate (count - tail.length) (1#u8) := by
      rw [List.take_append]
      congr 1
      simp only [more]
      exact List.take_left' (by simp)
    have more_length : more.length = (count - tail.length) + 64 * count := by simp [more]
    have digests := digests_take_at_most_64_each ((tail ++ more).take count)
    have taken_length : ((tail ++ more).take count).length ≤ count := List.length_take_le _ _
    refine ⟨more, count, 4 + count + (((tail ++ more).take count).map AlgorithmLength).sum, ?_⟩
    rw [List.cons_append, List.cons_append, List.cons_append, List.cons_append]
    rw [begins_with_a_head_when]
    refine ⟨rfl, at_least, at_most, ?_, ?_, rfl, ?_⟩
    · intro a member
      rw [taken] at member
      rcases List.mem_append.mp member with in_tail | missing
      · exact known a in_tail
      · rw [(List.eq_of_mem_replicate missing)]
        simp [AlgorithmLength]
    · simp only [List.length_append, more_length]; omega
    · simp only [List.length_append, more_length]; omega

end RequestCore
