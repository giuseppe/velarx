-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `worked_examples`, the examples of Spec.lean: a head with two
-- digests of different algorithms, read whole (also with bytes after it), read with its last
-- byte missing, and with an unknown algorithm byte.  Each is worked out from the claims about
-- `parse`, by reading what `IsAHead` says of the bytes of the example, not by running the code.
-- Why it is needed: Theorems.lean ties each claim of Spec.lean to a proof, and this is the one for
-- the examples; they show that the claims can be met (a head is read, a byte that is missing is
-- asked for, an unknown algorithm is refused).
-- Read before this file: Spec.lean, ClaimsOfParse.lean.
-- Notation: `decide` computes a statement about small numbers and short lists; `simp` rewrites with
-- the facts it is given.
import RequestCore.ClaimsOfParse

open Aeneas Aeneas.Std Result velarx_request_core

open Classical

namespace RequestCore

/-- The bytes of an example as a slice are the list of the example. -/
theorem bytes_of_val (bytes : List Std.U8) (few : bytes.length ≤ 255) :
    (BytesOf bytes few).val = bytes := Slice.from_val _ _

/-- `TwoDigests` is a head of 2 digests for the bound 256: the operation 7, the urgency 1, the
count `0 * 256 + 2`, the algorithm bytes 0x81 and 2, and 32 and 64 bytes of digests. -/
theorem two_digests_is_a_head : IsAHead 256 TwoDigests 2 := by
  refine ⟨7#u8, 1#u8, 0#u8, 2#u8, [129#u8, 2#u8],
    List.replicate 32 170#u8 ++ List.replicate 64 187#u8, ?_, ?_, by omega, by omega, rfl, ?_, ?_⟩
  · simp [TwoDigests]
  · rfl
  · intro a member
    simp only [List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl <;> simp [AlgorithmLength]
  · simp [AlgorithmLength]

/-- `TwoDigests` is 102 bytes long. -/
theorem two_digests_length : TwoDigests.length = 102 := by
  simp [TwoDigests]

/-- Bytes that are `TwoDigests` and then `more` are `Done 2 102`. -/
theorem two_digests_is_done (bytes more : List Std.U8) (is_bytes : bytes = TwoDigests ++ more)
    (few : bytes.length ≤ 255) :
    parse (BytesOf bytes few) 256#usize ⦃ r => r = Parse.Done 2#usize 102#usize ⦄ := by
  refine WP.spec_mono (done_is_said_when_a_head_begins _ _) ?_
  intro r is_done
  refine (is_done 2#usize 102#usize).mpr ?_
  rw [bytes_of_val]
  exact ⟨TwoDigests, more, is_bytes, two_digests_is_a_head, two_digests_length⟩

/-- The answer `r` of `parse` that says `need 102` is `Need 102`. -/
theorem says_need_102 (r : Parse) (agrees : Says r (.need 102)) : r = Parse.Need 102#usize := by
  cases r <;> simp only [Says] at agrees
  rename_i total
  exact congrArg Parse.Need (UScalar.eq_of_val_eq agrees)

/-- Without its last byte, `TwoDigests` is `Need 102`. -/
theorem two_digests_without_the_last_byte_needs_it (few : (TwoDigests.take 101).length ≤ 255) :
    parse (BytesOf (TwoDigests.take 101) few) 256#usize ⦃ r => r = Parse.Need 102#usize ⦄ := by
  have complete : TwoDigests.take 101 ++ [187#u8] = TwoDigests := by decide
  -- it is not a head yet: the head of its first bytes is 102 bytes long
  have no_head : ¬ ∃ count used, BeginsWithAHead 256 (TwoDigests.take 101) count used := by
    have shape : TwoDigests.take 101 =
        7#u8 :: 1#u8 :: 0#u8 :: 2#u8 :: ((TwoDigests.take 101).drop 4) := by decide
    have first : ((TwoDigests.take 101).drop 4).take 2 = [129#u8, 2#u8] := by decide
    have tail_length : ((TwoDigests.take 101).drop 4).length = 97 := by decide
    rintro ⟨count, used, begins⟩
    generalize (TwoDigests.take 101).drop 4 = tail at shape first tail_length
    rw [shape] at begins
    obtain ⟨is_count, _, _, _, _, is_used, fits⟩ :=
      (begins_with_a_head_when 256 count used 7#u8 1#u8 0#u8 2#u8 tail).mp begins
    have count_is : count = 2 := by rw [← is_count]; rfl
    rw [count_is, first] at is_used
    simp [AlgorithmLength] at is_used
    omega
  -- and it can become one: with its last byte it is `TwoDigests`
  have can : CanBecomeAHead 256 (TwoDigests.take 101) :=
    ⟨[187#u8], 2, 102, by
      rw [complete]
      exact ⟨TwoDigests, [], by simp, two_digests_is_a_head, two_digests_length⟩⟩
  refine WP.spec_mono (parse_answers_as_described _ _) ?_
  intro r agrees
  have bound : (256#usize).val = 256 := rfl
  rw [bytes_of_val, bound] at agrees
  obtain ⟨n, is_need⟩ := (need_exactly_when_a_head_can_still_begin _ _).mpr
    ⟨no_head, Or.inr can⟩
  obtain ⟨more_than_held, no_more_than_a_head, _⟩ :=
    need_answer_asks_for_what_a_head_takes _ _ n is_need
  have at_most := no_more_than_a_head TwoDigests 2 two_digests_is_a_head
    (by rw [← complete]; exact List.prefix_append _ _)
  have at_least : 101 < n := by
    have : (TwoDigests.take 101).length = 101 := by simp [two_digests_length]
    omega
  rw [two_digests_length] at at_most
  have n_is : n = 102 := by omega
  rw [n_is] at is_need
  rw [is_need] at agrees
  exact says_need_102 r agrees

/-- A head of which the second algorithm byte is 3, an unknown algorithm, is `Bad`, with the bytes
after the six first or without them. -/
theorem an_unknown_second_algorithm_is_bad (bytes : List Std.U8)
    (is_bytes : bytes.take 6 = [7#u8, 1#u8, 0#u8, 2#u8, 129#u8, 3#u8]) (few : bytes.length ≤ 255) :
    parse (BytesOf bytes few) 256#usize ⦃ r => r = Parse.Bad ⦄ := by
  refine an_unknown_algorithm_is_refused (BytesOf bytes few) 256#usize 0#u8 2#u8 3#u8 1 ?_ ?_
    (by decide) (by decide) (by decide) ?_ (by decide)
  · rw [bytes_of_val, ← List.getElem?_take_of_lt (show 2 < 6 by omega), is_bytes]; rfl
  · rw [bytes_of_val, ← List.getElem?_take_of_lt (show 3 < 6 by omega), is_bytes]; rfl
  · rw [bytes_of_val, show 4 + 1 = 5 by rfl, ← List.getElem?_take_of_lt (show 5 < 6 by omega),
      is_bytes]; rfl

theorem worked_examples : WorkedExamples := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · exact two_digests_is_done _ [] (by simp) _
  · exact two_digests_is_done _ [9#u8, 9#u8, 9#u8] rfl _
  · exact two_digests_without_the_last_byte_needs_it _
  · exact an_unknown_second_algorithm_is_bad _ (by decide) _
  · exact an_unknown_second_algorithm_is_bad _ (by decide) _

end RequestCore
