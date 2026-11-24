-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `parse` answers for the bytes of a list, in plain terms.  With fewer
-- than four bytes it asks for four.  Otherwise the count is the number the third and fourth bytes
-- say; a count that is 0 or above the bound is `Bad`; so is an unknown algorithm among the
-- algorithm bytes that are there; with some algorithm bytes missing it asks for the head as far
-- as it is known (the four bytes and the algorithm bytes); with the algorithm bytes all there
-- it asks for the length they say, and answers `Done` when the bytes are that long.
-- Why it is needed: it is the one place where the code of `parse` is followed; the claims of
-- Spec.lean are then proved of this plain description, and not of the code.
-- Read before this file: Spec.lean, ScanLoop.lean.
-- Notation: `Answer` is the three answers of `parse` with plain numbers in them; `Says r a` reads
-- "the answer `r` of the Rust function is `a`, with the numbers `usize` of `r` as numbers".
import RequestCore.ScanLoop
import RequestCore.ReturnedAnswers

open Aeneas Aeneas.Std Result velarx_request_core

open Classical

namespace RequestCore

noncomputable section

/-- The three answers of `parse`, with numbers. -/
inductive Answer where
  | need (total : Nat)
  | bad
  | done (count used : Nat)

/-- What `parse` answers for the bytes `bytes` and the bound `max`, said plainly (see the
header of this file). -/
def answer (bytes : List Std.U8) (max : Nat) : Answer :=
  match bytes with
  | _ :: _ :: high :: low :: tail =>
    let count := high.val * 256 + low.val
    let algorithms := tail.take count
    let used := 4 + count + (algorithms.map AlgorithmLength).sum
    if count = 0 ∨ max < count then .bad
    else if ¬ ∀ a ∈ algorithms, AlgorithmLength a ≠ 0 then .bad
    else if tail.length < count then .need (4 + count)
    else if bytes.length < used then .need used
    else .done count used
  | _ => .need 4

/-- The answer `r` of `parse` is the answer `a`, with the numbers of `r` as numbers. -/
def Says (r : Parse) (a : Answer) : Prop :=
  match r, a with
  | .Need n, .need total => n.val = total
  | .Bad, .bad => True
  | .Done count used, .done count' used' => count.val = count' ∧ used.val = used'
  | _, _ => False

/-- A count that is not 0 and not above the bound is none of the two things `parse` tests. -/
theorem a_valid_count_passes_the_tests (count max : Std.Usize)
    (valid : ¬ (count.val = 0 ∨ max.val < count.val)) : ¬ count = 0#usize ∧ ¬ count > max := by
  constructor <;> scalar_tac

/-- A count that is 0 or above the bound is one of the two things `parse` tests. -/
theorem an_invalid_count_fails_a_test (count max : Std.Usize)
    (invalid : count.val = 0 ∨ max.val < count.val) : count = 0#usize ∨ count > max := by
  by_cases zero : count = 0#usize
  · exact Or.inl zero
  · right; scalar_tac

/-- The answer for a count that is valid and an unknown algorithm byte among those there: `Bad`. -/
theorem answer_when_an_algorithm_is_unknown (operation urgency high low : Std.U8)
    (tail : List Std.U8) (max count : Nat) (is_count : high.val * 256 + low.val = count)
    (valid : ¬ (count = 0 ∨ max < count))
    (unknown : ¬ ∀ a ∈ tail.take count, AlgorithmLength a ≠ 0) :
    answer (operation :: urgency :: high :: low :: tail) max = .bad := by
  simp only [answer, is_count]
  split_ifs
  rfl

/-- The answer for a valid count, known algorithms, and some algorithm bytes missing: the four
bytes and the algorithm bytes are asked for. -/
theorem answer_when_algorithms_are_missing (operation urgency high low : Std.U8)
    (tail : List Std.U8) (max count : Nat) (is_count : high.val * 256 + low.val = count)
    (valid : ¬ (count = 0 ∨ max < count))
    (known : ∀ a ∈ tail.take count, AlgorithmLength a ≠ 0) (missing : tail.length < count) :
    answer (operation :: urgency :: high :: low :: tail) max = .need (4 + count) := by
  simp only [answer, is_count]
  split_ifs
  rfl

/-- The answer for a valid count, known algorithms, all algorithm bytes there, and fewer bytes
than the head takes: the length of the head is asked for. -/
theorem answer_when_the_digests_are_missing (operation urgency high low : Std.U8)
    (tail : List Std.U8) (max count : Nat) (is_count : high.val * 256 + low.val = count)
    (valid : ¬ (count = 0 ∨ max < count))
    (known : ∀ a ∈ tail.take count, AlgorithmLength a ≠ 0) (there : ¬ tail.length < count)
    (short : tail.length + 4 < 4 + count + ((tail.take count).map AlgorithmLength).sum) :
    answer (operation :: urgency :: high :: low :: tail) max =
      .need (4 + count + ((tail.take count).map AlgorithmLength).sum) := by
  simp only [answer, is_count, List.length_cons]
  split_ifs
  rfl

/-- The answer for a valid count, known algorithms and all the head there: `Done`. -/
theorem answer_when_the_head_is_there (operation urgency high low : Std.U8)
    (tail : List Std.U8) (max count : Nat) (is_count : high.val * 256 + low.val = count)
    (valid : ¬ (count = 0 ∨ max < count))
    (known : ∀ a ∈ tail.take count, AlgorithmLength a ≠ 0) (there : ¬ tail.length < count)
    (long : ¬ tail.length + 4 < 4 + count + ((tail.take count).map AlgorithmLength).sum) :
    answer (operation :: urgency :: high :: low :: tail) max =
      .done count (4 + count + ((tail.take count).map AlgorithmLength).sum) := by
  simp only [answer, is_count, List.length_cons]
  split_ifs
  rfl

/-- The length of the slice, as the number of its list. -/
theorem slice_len_is_length (bytes : Slice Std.U8) : (Slice.len bytes).val = bytes.val.length :=
  rfl

/-- **`parse` answers as `answer` says**, and always returns. -/
theorem parse_answers_as_described (bytes : Slice Std.U8) (max : Std.Usize) :
    parse bytes max ⦃ r => Says r (answer bytes.val max.val) ⦄ := by
  unfold parse
  have bytes_length : bytes.length = bytes.val.length := rfl
  simp only [header_is_four]
  by_cases short : bytes.length < 4
  · -- fewer than four bytes: four are asked for
    have short' : Slice.len bytes < 4#usize := by scalar_tac
    simp only [short', ite_true]
    refine (WP.spec_ok _).mpr ?_
    have short_list : bytes.val.length < 4 := by omega
    rcases is_bytes : bytes.val with _ | ⟨_, _ | ⟨_, _ | ⟨_, _ | ⟨_, tail⟩⟩⟩⟩
    · simp [answer, Says]
    · simp [answer, Says]
    · simp [answer, Says]
    · simp [answer, Says]
    · rw [is_bytes] at short_list
      simp only [List.length_cons] at short_list
      omega
  · have long : ¬ Slice.len bytes < 4#usize := by scalar_tac
    simp only [long, ite_false]
    obtain ⟨operation, urgency, high, low, tail, is_bytes⟩ :
        ∃ operation urgency high low tail,
          bytes.val = operation :: urgency :: high :: low :: tail := by
      rcases is_bytes : bytes.val with _ | ⟨operation, _ | ⟨urgency, _ | ⟨high, _ | ⟨low, tail⟩⟩⟩⟩
      · simp_all
      · simp_all
      · simp_all
      · simp_all
      · exact ⟨operation, urgency, high, low, tail, rfl⟩
    have is_high : bytes.val[2]? = some high := by simp [is_bytes]
    have is_low : bytes.val[3]? = some low := by simp [is_bytes]
    step as ⟨ high', is_high' ⟩
    have high_is : high' = high := by rw [is_high']; simp [is_bytes]
    simp only [lift, bind_ok]
    step as ⟨ i3, is_i3 ⟩
    step as ⟨ low', is_low' ⟩
    have low_is : low' = low := by rw [is_low']; simp [is_bytes]
    step as ⟨ count, is_count ⟩
    subst high_is low_is
    have count_is : count.val = high'.val * 256 + low'.val := by scalar_tac
    have count_small : count.val ≤ 65535 := by scalar_tac
    have tail_length : tail.length = bytes.length - 4 := by
      rw [bytes_length, is_bytes]; simp
    have the_count : high'.val * 256 + low'.val = count.val := count_is.symm
    by_cases invalid : count.val = 0 ∨ max.val < count.val
    · -- the count is not valid: `Bad`
      have bad_answer : answer bytes.val max.val = .bad := by
        simp only [answer, is_bytes, the_count]
        simp [invalid]
      rw [bad_answer]
      rcases an_invalid_count_fails_a_test count max invalid with zero | above
      · simp only [zero, ite_true]
        exact (WP.spec_ok _).mpr trivial
      · by_cases zero : count = 0#usize
        · simp only [zero, ite_true]
          exact (WP.spec_ok _).mpr trivial
        · simp only [zero, above, ite_false, ite_true]
          exact (WP.spec_ok _).mpr trivial
    · -- the count is valid: the algorithm bytes that are there are looked at
      obtain ⟨not_zero, not_above⟩ := a_valid_count_passes_the_tests count max invalid
      simp only [not_zero, not_above, ite_false]
      have length_ge : 4 ≤ bytes.val.length := by omega
      have len_val : (Slice.len bytes).val = tail.length + 4 := by
        rw [slice_len_is_length, is_bytes]; simp
      have four : (4#usize).val = 4 := rfl
      step as ⟨ i7, is_i7 ⟩
      -- the algorithm bytes that are there: as many as the count, or all that follow the four
      obtain ⟨seen, is_seen, seen_val⟩ : ∃ seen : Std.Usize,
          (if i7 < count then (bytes.len - 4#usize) else ok count) = ok seen ∧
            seen.val = min tail.length count.val := by
        by_cases fewer : i7 < count
        · obtain ⟨seen, is_seen, seen_val⟩ := returned_answer
            (Usize.sub_spec (x := bytes.len) (y := 4#usize) (by simp [len_val, four]))
          have fewer_val := (UScalar.lt_equiv i7 count).mp fewer
          exact ⟨seen, by simp [fewer, is_seen], by simp [seen_val, len_val, four]; omega⟩
        · have not_fewer := mt (UScalar.lt_equiv i7 count).mpr fewer
          exact ⟨count, by simp [fewer], by omega⟩
      rw [is_seen]
      simp only [bind_ok]
      have there : 4 + seen.val ≤ bytes.length := by omega
      have small : seen.val ≤ 65535 := by omega
      step with scan_loop_reads bytes seen there small
      step as ⟨ i8, is_i8 ⟩
      step as ⟨ used, is_used ⟩
      have taken : (bytes.val.drop 4).take seen.val = tail.take count.val := by
        rw [is_bytes, seen_val]
        simp only [List.drop_succ_cons, List.drop_zero]
        rcases Nat.le_total tail.length count.val with fewer | enough
        · rw [min_eq_left fewer, List.take_of_length_le fewer, List.take_length]
        · rw [min_eq_right enough]
      rw [taken] at raw_post raw_post1
      have seen_below_count : seen < count ↔ tail.length < count.val := by
        rw [UScalar.lt_equiv, seen_val]
        omega
      rw [is_bytes]
      by_cases ok1_true : ok1 = true
      · -- every algorithm byte that is there is known
        have known := raw_post.mp ok1_true
        have raw_is := raw_post1 ok1_true
        simp only [ok1_true, ite_true]
        by_cases missing : tail.length < count.val
        · -- some algorithm bytes are missing: the four bytes and the algorithms are asked for
          rw [answer_when_algorithms_are_missing operation urgency high' low' tail max.val
            count.val the_count invalid known missing]
          simp only [seen_below_count.mpr missing, ite_true]
          exact (WP.spec_ok _).mpr (by simp only [Says]; omega)
        · have not_below : ¬ seen < count := fun below => missing (seen_below_count.mp below)
          simp only [not_below, ite_false]
          by_cases short : bytes.len < used
          · simp only [short, ite_true]
            have short_list : tail.length + 4 < 4 + count.val +
                ((tail.take count.val).map AlgorithmLength).sum := by
              rw [UScalar.lt_equiv] at short
              omega
            rw [answer_when_the_digests_are_missing operation urgency high' low' tail max.val
              count.val the_count invalid known missing short_list]
            exact (WP.spec_ok _).mpr (by simp only [Says]; omega)
          · simp only [short, ite_false]
            have long_list : ¬ tail.length + 4 < 4 + count.val +
                ((tail.take count.val).map AlgorithmLength).sum := by
              intro below
              exact short ((UScalar.lt_equiv _ _).mpr (by omega))
            rw [answer_when_the_head_is_there operation urgency high' low' tail max.val
              count.val the_count invalid known missing long_list]
            exact (WP.spec_ok _).mpr (by simp only [Says, true_and]; omega)
      · -- an algorithm byte that is there is not known: `Bad`
        have unknown : ¬ ∀ a ∈ tail.take count.val, AlgorithmLength a ≠ 0 :=
          fun known => ok1_true (raw_post.mpr known)
        rw [answer_when_an_algorithm_is_unknown operation urgency high' low' tail max.val
          count.val the_count invalid unknown]
        simp only [ok1_true]
        exact (WP.spec_ok _).mpr trivial

end

end RequestCore
