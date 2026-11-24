-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the loop of `parse` answers.  It looks at the algorithm bytes that are
-- there (`seen` of them, at the places 4, 5, ... of the bytes), adds the lengths of the algorithms,
-- and stops at the first one that is not known.  Its flag at the end is true exactly when every
-- algorithm byte it was to look at is known, and then the sum it holds is the sum of their lengths.
-- Why it is needed: `parse` says `Bad` when the flag is false, and otherwise reads from the sum how
-- long the head is; the claims about `Done`, `Need` and `Bad` are read from this.
-- Read before this file: Spec.lean, AlgorithmLengths.lean.
-- Notation: `(bytes.drop 4).take seen` is the algorithm bytes that are there: the bytes from the
-- fifth, the first `seen` of them.  `loop body x ⦃ post ⦄` reads: the loop returns and its answer
-- satisfies `post`.  `step` goes through one line of the Rust function, and `scalar_tac` proves a
-- fact about the numbers of the machine by arithmetic.
import RequestCore.AlgorithmLengths

open Aeneas Aeneas.Std Result velarx_request_core

namespace RequestCore

/-- The four bytes before the algorithms, as a number. -/
theorem header_is_four : HEADER = 4#usize := by
  unfold HEADER; rfl

/-- **The loop of `parse`**, run from the first algorithm byte, with `seen` algorithm bytes in the
bytes (`seen` at most 65535, as a count is): it returns; its flag is true exactly when every one
of them is known, and then the sum it holds is the sum of their lengths. -/
theorem scan_loop_reads (bytes : Slice Std.U8) (seen : Std.Usize)
    (there : 4 + seen.val ≤ bytes.length) (small : seen.val ≤ 65535) :
    parse_loop bytes seen 0#usize 0#usize true ⦃ r =>
      (r.2 = true ↔ ∀ a ∈ (bytes.val.drop 4).take seen.val, AlgorithmLength a ≠ 0) ∧
      (r.2 = true → r.1.val = (((bytes.val.drop 4).take seen.val).map AlgorithmLength).sum) ∧
      r.1.val ≤ 64 * seen.val ⦄ := by
  unfold parse_loop
  apply loop.spec_decr_nat (fun (q : Std.Usize × Std.Usize × Bool) => seen.val - q.2.1.val)
    (fun (q : Std.Usize × Std.Usize × Bool) =>
      q.2.1.val ≤ seen.val ∧
      (q.2.2 = true ↔ ∀ a ∈ (bytes.val.drop 4).take q.2.1.val, AlgorithmLength a ≠ 0) ∧
      (q.2.2 = true → q.1.val = (((bytes.val.drop 4).take q.2.1.val).map AlgorithmLength).sum) ∧
      q.1.val ≤ 64 * q.2.1.val)
  · rintro ⟨raw, i, flag⟩ ⟨inside, flag_is, raw_is, raw_small⟩
    simp only at inside flag_is raw_is raw_small ⊢
    unfold parse_loop.body
    have bytes_length : bytes.length = bytes.val.length := rfl
    by_cases below : i.val < seen.val
    · have below' : i < seen := by scalar_tac
      simp only [below', ite_true]
      by_cases still : flag = true
      · -- the algorithm byte at the place `i` is read
        simp only [still, ite_true]
        simp only [header_is_four]
        step as ⟨ i1, is_i1 ⟩
        step as ⟨ byte, is_byte ⟩
        step with alg_len_returns_the_length as ⟨ n, is_n ⟩
        have n_small : n.val ≤ 64 := by
          rw [is_n]; exact an_algorithm_is_at_most_64 byte
        step as ⟨ raw1, is_raw1 ⟩
        step as ⟨ i2, is_i2 ⟩
        -- the bytes seen grow by the one that was read
        have byte_at : (bytes.val.drop 4)[i.val]? = some byte := by
          rw [List.getElem?_drop, is_byte]
          have : 4 + i.val = i1.val := by omega
          rw [this]
          exact List.getElem?_eq_getElem (by scalar_tac)
        have grown : (bytes.val.drop 4).take i2.val =
            (bytes.val.drop 4).take i.val ++ [byte] := by
          rw [is_i2, List.take_add_one, byte_at]
          rfl
        have all_known := flag_is.mp still
        have byte_known : (n != 0#usize) = true ↔ AlgorithmLength byte ≠ 0 := by
          rw [← is_n]
          simp only [bne_iff_ne, ne_eq]
          constructor <;> intro different equal <;> apply different <;> scalar_tac
        refine ⟨by scalar_tac, ?_, ?_, by scalar_tac, by scalar_tac⟩
        · rw [grown, byte_known]
          constructor
          · intro known a member
            rcases List.mem_append.mp member with seen_before | is_byte
            · exact all_known a seen_before
            · rw [List.mem_singleton.mp is_byte]; exact known
          · intro known
            exact known byte (by simp)
        · intro _
          rw [grown, List.map_append, List.sum_append, is_raw1, raw_is still, is_n]
          simp
      · -- the flag is false: the loop ends with what it holds
        simp only [still]
        refine (WP.spec_ok _).mpr ?_
        have not_all : ¬ ∀ a ∈ (bytes.val.drop 4).take seen.val, AlgorithmLength a ≠ 0 := by
          intro all_known
          apply still
          rw [flag_is]
          intro a member
          have inside_seen : (bytes.val.drop 4).take i.val =
              ((bytes.val.drop 4).take seen.val).take i.val := by
            rw [List.take_take, min_eq_left inside]
          rw [inside_seen] at member
          exact all_known a (List.mem_of_mem_take member)
        have raw_below : raw.val ≤ 64 * seen.val := by omega
        simp [not_all, raw_below]
    · -- every algorithm byte was looked at: the loop ends with what it holds
      have not_below : ¬ i < seen := by scalar_tac
      simp only [not_below, ite_false]
      refine (WP.spec_ok _).mpr ?_
      have all_seen : i.val = seen.val := by omega
      rw [← all_seen]
      exact ⟨flag_is, raw_is, raw_small⟩
  · refine ⟨by simp, by simp, by simp, by simp⟩

end RequestCore
