-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `der::element_in` answers: it accepts the element `DerContent` finds,
-- and refuses the others.
-- Why it is needed: it is the one function that reads a DER tag and length, and `element` and
-- `sequence_items` are built on it.  The theorems before it say what `DerContent` is for a length
-- of one byte and for a length of 1 to 4 bytes.
-- Read before this file: BigEndian.lean and Spec.lean (`DerContent`).
-- Notation: as in BigEndian.lean; `split` makes one case of each `if` of the Rust function.
import SigparseCore.BigEndian
open Aeneas Aeneas.Std Result velarx_sigparse_core
namespace SigparseCore

/-- The loop of `element_in` is the loop of `be`: the same twelve lines, read from `start`. -/
theorem element_loop_is_the_loop_of_be (data : Slice Std.U8) (len start n i : Std.Usize) :
    der.element_in_loop data len start n i = be_loop data start n len i := rfl

/-- Taking the low seven bits of a byte that has its top bit set takes 128 from it. -/
theorem low_bits_of_a_byte (x : Nat) (byte : x < 256) (top : 128 ≤ x) : x &&& 127 = x - 128 := by
  have := Nat.and_two_pow_sub_one_eq_mod x 7
  norm_num at this
  omega

/-- A length of one byte: the content is the `first` bytes after the two header bytes, if they fit
before `stop`. -/
theorem der_content_short (bytes : List Std.U8) (start stop : Nat) (first : Std.U8)
    (is_first : bytes[start + 1]? = some first) (header : start + 2 ≤ stop)
    (short : first.val < 128) :
    DerContent bytes start stop =
      if start + 2 + first.val ≤ stop then some (start + 2, first.val) else none := by
  simp [DerContent, is_first, short, show ¬ stop < start + 2 by omega]

/-- A length of 1 to 4 bytes after the first: the content is that many bytes after them, if they fit
before `stop`. -/
theorem der_content_long (bytes : List Std.U8) (start stop : Nat) (first : Std.U8)
    (is_first : bytes[start + 1]? = some first) (header : start + 2 ≤ stop)
    (long : 128 ≤ first.val) :
    DerContent bytes start stop =
      if first.val - 128 = 0 ∨ 4 < first.val - 128 ∨ stop < start + 2 + (first.val - 128) then none
      else if start + 2 + (first.val - 128) + BigEndian bytes (start + 2) (first.val - 128) ≤ stop
        then some (start + 2 + (first.val - 128), BigEndian bytes (start + 2) (first.val - 128))
        else none := by
  simp [DerContent, is_first, show ¬ first.val < 128 by omega, show ¬ stop < start + 2 by omega]

/-- An element that is read has its content after the two bytes of its header and before `stop`. -/
theorem der_content_is_inside (bytes : List Std.U8) (start stop off len : Nat)
    (content : DerContent bytes start stop = some (off, len)) :
    start + 2 ≤ off ∧ off + len ≤ stop := by
  unfold DerContent at content
  split at content
  · simp at content
  · split_ifs at content <;> simp at content <;> omega

/-- `element_in` reads the element at `at_` as `DerContent` says: it returns, its answer is the tag
and the content when there is one, and a refusal exactly when there is none. -/
theorem element_in_reads (data : Slice Std.U8) (at_ end_ : Std.Usize) (ordered : at_.val ≤ end_.val)
    (inside : end_.val ≤ data.val.length) :
    der.element_in data at_ end_ ⦃ r =>
      (∀ tag c, r = core.result.Result.Ok (tag, c) →
        data.val[at_.val]? = some tag ∧
        DerContent data.val at_.val end_.val = some (c.off.val, c.len.val)) ∧
      (∀ e, r = core.result.Result.Err e → DerContent data.val at_.val end_.val = none) ⦄ := by
  unfold der.element_in
  step as ⟨ room, hroom ⟩
  split
  · rename_i short
    simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
    intro e _
    have : end_.val < at_.val + 2 := by scalar_tac
    simp only [DerContent, this, ite_true]
    split <;> rfl
  · rename_i header
    have header : at_.val + 2 ≤ end_.val := by scalar_tac
    have := data.property
    step as ⟨ i1, hi1 ⟩
    step as ⟨ first, hfirst ⟩
    step with widen_a_byte as ⟨ len, hlen ⟩
    step as ⟨ start, hstart ⟩
    have is_first : data.val[at_.val + 1]? = some first := by simp [hfirst, hi1]
    split
    · rename_i long
      have long : 128 ≤ first.val := by scalar_tac
      rw [der_content_long _ _ _ first is_first header long]
      step as ⟨ low, hlow ⟩
      step with widen_a_byte as ⟨ n, hn ⟩
      have n_is : n.val = first.val - 128 := by
        rw [hn, hlow, UScalar.val_and]
        have := low_bits_of_a_byte first.val (by scalar_tac) long
        simpa using this
      split
      · rename_i indefinite
        have : n.val = 0 := by simpa using congrArg UScalar.val indefinite
        simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
        intro e _
        split_ifs <;> first | rfl | (exfalso; omega)
      split
      · rename_i too_long
        have : 4 < n.val := by scalar_tac
        simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
        intro e _
        split_ifs <;> first | rfl | (exfalso; omega)
      have n_ok : 0 < n.val ∧ n.val ≤ 4 := by scalar_tac
      step as ⟨ room_for_length, hroom_for_length ⟩
      split
      · rename_i cut
        have : end_.val < start.val + n.val := by scalar_tac
        simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
        intro e _
        split_ifs <;> first | rfl | (exfalso; omega)
      · rename_i fits
        have fits : start.val + n.val ≤ end_.val := by scalar_tac
        rw [element_loop_is_the_loop_of_be]
        step with be_loop_reads as ⟨ len1, hlen1 ⟩
        · simp [big_endian_none]
        rw [hstart, n_is] at hlen1
        step as ⟨ start1, hstart1 ⟩
        step as ⟨ room_for_content, hroom_for_content ⟩
        split
        · rename_i past
          have : end_.val - start1.val < len1.val := by scalar_tac
          simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
          intro e _
          split_ifs <;> first | rfl | (exfalso; omega)
        · rename_i inside_content
          have inside_content : len1.val ≤ end_.val - start1.val := by scalar_tac
          step as ⟨ tag, htag ⟩
          simp only [reduceCtorEq, false_implies, implies_true, and_true]
          intro tag' c same
          cases same
          have in_data : at_.val < data.val.length := by omega
          refine ⟨by simp [htag, in_data], ?_⟩
          split_ifs <;> first
            | (exfalso; omega)
            | (simp; omega)
    · rename_i short
      have short : first.val < 128 := by scalar_tac
      rw [der_content_short _ _ _ first is_first header short]
      step as ⟨ room_for_content, hroom_for_content ⟩
      split
      · rename_i past
        have : end_.val - start.val < len.val := by scalar_tac
        simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
        intro e _
        split_ifs <;> first | rfl | (exfalso; omega)
      · rename_i inside_content
        have inside_content : len.val ≤ end_.val - start.val := by scalar_tac
        step as ⟨ tag, htag ⟩
        simp only [reduceCtorEq, false_implies, implies_true, and_true]
        intro tag' c same
        cases same
        have in_data : at_.val < data.val.length := by omega
        refine ⟨by simp [htag, in_data], ?_⟩
        split_ifs <;> first
          | (exfalso; omega)
          | (simp; omega)

end SigparseCore
