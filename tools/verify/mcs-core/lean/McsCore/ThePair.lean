-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `put_number` and `pair_label`: the label `s0:cA,cB` of a pair of
--    categories.
-- Why it is needed: the fresh level of a container is written by `pair_label`, and read back by
--    `read_pair`.
-- Read before this file: TheDecimal.lean, TheLoops.lean.
-- Notation: `PairText a b` is the text `s0:cA,cB`.
import McsCore.TheDecimal
import McsCore.TheLoops
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- How many digits the number writes, `0` for `0` (nothing left to write). -/
def ndig (r : Nat) : Nat := if r = 0 then 0 else (Decimal r).length

/-- A number above zero has one digit more than a tenth of it. -/
theorem ndig_succ (r : Nat) (pos : 0 < r) : ndig r = ndig (r / 10) + 1 := by
  unfold ndig
  rw [if_neg (by omega)]
  by_cases h : r < 10
  · rw [decimal_small r h]; simp; omega
  · rw [decimal_big r (by omega), if_neg (by omega)]; simp

/-- The length of the decimal writing of `c` is one more than the digits of a tenth of `c`. -/
theorem decimal_length (c : Nat) : (Decimal c).length = ndig (c / 10) + 1 := by
  by_cases h : c < 10
  · rw [decimal_small c h]; simp [ndig, show c / 10 = 0 by omega]
  · rw [decimal_big c (by omega)]
    simp [ndig, show c / 10 ≠ 0 by omega]

/-- A number below 10 to the `k` has at most `k` digits. -/
theorem ndig_le (k : Nat) : ∀ r, r < 10 ^ k → ndig r ≤ k := by
  induction k with
  | zero => intro r h; simp at h; subst h; simp [ndig]
  | succ k ih =>
    intro r h
    by_cases pos : 0 < r
    · rw [ndig_succ r pos]
      have : r / 10 < 10 ^ k := by rw [pow_succ] at h; omega
      have := ih _ this
      omega
    · have : r = 0 := by omega
      subst this; simp [ndig]

/-- The first loop of `put_number` counts the digits of the number: it adds their count to the size
it is given. -/
theorem put_number_loop0_spec (size : Std.Usize) (rest : Std.U16)
    (small : size.val + ndig rest.val ≤ 100) :
    put_number_loop0 size rest ⦃ r => r.val = size.val + ndig rest.val ⦄ := by
  unfold put_number_loop0
  apply loop_answers (fun x : Std.Usize × Std.U16 => put_number_loop0.body x.1 x.2)
    (fun x y => y.val = x.1.val + ndig x.2.val) (fun x => x.2.val)
    (fun x => x.1.val + ndig x.2.val ≤ 100)
  · rintro ⟨size', rest'⟩ small'
    simp only at small' ⊢
    unfold put_number_loop0.body
    by_cases pos : rest' > 0#u16
    · simp only [pos, ite_true]
      have pos' : 0 < rest'.val := by scalar_tac
      have nd := ndig_succ rest'.val pos'
      step as ⟨ size1, is_size1 ⟩
      step as ⟨ rest1, is_rest1 ⟩
      refine ⟨by rw [is_rest1]; omega, by omega, ?_⟩
      intro y h
      rw [h, is_size1, is_rest1]
      omega
    · simp only [pos, ite_false]
      refine (WP.spec_ok _).mpr ?_
      have : rest'.val = 0 := by scalar_tac
      simp [this, ndig]
  · exact small

/-- The bytes written by `put_number_loop1`: from the place `at`, the digits of `v`, then what was
there before. -/
theorem getD_append_left {α : Type} [Inhabited α] (l1 l2 : List α) (j : Nat) (h : j < l1.length) :
    (l1 ++ l2)[j]! = l1[j]! := by
  simp only [List.getElem!_eq_getElem?_getD]
  rw [List.getElem?_append_left h]

/-- A place past the first list of two joined lists is a place of the second. -/
theorem getD_append_right {α : Type} [Inhabited α] (l1 l2 : List α) (j : Nat) (h : l1.length ≤ j) :
    (l1 ++ l2)[j]! = l2[j - l1.length]! := by
  simp only [List.getElem!_eq_getElem?_getD]
  rw [List.getElem?_append_right h]

/-- The place that was set holds what was put there. -/
theorem getD_set_eq {α : Type} [Inhabited α] (l : List α) (j : Nat) (x : α) (h : j < l.length) :
    (l.set j x)[j]! = x := by
  simp only [List.getElem!_eq_getElem?_getD]
  simp [List.getElem?_set, h]

/-- A place other than the one that was set is unchanged. -/
theorem getD_set_ne {α : Type} [Inhabited α] (l : List α) (j k : Nat) (x : α) (h : j ≠ k) :
    (l.set j x)[k]! = l[k]! := by
  simp only [List.getElem!_eq_getElem?_getD]
  rw [List.getElem?_set_ne h]

/-- Two lists of the same length that agree at every place are equal. -/
theorem list_ext_bang {α : Type} [Inhabited α] (l1 l2 : List α) (len : l1.length = l2.length)
    (same : ∀ j, j < l1.length → l1[j]! = l2[j]!) : l1 = l2 := by
  apply List.ext_getElem len
  intro j h1 h2
  have := same j h1
  simp only [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem h1,
    List.getElem?_eq_getElem h2] at this
  simpa using this

/-- A place inside the beginning of a list is the same place of the list. -/
theorem getD_take {α : Type} [Inhabited α] (l : List α) (n j : Nat) (h : j < n) :
    (l.take n)[j]! = l[j]! := by
  simp only [List.getElem!_eq_getElem?_getD]
  rw [List.getElem?_take_of_lt h]

/-- The second loop of `put_number` writes the digits of the number, last first, at the places from
`start`: afterwards those places hold the digits and the others are unchanged. -/
theorem put_number_loop1_spec (start : Std.Usize) (out : Std.Array Std.U8 14#usize) (v : Std.U16)
    (i : Std.Usize) (fits : start.val + i.val ≤ 14)
    (digits : (i.val = 0 ∧ v.val = 0) ∨ (1 ≤ i.val ∧ (Decimal v.val).length = i.val)) :
    put_number_loop1 out start v i ⦃ r => ∀ j,
      r.val[j]! = if start.val ≤ j ∧ j < start.val + i.val then (Decimal v.val)[j - start.val]!
        else out.val[j]! ⦄ := by
  unfold put_number_loop1
  apply loop_answers (fun x : Std.Array Std.U8 14#usize × Std.U16 × Std.Usize =>
      put_number_loop1.body start x.1 x.2.1 x.2.2)
    (fun x y => ∀ j, y.val[j]! = if start.val ≤ j ∧ j < start.val + x.2.2.val then
        (Decimal x.2.1.val)[j - start.val]! else x.1.val[j]!)
    (fun x => x.2.2.val)
    (fun x => start.val + x.2.2.val ≤ 14 ∧
      ((x.2.2.val = 0 ∧ x.2.1.val = 0) ∨ (1 ≤ x.2.2.val ∧ (Decimal x.2.1.val).length = x.2.2.val)))
  · rintro ⟨out', v', i'⟩ ⟨fits', digits'⟩
    simp only at fits' digits' ⊢
    unfold put_number_loop1.body
    by_cases pos : i' > 0#usize
    · simp only [pos, ite_true]
      have pos' : 0 < i'.val := by scalar_tac
      step as ⟨ i1, is_i1 ⟩
      step as ⟨ i2, is_i2 ⟩
      step as ⟨ i3, is_i3 ⟩
      have i3v : i3.val = v'.val % 10 := by
        rw [is_i3, UScalar.cast_val_eq]; simp [is_i2]; omega
      step as ⟨ i4, is_i4 ⟩
      step as ⟨ i5, is_i5 ⟩
      step as ⟨ a, is_a ⟩
      step as ⟨ v1, is_v1 ⟩
      have i4_is : i4 = digitByte (v'.val % 10) := by
        apply UScalar.eq_of_val_eq
        rw [digitByte_val _ (by omega)]; omega
      have words : (Decimal v'.val).length = i'.val := by
        rcases digits' with ⟨h, _⟩ | ⟨_, h⟩
        · omega
        · exact h
      have len14 : out'.val.length = 14 := by simp
      by_cases small : v'.val < 10
      · have dec : Decimal v'.val = [digitByte v'.val] := decimal_small _ small
        have i_one : i'.val = 1 := by rw [dec] at words; simpa using words.symm
        have v1_zero : v1.val = 0 := by omega
        refine ⟨by omega, Or.inl ⟨by omega, v1_zero⟩, by omega, ?_⟩
        intro y hy j
        have hj := hy j
        have mod_eq : v'.val % 10 = v'.val := by omega
        by_cases hin : start.val ≤ j ∧ j < start.val + i'.val
        · have jeq : j = start.val + i1.val := by omega
          have not_in : ¬ (start.val ≤ j ∧ j < start.val + i1.val) := by omega
          rw [if_neg not_in, is_a, Array.set_val_eq] at hj
          rw [hj, if_pos hin, dec, jeq, is_i5, getD_set_eq _ _ _ (by omega)]
          simp [i4_is, mod_eq, show start.val + i1.val - start.val = 0 by omega]
        · have not_in : ¬ (start.val ≤ j ∧ j < start.val + i1.val) := by omega
          have ne : i5.val ≠ j := by omega
          rw [if_neg not_in, is_a, Array.set_val_eq, getD_set_ne _ _ _ _ ne] at hj
          rw [hj, if_neg hin]
      · have dec : Decimal v'.val = Decimal v1.val ++ [digitByte (v'.val % 10)] := by
          rw [decimal_big _ (by omega), is_v1]
        have len1 : (Decimal v1.val).length = i1.val := by
          rw [dec] at words; simp at words; omega
        have i1_pos : 1 ≤ i1.val := by
          have := decimal_ne_nil v1.val
          have : 0 < (Decimal v1.val).length := List.length_pos_iff.mpr this
          omega
        refine ⟨by omega, Or.inr ⟨i1_pos, len1⟩, by omega, ?_⟩
        intro y hy j
        have hj := hy j
        by_cases hlast : j = start.val + i1.val
        · have not_in : ¬ (start.val ≤ j ∧ j < start.val + i1.val) := by omega
          rw [if_neg not_in, is_a, Array.set_val_eq] at hj
          have hin : start.val ≤ j ∧ j < start.val + i'.val := by omega
          rw [hj, if_pos hin, dec, hlast, is_i5, getD_set_eq _ _ _ (by omega),
            getD_append_right _ _ _ (by omega)]
          simp [i4_is, len1]
        · by_cases hmid : start.val ≤ j ∧ j < start.val + i1.val
          · rw [if_pos hmid] at hj
            have hin : start.val ≤ j ∧ j < start.val + i'.val := by omega
            rw [hj, if_pos hin, dec, getD_append_left _ _ _ (by omega)]
          · have ne : i5.val ≠ j := by omega
            rw [if_neg hmid, is_a, Array.set_val_eq, getD_set_ne _ _ _ _ ne] at hj
            have hin : ¬ (start.val ≤ j ∧ j < start.val + i'.val) := by omega
            rw [hj, if_neg hin]
    · simp only [pos, ite_false]
      refine (WP.spec_ok _).mpr ?_
      have : i'.val = 0 := by scalar_tac
      intro j
      simp [this]
  · exact ⟨fits, digits⟩

/-- What `put_number` does: it writes the decimal digits of `c` from `start` and answers the place
after them; the other bytes are unchanged. -/
theorem put_number_spec (out : Std.Array Std.U8 14#usize) (start : Std.Usize) (c : Std.U16)
    (small : c.val < 1024) (fits : start.val + (Decimal c.val).length ≤ 14) :
    put_number out start c ⦃ r =>
      r.1.val = start.val + (Decimal c.val).length ∧
      ∀ j, r.2.val[j]! = if start.val ≤ j ∧ j < start.val + (Decimal c.val).length
        then (Decimal c.val)[j - start.val]! else out.val[j]! ⦄ := by
  unfold put_number
  step as ⟨ rest, is_rest ⟩
  have rest_small : rest.val < 10 ^ 3 := by omega
  have nd := ndig_le 3 rest.val rest_small
  have one : (1#usize).val = 1 := rfl
  step with put_number_loop0_spec 1#usize rest (by rw [one]; omega) as ⟨ size, is_size ⟩
  have size_is : size.val = (Decimal c.val).length := by
    rw [is_size, decimal_length, is_rest]; omega
  step with put_number_loop1_spec start out c size (by omega)
    (Or.inr ⟨by rw [size_is]; exact List.length_pos_iff.mpr (decimal_ne_nil _), size_is.symm⟩)
    as ⟨ out1, is_out1 ⟩
  step as ⟨ i, is_i ⟩
  refine ⟨by omega, ?_⟩
  intro j
  rw [is_out1 j, size_is]

/-- What `pair_label` does: it answers nothing exactly when the pair is not low < high < 1024, and
otherwise its label has the bytes `s0:cLOW,cHIGH`. -/
theorem pair_label_spec (low high : Std.U16) :
    pair_label low high ⦃ r =>
      (r = none ↔ ¬ (low.val < high.val ∧ high.val < 1024)) ∧
      ∀ label, r = some label → Label.as_bytes label ⦃ b => b.val = PairText low.val high.val ⦄ ⦄ := by
  unfold pair_label
  have cat : CATEGORIES.val = 1024 := by simp [CATEGORIES]
  by_cases c1 : low ≥ high
  · simp only [c1, ite_true]
    refine (WP.spec_ok _).mpr ⟨?_, by simp⟩
    have : ¬ low.val < high.val := by scalar_tac
    simp [this]
  · simp only [c1, ite_false]
    by_cases c2 : high ≥ CATEGORIES
    · simp only [c2, ite_true]
      refine (WP.spec_ok _).mpr ⟨?_, by simp⟩
      have : ¬ high.val < 1024 := by scalar_tac
      simp [this]
    · simp only [c2, ite_false]
      have lt1 : low.val < high.val := by scalar_tac
      have lt2 : high.val < 1024 := by scalar_tac
      step as ⟨ bytes1, is_b1 ⟩
      step as ⟨ bytes2, is_b2 ⟩
      step as ⟨ bytes3, is_b3 ⟩
      step as ⟨ bytes4, is_b4 ⟩
      have b4 : bytes4.val = [115#u8, 48#u8, 58#u8, 99#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8] := by
        rw [is_b4, is_b3, is_b2, is_b1]
        simp [Array.repeat_val, Array.set_val_eq]
      have dlow : (Decimal low.val).length ≤ 4 := by
        have := decimal_length low.val
        have := ndig_le 3 (low.val / 10) (by omega)
        omega
      have dhigh : (Decimal high.val).length ≤ 4 := by
        have := decimal_length high.val
        have := ndig_le 3 (high.val / 10) (by omega)
        omega
      step with put_number_spec bytes4 4#usize low (by omega) (by simp; omega) as ⟨ at1, bytes5, h5, h5pos ⟩
      step as ⟨ bytes6, is_b6 ⟩
      step as ⟨ i, is_i ⟩
      step as ⟨ bytes7, is_b7 ⟩
      step as ⟨ i1, is_i1 ⟩
      step with put_number_spec bytes7 i1 high (by omega) (by omega) as ⟨ len, bytes8, h8, h8pos ⟩
      refine ⟨by simp [lt1, lt2], ?_⟩
      intro label hl
      have lab : label = { bytes := bytes8, len := len } := (Option.some.inj hl).symm
      subst lab
      unfold Label.as_bytes
      simp only [Array.index_SliceIndexRangeToUsizeSlice]
      have len_is : len.val = 4 + (Decimal low.val).length + 2 + (Decimal high.val).length := by omega
      have len_le : len.val ≤ 14 := by omega
      unfold core.slice.index.SliceIndexRangeToUsizeSlice.index
      have fits : ({ «end» := len } : core.ops.range.RangeTo Usize).end ≤ bytes8.to_slice.length := by
        simp [Array.to_slice, Slice.length]; scalar_tac
      simp only [fits, ite_true]
      refine (WP.spec_ok _).mpr ?_
      have take_eq : bytes8.val.take len.val = PairText low.val high.val := by
        have pt : PairText low.val high.val =
            [115#u8, 48#u8, 58#u8, 99#u8] ++ Decimal low.val ++ [44#u8, 99#u8] ++ Decimal high.val := by
          unfold PairText; congr 3 <;> decide
        have bytes8_len : bytes8.val.length = 14 := by simp
        apply list_ext_bang
        · rw [pt]; simp only [List.length_take, bytes8_len, List.length_append, List.length_cons,
            List.length_nil]; omega
        · intro j hj
          have hj' : j < len.val := by simpa [bytes8_len, Nat.min_def, show len.val ≤ 14 from len_le] using hj
          rw [getD_take _ _ _ hj', h8pos j, pt]
          have lenA : ([115#u8, 48#u8, 58#u8, 99#u8] : List Std.U8).length = 4 := rfl
          have lenB : ([44#u8, 99#u8] : List Std.U8).length = 2 := rfl
          have at1v : at1.val = 4 + (Decimal low.val).length := h5
          have iv : i.val = at1.val + 1 := is_i
          have i1v : i1.val = at1.val + 2 := is_i1
          have b6 : bytes6.val = bytes5.val.set at1.val 44#u8 := by rw [is_b6, Array.set_val_eq]
          have b7 : bytes7.val = bytes6.val.set i.val 99#u8 := by rw [is_b7, Array.set_val_eq]
          have len5 : bytes5.val.length = 14 := by simp
          have len6 : bytes6.val.length = 14 := by simp
          by_cases r4 : i1.val ≤ j
          · -- the digits of the second category
            have : j < i1.val + (Decimal high.val).length := by omega
            rw [if_pos ⟨r4, this⟩]
            rw [getD_append_right _ _ _ (by simp [lenA, lenB]; omega)]
            simp only [List.length_append, lenA, lenB]
            congr 1; omega
          · rw [if_neg (by omega)]
            rw [getD_append_left _ _ _ (by simp [lenA, lenB]; omega)]
            by_cases r3 : j = at1.val + 1
            · have ji : i.val = j := by omega
              rw [b7, ← ji, getD_set_eq _ _ _ (by omega)]
              rw [getD_append_right _ _ _ (by simp [lenA]; omega)]
              simp only [List.length_append, lenA]
              rw [show i.val - (4 + (Decimal low.val).length) = 1 by omega]; rfl
            · rw [b7, getD_set_ne _ _ _ _ (by omega)]
              by_cases r2 : j = at1.val
              · have ja : at1.val = j := r2.symm
                rw [b6, ← ja, getD_set_eq _ _ _ (by omega)]
                rw [getD_append_right _ _ _ (by simp [lenA]; omega)]
                simp only [List.length_append, lenA]
                rw [show at1.val - (4 + (Decimal low.val).length) = 0 by omega]; rfl
              · rw [b6, getD_set_ne _ _ _ _ (by omega), h5pos j]
                by_cases r1 : 4 ≤ j ∧ j < 4 + (Decimal low.val).length
                · rw [if_pos r1, getD_append_left _ _ _ (by simp [lenA]; omega),
                    getD_append_right _ _ _ (by simp [lenA]; omega)]
                  simp [lenA]
                · rw [if_neg r1, b4]
                  have j4 : j < 4 := by omega
                  rw [getD_append_left _ _ _ (by simp [lenA]; omega),
                    getD_append_left _ _ _ (by simp [lenA]; omega)]
                  obtain rfl | rfl | rfl | rfl : j = 0 ∨ j = 1 ∨ j = 2 ∨ j = 3 := by omega
                  all_goals rfl
      simpa [Array.to_slice, List.slice] using take_eq

end McsCore
