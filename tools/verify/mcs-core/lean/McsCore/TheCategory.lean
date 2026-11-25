-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `category`, which reads `cN` at a place: the number saturates at 1024 and
--    what it answers is what the digits write.
-- Why it is needed: a category is the base of a level; `parse` calls it for each category.
-- Read before this file: TheLoops.lean.
-- Notation: `run l` is the digits at the beginning of the list `l`.
import McsCore.TheLoops
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- The byte is a digit, as a boolean (for `takeWhile`). -/
def isDigitB (b : Std.U8) : Bool := decide (IsDigit b)

/-- The digits at the beginning of a list. -/
def run (l : List Std.U8) : List Std.U8 := l.takeWhile isDigitB

/-- What the number of `category` is after reading more digits: it stops at 1024. -/
def satFold (v : Nat) (ds : List Std.U8) : Nat :=
  ds.foldl (fun v d => min 1024 (10 * v + (d.val - 48))) v

/-- The digits at the beginning of a list that begins with a digit are that digit and the digits
after it. -/
theorem run_digit (l : List Std.U8) (b : Std.U8) (isd : IsDigit b) : run (b :: l) = b :: run l := by
  unfold run isDigitB
  simp [List.takeWhile_cons, isd]

/-- A list that does not begin with a digit has no digit at its beginning. -/
theorem run_not_digit (l : List Std.U8) (b : Std.U8) (isd : ¬ IsDigit b) : run (b :: l) = [] := by
  unfold run isDigitB
  simp [List.takeWhile_cons, isd]

/-- What the loop of `category` does: it reads the digits from place `i`, keeps the number at most
1024 on the way, and counts the digits. -/
theorem category_loop_spec (s : Slice Std.U8) (i : Std.Usize) (v : Std.U16) (d : Std.Usize)
    (inside : i.val ≤ s.length) (small : v.val ≤ 1024)
    (room : d.val + (s.val.drop i.val).length ≤ Std.Usize.max) :
    category_loop s i v d ⦃ r =>
      r.1.val = i.val + (run (s.val.drop i.val)).length ∧
      r.2.1.val = satFold v.val (run (s.val.drop i.val)) ∧
      r.2.2.val = d.val + (run (s.val.drop i.val)).length ⦄ := by
  unfold category_loop
  apply loop_answers (fun x => category_loop.body s x.1 x.2.1 x.2.2)
    (fun x y => y.1.val = x.1.val + (run (s.val.drop x.1.val)).length ∧
      y.2.1.val = satFold x.2.1.val (run (s.val.drop x.1.val)) ∧
      y.2.2.val = x.2.2.val + (run (s.val.drop x.1.val)).length)
    (fun x => s.length - x.1.val)
    (fun x => x.1.val ≤ s.length ∧ x.2.1.val ≤ 1024 ∧
      x.2.2.val + (s.val.drop x.1.val).length ≤ Std.Usize.max)
  · rintro ⟨i', v', d'⟩ ⟨inside', small', room'⟩
    simp only at inside' small' room' ⊢
    unfold category_loop.body
    have is_len : (Slice.len s).val = s.length := by simp [Slice.len]
    by_cases below : i' < Slice.len s
    · simp only [below, ite_true]
      have below' : i'.val < s.length := by scalar_tac
      step as ⟨ b, is_b ⟩
      have cat : CATEGORIES.val = 1024 := by simp [CATEGORIES]
      have here : s.val.drop i'.val = b :: s.val.drop (i'.val + 1) := by
        rw [is_b]; exact List.drop_eq_getElem_cons below'
      by_cases digit : IsDigit b
      · have ge : b ≥ 48#u8 := by have := digit.1; scalar_tac
        have le : b ≤ 57#u8 := by have := digit.2; scalar_tac
        simp only [ge, le, ite_true]
        have bv : 48 ≤ b.val ∧ b.val ≤ 57 := digit
        step as ⟨ i3, is_i3 ⟩
        step as ⟨ i4, is_i4 ⟩
        step as ⟨ i5, is_i5 ⟩
        step as ⟨ value1, is_value1 ⟩
        have i5v : i5.val = b.val - 48 := by rw [is_i5, UScalar.cast_val_eq]; simp [is_i4]; omega
        have value1v : value1.val = v'.val * 10 + (b.val - 48) := by omega
        have dlen : (s.val.drop (i'.val + 1)).length + 1 = (s.val.drop i'.val).length := by
          rw [here]; simp
        obtain ⟨value2, is_value2, value2v⟩ : ∃ value2 : Std.U16,
            (if value1 > CATEGORIES then ok CATEGORIES else ok value1 : Result Std.U16) = ok value2 ∧
            value2.val = min 1024 (10 * v'.val + (b.val - 48)) := by
          by_cases big : value1 > CATEGORIES
          · refine ⟨CATEGORIES, by simp [big], ?_⟩
            have : value1.val > 1024 := by scalar_tac
            omega
          · refine ⟨value1, by simp [big], ?_⟩
            have : ¬ value1.val > 1024 := by scalar_tac
            omega
        simp only [is_value2, bind_tc_ok, bind_ok]
        step as ⟨ digits1, is_digits1 ⟩
        step as ⟨ i6, is_i6 ⟩
        refine ⟨by omega, by omega, ?_, by omega, ?_⟩
        · rw [is_i6]; omega
        intro y h1 h2 h3
        rw [is_i6] at h1 h2 h3
        rw [is_digits1] at h3
        rw [value2v] at h2
        rw [here, run_digit _ _ digit]
        simp only [List.length_cons, satFold, List.foldl_cons]
        simp only [satFold] at h2
        refine ⟨by omega, h2, by omega⟩
      · have not_both : ¬ (b ≥ 48#u8 ∧ b ≤ 57#u8) := by
          rintro ⟨ge, le⟩; exact digit ⟨by scalar_tac, by scalar_tac⟩
        have done_case : i'.val = i'.val + (run (s.val.drop i'.val)).length ∧
            v'.val = satFold v'.val (run (s.val.drop i'.val)) ∧
            d'.val = d'.val + (run (s.val.drop i'.val)).length := by
          rw [here, run_not_digit _ _ digit]; simp [satFold]
        by_cases ge : b ≥ 48#u8
        · have : ¬ b ≤ 57#u8 := fun le => not_both ⟨ge, le⟩
          simp only [ge, this, ite_true, ite_false]
          exact (WP.spec_ok _).mpr done_case
        · simp only [ge, ite_false]
          exact (WP.spec_ok _).mpr done_case
    · simp only [below, ite_false]
      refine (WP.spec_ok _).mpr ?_
      have : (s.val.drop i'.val) = [] := by
        apply List.drop_of_length_le; scalar_tac
      simp [this, run, satFold]
  · exact ⟨inside, small, room⟩

/-- Reading digits and keeping the number at most 1024 on the way gives the number the digits write,
at most 1024. -/
theorem satFold_cap (ds : List Std.U8) (x : Nat) :
    min 1024 (ds.foldl (fun n d => 10 * n + (d.val - 48)) (min 1024 x)) =
      min 1024 (ds.foldl (fun n d => 10 * n + (d.val - 48)) x) := by
  induction ds generalizing x with
  | nil => simp
  | cons d ds ih =>
    simp only [List.foldl_cons]
    have same : min 1024 (10 * min 1024 x + (d.val - 48)) = min 1024 (10 * x + (d.val - 48)) := by
      omega
    rw [← ih (10 * min 1024 x + (d.val - 48)), ← ih (10 * x + (d.val - 48)), same]

/-- Keeping the number at most 1024 at every digit gives the number the digits write, or 1024 when
that is more. -/
theorem satFold_eq (ds : List Std.U8) (v : Nat) (small : v ≤ 1024) :
    satFold v ds = min 1024 (ds.foldl (fun n d => 10 * n + (d.val - 48)) v) := by
  induction ds generalizing v with
  | nil => simp [satFold]; omega
  | cons d ds ih =>
    simp only [satFold, List.foldl_cons] at ih ⊢
    rw [ih _ (by omega), satFold_cap]

/-- What `category` answers at a place: after a `c`, the end of the digits, the number (at most
1024) and whether it is a category (digits, and a number below 1024); anywhere else, not a
category. -/
theorem category_spec (s : Slice Std.U8) (start : Std.Usize) :
    category s start ⦃ r =>
      (∀ rest, s.val.drop start.val = 99#u8 :: rest →
        r.end.val = start.val + 1 + (run rest).length ∧
        (r.ok = true ↔ run rest ≠ [] ∧ Value (run rest) < 1024) ∧
        r.value.val = min 1024 (Value (run rest))) ∧
      ((s.val.drop start.val).head? ≠ some 99#u8 → r.end = start ∧ r.ok = false) ⦄ := by
  unfold category
  have cat : CATEGORIES.val = 1024 := by simp [CATEGORIES]
  have is_len : (Slice.len s).val = s.length := by simp [Slice.len]
  by_cases below : start < Slice.len s
  · simp only [below, ite_true]
    have below' : start.val < s.length := by scalar_tac
    step as ⟨ b, is_b ⟩
    have here : s.val.drop start.val = b :: s.val.drop (start.val + 1) := by
      rw [is_b]; exact List.drop_eq_getElem_cons below'
    by_cases is_c : b = 99#u8
    · simp only [is_c, ite_true]
      step as ⟨ i2, is_i2 ⟩
      step with category_loop_spec s i2 0#u16 0#usize (by omega) (by simp)
        (by simp; have := s.property; scalar_tac) as ⟨ i3, value, digits, at_end, at_value, at_digits ⟩
      have value_is : value.val = min 1024 (Value (run (s.val.drop i2.val))) := by
        rw [at_value, satFold_eq _ _ (by omega)]; rfl
      have big : value.val ≤ 1024 := by omega
      have rest_is : ∀ rest, s.val.drop start.val = 99#u8 :: rest → rest = s.val.drop i2.val := by
        intro rest h
        rw [here] at h
        have := (List.cons.injEq _ _ _ _).mp h
        rw [is_i2]; exact this.2.symm
      have facts : ∀ rest, s.val.drop start.val = 99#u8 :: rest →
          i3.val = start.val + 1 + (run rest).length ∧ digits.val = (run rest).length ∧
          value.val = min 1024 (Value (run rest)) := by
        intro rest h
        rw [rest_is rest h]
        exact ⟨by omega, by omega, value_is⟩
      by_cases positive : digits > 0#usize
      · simp only [positive, ↓reduceIte]
        refine (WP.spec_ok _).mpr ⟨?_, ?_⟩
        · intro rest h
          obtain ⟨e1, e2, e3⟩ := facts rest h
          refine ⟨e1, ?_, e3⟩
          have ne : run rest ≠ [] := by
            intro empty; rw [empty] at e2
            have : digits.val > 0 := by simpa using (UScalar.lt_equiv 0#usize digits).mp positive
            simp at e2; omega
          have cat' : value < CATEGORIES ↔ Value (run rest) < 1024 := by
            rw [UScalar.lt_equiv, cat, e3]; omega
          simp only [cat', decide_eq_true_eq, ne_eq, ne, not_false_eq_true, true_and]
        · intro hne; exfalso; apply hne; rw [here]; simp [is_c]
      · simp only [positive, ↓reduceIte]
        refine (WP.spec_ok _).mpr ⟨?_, ?_⟩
        · intro rest h
          obtain ⟨e1, e2, e3⟩ := facts rest h
          have empty : run rest = [] := by
            have : ¬ digits.val > 0 := by simpa using (not_congr (UScalar.lt_equiv 0#usize digits)).mp positive
            apply List.length_eq_zero_iff.mp; omega
          refine ⟨e1, ?_, e3⟩
          simp [empty]
        · intro hne; exfalso; apply hne; rw [here]; simp [is_c]
    · simp only [is_c, ite_false]
      refine (WP.spec_ok _).mpr ⟨?_, ?_⟩
      · intro rest h
        rw [here] at h
        exact absurd (List.cons.inj h).1 is_c
      · intro _; simp
  · simp only [below, ite_false]
    refine (WP.spec_ok _).mpr ⟨?_, ?_⟩
    · intro rest h
      have : s.val.drop start.val = [] := by
        apply List.drop_of_length_le; scalar_tac
      rw [this] at h; simp at h
    · intro _; simp

end McsCore
