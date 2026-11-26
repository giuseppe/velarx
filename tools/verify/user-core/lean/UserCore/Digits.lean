-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: digits, their decimal value, and what `is_digits` and `parse_id` answer (the proof of AnIdIsTheNumberWritten).
-- Why it is needed: `resolve` reads every id of the files and of the user string with these two.
-- Read before this file: Spec.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` is the number a
--    machine integer is.
import UserCore.Spec
open Aeneas Aeneas.Std Result velarx_user_core
namespace UserCore

/-- A condition that holds picks the first branch. -/
theorem if_yes {α : Type _} {c : Prop} [Decidable c] (h : c) (a b : α) :
    (if c then a else b) = a := by simp [h]

/-- A condition that does not hold picks the second branch. -/
theorem if_no {α : Type _} {c : Prop} [Decidable c] (h : ¬ c) (a b : α) :
    (if c then a else b) = b := by simp [h]

/-- Every byte at a place from `i` to before `k` is a digit. -/
def DigitsIn (s : List Std.U8) (i k : Nat) : Prop :=
  ∀ j, i ≤ j → j < k → ∀ b, s[j]? = some b → IsDigit b

/-- All the places of a list are digits exactly when every byte of it is. -/
theorem digitsIn_all (s : List Std.U8) : DigitsIn s 0 s.length ↔ ∀ b ∈ s, IsDigit b := by
  constructor
  · intro h b hb
    obtain ⟨j, hj, rfl⟩ := List.getElem_of_mem hb
    exact h j (by omega) hj _ (by simp)
  · intro h j _ hj b hb
    exact h b (List.mem_of_getElem? hb)

/-- One more place is digits when the places before are and its byte is. -/
theorem digitsIn_succ (s : List Std.U8) (i k : Nat) (hik : i ≤ k) (b : Std.U8)
    (hb : s[k]? = some b) : DigitsIn s i (k + 1) ↔ DigitsIn s i k ∧ IsDigit b := by
  constructor
  · intro h
    exact ⟨fun j h1 h2 => h j h1 (by omega), h k hik (by omega) b hb⟩
  · rintro ⟨h, hd⟩ j h1 h2 c hc
    by_cases e : j = k
    · subst e; rw [hb] at hc; cases hc; exact hd
    · exact h j h1 (by omega) c hc

/-- The loop of `is_digits` returns true exactly when the flag was true and all the bytes from the place are digits. -/
theorem is_digits_loop_spec (s : Slice Std.U8) (flag : Bool) (i : Std.Usize) (hi : i.val ≤ s.length) :
    is_digits_loop s flag i ⦃ r => (r = true ↔ flag = true ∧ DigitsIn s.val i.val s.length) ⦄ := by
  unfold is_digits_loop
  apply loop.spec_decr_nat (fun (q : Bool × Std.Usize) => s.length - q.2.val)
    (fun (q : Bool × Std.Usize) => i.val ≤ q.2.val ∧ q.2.val ≤ s.length ∧
      (q.1 = true ↔ flag = true ∧ DigitsIn s.val i.val q.2.val))
    (fun r => r = true ↔ flag = true ∧ DigitsIn s.val i.val s.length)
  · rintro ⟨ok1, i1⟩ ⟨hii, hi1, hok⟩
    simp only at hi1 hok ⊢
    unfold is_digits_loop.body
    step*
    · rename_i below running
      have below' : i1.val < s.length := by scalar_tac
      have digits := hok.mp running
      have byte : s.val[i1.val]? = some i2 := by rw [i2_post]; simp [below']
      have grow := digitsIn_succ s.val i.val i1.val (by omega) i2 byte
      have lo_iff : i2 ≥ 48#u8 ↔ 48 ≤ i2.val := by scalar_tac
      have hi_iff : i2 ≤ 57#u8 ↔ i2.val ≤ 57 := by scalar_tac
      by_cases lo : i2 ≥ 48#u8
      · simp only [lo, ite_true]
        step*
        refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
        rw [i3_post, grow]
        simp only [decide_eq_true_eq, hi_iff, IsDigit, digits.1, true_and, digits.2]
        exact ⟨fun h => ⟨(lo_iff.mp lo), h⟩, fun h => h.2⟩
      · simp only [lo, ite_false]
        step*
        refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
        rw [i3_post, grow]
        simp only [Bool.false_eq_true, false_iff, not_and]
        intro _ _ h
        exact lo (lo_iff.mpr h.1)
    · rename_i below running
      have not_running : ¬ ok1 = true := running
      simp only [Bool.false_eq_true, false_iff, not_and]
      intro hf hd
      exact not_running (hok.mpr ⟨hf, fun j h1 h2 => hd j h1 (by omega)⟩)
  · exact ⟨le_refl _, hi, by simp [DigitsIn]; intro _ j hj hj2; omega⟩

/-- `is_digits` is true exactly when the bytes are one or more digits. -/
theorem is_digits_spec (s : Slice Std.U8) :
    is_digits s ⦃ b => b = true ↔ IsDigits s.val ⦄ := by
  unfold is_digits
  step as ⟨ e, e_post ⟩
  step with is_digits_loop_spec as ⟨ r, r_post ⟩
  have empty : s.val = [] ↔ e = true := by
    rw [e_post]; simp [Slice.length]
  have all : DigitsIn s.val 0 s.length ↔ ∀ b ∈ s.val, IsDigit b := digitsIn_all s.val
  rw [r_post, all, IsDigits]
  simp [← empty]

/-- test -/
theorem no_id_is : NO_ID = ok 4294967295#u64 := by
  unfold NO_ID; rfl

/-- Adding a digit at the end multiplies the number by ten and adds the digit. -/
theorem value_snoc (xs : List Std.U8) (b : Std.U8) : Value (xs ++ [b]) = 10 * Value xs + (b.val - 48) := by
  unfold Value; simp [List.foldl_append]

/-- Adding digits at the end does not make the number smaller. -/
theorem value_le_append (xs ys : List Std.U8) : Value xs ≤ Value (xs ++ ys) := by
  induction ys generalizing xs with
  | nil => simp
  | cons y ys ih =>
    have := ih (xs ++ [y])
    rw [value_snoc] at this
    simpa using (by omega : Value xs ≤ 10 * Value xs + (y.val - 48)).trans this

/-- The number of the first bytes up to one more is ten times the number before, plus the digit. -/
theorem value_take_succ (s : List Std.U8) (i : Nat) (b : Std.U8) (hb : s[i]? = some b) :
    Value (s.take (i + 1)) = 10 * Value (s.take i) + (b.val - 48) := by
  rw [List.take_add_one, hb]
  simpa using value_snoc (s.take i) b

/-- The loop of `parse_id` returns the number written, or a number of `NoId` or more when it stopped early because that was reached (and then the number written is of `NoId` or more too). -/
theorem parse_id_loop_spec (s : Slice Std.U8) (digits : DigitsIn s.val 0 s.length)
    (v : Std.U64) (i : Std.Usize) (hi : i.val ≤ s.length) (hv : v.val = Value (s.val.take i.val)) :
    parse_id_loop s v i ⦃ r => r.val = Value s.val ∨ (NoId ≤ r.val ∧ NoId ≤ Value s.val) ⦄ := by
  unfold parse_id_loop
  apply loop.spec_decr_nat (fun (q : Std.U64 × Std.Usize) => s.length - q.2.val)
    (fun (q : Std.U64 × Std.Usize) => q.2.val ≤ s.length ∧ q.1.val = Value (s.val.take q.2.val))
    (fun (r : Std.U64) => r.val = Value s.val ∨ (NoId ≤ r.val ∧ NoId ≤ Value s.val))
  · rintro ⟨v1, i1⟩ ⟨hi1, hv1⟩
    simp only at hi1 hv1 ⊢
    unfold parse_id_loop.body
    have whole : s.val.take s.length = s.val := List.take_of_length_le (le_refl _)
    step*
    rename_i below
    simp only [no_id_is, bind_ok]
    by_cases small : v1 < 4294967295#u64
    · simp only [small, ite_true]
      have below' : i1.val < s.length := by scalar_tac
      have small' : v1.val < 4294967295 := by scalar_tac
      step as ⟨ i3, i3_post ⟩
      step as ⟨ i4, i4_post ⟩
      have byte : s.val[i1.val]? = some i4 := by rw [i4_post]; simp [below']
      have digit := digits i1.val (by omega) below' i4 byte
      step as ⟨ i5, i5_post ⟩
      step as ⟨ i6, i6_post ⟩
      step as ⟨ v2, v2_post ⟩
      step as ⟨ i7, i7_post ⟩
      have six : i6.val = i5.val := by rw [i6_post]; simp
      refine ⟨by scalar_tac, ?_, by scalar_tac⟩
      rw [i7_post, value_take_succ s.val i1.val i4 byte, v2_post, six, i3_post, hv1]
      omega
    · simp only [small, ite_false]
      refine (WP.spec_ok _).mpr ?_
      right
      have big : NoId ≤ v1.val := by unfold NoId; scalar_tac
      refine ⟨big, ?_⟩
      rw [hv1] at big
      have := value_le_append (s.val.take i1.val) (s.val.drop i1.val)
      rw [List.take_append_drop] at this
      omega
  · exact ⟨hi, hv⟩

/-- Proof of `AnIdIsTheNumberWritten`. -/
theorem parse_id_spec : AnIdIsTheNumberWritten := by
  intro s
  unfold ParsedId
  unfold parse_id
  step with is_digits_spec as ⟨ b, b_post ⟩
  by_cases is : b = true
  · have d := b_post.mp is
    have all : DigitsIn s.val 0 s.length := (digitsIn_all s.val).mpr d.2
    simp only [is, ite_true]
    step with parse_id_loop_spec s all 0#u64 0#usize as ⟨ v, v_post ⟩
    · rfl
    simp only [no_id_is, bind_ok]
    by_cases big : v >= 4294967295#u64
    · simp only [big, ite_true]
      refine (WP.spec_ok _).mpr ?_
      intro n
      have : NoId ≤ v.val := by unfold NoId; scalar_tac
      have : NoId ≤ Value s.val := by omega
      simp only [reduceCtorEq, false_iff, not_and, not_lt]
      intro _ _ ; omega
    · simp only [big, ite_false]
      step as ⟨ w, w_post ⟩
      have small : v.val < NoId := by unfold NoId; scalar_tac
      have same : v.val = Value s.val := by omega
      intro n
      simp only [Option.some.injEq, d, true_and]
      constructor
      · rintro rfl
        have : w.val = v.val := by rw [w_post]; simp; scalar_tac
        omega
      · rintro ⟨h1, h2⟩
        scalar_tac
  · simp only [is]
    refine (WP.spec_ok _).mpr ?_
    intro n
    simp only [reduceCtorEq, false_iff, not_and]
    intro d
    exact absurd (b_post.mpr d) is

end UserCore
