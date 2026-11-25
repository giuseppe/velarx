-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `category` reads, said in terms of the grammar of Spec.lean: the text
--    of a category and what follows it.
-- Why it is needed: the loop of `parse` takes a category and then looks at the byte after it.
-- Read before this file: TheCategory.lean, TheSensitivities.lean.
-- Notation: `CatText l n`: `l` is the text of the category `cN`.
import McsCore.TheCategory
import McsCore.TheSensitivities
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- The digits at the beginning of some digits followed by something that is not a digit are those
digits. -/
theorem run_of_digits_then (ds tail : List Std.U8) (digits : ∀ d ∈ ds, IsDigit d)
    (stop : tail = [] ∨ ∃ x rest, tail = x :: rest ∧ ¬ IsDigit x) : run (ds ++ tail) = ds := by
  induction ds with
  | nil =>
    rcases stop with rfl | ⟨x, rest, rfl, not_digit⟩
    · simp [run]
    · simpa using run_not_digit rest x not_digit
  | cons d ds ih =>
    rw [List.cons_append, run_digit _ _ (digits d (by simp)), ih (fun e he => digits e (by simp [he]))]

/-- Every byte of the digits at the beginning of a list is a digit. -/
theorem run_is_digits (l : List Std.U8) : ∀ d ∈ run l, IsDigit d := by
  induction l with
  | nil => simp [run]
  | cons b l ih =>
    by_cases h : IsDigit b
    · rw [run_digit _ _ h]
      intro d hd
      rcases List.mem_cons.mp hd with rfl | hd
      · exact h
      · exact ih d hd
    · rw [run_not_digit _ _ h]; simp

/-- A list is its beginning digits and then the rest. -/
theorem run_prefix (l : List Std.U8) : ∃ rest, l = run l ++ rest := by
  induction l with
  | nil => exact ⟨[], by simp [run]⟩
  | cons b l ih =>
    by_cases h : IsDigit b
    · obtain ⟨rest, hrest⟩ := ih
      refine ⟨rest, ?_⟩
      rw [run_digit _ _ h]
      simpa using hrest
    · exact ⟨b :: l, by rw [run_not_digit _ _ h]; simp⟩

/-- `category` reads the text `l` of a category that is followed by something that is not a digit. -/
theorem category_reads (s : Slice Std.U8) (start : Std.Usize) (l tail : List Std.U8) (n : Nat)
    (here : s.val.drop start.val = l ++ tail) (cat : CatText l n)
    (stop : tail = [] ∨ ∃ x rest, tail = x :: rest ∧ ¬ IsDigit x) :
    category s start ⦃ r => r.ok = true ∧ r.value.val = n ∧ r.end.val = start.val + l.length ⦄ := by
  obtain ⟨ds, rfl, ne, digits, value, small⟩ := cat
  refine WP.spec_mono (category_spec s start) ?_
  rintro r ⟨reads, _⟩
  have here' : s.val.drop start.val = 99#u8 :: (ds ++ tail) := by rw [here, text_c]; rfl
  obtain ⟨e1, e2, e3⟩ := reads _ here'
  rw [run_of_digits_then ds tail digits stop] at e1 e2 e3
  refine ⟨e2.mpr ⟨ne, by rw [value]; exact small⟩, ?_, ?_⟩
  · rw [e3]; omega
  · rw [e1, text_c]; simp; omega

/-- The other way: when `category` is `ok`, the text from `start` is a category and what follows. -/
theorem category_read (s : Slice Std.U8) (start : Std.Usize) :
    category s start ⦃ r => r.ok = true →
      ∃ l tail n, s.val.drop start.val = l ++ tail ∧ CatText l n ∧ r.value.val = n ∧
        r.end.val = start.val + l.length ∧ s.val.drop r.end.val = tail ⦄ := by
  refine WP.spec_mono (category_spec s start) ?_
  rintro r ⟨reads, off⟩ ok
  by_cases is_c : (s.val.drop start.val).head? = some 99#u8
  · obtain ⟨rest, hrest⟩ : ∃ rest, s.val.drop start.val = 99#u8 :: rest := by
      cases h : s.val.drop start.val with
      | nil => rw [h] at is_c; simp at is_c
      | cons b rest => rw [h] at is_c; simp at is_c; exact ⟨rest, by rw [is_c]⟩
    obtain ⟨e1, e2, e3⟩ := reads rest hrest
    obtain ⟨ne, small⟩ := e2.mp ok
    obtain ⟨tail, htail⟩ := run_prefix rest
    refine ⟨99#u8 :: run rest, tail, Value (run rest), ?_, ?_, ?_, ?_, ?_⟩
    · rw [hrest]; simp; exact htail
    · exact ⟨run rest, by rw [text_c]; rfl, ne, run_is_digits rest, rfl, small⟩
    · rw [e3]; omega
    · rw [e1]; simp; omega
    · have h2 : s.val.drop (start.val + 1) = rest := by
        have := congrArg (List.drop 1) hrest
        simpa [List.drop_drop, Nat.add_comm] using this
      have hdrop : (run rest ++ tail).drop (run rest).length = tail := List.drop_left' rfl
      rw [← htail] at hdrop
      have := congrArg (List.drop (run rest).length) h2
      rw [List.drop_drop, hdrop] at this
      rw [e1]; exact this
  · have := (off is_c).2
    rw [this] at ok; simp at ok

end McsCore
