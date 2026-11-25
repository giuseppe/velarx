-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `parse` as a whole: it returns, and answers the categories of a level of
--    the grammar, and a level of the grammar for any set it answers.
-- Why it is needed: every other function of the crate is built on `parse`.
-- Read before this file: TheParseLoop.lean, TheColon.lean, TheSensitivities.lean.
-- Notation: `Level t S`: `t` is a level, `S` the set of its categories.
import McsCore.TheParseLoop
import McsCore.TheColon
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- A digit is not a colon. -/
theorem digit_ne_colon {b : Std.U8} (h : IsDigit b) : b ≠ 58#u8 := by
  rintro rfl; exact absurd h.2 (by decide)

/-- The text of a sensitivity has no colon. -/
theorem sens_text_no_colon {p : List Std.U8} (h : SensText p) : ∀ b ∈ p, b ≠ 58#u8 := by
  obtain ⟨ds, rfl, _, digits⟩ := h
  intro b hb
  rw [text_s] at hb
  rcases List.mem_append.mp hb with h | h
  · simp at h; rw [h]; decide
  · exact fun e => digit_ne_colon (digits b h) e

/-- A range of sensitivities has no colon. -/
theorem sens_no_colon {p : List Std.U8} (h : Sens p) : ∀ b ∈ p, b ≠ 58#u8 := by
  induction h with
  | first t => exact sens_text_no_colon t
  | more _ t ih =>
    intro b hb
    rw [text_dash] at hb
    simp only [List.mem_append, List.mem_singleton] at hb
    rcases hb with (h | h) | h
    · exact ih b h
    · rw [h]; decide
    · exact sens_text_no_colon t b h

/-- The text of a category has no colon. -/
theorem cat_text_no_colon {p : List Std.U8} {n : Nat} (h : CatText p n) : ∀ b ∈ p, b ≠ 58#u8 := by
  obtain ⟨ds, rfl, _, digits, _⟩ := h
  intro b hb
  rw [text_c] at hb
  rcases List.mem_append.mp hb with h | h
  · simp at h; rw [h]; decide
  · exact fun e => digit_ne_colon (digits b h) e

/-- A group of categories has no colon. -/
theorem item_no_colon {p : List Std.U8} {S : Nat → Prop} (h : Item p S) : ∀ b ∈ p, b ≠ 58#u8 := by
  cases h with
  | single c => exact cat_text_no_colon c
  | range c1 c2 _ =>
    intro b hb
    rw [text_dot] at hb
    simp only [List.mem_append, List.mem_singleton] at hb
    rcases hb with (h | h) | h
    · exact cat_text_no_colon c1 b h
    · rw [h]; decide
    · exact cat_text_no_colon c2 b h

/-- Groups of categories have no colon. -/
theorem items_no_colon {p : List Std.U8} {S : Nat → Prop} (h : Items p S) : ∀ b ∈ p, b ≠ 58#u8 := by
  induction h with
  | last i => exact item_no_colon i
  | more i _ ih =>
    intro b hb
    rw [text_comma] at hb
    simp only [List.mem_append, List.mem_singleton] at hb
    rcases hb with (h | h) | h
    · exact item_no_colon i b h
    · rw [h]; decide
    · exact ih b h

/-- A level is a sensitivity alone with no category, or sensitivities, a colon and groups of
categories. -/
theorem level_cases {l : List Std.U8} {S : Nat → Prop} (h : Level l S) :
    (Sens l ∧ ∀ c, ¬ S c) ∨ ∃ ls r, Sens ls ∧ Items r S ∧ l = ls ++ 58#u8 :: r := by
  cases h with
  | plain h => exact Or.inl ⟨h, fun c => id⟩
  | categories hs hi => exact Or.inr ⟨_, _, hs, hi, by simp [text_colon]⟩

/-- Sensitivities alone are a level with no category. -/
theorem level_plain {l : List Std.U8} (h : Sens l) : Level l (fun _ => False) := Level.plain h

/-- Sensitivities, a colon and groups of categories are a level with these categories. -/
theorem level_categories {ls r : List Std.U8} {S : Nat → Prop} (hs : Sens ls) (hi : Items r S) :
    Level (ls ++ 58#u8 :: r) S := by
  have := Level.categories hs hi
  simpa [text_colon] using this

/-- The first colon of a text: it is at `k` exactly when the text is something without a colon, a
colon, and the rest. -/
theorem first_colon_of_split (ls r : List Std.U8) (no : ∀ b ∈ ls, b ≠ 58#u8) :
    FirstColon (ls ++ 58#u8 :: r) ls.length := by
  refine ⟨by simp, ?_, ?_⟩
  · simp
  · intro j hj
    rw [List.getElem!_eq_getElem?_getD, List.getElem?_append_left hj]
    have : ls[j]? = some ls[j] := List.getElem?_eq_getElem hj
    rw [this]
    simpa using no _ (List.getElem_mem hj)

/-- A text with a first colon is what is before it (no colon), the colon and what is after. -/
theorem split_of_first_colon (l : List Std.U8) (k : Nat) (h : FirstColon l k) :
    l = l.take k ++ 58#u8 :: l.drop (k + 1) ∧ ∀ b ∈ l.take k, b ≠ 58#u8 := by
  obtain ⟨lt, at_k, before⟩ := h
  constructor
  · have : l.drop k = 58#u8 :: l.drop (k + 1) := by
      rw [List.drop_eq_getElem_cons lt]
      congr 1
      rw [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem lt] at at_k
      simpa using at_k
    conv_lhs => rw [← List.take_append_drop k l]
    rw [this]
  · intro b hb
    obtain ⟨j, hj, rfl⟩ := List.getElem_of_mem hb
    have hj' : j < k := (by simpa using hj : j < k ∧ j < l.length).1
    have hl : j < l.length := (by simpa using hj : j < k ∧ j < l.length).2
    have := before j hj'
    rw [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem hl] at this
    simpa using this

/-- A text has one first colon. -/
theorem first_colon_unique {l : List Std.U8} {k k' : Nat} (h : FirstColon l k) (h' : FirstColon l k') :
    k = k' := by
  rcases Nat.lt_trichotomy k k' with lt | eq | gt
  · exact absurd h.2.1 (h'.2.2 k lt)
  · exact eq
  · exact absurd h'.2.1 (h.2.2 k' gt)

/-- What `parse` answers: it returns; for a level of the grammar it answers its categories, and what
it answers is a level of the grammar with these categories. -/
theorem parse_spec (level : Slice Std.U8) :
    parse level ⦃ r =>
      (∀ S, Level level.val S → ∃ cats, r = some cats ∧ ∀ c, Mem cats c ↔ S c) ∧
      (∀ cats, r = some cats → ∃ S, Level level.val S ∧ ∀ c, Mem cats c ↔ S c) ⦄ := by
  unfold parse
  have is_len : (Slice.len level).val = level.length := by simp [Slice.len]
  have sl : level.length = level.val.length := rfl
  step with parse_loop0_spec level (Slice.len level) false 0#usize (by simp)
    as ⟨ colon, found, h1, h2, h3, h4 ⟩
  have colon_le : colon.val ≤ level.length := by
    by_cases hf : found = true
    · have := (h3 hf).2.2.1; omega
    · have hf' : found = false := by simpa using hf
      rw [h4 hf', ← is_len]
  step with sensitivities_spec level colon colon_le as ⟨ ok1, hok1 ⟩
  step with empty_spec as ⟨ cats0, hcats0 ⟩
  by_cases ok : ok1 = true
  · have sens : Sens (level.val.take colon.val) := hok1.mp ok
    simp only [ok, ite_true]
    by_cases hf : found = true
    · simp only [hf, ite_true]
      obtain ⟨_, at_colon, lt_colon, before⟩ := h3 hf
      have fc : FirstColon level.val colon.val := ⟨lt_colon, at_colon, fun j hj => before j (Nat.zero_le _) hj⟩
      obtain ⟨split, no_colon⟩ := split_of_first_colon level.val colon.val fc
      step as ⟨ start, is_start ⟩
      step with parse_loop1_spec level cats0 start as ⟨ ok2, cats1, hp1, hp2 ⟩
      have drop_is : level.val.drop start.val = level.val.drop (colon.val + 1) := by rw [is_start]
      rw [drop_is] at hp1 hp2
      have complete : ∀ S, Level level.val S → Items (level.val.drop (colon.val + 1)) S := by
        intro S lvl
        rcases level_cases lvl with ⟨sens', _⟩ | ⟨ls, r, _, items, eq⟩
        · exfalso
          have mem : level.val[colon.val] ∈ level.val := List.getElem_mem lt_colon
          have is58 : level.val[colon.val] = 58#u8 := by
            have := at_colon
            rwa [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem lt_colon, Option.getD_some] at this
          exact sens_no_colon sens' _ mem is58
        · have fc' := first_colon_of_split ls r (sens_no_colon ‹Sens ls›)
          rw [← eq] at fc'
          have : ls.length = colon.val := first_colon_unique fc' fc
          rw [eq, ← this]
          simpa using items
      by_cases hok2 : ok2 = true
      · simp only [hok2, ite_true]
        obtain ⟨S, items⟩ := hp1.mp hok2
        refine (WP.spec_ok _).mpr ⟨?_, ?_⟩
        · intro S0 lvl
          exact ⟨cats1, rfl, fun c => by rw [hp2 S0 (complete S0 lvl) c]; simp [hcats0]⟩
        · intro cats hc
          have : cats1 = cats := Option.some.inj hc
          subst this
          refine ⟨S, ?_, fun c => by rw [hp2 S items c]; simp [hcats0]⟩
          have lv := level_categories sens items
          rw [← split] at lv
          exact lv
      · have ok2_false : ok2 = false := by simpa using hok2
        simp only [ok2_false, Bool.false_eq_true, ite_false]
        refine (WP.spec_ok _).mpr ⟨?_, ?_⟩
        · intro S0 lvl
          exact absurd (hp1.mpr ⟨S0, complete S0 lvl⟩) hok2
        · intro cats hc; simp at hc
    · have hf' : found = false := by simpa using hf
      have colon_end : colon.val = level.val.length := by rw [h4 hf', is_len]
      have whole : level.val.take colon.val = level.val := by rw [colon_end]; exact List.take_length
      rw [whole] at sens
      simp only [hf, ite_false, ok, ite_true]
      refine (WP.spec_ok _).mpr ⟨?_, ?_⟩
      · intro S lvl
        rcases level_cases lvl with ⟨_, none⟩ | ⟨ls, r, _, _, eq⟩
        · exact ⟨cats0, rfl, fun c => ⟨fun m => absurd m (hcats0 c), fun s => absurd s (none c)⟩⟩
        · exfalso
          have fc := first_colon_of_split ls r (sens_no_colon ‹Sens ls›)
          rw [← eq] at fc
          have := h2.mpr ⟨ls.length, Nat.zero_le _, fc.1, fc.2.1⟩
          exact hf this
      · intro cats hc
        have : cats0 = cats := Option.some.inj hc
        subst this
        exact ⟨_, level_plain sens, fun c => ⟨fun m => absurd m (hcats0 c), fun s => s.elim⟩⟩
  · have ok' : ok1 = false := by simpa using ok
    simp only [ok', Bool.false_eq_true, ite_false]
    refine (WP.spec_ok _).mpr ⟨?_, ?_⟩
    · intro S lvl
      exfalso
      by_cases hf : found = true
      · obtain ⟨_, at_colon, lt_colon, before⟩ := h3 hf
        have fc : FirstColon level.val colon.val :=
          ⟨lt_colon, at_colon, fun j hj => before j (Nat.zero_le _) hj⟩
        rcases level_cases lvl with ⟨sens', _⟩ | ⟨ls, r, hs, _, eq⟩
        · have mem : level.val[colon.val] ∈ level.val := List.getElem_mem lt_colon
          have is58 : level.val[colon.val] = 58#u8 := by
            have := at_colon
            rwa [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem lt_colon, Option.getD_some] at this
          exact sens_no_colon sens' _ mem is58
        · have fc' := first_colon_of_split ls r (sens_no_colon hs)
          rw [← eq] at fc'
          have : ls.length = colon.val := first_colon_unique fc' fc
          have take_eq : level.val.take colon.val = ls := by
            rw [eq, ← this]; simp
          exact ok (hok1.mpr (by rw [take_eq]; exact hs))
      · have hf' : found = false := by simpa using hf
        have colon_end : colon.val = level.val.length := by rw [h4 hf', is_len]
        have whole : level.val.take colon.val = level.val := by rw [colon_end]; exact List.take_length
        rcases level_cases lvl with ⟨sens', _⟩ | ⟨ls, r, hs, _, eq⟩
        · exact ok (hok1.mpr (by rw [whole]; exact sens'))
        · have fc := first_colon_of_split ls r (sens_no_colon hs)
          rw [← eq] at fc
          exact hf (h2.mpr ⟨ls.length, Nat.zero_le _, fc.1, fc.2.1⟩)
    · intro cats hc; simp at hc

end McsCore
