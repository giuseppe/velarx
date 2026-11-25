-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: one round of the loop of `parse` that reads the groups of categories, in
--    two directions: when it says `ok`, the text read was a group followed by nothing or a comma;
--    when the text is a group followed by nothing or a comma, it says `ok`.
-- Why it is needed: both directions are needed so that `parse` refuses what is not a level and
--    takes every level.
-- Read before this file: TheItems.lean, TheRange.lean, TheColon.lean.
-- Notation: `Item l S`: `l` is a group of categories, `S` the set of its categories.
import McsCore.TheItems
import McsCore.TheRange
import McsCore.TheColon
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- When the list from place `k` begins with `x`, the byte at `k` is `x`. -/
theorem getElem_of_drop (l : List Std.U8) (k : Nat) (x : Std.U8) (rest : List Std.U8)
    (h : l.drop k = x :: rest) : l[k]! = x := by
  have lt : k < l.length := by
    by_contra no
    rw [List.drop_of_length_le (by omega)] at h; simp at h
  rw [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem lt]
  simp
  have := List.drop_eq_getElem_cons lt
  rw [this] at h
  exact (List.cons.inj h).1

/-- The text of a category is never empty (it has the `c`). -/
theorem cat_text_ne_nil {l : List Std.U8} {n : Nat} (h : CatText l n) : l ≠ [] := by
  obtain ⟨ds, rfl, ne, _⟩ := h
  rw [text_c]; simp

/-- When the bytes from `start` are `l` and then `tail`, and `l` is not empty, the bytes from the
end of `l` are `tail`, and that end is inside the bytes. -/
theorem drop_append_end (level : List Std.U8) (start : Nat) (l tail : List Std.U8)
    (hdrop : level.drop start = l ++ tail) (ne : l ≠ []) :
    start + l.length ≤ level.length ∧ level.drop (start + l.length) = tail := by
  have len := congrArg List.length hdrop
  simp only [List.length_drop, List.length_append] at len
  have pos : 0 < l.length := List.length_pos_iff.mpr ne
  refine ⟨by omega, ?_⟩
  have := congrArg (List.drop l.length) hdrop
  rw [List.drop_drop, List.drop_left' rfl] at this
  exact this

/-- What the body of the loop of `parse` does when it is run with `ok1` and `more` set: it goes on, and
if it still says `ok`, the text from `at` was a group of categories, and what follows it is nothing
(the end) or a comma. -/
theorem parse_loop1_body_sound (level : Slice Std.U8) (cats : Cats) (start : Std.Usize) :
    parse_loop1.body level (Slice.len level) true cats start true ⦃ r =>
      ∃ ok2 cats2 at2 more2, r = ControlFlow.cont (ok2, cats2, at2, more2) ∧
        (ok2 = true → ∃ l S tail, level.val.drop start.val = l ++ tail ∧ Item l S ∧
          (∀ d, Mem cats2 d ↔ Mem cats d ∨ S d) ∧
          ((tail = [] ∧ more2 = false) ∨
            ∃ rest, tail = 44#u8 :: rest ∧ level.val.drop at2.val = rest ∧ more2 = true)) ⦄ := by
  unfold parse_loop1.body
  simp only [ite_true]
  step with category_read level start as ⟨ lo, hlo ⟩
  have is_len : (Slice.len level).val = level.length := by simp [Slice.len]
  by_cases hl : lo.ok = true
  · obtain ⟨l, tail, n0, hdrop, cat, hv, hend, htail⟩ := hlo hl
    have ne := cat_text_ne_nil cat
    obtain ⟨end_le, _⟩ := drop_append_end level.val start.val l tail hdrop ne
    have n0small : n0 < 1024 := by obtain ⟨_, _, _, _, _, small⟩ := cat; exact small
    simp only [hl, ite_true]
    by_cases lt : lo.end < Slice.len level
    · simp only [lt, ite_true]
      have lt' : lo.end.val < level.length := by scalar_tac
      step as ⟨ x, is_x ⟩
      obtain ⟨rest, hrest⟩ : ∃ rest, tail = x :: rest := by
        refine ⟨level.val.drop (lo.end.val + 1), ?_⟩
        rw [← htail, is_x]; exact List.drop_eq_getElem_cons lt'
      by_cases dot : x = 46#u8
      · simp only [dot, ite_true]
        have rest_is : level.val.drop (lo.end.val + 1) = rest := by
          have := congrArg (List.drop 1) (htail.trans hrest)
          simpa [List.drop_drop, Nat.add_comm] using this
        step as ⟨ i1, is_i1 ⟩
        step with category_read level i1 as ⟨ hi, hhi ⟩
        obtain ⟨ok2, is_ok2, ok2_iff⟩ : ∃ ok2 : Bool,
            (if hi.ok = true then ok (decide (lo.value ≤ hi.value)) else ok false : Result Bool) = ok ok2 ∧
            (ok2 = true ↔ hi.ok = true ∧ lo.value.val ≤ hi.value.val) := by
          by_cases hh : hi.ok = true
          · refine ⟨decide (lo.value ≤ hi.value), by simp [hh], ?_⟩
            simp [hh, UScalar.le_equiv]
          · exact ⟨false, by simp [hh], by simp [hh]⟩
        simp only [is_ok2, bind_tc_ok, bind_ok]
        have small2 : ok2 = true → hi.value.val < 1024 := by
          intro h
          obtain ⟨hh, _⟩ := ok2_iff.mp h
          obtain ⟨l2, tail2, n1, _, cat2, hv2, _⟩ := hhi hh
          obtain ⟨_, _, _, _, _, s2⟩ := cat2
          omega
        step with parse_loop1_loop0_spec ok2 cats hi.value lo.value small2 as ⟨ cats1, hcats1 ⟩
        by_cases hok2 : ok2 = true
        · obtain ⟨hh, hle⟩ := ok2_iff.mp hok2
          obtain ⟨l2, tail2, n1, hdrop2, cat2, hv2, hend2, htail2⟩ := hhi hh
          have ne2 := cat_text_ne_nil cat2
          have rest_eq : rest = l2 ++ tail2 := by
            rw [← rest_is, ← is_i1]; exact hdrop2
          have drop_eq : level.val.drop start.val = (l ++ Text "." ++ l2) ++ tail2 := by
            rw [hdrop, hrest, dot, text_dot, rest_eq]; simp
          have members : ∀ d, Mem cats1 d ↔ Mem cats d ∨ (n0 ≤ d ∧ d ≤ n1) := by
            intro d; rw [hcats1 d, hv, hv2] at *; simp [hok2, hv, hv2]
          have item : Item (l ++ Text "." ++ l2) (fun c => n0 ≤ c ∧ c ≤ n1) :=
            Item.range cat cat2 (by rw [← hv, ← hv2]; scalar_tac)
          obtain ⟨end_le2, _⟩ := drop_append_end level.val i1.val l2 tail2 hdrop2 ne2
          simp only [hok2, ite_true]
          by_cases hiend : hi.end = Slice.len level
          · simp only [hiend, ite_true]
            have tail2_nil : tail2 = [] := by
              rw [← htail2, show hi.end.val = level.val.length by rw [hiend, is_len],
                List.drop_length]
            refine (WP.spec_ok _).mpr ?_
            exact ⟨true, cats1, level.len, false, rfl, fun _ =>
              ⟨l ++ Text "." ++ l2, _, tail2, drop_eq, item, members, Or.inl ⟨tail2_nil, rfl⟩⟩⟩
          · simp only [hiend, ite_false, hok2, ite_true]
            have lt2 : hi.end.val < level.length := by
              have : hi.end.val ≠ level.length := by
                intro h; apply hiend; apply UScalar.eq_of_val_eq; rw [h, is_len]
              have sl : level.length = level.val.length := rfl
              omega
            step as ⟨ x2, is_x2 ⟩
            obtain ⟨rest2, hrest2⟩ : ∃ rest2, tail2 = x2 :: rest2 := by
              refine ⟨level.val.drop (hi.end.val + 1), ?_⟩
              rw [← htail2, is_x2]; exact List.drop_eq_getElem_cons lt2
            by_cases comma2 : x2 = 44#u8
            · simp only [comma2, ite_true]
              step as ⟨ at1, is_at1 ⟩
              refine ⟨true, cats1, at1, true, rfl, fun _ =>
                ⟨l ++ Text "." ++ l2, _, tail2, drop_eq, item, members, Or.inr ⟨rest2, ?_, ?_, rfl⟩⟩⟩
              · rw [hrest2, comma2]
              · rw [is_at1]
                have := congrArg (List.drop 1) (htail2.trans hrest2)
                simpa [List.drop_drop, Nat.add_comm] using this
            · simp only [comma2, ite_false]
              refine (WP.spec_ok _).mpr ?_
              exact ⟨false, cats1, hi.end, true, rfl, fun h => absurd h (by simp)⟩
        · have ok2_false : ok2 = false := by simpa using hok2
          simp only [ok2_false, Bool.false_eq_true, ite_false]
          exact (WP.spec_ok _).mpr ⟨false, cats1, hi.end, true, rfl, fun h => absurd h (by simp)⟩
      · simp only [dot, ite_false]
        step with add_spec cats lo.value (by omega) as ⟨ cats1, is_cats1 ⟩
        have not_end : ¬ lo.end = Slice.len level := by intro h; rw [h] at lt; exact absurd lt (lt_irrefl _)
        simp only [not_end, ite_false]
        by_cases comma : x = 44#u8
        · simp only [comma, ite_true]
          step as ⟨ at1, is_at1 ⟩
          refine ⟨true, cats1, at1, true, rfl, fun _ => ?_⟩
          refine ⟨l, fun c => c = n0, tail, hdrop, Item.single cat, ?_, Or.inr ⟨rest, ?_, ?_, rfl⟩⟩
          · intro d; rw [is_cats1 d, hv]
          · rw [hrest, comma]
          · rw [is_at1]
            have : level.val.drop (lo.end.val + 1) = rest := by
              have := congrArg (List.drop 1) (htail.trans hrest)
              simpa [List.drop_drop, Nat.add_comm] using this
            exact this
        · simp only [comma, ite_false]
          refine (WP.spec_ok _).mpr ?_
          exact ⟨false, cats1, lo.end, true, rfl, fun h => absurd h (by simp)⟩
    · simp only [lt, ite_false]
      have sl : level.length = level.val.length := rfl
      have at_end : lo.end.val = level.length := by
        have : ¬ lo.end.val < level.length := by scalar_tac
        omega
      have tail_nil : tail = [] := by
        rw [← htail, List.drop_of_length_le (by omega)]
      step with add_spec cats lo.value (by omega) as ⟨ cats1, is_cats1 ⟩
      have is_end : lo.end = Slice.len level := by
        apply UScalar.eq_of_val_eq; rw [at_end, is_len]
      simp only [is_end, ite_true]
      refine (WP.spec_ok _).mpr ?_
      refine ⟨true, cats1, level.len, false, rfl, fun _ => ?_⟩
      refine ⟨l, fun c => c = n0, tail, hdrop, Item.single cat, ?_, Or.inl ⟨tail_nil, rfl⟩⟩
      intro d; rw [is_cats1 d, hv]
  · simp only [hl, Bool.false_eq_true, ite_false]
    refine WP.spec_bind (Pₘ := fun x => x = cats) ((WP.spec_ok cats).mpr rfl) ?_
    intro c hc
    refine (WP.spec_ok _).mpr ?_
    exact ⟨false, c, lo.end, true, rfl, fun h => absurd h (by simp)⟩

/-- The other way: when the text from `at` is a group of categories followed by nothing or a comma,
the body of the loop of `parse` takes it and says `ok`. -/
theorem parse_loop1_body_complete (level : Slice Std.U8) (cats : Cats) (start : Std.Usize)
    (l : List Std.U8) (S : Nat → Prop) (tail : List Std.U8)
    (item : Item l S) (hdrop : level.val.drop start.val = l ++ tail)
    (follows : tail = [] ∨ ∃ rest, tail = 44#u8 :: rest) :
    parse_loop1.body level (Slice.len level) true cats start true ⦃ r =>
      ∃ cats2 at2 more2, r = ControlFlow.cont (true, cats2, at2, more2) ∧
        (∀ d, Mem cats2 d ↔ Mem cats d ∨ S d) ∧
        ((tail = [] ∧ more2 = false) ∨
          ∃ rest, tail = 44#u8 :: rest ∧ level.val.drop at2.val = rest ∧ more2 = true) ⦄ := by
  unfold parse_loop1.body
  simp only [ite_true]
  have is_len : (Slice.len level).val = level.length := by simp [Slice.len]
  have sl : level.length = level.val.length := rfl
  have stop : tail = [] ∨ ∃ x rest, tail = x :: rest ∧ ¬ IsDigit x := by
    rcases follows with h | ⟨rest, h⟩
    · exact Or.inl h
    · exact Or.inr ⟨44#u8, rest, h, fun d => absurd d.1 (by decide)⟩
  rcases item with ⟨cat⟩ | ⟨cat1, cat2, le⟩
  · rename_i n0
    step with category_reads level start l tail n0 hdrop cat stop as ⟨ lo, lo_ok, lo_val, lo_end ⟩
    have ne := cat_text_ne_nil cat
    obtain ⟨end_le, htail⟩ := drop_append_end level.val start.val l tail hdrop ne
    have n0small : n0 < 1024 := by obtain ⟨_, _, _, _, _, small⟩ := cat; exact small
    simp only [lo_ok, ite_true]
    have htail' : level.val.drop lo.end.val = tail := by rw [lo_end]; exact htail
    rcases follows with tail_nil | ⟨rest, tail_eq⟩
    · have at_end : lo.end.val = level.length := by
        have : level.val.length ≤ lo.end.val := by
          by_contra no
          have := List.drop_eq_nil_iff.not.mpr (by omega : ¬ level.val.length ≤ lo.end.val)
          rw [htail', tail_nil] at this; exact this rfl
        omega
      have is_end : lo.end = Slice.len level := by
        apply UScalar.eq_of_val_eq; rw [at_end, is_len]
      have not_lt : ¬ lo.end < Slice.len level := by rw [is_end]; exact lt_irrefl _
      simp only [not_lt, ite_false]
      step with add_spec cats lo.value (by omega) as ⟨ cats1, is_cats1 ⟩
      simp only [is_end, ite_true]
      refine (WP.spec_ok _).mpr ?_
      refine ⟨cats1, level.len, false, rfl, ?_, Or.inl ⟨tail_nil, rfl⟩⟩
      intro d; rw [is_cats1 d, lo_val]
    · have lt' : lo.end.val < level.length := by
        by_contra no
        have : level.val.drop lo.end.val = [] := List.drop_of_length_le (by omega)
        rw [htail', tail_eq] at this; simp at this
      have lt : lo.end < Slice.len level := by scalar_tac
      simp only [lt, ite_true]
      have x_is : level.val[lo.end.val]! = 44#u8 := getElem_of_drop _ _ _ rest (htail'.trans tail_eq)
      step as ⟨ x, is_x ⟩
      have x44 : x = 44#u8 := by rw [is_x, ← x_is]; simp [List.getElem!_eq_getElem?_getD, lt']
      have not_dot : ¬ x = 46#u8 := by rw [x44]; decide
      simp only [not_dot, ite_false]
      step with add_spec cats lo.value (by omega) as ⟨ cats1, is_cats1 ⟩
      have not_end : ¬ lo.end = Slice.len level := by
        intro h; rw [h] at lt; exact absurd lt (lt_irrefl _)
      simp only [not_end, ite_false, x44, ite_true]
      step as ⟨ at1, is_at1 ⟩
      refine ⟨cats1, at1, true, rfl, ?_, Or.inr ⟨rest, tail_eq, ?_, rfl⟩⟩
      · intro d; rw [is_cats1 d, lo_val]
      · rw [is_at1]
        have := congrArg (List.drop 1) (htail'.trans tail_eq)
        simpa [List.drop_drop, Nat.add_comm] using this
  · rename_i l1 l2 a b
    have hdrop1 : level.val.drop start.val = l1 ++ (46#u8 :: (l2 ++ tail)) := by
      rw [hdrop, text_dot]; simp
    have stop1 : (46#u8 :: (l2 ++ tail)) = [] ∨ ∃ x rest, (46#u8 :: (l2 ++ tail)) = x :: rest ∧ ¬ IsDigit x :=
      Or.inr ⟨46#u8, _, rfl, fun d => absurd d.1 (by decide)⟩
    step with category_reads level start l1 _ a hdrop1 cat1 stop1 as ⟨ lo, lo_ok, lo_val, lo_end ⟩
    have ne1 := cat_text_ne_nil cat1
    have ne2 := cat_text_ne_nil cat2
    obtain ⟨end_le, htail⟩ := drop_append_end level.val start.val l1 _ hdrop1 ne1
    have asmall : a < 1024 := by obtain ⟨_, _, _, _, _, small⟩ := cat1; exact small
    have bsmall : b < 1024 := by obtain ⟨_, _, _, _, _, small⟩ := cat2; exact small
    simp only [lo_ok, ite_true]
    have htail' : level.val.drop lo.end.val = 46#u8 :: (l2 ++ tail) := by rw [lo_end]; exact htail
    have lt' : lo.end.val < level.length := by
      by_contra no
      have : level.val.drop lo.end.val = [] := List.drop_of_length_le (by omega)
      rw [htail'] at this; simp at this
    have lt : lo.end < Slice.len level := by scalar_tac
    simp only [lt, ite_true]
    have x_is : level.val[lo.end.val]! = 46#u8 := getElem_of_drop _ _ _ _ htail'
    step as ⟨ x, is_x ⟩
    have x46 : x = 46#u8 := by rw [is_x, ← x_is]; simp [List.getElem!_eq_getElem?_getD, lt']
    simp only [x46, ite_true]
    step as ⟨ i1, is_i1 ⟩
    have hdrop2 : level.val.drop i1.val = l2 ++ tail := by
      rw [is_i1]
      have := congrArg (List.drop 1) htail'
      simpa [List.drop_drop, Nat.add_comm] using this
    step with category_reads level i1 l2 tail b hdrop2 cat2 stop as ⟨ hi, hi_ok, hi_val, hi_end ⟩
    have is_ok2 : (if hi.ok = true then ok (decide (lo.value ≤ hi.value)) else ok false : Result Bool) =
        ok true := by
      simp [hi_ok, UScalar.le_equiv, lo_val, hi_val, le]
    simp only [is_ok2, bind_tc_ok, bind_ok]
    step with parse_loop1_loop0_spec true cats hi.value lo.value (fun _ => by omega)
      as ⟨ cats1, hcats1 ⟩
    have members : ∀ d, Mem cats1 d ↔ Mem cats d ∨ (a ≤ d ∧ d ≤ b) := by
      intro d; rw [hcats1 d, lo_val, hi_val]
    obtain ⟨end_le2, htail2⟩ := drop_append_end level.val i1.val l2 tail hdrop2 ne2
    have htail2' : level.val.drop hi.end.val = tail := by rw [hi_end]; exact htail2
    simp only [ite_true]
    rcases follows with tail_nil | ⟨rest, tail_eq⟩
    · have at_end : hi.end.val = level.length := by
        have : level.val.length ≤ hi.end.val := by
          by_contra no
          have := List.drop_eq_nil_iff.not.mpr (by omega : ¬ level.val.length ≤ hi.end.val)
          rw [htail2', tail_nil] at this; exact this rfl
        omega
      have is_end : hi.end = Slice.len level := by
        apply UScalar.eq_of_val_eq; rw [at_end, is_len]
      simp only [is_end, ite_true]
      refine (WP.spec_ok _).mpr ?_
      exact ⟨cats1, level.len, false, rfl, members, Or.inl ⟨tail_nil, rfl⟩⟩
    · have lt2' : hi.end.val < level.length := by
        by_contra no
        have : level.val.drop hi.end.val = [] := List.drop_of_length_le (by omega)
        rw [htail2', tail_eq] at this; simp at this
      have not_end : ¬ hi.end = Slice.len level := by
        intro h; have := congrArg UScalar.val h; rw [is_len] at this; omega
      simp only [not_end, ite_false, ite_true]
      have x2_is : level.val[hi.end.val]! = 44#u8 := getElem_of_drop _ _ _ rest (htail2'.trans tail_eq)
      step as ⟨ x2, is_x2 ⟩
      have x244 : x2 = 44#u8 := by rw [is_x2, ← x2_is]; simp [List.getElem!_eq_getElem?_getD, lt2']
      simp only [x244, ite_true]
      step as ⟨ at1, is_at1 ⟩
      refine ⟨cats1, at1, true, rfl, members, Or.inr ⟨rest, tail_eq, ?_, rfl⟩⟩
      rw [is_at1]
      have := congrArg (List.drop 1) (htail2'.trans tail_eq)
      simpa [List.drop_drop, Nat.add_comm] using this

end McsCore
