-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `sensitivities`, which says whether the beginning of a text is `sN` or
--    `sN-sM-...`.
-- Why it is needed: `parse` checks the part before the colon with it.
-- Read before this file: TheLoops.lean, Spec.lean.
-- Notation: `Expects p`: the text so far ends where an `s` must come.
import McsCore.TheLoops
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- The text `s` is the byte 115. -/
theorem text_s : Text "s" = [115#u8] := by decide
/-- The text `-` is the byte 45. -/
theorem text_dash : Text "-" = [45#u8] := by decide
/-- The text `c` is the byte 99. -/
theorem text_c : Text "c" = [99#u8] := by decide
/-- The text `.` is the byte 46. -/
theorem text_dot : Text "." = [46#u8] := by decide
/-- The text `,` is the byte 44. -/
theorem text_comma : Text "," = [44#u8] := by decide
/-- The text `:` is the byte 58. -/
theorem text_colon : Text ":" = [58#u8] := by decide

/-- The text so far is empty or ends with the dash after a sensitivity: a `s` is next. -/
def Expects (p : List Std.U8) : Prop := p = [] ∨ ∃ q, Sens q ∧ p = q ++ [45#u8]

/-- The text so far ends with the `s` of a sensitivity: digits are next. -/
def AfterS (p : List Std.U8) : Prop := ∃ q, Expects q ∧ p = q ++ [115#u8]

/-- The text of a sensitivity with one more byte at its end is the text of a sensitivity when the
byte is a digit. -/
theorem sens_text_snoc (p : List Std.U8) (b : Std.U8) :
    SensText (p ++ [b]) ↔ IsDigit b ∧ (p = [115#u8] ∨ SensText p) := by
  unfold SensText
  rw [text_s]
  constructor
  · rintro ⟨ds, eq, ne, digits⟩
    rcases List.eq_nil_or_concat' ds with rfl | ⟨L, b', rfl⟩
    · exact absurd rfl ne
    · have eq' : p ++ [b] = ([115#u8] ++ L) ++ [b'] := by simpa using eq
      obtain ⟨hp, hb⟩ := List.append_inj' eq' rfl
      have hb' : b = b' := by simpa using hb
      subst hb'
      refine ⟨digits _ (by simp), ?_⟩
      rcases List.eq_nil_or_concat' L with rfl | ⟨L', b'', rfl⟩
      · left; simpa using hp
      · right
        exact ⟨L' ++ [b''], hp, by simp, fun d hd => digits d (List.mem_append_left _ hd)⟩
  · rintro ⟨isd, rfl | ⟨ds, eq, ne, digits⟩⟩
    · exact ⟨[b], by simp, by simp, by simpa using isd⟩
    · refine ⟨ds ++ [b], by simp [eq], by simp, ?_⟩
      intro d hd
      rcases List.mem_append.mp hd with h | h
      · exact digits d h
      · simpa [List.mem_singleton.mp h] using isd

/-- Sensitivities with one more byte at the end are sensitivities exactly when the byte is a digit
after an `s` or after sensitivities. -/
theorem sens_snoc (p : List Std.U8) (b : Std.U8) :
    Sens (p ++ [b]) ↔ IsDigit b ∧ (AfterS p ∨ Sens p) := by
  constructor
  · intro h
    generalize eq : p ++ [b] = full at h
    cases h with
    | first hs =>
      rw [← eq] at hs
      obtain ⟨isd, rfl | hs'⟩ := (sens_text_snoc p b).mp hs
      · exact ⟨isd, Or.inl ⟨[], Or.inl rfl, by simp⟩⟩
      · exact ⟨isd, Or.inr (Sens.first hs')⟩
    | more hl hr =>
      rename_i l r
      rw [text_dash] at eq
      rcases List.eq_nil_or_concat' r with rfl | ⟨r', b', rfl⟩
      · obtain ⟨ds, h, ne, _⟩ := hr
        simp only [text_s] at h
        simp at h
      · have eq' : p ++ [b] = (l ++ [45#u8] ++ r') ++ [b'] := by simpa using eq
        obtain ⟨hp, hb⟩ := List.append_inj' eq' rfl
        have hb' : b = b' := by simpa using hb
        subst hb'
        obtain ⟨isd, rfl | hr'⟩ := (sens_text_snoc r' b).mp hr
        · exact ⟨isd, Or.inl ⟨l ++ [45#u8], Or.inr ⟨l, hl, rfl⟩, by simp [hp]⟩⟩
        · refine ⟨isd, Or.inr ?_⟩
          rw [hp, ← text_dash]
          exact Sens.more hl hr'
  · rintro ⟨isd, ⟨q, hq, rfl⟩ | hs⟩
    · rcases hq with rfl | ⟨q', hq', rfl⟩
      · have := Sens.first ((sens_text_snoc [115#u8] b).mpr ⟨isd, Or.inl rfl⟩)
        simpa using this
      · have := Sens.more hq' ((sens_text_snoc [115#u8] b).mpr ⟨isd, Or.inl rfl⟩)
        rw [text_dash] at this
        simpa using this
    · cases hs with
      | first h => exact Sens.first ((sens_text_snoc _ b).mpr ⟨isd, Or.inr h⟩)
      | more hl hr =>
        have := Sens.more hl ((sens_text_snoc _ b).mpr ⟨isd, Or.inr hr⟩)
        simpa using this

/-- The text so far expects a `s` after one more byte exactly when the byte is a dash after
sensitivities. -/
theorem expects_snoc (p : List Std.U8) (b : Std.U8) : Expects (p ++ [b]) ↔ b = 45#u8 ∧ Sens p := by
  unfold Expects
  constructor
  · rintro (h | ⟨q, hq, h⟩)
    · simp at h
    · obtain ⟨hp, hb⟩ := List.append_inj' h rfl
      exact ⟨by simpa using hb, hp ▸ hq⟩
  · rintro ⟨rfl, h⟩
    exact Or.inr ⟨p, h, rfl⟩

/-- The text so far ends with the `s` of a sensitivity after one more byte exactly when the byte is
a `s` where one is expected. -/
theorem afterS_snoc (p : List Std.U8) (b : Std.U8) : AfterS (p ++ [b]) ↔ b = 115#u8 ∧ Expects p := by
  unfold AfterS
  constructor
  · rintro ⟨q, hq, h⟩
    obtain ⟨hp, hb⟩ := List.append_inj' h rfl
    exact ⟨by simpa using hb, hp ▸ hq⟩
  · rintro ⟨rfl, h⟩
    exact ⟨p, h, rfl⟩

/-- Sensitivities are never empty. -/
theorem sens_ne_nil {x : List Std.U8} (h : Sens x) : x ≠ [] := by
  cases h with
  | first hs => obtain ⟨ds, eq, _⟩ := hs; rw [eq, text_s]; simp
  | more hl hr => rw [text_dash]; simp

/-- The empty text is not sensitivities. -/
theorem not_sens_nil : ¬ Sens [] := fun h => sens_ne_nil h rfl

/-- The empty text does not end with a `s`. -/
theorem not_afterS_nil : ¬ AfterS [] := by
  rintro ⟨q, _, h⟩
  simp at h

/-- What the three states of the loop of `sensitivities` mean about the text read so far. -/
def Reads (p : List Std.U8) (state : Std.I32) (ok : Bool) : Prop :=
  (state = 0#i32 ∨ state = 1#i32 ∨ state = 2#i32) ∧
  (ok = true ∧ state = 0#i32 ↔ Expects p) ∧
  (ok = true ∧ state = 1#i32 ↔ AfterS p) ∧
  (ok = true ∧ state = 2#i32 ↔ Sens p)

/-- What the loop of `sensitivities` does with a byte: from `state` with the flag `ok` it goes to
`state1` with the flag `ok2`. -/
def Trans (state : Std.I32) (ok : Bool) (b : Std.U8) (state1 : Std.I32) (ok2 : Bool) : Prop :=
  (state = 0#i32 ∧ b = 115#u8 ∧ state1 = 1#i32 ∧ ok2 = ok) ∨
  (1#i32 ≤ state ∧ IsDigit b ∧ state1 = 2#i32 ∧ ok2 = ok) ∨
  (state = 2#i32 ∧ b = 45#u8 ∧ state1 = 0#i32 ∧ ok2 = ok) ∨
  (¬ (state = 0#i32 ∧ b = 115#u8) ∧ ¬ (1#i32 ≤ state ∧ IsDigit b) ∧ ¬ (state = 2#i32 ∧ b = 45#u8) ∧
    state1 = state ∧ ok2 = false)

/-- A digit is not a dash. -/
theorem digit_ne_dash {b : Std.U8} (h : IsDigit b) : b ≠ 45#u8 := by
  rintro rfl; exact absurd h.1 (by decide)

/-- A digit is not an `s`. -/
theorem digit_ne_s {b : Std.U8} (h : IsDigit b) : b ≠ 115#u8 := by
  rintro rfl; exact absurd h.2 (by decide)

/-- A dash is not a digit. -/
theorem not_digit_dash : ¬ IsDigit 45#u8 := fun h => absurd h.1 (by decide)

/-- An `s` is not a digit. -/
theorem not_digit_s : ¬ IsDigit 115#u8 := fun h => absurd h.2 (by decide)

/-- One more byte, taken as the loop of `sensitivities` takes it, keeps what the three states mean. -/
theorem reads_next (p : List Std.U8) (b : Std.U8) (state : Std.I32) (ok : Bool)
    (reads : Reads p state ok) (state1 : Std.I32) (ok2 : Bool) (trans : Trans state ok b state1 ok2) :
    Reads (p ++ [b]) state1 ok2 := by
  obtain ⟨hst, hE', hA', hS'⟩ := reads
  unfold Reads
  rw [expects_snoc, afterS_snoc, sens_snoc]
  unfold Trans at trans
  rcases hst with rfl | rfl | rfl <;> rcases trans with ⟨h1, h2, rfl, rfl⟩ | ⟨h1, h2, rfl, rfl⟩ | ⟨h1, h2, rfl, rfl⟩ | ⟨h1, h2, h3, h4, rfl, rfl⟩ <;>
    simp_all [digit_ne_dash, digit_ne_s, not_digit_dash, not_digit_s]

/-- The loop of `sensitivities` ends in the state that says the text is sensitivities exactly when
it is. -/
theorem sensitivities_loop_spec (s : Slice Std.U8) (stop : Std.Usize) (state : Std.I32) (ok : Bool)
    (i : Std.Usize) (inside : stop.val ≤ s.length) (before : i.val ≤ stop.val)
    (reads : Reads (s.val.take i.val) state ok) :
    sensitivities_loop s stop state ok i ⦃ r =>
      (r.2 = true ∧ r.1 = 2#i32 ↔ Sens (s.val.take stop.val)) ⦄ := by
  unfold sensitivities_loop
  apply loop_answers (fun x => sensitivities_loop.body s stop x.1 x.2.1 x.2.2)
    (fun _ y => (y.2 = true ∧ y.1 = 2#i32 ↔ Sens (s.val.take stop.val)))
    (fun x => stop.val - x.2.2.val)
    (fun x => x.2.2.val ≤ stop.val ∧ Reads (s.val.take x.2.2.val) x.1 x.2.1)
  · rintro ⟨state', ok', i'⟩ ⟨before', reads'⟩
    simp only at before' reads' ⊢
    unfold sensitivities_loop.body
    by_cases below : i' < stop
    · simp only [below, ite_true]
      have below' : i'.val < stop.val := by scalar_tac
      have lt : i'.val < s.length := by omega
      step as ⟨ b, is_b ⟩
      have snoc : s.val.take (i'.val + 1) = s.val.take i'.val ++ [b] := by
        rw [is_b]; exact List.take_succ_eq_append_getElem lt
      have room : i'.val + 1 ≤ Usize.max := by scalar_tac
      have hst := reads'.1
      rcases hst with rfl | rfl | rfl <;>
      repeat' split
      all_goals simp only [bind_tc_ok, bind_ok]
      all_goals step as ⟨ i1, is_i1 ⟩
      all_goals refine ⟨by scalar_tac, ?_, by scalar_tac, fun _ h => h⟩
      all_goals rw [is_i1, snoc]
      all_goals refine reads_next _ b _ _ reads' _ _ ?_
      all_goals clear reads reads' snoc
      all_goals unfold Trans
      all_goals simp_all [IsDigit, UScalar.le_equiv]
    · simp only [below, ite_false]
      have at_stop : i'.val = stop.val := by scalar_tac
      rw [at_stop] at reads'
      refine (WP.spec_ok _).mpr ?_
      exact reads'.2.2.2
  · exact ⟨before, reads⟩

/-- What `sensitivities` answers: true exactly when the beginning of the text is sensitivities. -/
theorem sensitivities_spec (s : Slice Std.U8) (stop : Std.Usize) (inside : stop.val ≤ s.length) :
    sensitivities s stop ⦃ r => r = true ↔ Sens (s.val.take stop.val) ⦄ := by
  unfold sensitivities
  have start : Reads (s.val.take (0#usize).val) 0#i32 true := by
    have z : (0#usize).val = 0 := rfl
    rw [z]
    refine ⟨Or.inl rfl, ?_, ?_, ?_⟩
    · simp [Expects]
    · simpa using not_afterS_nil
    · simpa using not_sens_nil
  step with sensitivities_loop_spec s stop 0#i32 true 0#usize inside (by simp) start
    as ⟨ state, ok1, loop ⟩
  by_cases ok : ok1 = true
  · simp only [ok, ite_true]
    refine (WP.spec_ok _).mpr ?_
    rw [← loop]
    simp [ok]
  · simp only [ok, ite_false]
    refine (WP.spec_ok _).mpr ?_
    rw [← loop]
    simp [ok]

end McsCore
