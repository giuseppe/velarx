-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `strict`: the levels that a user or the CRI may give.
-- Why it is needed: it is `parse` with two more rules, and the proof says it exactly.
-- Read before this file: TheParse.lean.
-- Notation: `NoLeadingZero l` is in Spec.lean.
import McsCore.TheParse
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- Reading a place of a slice answers its byte. -/
theorem index_bang (s : Slice Std.U8) (j : Std.Usize) (h : j.val < s.length) :
    s.index_usize j = ok s.val[j.val]! := by
  obtain ⟨x, hx, hx'⟩ := spec_returns (Slice.index_usize_spec s j h)
  rw [hx]
  congr 1
  rw [hx']
  simp [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem h]

/-- The check of the loop of `strict` at one place: the flag stays unless a leading zero starts
there. -/
theorem strict_window (level : Slice Std.U8) (ok1 : Bool) (i : Std.Usize) (below : i.val < level.length)
    (room : i.val + 2 ≤ Usize.max) :
    ∃ r : Bool, (do
      let i2 ← i + 2#usize
      let i3 := Slice.len level
      if i2 < i3 then do
        let i4 ← i + 1#usize
        let i5 ← level.index_usize i4
        if i5 = 48#u8 then do
          let i6 ← level.index_usize i2
          if i6 ≥ 48#u8 then do
            let i7 ← level.index_usize i2
            if i7 ≤ 57#u8 then ok false else ok ok1
          else ok ok1
        else ok ok1
      else ok ok1 : Result Bool) = ok r ∧
      (r = true ↔ ok1 = true ∧ ¬ (i.val + 2 < level.length ∧ level.val[i.val + 1]! = 48#u8 ∧
        IsDigit level.val[i.val + 2]!)) := by
  have is_len : (Slice.len level).val = level.length := by simp [Slice.len]
  obtain ⟨i2, hi2, hi2v⟩ : ∃ i2 : Std.Usize, (i + 2#usize : Result Std.Usize) = ok i2 ∧ i2.val = i.val + 2 := by
    obtain ⟨x, hx, hx'⟩ := spec_returns (Std.Usize.add_spec (x := i) (y := 2#usize) (by simpa using room))
    exact ⟨x, hx, by simpa using hx'⟩
  rw [hi2, bind_ok]
  by_cases lt2 : i2 < Slice.len level
  · have lt2' : i.val + 2 < level.length := by scalar_tac
    simp only [lt2, ite_true]
    obtain ⟨i4, hi4, hi4v⟩ : ∃ i4 : Std.Usize, (i + 1#usize : Result Std.Usize) = ok i4 ∧ i4.val = i.val + 1 := by
      obtain ⟨x, hx, hx'⟩ := spec_returns (Std.Usize.add_spec (x := i) (y := 1#usize)
        (by simpa using (by omega : i.val + 1 ≤ Usize.max)))
      exact ⟨x, hx, by simpa using hx'⟩
    rw [hi4, bind_ok]
    have g1 : level.index_usize i4 = ok level.val[i.val + 1]! := by
      rw [index_bang level i4 (by omega), hi4v]
    have g2 : level.index_usize i2 = ok level.val[i.val + 2]! := by
      rw [index_bang level i2 (by omega), hi2v]
    simp only [g1, g2, bind_ok]
    by_cases e48 : level.val[i.val + 1]! = 48#u8
    · simp only [e48, ite_true]
      by_cases ge : level.val[i.val + 2]! ≥ 48#u8
      · simp only [ge, ite_true]
        by_cases le : level.val[i.val + 2]! ≤ 57#u8
        · simp only [le, ite_true]
          have dig : IsDigit level.val[i.val + 2]! := ⟨by scalar_tac, by scalar_tac⟩
          refine ⟨false, rfl, ⟨fun h => absurd h (by simp), fun ⟨_, hn⟩ => absurd ⟨lt2', trivial, dig⟩ hn⟩⟩
        · simp only [le, ite_false]
          have dig : ¬ IsDigit level.val[i.val + 2]! := fun h => le (by have := h.2; scalar_tac)
          exact ⟨ok1, rfl, ⟨fun h => ⟨h, fun ⟨_, _, d⟩ => dig d⟩, fun h => h.1⟩⟩
      · simp only [ge, ite_false]
        have dig : ¬ IsDigit level.val[i.val + 2]! := fun h => ge (by have := h.1; scalar_tac)
        exact ⟨ok1, rfl, ⟨fun h => ⟨h, fun ⟨_, _, d⟩ => dig d⟩, fun h => h.1⟩⟩
    · simp only [e48, ite_false]
      exact ⟨ok1, rfl, ⟨fun h => ⟨h, fun ⟨_, e, _⟩ => e.elim⟩, fun h => h.1⟩⟩
  · simp only [lt2, ite_false]
    have : ¬ i.val + 2 < level.length := by scalar_tac
    exact ⟨ok1, rfl, ⟨fun h => ⟨h, fun ⟨l, _⟩ => this l⟩, fun h => h.1⟩⟩

/-- The loop of `strict` says `ok` exactly when no leading zero starts at a place from `i`, and
counts the dashes. -/
theorem strict_loop_spec (level : Slice Std.U8) (ok1 : Bool) (dashes : Std.Usize) (i : Std.Usize)
    (inside : i.val ≤ level.length) (room : dashes.val + level.length ≤ Usize.max)
    (small : level.length + 2 ≤ Usize.max) :
    strict_loop level ok1 dashes i ⦃ r =>
      (r.1 = true ↔ ok1 = true ∧ ∀ k, i.val ≤ k → k + 2 < level.length →
        (level.val[k]! = 115#u8 ∨ level.val[k]! = 99#u8) → level.val[k + 1]! = 48#u8 →
          ¬ IsDigit level.val[k + 2]!) ∧
      r.2.val = dashes.val + ((level.val.drop i.val).count 45#u8) ⦄ := by
  unfold strict_loop
  apply loop_answers (fun x : Bool × Std.Usize × Std.Usize => strict_loop.body level x.1 x.2.1 x.2.2)
    (fun x y =>
      (y.1 = true ↔ x.1 = true ∧ ∀ k, x.2.2.val ≤ k → k + 2 < level.length →
        (level.val[k]! = 115#u8 ∨ level.val[k]! = 99#u8) → level.val[k + 1]! = 48#u8 →
          ¬ IsDigit level.val[k + 2]!) ∧
      y.2.val = x.2.1.val + ((level.val.drop x.2.2.val).count 45#u8))
    (fun x => level.length - x.2.2.val)
    (fun x => x.2.2.val ≤ level.length ∧ x.2.1.val + (level.length - x.2.2.val) ≤ Usize.max)
  · rintro ⟨ok', dashes', i'⟩ ⟨inside', room'⟩
    simp only at inside' room' ⊢
    unfold strict_loop.body
    have is_len : (Slice.len level).val = level.length := by simp [Slice.len]
    by_cases below : i' < Slice.len level
    · simp only [below, ite_true]
      have below' : i'.val < level.length := by scalar_tac
      have room2 : i'.val + 2 ≤ Usize.max := by omega
      have b_is : level.index_usize i' = ok level.val[i'.val]! := index_bang level i' below'
      rw [b_is, bind_ok]
      obtain ⟨dashes1, hd, hdv⟩ : ∃ d : Std.Usize, (if level.val[i'.val]! = 45#u8 then dashes' + 1#usize
          else ok dashes' : Result Std.Usize) = ok d ∧
          d.val = dashes'.val + (if level.val[i'.val]! = 45#u8 then 1 else 0) := by
        by_cases d45 : level.val[i'.val]! = 45#u8
        · obtain ⟨x, hx, hx'⟩ := spec_returns (Std.Usize.add_spec (x := dashes') (y := 1#usize)
            (by simpa using (by omega : dashes'.val + 1 ≤ Usize.max)))
          exact ⟨x, by rw [if_pos d45, hx], by rw [if_pos d45]; simpa using hx'⟩
        · exact ⟨dashes', by rw [if_neg d45], by rw [if_neg d45, Nat.add_zero]⟩
      rw [hd, bind_ok]
      obtain ⟨ok2, hok2, hiff⟩ : ∃ r : Bool, (if level.val[i'.val]! = 115#u8 then (do
          let i2 ← i' + 2#usize
          let i3 := Slice.len level
          if i2 < i3 then do
            let i4 ← i' + 1#usize
            let i5 ← level.index_usize i4
            if i5 = 48#u8 then do
              let i6 ← level.index_usize i2
              if i6 ≥ 48#u8 then do
                let i7 ← level.index_usize i2
                if i7 ≤ 57#u8 then ok false else ok ok'
              else ok ok'
            else ok ok'
          else ok ok') else if level.val[i'.val]! = 99#u8 then (do
          let i2 ← i' + 2#usize
          let i3 := Slice.len level
          if i2 < i3 then do
            let i4 ← i' + 1#usize
            let i5 ← level.index_usize i4
            if i5 = 48#u8 then do
              let i6 ← level.index_usize i2
              if i6 ≥ 48#u8 then do
                let i7 ← level.index_usize i2
                if i7 ≤ 57#u8 then ok false else ok ok'
              else ok ok'
            else ok ok'
          else ok ok') else ok ok' : Result Bool) = ok r ∧
          (r = true ↔ ok' = true ∧ ((level.val[i'.val]! = 115#u8 ∨ level.val[i'.val]! = 99#u8) →
            (i'.val + 2 < level.length → level.val[i'.val + 1]! = 48#u8 → ¬ IsDigit level.val[i'.val + 2]!))) := by
        have window := strict_window level ok' i' below' room2
        obtain ⟨r, hr, hiffw⟩ := window
        by_cases h115 : level.val[i'.val]! = 115#u8
        · simp only [h115, ite_true]
          refine ⟨r, hr, ?_⟩
          rw [hiffw]
          constructor
          · rintro ⟨h, hn⟩
            exact ⟨h, fun _ l e d => hn ⟨l, e, d⟩⟩
          · rintro ⟨h, hn⟩
            exact ⟨h, fun ⟨l, e, d⟩ => hn (Or.inl trivial) l e d⟩
        · by_cases h99 : level.val[i'.val]! = 99#u8
          · simp only [h115, ite_false, h99, ite_true]
            refine ⟨r, hr, ?_⟩
            rw [hiffw]
            constructor
            · rintro ⟨h, hn⟩
              exact ⟨h, fun _ l e d => hn ⟨l, e, d⟩⟩
            · rintro ⟨h, hn⟩
              exact ⟨h, fun ⟨l, e, d⟩ => hn (Or.inr trivial) l e d⟩
          · simp only [h115, ite_false, h99]
            refine ⟨ok', rfl, ?_⟩
            constructor
            · intro h; exact ⟨h, fun h' => h'.elim (fun e => e.elim) (fun e => e.elim)⟩
            · exact fun h => h.1
      rw [hok2, bind_ok]
      step as ⟨ i2, is_i2 ⟩
      have sl : level.length = level.val.length := rfl
      have hd_le : dashes1.val ≤ dashes'.val + 1 := by rw [hdv]; split <;> omega
      have smaller : level.length - i2.val < level.length - i'.val := by omega
      refine ⟨by omega, by omega, smaller, ?_⟩
      intro y hy1 hy2
      refine ⟨?_, ?_⟩
      · rw [hy1, hiff]
        constructor
        · rintro ⟨⟨h, hn⟩, rest⟩
          refine ⟨h, fun k a lt hs hz => ?_⟩
          rcases Nat.eq_or_lt_of_le a with eq | lt'
          · rw [← eq] at hz hs lt ⊢; exact hn hs lt hz
          · exact rest k (by omega) lt hs hz
        · rintro ⟨h, all⟩
          exact ⟨⟨h, fun hs lt hz => all i'.val (le_refl _) lt hs hz⟩,
            fun k a lt hs hz => all k (by omega) lt hs hz⟩
      · rw [hy2, hdv]
        have drop_eq : level.val.drop i'.val = level.val[i'.val]! :: level.val.drop (i'.val + 1) := by
          rw [List.drop_eq_getElem_cons below']
          simp [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem below']
        rw [drop_eq, List.count_cons, is_i2]
        by_cases d45 : level.val[i'.val]! = 45#u8
        · simp [d45]; omega
        · simp [d45]; omega
    · simp only [below, ite_false]
      refine (WP.spec_ok _).mpr ?_
      have at_end : i'.val = level.length := by scalar_tac
      have sl : level.length = level.val.length := rfl
      refine ⟨⟨fun h => ⟨h, fun k a lt => by omega⟩, fun h => h.1⟩, ?_⟩
      rw [at_end, sl, List.drop_length]; simp
  · exact ⟨inside, Nat.le_trans (Nat.add_le_add_left (Nat.sub_le _ _) _) room⟩

/-- What `strict` answers: true exactly when the text is a level, has no leading zero and has at
most one dash. -/
theorem strict_spec (level : Slice Std.U8) (small : level.length + 2 ≤ Usize.max) :
    strict level ⦃ r => r = true ↔ (∃ S, Level level.val S) ∧ NoLeadingZero level.val ∧
      level.val.count 45#u8 ≤ 1 ⦄ := by
  unfold strict
  step with parse_spec level as ⟨ o, hc, hs ⟩
  have zero : (0#usize).val = 0 := rfl
  step with strict_loop_spec level o.isSome 0#usize 0#usize (by simp)
    (by simp) small as ⟨ ok2, dashes, h1, h2 ⟩
  have some_iff : o.isSome = true ↔ ∃ S, Level level.val S := by
    cases o with
    | none =>
      simp only [Option.isSome, Bool.false_eq_true, false_iff]
      rintro ⟨S, lvl⟩
      obtain ⟨c, hcc, _⟩ := hc S lvl
      simp at hcc
    | some cats =>
      simp only [Option.isSome, true_iff]
      obtain ⟨S, lvl, _⟩ := hs cats rfl
      exact ⟨S, lvl⟩
  have nlz : (∀ k, 0 ≤ k → k + 2 < level.length →
      (level.val[k]! = 115#u8 ∨ level.val[k]! = 99#u8) → level.val[k + 1]! = 48#u8 →
        ¬ IsDigit level.val[k + 2]!) ↔ NoLeadingZero level.val := by
    unfold NoLeadingZero
    constructor
    · intro h i lt a b; exact h i (Nat.zero_le _) lt a b
    · intro h k _ lt a b; exact h k lt a b
  by_cases ok2_t : ok2 = true
  · simp only [ok2_t, ite_true]
    refine (WP.spec_ok _).mpr ?_
    have dashes_is : dashes.val = level.val.count 45#u8 := by simpa using h2
    constructor
    · intro hd
      have hd' : dashes.val ≤ 1 := by scalar_tac
      obtain ⟨ok1, all⟩ := h1.mp ok2_t
      exact ⟨some_iff.mp ok1, nlz.mp all, by omega⟩
    · rintro ⟨lvl, no, cnt⟩
      have : dashes ≤ 1#usize := by
        rw [UScalar.le_equiv]; simp; omega
      simpa using this
  · simp only [ok2_t, Bool.false_eq_true, ite_false]
    refine (WP.spec_ok _).mpr ?_
    simp only [Bool.false_eq_true, false_iff]
    rintro ⟨lvl, no, _⟩
    exact ok2_t (h1.mpr ⟨some_iff.mpr lvl, nlz.mpr no⟩)

end McsCore
