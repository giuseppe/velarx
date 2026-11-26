-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the places of the first six colons of a line (`colons`) and `is_text`, the test of a range of bytes against a text.
-- Why it is needed: a line is cut at its colons, and names are compared with `is_text`.
-- Read before this file: Lines.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` is the number a
--    machine integer is.
import UserCore.Lines
open Aeneas Aeneas.Std Result velarx_user_core
namespace UserCore

/-- One more byte adds its place to the colons when it is a colon. -/
theorem colons_succ (d : List Std.U8) (start i : Nat) (h : start ≤ i) :
    Colons d start (i + 1) = Colons d start i ++ (if ByteAt d i 58 then [i] else []) := by
  unfold Colons
  rw [show i + 1 - start = (i - start) + 1 by omega, List.range'_concat]
  simp only [List.filter_append]
  split <;> simp_all

/-- The colons of a range are those of its first part, then those of its second. -/
theorem colons_split (d : List Std.U8) (start i stop : Nat) (h1 : start ≤ i) (h2 : i ≤ stop) :
    Colons d start stop = Colons d start i ++ Colons d i stop := by
  unfold Colons
  rw [show stop - start = (i - start) + (stop - i) by omega, ← List.range'_append_1,
    List.filter_append, show start + (i - start) = i by omega]

/-- When the first six colons are found before a place, they are the first six of the whole range. -/
theorem colons_take_six (d : List Std.U8) (start i stop : Nat) (h1 : start ≤ i) (h2 : i ≤ stop)
    (six : ((Colons d start i).take 6).length = 6) :
    (Colons d start stop).take 6 = (Colons d start i).take 6 := by
  rw [colons_split d start i stop h1 h2, List.take_append_of_le_length (by simp at six; omega)]

/-- Setting a place of a list and taking up to it gives the part before and the new element. -/
theorem take_set_succ {α : Type _} (l : List α) (n : Nat) (x : α) (h : n < l.length) :
    (l.set n x).take (n + 1) = l.take n ++ [x] := by
  rw [List.set_eq_take_append_cons_drop, if_yes h]
  simp [List.take_append, List.length_take, show min n l.length = n by omega]

/-- Adding a sixth or earlier element to a short list of places adds it to the first six. -/
theorem take_six_snoc (L : List Nat) (j : Nat) (h : (L.take 6).length < 6) :
    (L ++ [j]).take 6 = L.take 6 ++ [j] := by
  simp only [List.length_take] at h
  have hl : L.length ≤ 6 := by omega
  rw [List.take_append, List.take_of_length_le hl, List.take_of_length_le (by simp; omega)]

/-- The loop of `colons` returns the first six colons and how many it found. -/
theorem colons_loop_spec (data : Slice Std.U8) (start stop : Std.Usize)
    (cut : Array Std.Usize 6#usize) (n i : Std.Usize)
    (hs : start.val ≤ i.val) (hi : i.val ≤ stop.val) (hstop : stop.val ≤ data.length)
    (hn : n.val ≤ 6) (hcut : (cut.val.take n.val).map (·.val) = (Colons data.val start.val i.val).take 6)
    (hfull : n.val = ((Colons data.val start.val i.val).take 6).length) :
    colons_loop data stop cut n i ⦃ r => r.2.val ≤ 6 ∧
      (r.1.val.take r.2.val).map (·.val) = (Colons data.val start.val stop.val).take 6 ⦄ := by
  unfold colons_loop
  apply loop.spec_decr_nat (fun (q : (Array Std.Usize 6#usize) × Std.Usize × Std.Usize) =>
      stop.val - q.2.2.val)
    (fun (q : (Array Std.Usize 6#usize) × Std.Usize × Std.Usize) =>
      start.val ≤ q.2.2.val ∧ q.2.2.val ≤ stop.val ∧ q.2.1.val ≤ 6 ∧
      (q.1.val.take q.2.1.val).map (·.val) = (Colons data.val start.val q.2.2.val).take 6 ∧
      q.2.1.val = ((Colons data.val start.val q.2.2.val).take 6).length)
  · rintro ⟨cut1, n1, j⟩ ⟨h1, h2, h3, h4, h5⟩
    simp only at h1 h2 h3 h4 h5 ⊢
    unfold colons_loop.body
    step*
    · rename_i jlt nlt
      have below' : j.val < data.length := by scalar_tac
      have room' : n1.val < 6 := by scalar_tac
      have byte : data.val[j.val]? = some i1 := by rw [i1_post]; simp [Slice.length] at *
      have step := colons_succ data.val start.val j.val h1
      by_cases colon : i1 = 58#u8
      · have is : ByteAt data.val j.val 58 := (byteAt_iff _ _ _ byte _).mpr (by scalar_tac)
        simp only [colon, ite_true]
        step as ⟨ a, a_post ⟩
        step as ⟨ n2, n2_post ⟩
        step as ⟨ i2, i2_post ⟩
        have len : cut1.val.length = 6 := by simp
        have grown : (a.val.take n2.val).map (·.val) = (Colons data.val start.val i2.val).take 6 := by
          rw [a_post, i2_post, step, if_yes is, n2_post]
          have setv : (cut1.set n1 j).val = cut1.val.set n1.val j := by simp [Std.Array.set]
          rw [setv, take_set_succ _ _ _ (by omega), List.map_append, h4,
            take_six_snoc _ _ (by omega)]
          simp
        refine ⟨by scalar_tac, by scalar_tac, by scalar_tac, grown, ?_, by scalar_tac⟩
        rw [← grown]
        simp only [List.length_map, List.length_take]
        have la : a.val.length = 6 := by simp
        omega
      · have not : ¬ ByteAt data.val j.val 58 := fun h => colon (by
          have := (byteAt_iff _ _ _ byte _).mp h; scalar_tac)
        simp only [colon, ite_false]
        step*
    · rename_i full
      have six : n1.val = 6 := by scalar_tac
      refine ⟨h3, ?_⟩
      rw [h4, colons_take_six _ _ _ _ h1 h2 (by omega)]
  · exact ⟨hs, hi, hn, hcut, hfull⟩

/-- `colons` finds the first six colons of a line: `n` of them, `cut` having their places. -/
theorem colons_spec (data : Slice Std.U8) (start stop : Std.Usize)
    (hs : start.val ≤ stop.val) (hstop : stop.val ≤ data.length) :
    colons data start stop ⦃ r => r.2.val ≤ 6 ∧
      (r.1.val.take r.2.val).map (·.val) = (Colons data.val start.val stop.val).take 6 ⦄ := by
  unfold colons
  step with colons_loop_spec data start stop _ 0#usize start
  · have none : Colons data.val start.val start.val = [] := by simp [Colons]
    simp [none]
  · have none : Colons data.val start.val start.val = [] := by simp [Colons]
    simp [none]
  exact ⟨r_post, r_post1⟩

/-- `is_text` says whether the bytes of a range are the text, when the range is inside the data. -/
theorem is_text_spec (data : Slice Std.U8) (a b : Std.Usize) (text : Slice Std.U8)
    (hab : a.val ≤ b.val) (hb : b.val ≤ data.length) :
    is_text data (a, b) text ⦃ r => r = true ↔ List.slice a.val b.val data.val = text.val ⦄ := by
  unfold is_text
  step*
  have ne : ∀ x y : Std.U8, core.cmp.PartialEqU8.ne x y ⦃ b => b ↔ ¬ (x = y) ⦄ := by
    intro x y
    refine (WP.spec_ok _).mpr ?_
    simp
  step with core.slice.cmp.PartialEqSlice.eq_homo_spec core.cmp.PartialEqU8 s text ne as ⟨ r, r_post ⟩
  rw [r_post, ← s_post]
  exact ⟨fun h => by rw [h], fun h => Slice.ext _ _ h⟩

end UserCore
