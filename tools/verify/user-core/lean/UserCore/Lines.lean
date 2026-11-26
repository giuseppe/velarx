-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `line_at` answers: where a line of the file ends and where its text ends.
-- Why it is needed: `passwd_find`, `has_gid`, `group_gid` and the group loop walk the file line by line.
-- Read before this file: Split.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` is the number a
--    machine integer is.
import UserCore.Split
open Aeneas Aeneas.Std Result velarx_user_core
namespace UserCore

/-- A byte read from the list is the byte at its place. -/
theorem byteAt_of_get (d : List Std.U8) (i : Nat) (b : Std.U8) (h : d[i]? = some b) :
    ByteAt d i b.val := by simp [ByteAt, h]

/-- The byte at a place is the number `c` exactly when the byte read there is. -/
theorem byteAt_iff (d : List Std.U8) (i : Nat) (b : Std.U8) (h : d[i]? = some b) (c : Nat) :
    ByteAt d i c ↔ b.val = c := by simp [ByteAt, h, eq_comm]

/-- The loop of `line_at` finds the first newline from the place, or the end. -/
theorem line_end_loop_spec (data : Slice Std.U8) (pos : Std.Usize) (hp : pos.val ≤ data.length) :
    line_at_loop data pos ⦃ r => pos.val ≤ r.val ∧ r.val ≤ data.length ∧
      NoByte data.val 10 pos.val r.val ∧ (r.val < data.length → ByteAt data.val r.val 10) ⦄ := by
  unfold line_at_loop
  apply loop.spec_decr_nat (fun (q : Std.Usize) => data.length - q.val)
    (fun (q : Std.Usize) => pos.val ≤ q.val ∧ q.val ≤ data.length ∧ NoByte data.val 10 pos.val q.val)
  · intro e ⟨h1, h2, h3⟩
    unfold line_at_loop.body
    step*
    · rename_i below _ isnt
      have below' : e.val < data.length := by scalar_tac
      have byte : data.val[e.val]? = some i1 := by rw [i1_post]; simp [below']
      have ne : i1.val ≠ 10 := by
        intro h; simp only [bne_iff_ne, ne_eq] at isnt; apply isnt; scalar_tac
      refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
      intro j hj1 hj2 hb
      by_cases hj : j = e.val
      · subst hj; exact ne ((byteAt_iff _ _ _ byte _).mp hb)
      · exact h3 j hj1 (by scalar_tac) hb
    · rename_i below isnt
      have below' : e.val < data.length := by scalar_tac
      have byte : data.val[e.val]? = some i1 := by rw [i1_post]; simp [below']
      have eq : i1.val = 10 := by
        by_contra h; apply isnt; simp only [bne_iff_ne, ne_eq]; scalar_tac
      exact ⟨h1, h2, h3, fun _ => (byteAt_iff _ _ _ byte _).mpr eq⟩
  · exact ⟨le_refl _, hp, fun i h1 h2 => by omega⟩

/-- `line_at` returns the end of the line and the end of its text, and the text is a line of the file. -/
theorem line_at_spec (data : Slice Std.U8) (pos : Std.Usize) (hp : pos.val ≤ data.length)
    (starts : pos.val = 0 ∨ ByteAt data.val (pos.val - 1) 10) :
    line_at data pos ⦃ r => IsLine data.val pos.val r.2.val ∧ r.2.val ≤ r.1.val ∧
      r.1.val ≤ data.length ∧ (r.1.val < data.length → ByteAt data.val r.1.val 10) ⦄ := by
  unfold line_at
  step with line_end_loop_spec as ⟨ e, h1, h2, h3, h4 ⟩
  have plain : IsLine data.val pos.val e.val := by
    refine ⟨h1, h2, starts, h3, ?_⟩
    by_cases lt : e.val < data.length
    · exact Or.inr (Or.inl (h4 lt))
    · exact Or.inl (by simp only [Slice.length] at *; omega)
  step*
  · rename_i below gt _ is13
    have below' : e.val < data.length := by scalar_tac
    have byte : data.val[i1.val]? = some i2 := by
      rw [i2_post]; simp only [Slice.length] at *; simp
    have c13 : i2.val = 13 := by rw [is13]; rfl
    refine ⟨⟨by scalar_tac, by scalar_tac, starts, fun j a b => h3 j a (by scalar_tac), ?_⟩, by scalar_tac, h2, h4⟩
    right; right
    refine ⟨(byteAt_iff _ _ _ byte _).mpr c13, ?_⟩
    have : i1.val + 1 = e.val := by omega
    rw [this]; exact h4 below'

end UserCore
