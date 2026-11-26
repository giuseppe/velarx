-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `is_member` answers: the name is a whole comma separated field of the members.
-- Why it is needed: the groups of a user are the lines that list its name.
-- Read before this file: Groups.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` is the number a
--    machine integer is.
import UserCore.Groups
open Aeneas Aeneas.Std Result velarx_user_core
namespace UserCore

/-- The inner loop of `is_member` finds the end of the field: the next comma or the end of the members. -/
theorem member_field_loop_spec (data : Slice Std.U8) (i upto : Std.Usize) (hi : i.val ≤ data.length)
    (ht : upto.val ≤ i.val) :
    is_member_loop0_loop0 data i upto ⦃ r => upto.val ≤ r.val ∧ r.val ≤ i.val ∧
      NoByte data.val 44 upto.val r.val ∧ (r.val < i.val → ByteAt data.val r.val 44) ⦄ := by
  unfold is_member_loop0_loop0
  apply loop.spec_decr_nat (fun (q : Std.Usize) => i.val - q.val)
    (fun (q : Std.Usize) => upto.val ≤ q.val ∧ q.val ≤ i.val ∧ NoByte data.val 44 upto.val q.val)
  · intro e ⟨h1, h2, h3⟩
    unfold is_member_loop0_loop0.body
    step*
    · rename_i below _ isnt
      have below' : e.val < data.length := by scalar_tac
      have byte : data.val[e.val]? = some i1 := by rw [i1_post]; simp [below']
      have ne : i1.val ≠ 44 := by
        intro h; simp only [bne_iff_ne, ne_eq] at isnt; apply isnt; scalar_tac
      refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
      intro j hj1 hj2 hb
      by_cases hj : j = e.val
      · subst hj; exact ne ((byteAt_iff _ _ _ byte _).mp hb)
      · exact h3 j hj1 (by scalar_tac) hb
    · rename_i below isnt
      have below' : e.val < data.length := by scalar_tac
      have byte : data.val[e.val]? = some i1 := by rw [i1_post]; simp [below']
      have eq : i1.val = 44 := by
        by_contra h; apply isnt; simp only [bne_iff_ne, ne_eq]; scalar_tac
      exact ⟨h1, h2, h3, fun _ => (byteAt_iff _ _ _ byte _).mpr eq⟩
  · exact ⟨le_refl _, ht, fun j h1 h2 => by omega⟩

/-- The loop of `is_member` returns, and says true only for a whole field of the members. -/
theorem is_member_loop_spec (data : Slice Std.U8) (m0 i : Std.Usize) (word : Slice Std.U8)
    (found : Bool) (from_ : Std.Usize) (hi : i.val < Std.Usize.max) (hlen : i.val ≤ data.length)
    (hfrom : m0.val ≤ from_.val ∧ from_.val ≤ i.val + 1)
    (starts : from_.val ≤ i.val → from_.val = m0.val ∨ ByteAt data.val (from_.val - 1) 44)
    (sound : found = true → Lists data.val (m0.val, i.val) word.val) :
    is_member_loop0 data i word found from_ ⦃ r =>
      r = true → Lists data.val (m0.val, i.val) word.val ⦄ := by
  unfold is_member_loop0
  apply loop.spec_decr_nat (fun (q : Bool × Std.Usize) => i.val + 1 - q.2.val)
    (fun (q : Bool × Std.Usize) => m0.val ≤ q.2.val ∧ q.2.val ≤ i.val + 1 ∧
      (q.2.val ≤ i.val → q.2.val = m0.val ∨ ByteAt data.val (q.2.val - 1) 44) ∧
      (q.1 = true → Lists data.val (m0.val, i.val) word.val))
  · rintro ⟨found1, f1⟩ ⟨h1, h2, h3, h4⟩
    simp only at h1 h2 h3 h4 ⊢
    unfold is_member_loop0.body
    step*
    rename_i inside notfound
    have fle : f1.val ≤ i.val := by scalar_tac
    step with member_field_loop_spec data i f1 hlen fle as ⟨ upto, hu1, hu2, hu3, hu4 ⟩
    step with is_text_spec data f1 upto word hu1 (by omega) as ⟨ b, hb ⟩
    have noovf : upto.val + 1 ≤ Std.Usize.max := by omega
    step as ⟨ f2, f2_post ⟩
    refine ⟨by omega, by omega, ?_, ?_, by omega⟩
    · intro le2
      right
      have := hu4 (by omega)
      rw [f2_post]; simpa using this
    · intro hb'
      refine ⟨f1.val, upto.val, ⟨h1, hu1, hu2, h3 fle, ?_, hu3⟩, hb.mp hb'⟩
      by_cases e : upto.val = i.val
      · exact Or.inl e
      · exact Or.inr (hu4 (by omega))
  · exact ⟨hfrom.1, hfrom.2, starts, sound⟩

/-- `is_member` returns, and says true only when the name is a whole field of the members. -/
theorem is_member_spec (data : Slice Std.U8) (m : Std.Usize × Std.Usize) (word : Slice Std.U8)
    (hab : m.1.val ≤ m.2.val) (hlen : m.2.val ≤ data.length) (short : data.length < Std.Usize.max) :
    is_member data m word ⦃ r => r = true → Lists data.val (m.1.val, m.2.val) word.val ⦄ := by
  obtain ⟨m0, m1⟩ := m
  simp only at hab hlen ⊢
  unfold is_member
  exact is_member_loop_spec data m0 m1 word false m0 (by omega) hlen ⟨le_refl _, by omega⟩
    (fun _ => Or.inl rfl) (by simp)

end UserCore
