-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `split_user` answers: the bytes before the first colon and those after it.
-- Why it is needed: the user part and the group part of a user string are read with it.
-- Read before this file: Digits.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` is the number a
--    machine integer is.
import UserCore.Digits
open Aeneas Aeneas.Std Result velarx_user_core
namespace UserCore

/-- The bytes before the first colon are as many as the place of the first colon. -/
theorem takeWhile_length_eq (l : List Std.U8) (r : Nat)
    (before : ∀ j, j < r → ∀ b, l[j]? = some b → Colon b = false)
    (hr : r ≤ l.length)
    (stop : r < l.length → ∀ b, l[r]? = some b → Colon b = true) :
    (l.takeWhile (fun b => !Colon b)).length = r := by
  induction l generalizing r with
  | nil => simp at hr; simp [hr]
  | cons x xs ih =>
    cases r with
    | zero =>
      have := stop (by simp) x (by simp)
      simp [this]
    | succ r =>
      have hx := before 0 (by omega) x (by simp)
      have hx' : Colon x = false := by simpa using hx
      simp only [List.takeWhile_cons, hx', Bool.not_false, ite_true, List.length_cons]
      have := ih r (fun j hj b hb => before (j + 1) (by omega) b (by simpa using hb)) (by simpa using hr)
        (fun h b hb => stop (by simpa using h) b (by simpa using hb))
      omega

/-- The test `b != 58` is the byte not being a colon. -/
theorem colon_iff (b : Std.U8) : (b != 58#u8) = true ↔ Colon b = false := by
  simp only [bne_iff_ne, ne_eq, Colon, beq_eq_false_iff_ne]
  constructor <;> intro h hh <;> apply h <;> scalar_tac

/-- The loop of `split_user` stops at the first colon or at the end. -/
theorem split_user_loop_spec (user : Slice Std.U8) (i : Std.Usize) (hi : i.val ≤ user.length) :
    split_user_loop user i ⦃ r => i.val ≤ r.val ∧ r.val ≤ user.length ∧
      (∀ j, i.val ≤ j → j < r.val → ∀ b, user.val[j]? = some b → Colon b = false) ∧
      (r.val < user.length → ∀ b, user.val[r.val]? = some b → Colon b = true) ⦄ := by
  unfold split_user_loop
  apply loop.spec_decr_nat (fun (q : Std.Usize) => user.length - q.val)
    (fun (q : Std.Usize) => i.val ≤ q.val ∧ q.val ≤ user.length ∧
      ∀ j, i.val ≤ j → j < q.val → ∀ b, user.val[j]? = some b → Colon b = false)
  · intro i1 ⟨h1, h2, h3⟩
    unfold split_user_loop.body
    step*
    · rename_i below isnt
      have below' : i1.val < user.length := by scalar_tac
      have byte : user.val[i1.val]? = some i2 := by rw [i2_post]; simp [below']
      have nc := (colon_iff i2).mp isnt
      refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
      intro j hj1 hj2 b hb
      by_cases e : j = i1.val
      · subst e; rw [byte] at hb; cases hb; exact nc
      · exact h3 j hj1 (by scalar_tac) b hb
    · rename_i below isnt
      have below' : i1.val < user.length := by scalar_tac
      have byte : user.val[i1.val]? = some i2 := by rw [i2_post]; simp [below']
      have c : Colon i2 = true := by
        have : ¬ (Colon i2 = false) := fun h => isnt ((colon_iff i2).mpr h)
        simpa using this
      refine ⟨h1, h2, h3, fun _ b hb => ?_⟩
      rw [byte] at hb; cases hb; exact c
  · exact ⟨le_refl _, hi, fun j h1 h2 => by omega⟩

/-- The user part is the first bytes up to its length. -/
theorem userpart_eq_take (l : List Std.U8) :
    UserPart l = l.take (UserPart l).length := by
  obtain ⟨t, ht⟩ : UserPart l <+: l := List.takeWhile_prefix _
  have := List.take_left (l₁ := UserPart l) (l₂ := t)
  rw [ht] at this
  exact this.symm

/-- `split_user` returns the bytes before the first colon and, if there is one, those after it. -/
theorem split_user_spec (user : Slice Std.U8) :
    split_user user ⦃ p => p.1.val = UserPart user.val ∧ p.2.map (·.val) = GroupPart user.val ⦄ := by
  unfold split_user
  step with split_user_loop_spec as ⟨ r, h0, h1, h2, h3 ⟩
  have len : (UserPart user.val).length = r.val := takeWhile_length_eq user.val r.val
    (fun j hj => h2 j (by omega) hj) h1 h3
  have prefix_eq : UserPart user.val = user.val.take r.val := by
    rw [← len]; exact userpart_eq_take _
  have below_iff : r < user.len ↔ r.val < user.length := by scalar_tac
  split
  · rename_i below
    have below' := below_iff.mp below
    step as ⟨ s, s_post ⟩
    step as ⟨ i2, i2_post ⟩
    step as ⟨ s1, s1_post ⟩
    have byte : ∃ b, user.val[r.val]? = some b := ⟨_, List.getElem?_eq_getElem below'⟩
    obtain ⟨c, hc⟩ := byte
    have colon := h3 below' c hc
    have any : user.val.any Colon = true :=
      List.any_eq_true.mpr ⟨c, List.mem_of_getElem? hc, colon⟩
    refine ⟨?_, ?_⟩
    · rw [s_post, prefix_eq]; simp [List.slice]
    · simp [GroupPart, any, len, s1_post, i2_post]
  · rename_i below
    have below' : ¬ r.val < user.length := fun h => below (below_iff.mpr h)
    have ulen : user.length = user.val.length := rfl
    have all : ∀ x ∈ user.val, Colon x = false := by
      intro x hx
      obtain ⟨j, hj, rfl⟩ := List.getElem_of_mem hx
      exact h2 j (by omega) (by omega) _ (List.getElem?_eq_getElem hj)
    have none : user.val.any Colon = false := by simpa using all
    refine (WP.spec_ok _).mpr ⟨?_, ?_⟩
    · rw [prefix_eq]; exact (List.take_of_length_le (l := user.val) (i := r.val) (by omega)).symm
    · simp [GroupPart, none]

end UserCore
