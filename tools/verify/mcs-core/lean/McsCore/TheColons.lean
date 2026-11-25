-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `context_colons`: the places of the first three colons of a context
--    `user:role:type:level`.
-- Why it is needed: the level of a context is what follows the third colon.
-- Read before this file: TheLoops.lean, Spec.lean.
-- Notation: `Found ctx at seen i`: after `i` bytes, the places held are the first colons.
import McsCore.ClaimsOfPick
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- What the loop of `context_colons` has found after reading the first `i` bytes. -/
def Found (ctx : List Std.U8) (at_ : List Std.Usize) (seen i : Nat) : Prop :=
  seen ≤ 3 ∧ at_.length = 3 ∧
  (∀ m, m < seen → at_[m]!.val < i ∧ ctx[at_[m]!.val]! = 58#u8) ∧
  (∀ m m', m < m' → m' < seen → at_[m]!.val < at_[m']!.val) ∧
  (∀ j, j < i → ctx[j]! = 58#u8 →
    (∃ m, m < seen ∧ at_[m]!.val = j) ∨ (seen = 3 ∧ at_[2]!.val < j))

/-- After a colon at place `i`, with room for it among the three places, the three places hold one
more colon and the loop has read one more byte. -/
theorem found_colon (ctx : List Std.U8) (at_ : List Std.Usize) (seen i : Nat) (x : Std.Usize)
    (found : Found ctx at_ seen i) (hx : x.val = i) (colon : ctx[i]! = 58#u8) (lt3 : seen < 3)
    (lt : i < ctx.length) : Found ctx (at_.set seen x) (seen + 1) (i + 1) := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := found
  have get_new : ∀ m, (at_.set seen x)[m]! = if m = seen then x else at_[m]! := by
    intro m
    by_cases e : m = seen
    · subst e; simp [getD_set_eq _ _ _ (by omega : m < at_.length)]
    · simp [e, getD_set_ne _ _ _ _ (Ne.symm e)]
  refine ⟨by omega, by simp [h2], ?_, ?_, ?_⟩
  · intro m hm
    rw [get_new m]
    by_cases e : m = seen
    · rw [if_pos e, hx]
      exact ⟨by omega, colon⟩
    · rw [if_neg e]
      have := h3 m (by omega)
      exact ⟨by omega, this.2⟩
  · intro m m' hmm hm'
    rw [get_new m, get_new m']
    have e : m ≠ seen := by omega
    rw [if_neg e]
    by_cases e' : m' = seen
    · rw [if_pos e', hx]
      have := h3 m (by omega)
      omega
    · rw [if_neg e']
      exact h4 m m' hmm (by omega)
  · intro j hj hjc
    by_cases e : j = i
    · refine Or.inl ⟨seen, by omega, ?_⟩
      rw [get_new seen, if_pos rfl, hx, e]
    · rcases h5 j (by omega) hjc with ⟨m, hm, hmj⟩ | ⟨h, _⟩
      · refine Or.inl ⟨m, by omega, ?_⟩
        rw [get_new m, if_neg (by omega), hmj]
      · omega

/-- A byte that is no colon, or a colon after the third, leaves the places as they are; the loop has
read one more byte. -/
theorem found_skip (ctx : List Std.U8) (at_ : List Std.Usize) (seen i : Nat)
    (found : Found ctx at_ seen i) (skip : ctx[i]! ≠ 58#u8 ∨ seen = 3) (lt : i < ctx.length) :
    Found ctx at_ seen (i + 1) := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := found
  refine ⟨h1, h2, fun m hm => ?_, h4, fun j hj hjc => ?_⟩
  · have := h3 m hm; exact ⟨by omega, this.2⟩
  · by_cases e : j = i
    · subst e
      rcases skip with s | s
      · exact absurd hjc s
      · subst s
        have := h3 2 (by omega)
        exact Or.inr ⟨rfl, this.1⟩
    · exact h5 j (by omega) hjc

/-- The loop of `context_colons` finds the first colons of the bytes: after it, the places it holds
are the first colons. -/
theorem context_colons_loop_spec (ctx : Slice Std.U8) (at_ : Std.Array Std.Usize 3#usize)
    (seen i : Std.Usize) (found : Found ctx.val at_.val seen.val i.val) (inside : i.val ≤ ctx.length) :
    context_colons_loop ctx at_ seen i ⦃ r =>
      Found ctx.val r.1.val r.2.val ctx.length ⦄ := by
  unfold context_colons_loop
  have main := loop_answers (fun x : Std.Array Std.Usize 3#usize × Std.Usize × Std.Usize =>
      context_colons_loop.body ctx x.1 x.2.1 x.2.2)
    (fun x y => Found ctx.val x.1.val x.2.1.val x.2.2.val → Found ctx.val y.1.val y.2.val ctx.length)
    (fun x => ctx.length - x.2.2.val)
    (fun x => Found ctx.val x.1.val x.2.1.val x.2.2.val ∧ x.2.2.val ≤ ctx.length)
    (at_, seen, i) ?_ ⟨found, inside⟩
  · exact WP.spec_mono main (fun y h => h found)
  · rintro ⟨at', seen', i'⟩ ⟨found', inside'⟩
    simp only at found' inside' ⊢
    unfold context_colons_loop.body
    have is_len : (Slice.len ctx).val = ctx.length := by simp [Slice.len]
    by_cases below : i' < Slice.len ctx
    · simp only [below, ite_true]
      have below' : i'.val < ctx.length := by scalar_tac
      have room : i'.val + 1 ≤ Usize.max := by scalar_tac
      step as ⟨ b, is_b ⟩
      have b_is : ctx.val[i'.val]! = b := by
        rw [is_b]; simp [List.getElem!_eq_getElem?_getD, List.getElem?_eq_getElem below']
      by_cases colon : b = 58#u8
      · simp only [colon, ite_true]
        by_cases lt3 : seen' < 3#usize
        · simp only [lt3, ite_true]
          have lt3' : seen'.val < 3 := by scalar_tac
          step as ⟨ a, is_a ⟩
          step as ⟨ seen2, is_seen2 ⟩
          step as ⟨ i3, is_i3 ⟩
          have fnew := found_colon ctx.val at'.val seen'.val i'.val i' found' rfl (by rw [b_is, colon]) lt3' below'
          have fnew' : Found ctx.val a.val seen2.val i3.val := by
            rw [is_a, Array.set_val_eq, is_seen2, is_i3]; exact fnew
          exact ⟨fnew', by omega, by omega, fun y h hf => h fnew'⟩
        · have not_lt : ¬ seen'.val < 3 := by scalar_tac
          have seen_le := found'.1
          simp only [lt3, ite_false, bind_tc_ok, bind_ok]
          step as ⟨ i3, is_i3 ⟩
          have fnew := found_skip ctx.val at'.val seen'.val i'.val found' (Or.inr (by omega)) below'
          have fnew' : Found ctx.val at'.val seen'.val i3.val := by rw [is_i3]; exact fnew
          exact ⟨fnew', by omega, by omega, fun y h hf => h fnew'⟩
      · simp only [colon, ite_false, bind_tc_ok, bind_ok]
        step as ⟨ i3, is_i3 ⟩
        have fnew := found_skip ctx.val at'.val seen'.val i'.val found' (Or.inl (by rw [b_is]; exact colon)) below'
        have fnew' : Found ctx.val at'.val seen'.val i3.val := by rw [is_i3]; exact fnew
        exact ⟨fnew', by omega, by omega, fun y h hf => h fnew'⟩
    · simp only [below, ite_false]
      refine (WP.spec_ok _).mpr ?_
      have at_end : i'.val = ctx.length := by scalar_tac
      intro hf
      rw [← at_end]; exact hf

/-- Proof of `ContextColonsAreTheFirstThree`. -/
theorem context_colons_are_the_first_three : ContextColonsAreTheFirstThree := by
  intro ctx
  unfold context_colons
  have start : Found ctx.val (Array.repeat 3#usize 0#usize).val 0#usize.val 0#usize.val := by
    have z : (0#usize).val = 0 := rfl
    rw [z]
    refine ⟨by omega, by simp, fun m hm => by omega, fun m m' h1 h2 => by omega, fun j hj => by omega⟩
  step with context_colons_loop_spec ctx (Array.repeat 3#usize 0#usize) 0#usize 0#usize start
    (by simp) as ⟨ at1, seen, hfound ⟩
  obtain ⟨h1, h2, h3, h4, h5⟩ := hfound
  by_cases three : seen = 3#usize
  · have seen3 : seen.val = 3 := by rw [three]; rfl
    simp only [three, ite_true]
    refine (WP.spec_ok _).mpr ⟨?_, fun h => by simp at h⟩
    intro a ha
    have a_is : a = at1 := (Option.some.inj ha).symm
    subst a_is
    rw [seen3] at h3 h4 h5
    have c0 := h3 0 (by omega)
    have c1 := h3 1 (by omega)
    have c2 := h3 2 (by omega)
    refine ⟨h4 0 1 (by omega) (by omega), h4 1 2 (by omega) (by omega), ?_, c0.2, c1.2, c2.2, ?_⟩
    · exact c2.1
    · intro j hj hjc
      rcases h5 j (by omega) hjc with ⟨m, hm, hmj⟩ | ⟨_, h⟩
      · have : m = 0 ∨ m = 1 ∨ m = 2 := by omega
        rcases this with rfl | rfl | rfl
        · exact Or.inl hmj.symm
        · exact Or.inr hmj.symm
        · omega
      · omega
  · have seen_lt : seen.val < 3 := by
      have : seen.val ≠ 3 := fun e => three (UScalar.eq_of_val_eq (by simpa using e))
      omega
    have three' : ¬ seen = 3#usize := three
    simp only [three', ite_false]
    refine (WP.spec_ok _).mpr ⟨fun a ha => by simp at ha, fun _ => ?_⟩
    rintro ⟨i0, i1, i2, l01, l12, lt2, c0, c1, c2⟩
    have ctx_len : ctx.length = ctx.val.length := rfl
    have p0 := h5 i0 (by omega) c0
    have p1 := h5 i1 (by omega) c1
    have p2 := h5 i2 (by omega) c2
    have pick : ∀ j, ((∃ m, m < seen.val ∧ at1.val[m]!.val = j) ∨ (seen.val = 3 ∧ at1.val[2]!.val < j)) →
        (seen.val ≥ 1 ∧ at1.val[0]!.val = j) ∨ (seen.val ≥ 2 ∧ at1.val[1]!.val = j) := by
      rintro j (⟨m, hm, hmj⟩ | ⟨h, _⟩)
      · have : m = 0 ∨ m = 1 := by omega
        rcases this with rfl | rfl
        · exact Or.inl ⟨by omega, hmj⟩
        · exact Or.inr ⟨by omega, hmj⟩
      · omega
    have q0 := pick _ p0
    have q1 := pick _ p1
    have q2 := pick _ p2
    have d01 : seen.val ≥ 2 → at1.val[0]!.val < at1.val[1]!.val := fun h => h4 0 1 (by omega) (by omega)
    omega

end McsCore
