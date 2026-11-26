-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `group_id`, `add_group` and `add_groups`: a group of the request becomes a gid and is added.
-- Why it is needed: the groups of `group_add` and the group part are read with them.
-- Read before this file: AddGid.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` is the number a
--    machine integer is.
import UserCore.AddGid
open Aeneas Aeneas.Std Result velarx_user_core
namespace UserCore

/-- `group_id` returns; an id it answers is below `NoId` and is what the text names; a refusal is for a bad id or an unknown name. -/
theorem group_id_spec (group g : Slice Std.U8) (which : Group) (short : group.length < Std.Usize.max) :
    group_id group g which ⦃ r =>
      (∀ x, r = core.result.Result.Ok x → x.val < NoId ∧ NamesGroup group.val g.val x) ∧
      (∀ e, r = core.result.Result.Err e → e = Refusal.BadGroupId which ∨ e = Refusal.NoGroup which) ⦄ := by
  unfold group_id
  step with parse_id_spec g as ⟨ o, o_post ⟩
  rcases o with _ | x
  · simp only []
    step with is_digits_spec g as ⟨ b, b_post ⟩
    by_cases hb : b = true
    · rw [if_yes hb]
      exact (WP.spec_ok _).mpr ⟨by simp, by simp⟩
    · rw [if_no hb]
      step with group_gid_spec group g short as ⟨ o1, o1_post ⟩
      rcases o1 with _ | gid
      · exact (WP.spec_ok _).mpr ⟨by simp, by simp⟩
      · refine (WP.spec_ok _).mpr ⟨?_, by simp⟩
        intro y hy
        cases hy
        have named := o1_post gid rfl
        obtain ⟨_, _, gl, _, entry, hg, _⟩ := id named
        have := entry.2
        obtain ⟨c0, c1, c2, rest, _, _, _, parsed, _⟩ := this
        refine ⟨by rw [← hg]; exact parsed.2.2, Or.inr ⟨fun h => hb (b_post.mpr h), named⟩⟩
  · exact (WP.spec_ok _).mpr ⟨fun y hy => by cases hy; exact ⟨((o_post x).mp rfl).2.2, Or.inl ((o_post x).mp rfl)⟩, by simp⟩

/-- `add_group` returns, keeps `GroupState`, adds the gid of the group `i` of `group_add` or nothing, and refuses only for the groups. -/
theorem add_group_spec (group : Slice Std.U8) (ga : Slice (alloc.vec.Vec Std.U8)) (i : Std.Usize)
    (gids seen : alloc.vec.Vec Std.U32) (short : group.length < Std.Usize.max)
    (hi : i.val < ga.length) (state : GroupState gids seen) :
    add_group group ga i gids seen ⦃ r => GroupState r.2.1 r.2.2 ∧
      (r.2.1.val = gids.val ∨ ∃ (x : Std.U32) (s : alloc.vec.Vec Std.U8), r.2.1.val = gids.val ++ [x] ∧
        ga.val[i.val]? = some s ∧
        NamesGroup group.val s.val x) ∧
      (∀ ref, r.1 = some ref → GroupRefusal ref) ⦄ := by
  unfold add_group
  -- the group at the place `i`
  step as ⟨ v, v_post ⟩
  have at_i : ga.val[i.val]? = some v := by
    rw [v_post]; simp [Slice.length] at *
  step with group_id_spec group (alloc.vec.Vec.deref v) (Group.Add i) short as ⟨ r, ok_post, err_post ⟩
  rcases r with x | e
  · -- it names a gid, which is added if there is room
    simp only []
    obtain ⟨small, names⟩ := ok_post x rfl
    have names : NamesGroup group.val v.val x := by simpa [alloc.vec.Vec.deref] using names
    step with add_gid_spec gids seen x state small as ⟨ b, gids1, seen1, st1, grew ⟩
    by_cases hb : b = true
    · rw [if_yes hb]
      refine (WP.spec_ok _).mpr ⟨st1, ?_, by simp⟩
      rcases grew with h | h
      · exact Or.inl h
      · exact Or.inr ⟨x, v, h, at_i, names⟩
    · rw [if_no hb]
      refine (WP.spec_ok _).mpr ⟨st1, ?_, ?_⟩
      · rcases grew with h | h
        · exact Or.inl h
        · exact Or.inr ⟨x, v, h, at_i, names⟩
      · intro ref href; cases href; exact Or.inl rfl
  · -- it is refused
    simp only []
    refine (WP.spec_ok _).mpr ⟨state, Or.inl rfl, ?_⟩
    intro ref href; cases href
    rcases err_post e rfl with h | h
    · exact Or.inr (Or.inl ⟨_, h⟩)
    · exact Or.inr (Or.inr ⟨_, h⟩)

/-- `add_groups` returns, keeps `GroupState`, adds only gids of the groups of `group_add`, and
refuses only for the groups. -/
theorem add_groups_spec (group : Slice Std.U8) (ga : Slice (alloc.vec.Vec Std.U8))
    (gids0 seen0 : alloc.vec.Vec Std.U32) (short : group.length < Std.Usize.max)
    (state : GroupState gids0 seen0) :
    add_groups group ga gids0 seen0 ⦃ r => GroupState r.2.1 r.2.2 ∧
      ∃ extra, r.2.1.val = gids0.val ++ extra ∧
        (∀ x ∈ extra, ∃ (k : Nat) (s : alloc.vec.Vec Std.U8), ga.val[k]? = some s ∧
          NamesGroup group.val s.val x) ∧
        (∀ ref, r.1 = some ref → GroupRefusal ref) ⦄ := by
  unfold add_groups add_groups_loop
  -- the loop goes through the groups in order, until the end or a refusal
  apply loop.spec_decr_nat
    (fun (q : (alloc.vec.Vec Std.U32) × (alloc.vec.Vec Std.U32) × (Option Refusal) × Std.Usize) =>
      ga.length - q.2.2.2.val)
    (fun (q : (alloc.vec.Vec Std.U32) × (alloc.vec.Vec Std.U32) × (Option Refusal) × Std.Usize) =>
      q.2.2.2.val ≤ ga.length ∧ GroupState q.1 q.2.1 ∧
      (∃ extra, q.1.val = gids0.val ++ extra ∧
        ∀ x ∈ extra, ∃ (k : Nat) (s : alloc.vec.Vec Std.U8), ga.val[k]? = some s ∧
          NamesGroup group.val s.val x) ∧
      (∀ ref, q.2.2.1 = some ref → GroupRefusal ref))
  · rintro ⟨gids1, seen1, refusal1, i1⟩ ⟨h_le, st1, ⟨extra1, hext1, src1⟩, refs1⟩
    simp only at h_le st1 hext1 src1 refs1 ⊢
    unfold add_groups_loop.body
    by_cases more : i1 < Slice.len ga
    · have lt : i1.val < ga.length := by scalar_tac
      simp only [more, ↓reduceIte]
      by_cases none_yet : refusal1.isNone = true
      · -- the group `i1` is added (or refused), and the loop goes on
        simp only [core.option.Option.is_none, none_yet, ↓reduceIte]
        step with add_group_spec group ga i1 gids1 seen1 short lt st1
          as ⟨ o, gids2, seen2, st2, grew, refused ⟩
        step as ⟨ i2, i2_post ⟩
        refine ⟨by omega, st2, ?_, refused, by omega⟩
        rcases grew with h | ⟨x, s, h, hs, hnames⟩
        · exact ⟨extra1, by rw [h, hext1], src1⟩
        · refine ⟨extra1 ++ [x], by rw [h, hext1]; simp, ?_⟩
          intro y hy
          rcases List.mem_append.mp hy with hy | hy
          · exact src1 y hy
          · simp at hy; subst hy; exact ⟨i1.val, s, hs, hnames⟩
      · -- a refusal ends the loop
        simp only [core.option.Option.is_none, none_yet, Bool.false_eq_true, ↓reduceIte]
        exact (WP.spec_ok _).mpr ⟨st1, extra1, hext1, src1, refs1⟩
    · -- the end of the list ends the loop
      simp only [more, ↓reduceIte]
      exact (WP.spec_ok _).mpr ⟨st1, extra1, hext1, src1, refs1⟩
  · exact ⟨by simp, state, ⟨[], by simp, by simp⟩, by simp⟩

end UserCore
