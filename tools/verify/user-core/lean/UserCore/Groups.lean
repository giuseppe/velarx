-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `group_gid` and `has_gid` answer, and the bounds of a group line.
-- Why it is needed: a group given by name becomes a gid with `group_gid`.
-- Read before this file: Find.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` is the number a
--    machine integer is.
import UserCore.Find
open Aeneas Aeneas.Std Result velarx_user_core
namespace UserCore

/-- The name and the members of a group line are ranges of its line. -/
theorem group_entry_bounds (d : List Std.U8) (start stop : Nat) (g : GroupLine)
    (h : IsGroupEntry d start stop g) :
    g.name.1.val ≤ g.name.2.val ∧ g.name.2.val < stop ∧ g.members.1.val ≤ g.members.2.val ∧
      g.members.2.val ≤ stop := by
  obtain ⟨_, c0, c1, c2, rest, hL, n1, n2, _, m1, m2⟩ := h
  have sorted := colons_sorted d start stop
  have inside : ∀ x ∈ Colons d start stop, start ≤ x ∧ x < stop := fun x hx => by
    have := (mem_colons _ _ _ _).mp hx; exact ⟨this.1, this.2.1⟩
  rw [hL] at sorted inside
  simp only [List.pairwise_cons, List.mem_cons] at sorted
  have c0in := inside c0 (by simp)
  have c2in := inside c2 (by simp)
  have lt12 : c1 < c2 := sorted.2.1 _ (by simp)
  refine ⟨by omega, by omega, ?_, ?_⟩
  all_goals
    cases rest with
    | nil => simp at m2; omega
    | cons r rs =>
      have rin := inside r (by simp)
      have lt2r : c2 < r := sorted.2.2.1 _ (by simp)
      simp at m2; omega

/-- The loop of `group_gid` returns, and a gid it answers is that of a group line of the file with that name. -/
theorem group_gid_loop_spec (group nm : Slice Std.U8) (pos : Std.Usize) (found : Option Std.U32)
    (short : group.length < Std.Usize.max) (hpos : pos.val ≤ group.length + 1)
    (starts : pos.val < group.length → pos.val = 0 ∨ ByteAt group.val (pos.val - 1) 10)
    (sound : ∀ g, found = some g → GroupNamed group.val nm.val g) :
    group_gid_loop group nm pos found ⦃ r => ∀ g, r = some g → GroupNamed group.val nm.val g ⦄ := by
  unfold group_gid_loop
  apply loop.spec_decr_nat (fun (q : Std.Usize × Option Std.U32) => group.length + 1 - q.1.val)
    (fun (q : Std.Usize × Option Std.U32) => q.1.val ≤ group.length + 1 ∧
      (q.1.val < group.length → q.1.val = 0 ∨ ByteAt group.val (q.1.val - 1) 10) ∧
      ∀ g, q.2 = some g → GroupNamed group.val nm.val g)
  · rintro ⟨pos1, found1⟩ ⟨h1, h2, h3⟩
    simp only at h1 h2 h3 ⊢
    unfold group_gid_loop.body
    step*
    rename_i below isnone
    have lt : pos1.val < group.length := by scalar_tac
    step with line_at_spec group pos1 (by omega) (h2 lt) as ⟨ fin, stop, hline, hsf, hfin_le, hfin_nl ⟩
    step with group_line_spec group pos1 stop hline.1 hline.2.1 as ⟨ o, o_post ⟩
    have hps : pos1.val ≤ stop.val := hline.1
    have noovf : fin.val + 1 ≤ Std.Usize.max := by scalar_tac
    have finish : ∀ (found2 : Option Std.U32) (pos2 : Std.Usize), pos2.val = fin.val + 1 →
        (∀ g, found2 = some g → GroupNamed group.val nm.val g) →
        pos2.val ≤ group.length + 1 ∧
        (pos2.val < group.length → pos2.val = 0 ∨ ByteAt group.val (pos2.val - 1) 10) ∧
        (∀ g, found2 = some g → GroupNamed group.val nm.val g) ∧
        group.length + 1 - pos2.val < group.length + 1 - pos1.val := by
      intro found2 pos2 pos2_post sound2
      refine ⟨by omega, ?_, sound2, by omega⟩
      intro lt2
      right
      have := hfin_nl (by omega)
      rw [pos2_post]; simpa using this
    rcases o with _ | g
    · simp only [bind_ok]
      step as ⟨ pos2, pos2_post ⟩
      exact finish found1 pos2 pos2_post h3
    · have entry := o_post g rfl
      have ⟨name_le, name_lt, _, _⟩ := group_entry_bounds _ _ _ g entry
      have name_in : g.name.2.val ≤ group.length := by omega
      simp only []
      step with is_text_spec group g.name.1 g.name.2 nm name_le name_in as ⟨ b1, hb1 ⟩
      by_cases hb : b1 = true
      · rw [if_yes hb]; simp only [bind_ok]
        step as ⟨ pos2, pos2_post ⟩
        refine finish (some g.gid) pos2 pos2_post ?_
        intro x hx; cases hx
        exact ⟨pos1.val, stop.val, g, hline, entry, rfl, hb1.mp hb⟩
      · rw [if_no hb]; simp only [bind_ok]
        step as ⟨ pos2, pos2_post ⟩
        exact finish found1 pos2 pos2_post h3
  · exact ⟨hpos, starts, sound⟩

/-- `group_gid` returns, and a gid it answers is that of a group line of the file with that name. -/
theorem group_gid_spec (group nm : Slice Std.U8) (short : group.length < Std.Usize.max) :
    group_gid group nm ⦃ r => ∀ g, r = some g → GroupNamed group.val nm.val g ⦄ := by
  unfold group_gid
  exact group_gid_loop_spec group nm 0#usize none short (by simp) (fun _ => Or.inl rfl) (by simp)

/-- The loop of `has_gid` returns. -/
theorem has_gid_loop_spec (group : Slice Std.U8) (gid : Std.U32) (pos : Std.Usize) (found : Bool)
    (short : group.length < Std.Usize.max) (hpos : pos.val ≤ group.length + 1)
    (starts : pos.val < group.length → pos.val = 0 ∨ ByteAt group.val (pos.val - 1) 10) :
    has_gid_loop group gid pos found ⦃ _ => True ⦄ := by
  unfold has_gid_loop
  apply loop.spec_decr_nat (fun (q : Std.Usize × Bool) => group.length + 1 - q.1.val)
    (fun (q : Std.Usize × Bool) => q.1.val ≤ group.length + 1 ∧
      (q.1.val < group.length → q.1.val = 0 ∨ ByteAt group.val (q.1.val - 1) 10))
  · rintro ⟨pos1, found1⟩ ⟨h1, h2⟩
    simp only at h1 h2 ⊢
    unfold has_gid_loop.body
    step*
    rename_i below _
    have lt : pos1.val < group.length := by scalar_tac
    step with line_at_spec group pos1 (by omega) (h2 lt) as ⟨ fin, stop, hline, hsf, hfin_le, hfin_nl ⟩
    step with group_line_spec group pos1 stop hline.1 hline.2.1 as ⟨ o, o_post ⟩
    have hps : pos1.val ≤ stop.val := hline.1
    have noovf : fin.val + 1 ≤ Std.Usize.max := by scalar_tac
    rcases o with _ | g
    · simp only [bind_ok]
      step as ⟨ pos2, pos2_post ⟩
      refine ⟨by omega, ?_, by omega⟩
      intro lt2; right
      have := hfin_nl (by omega)
      rw [pos2_post]; simpa using this
    · simp only [bind_ok]
      step as ⟨ pos2, pos2_post ⟩
      refine ⟨by omega, ?_, by omega⟩
      intro lt2; right
      have := hfin_nl (by omega)
      rw [pos2_post]; simpa using this
  · exact ⟨hpos, starts⟩

/-- `has_gid` returns. -/
theorem has_gid_spec (group : Slice Std.U8) (gid : Std.U32) (short : group.length < Std.Usize.max) :
    has_gid group gid ⦃ _ => True ⦄ := by
  unfold has_gid
  exact has_gid_loop_spec group gid 0#usize false short (by simp) (fun _ => Or.inl rfl)

end UserCore
