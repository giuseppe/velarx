-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `add_member_groups`: the gids of the groups that list the user are added.
-- Why it is needed: the last step of `resolve` for a user with no group part.
-- Read before this file: Members.lean, GroupIds.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` is the number a
--    machine integer is.
import UserCore.GroupIds
open Aeneas Aeneas.Std Result velarx_user_core
namespace UserCore

/-- The loop of `add_member_groups` returns, keeps `GroupState`, and adds only gids of lines that list the name. -/
theorem member_groups_loop_spec (group who : Slice Std.U8) (gids0 : alloc.vec.Vec Std.U32)
    (short : group.length < Std.Usize.max)
    (gids seen : alloc.vec.Vec Std.U32) (pos : Std.Usize) (room : Bool)
    (hpos : pos.val ≤ group.length + 1)
    (starts : pos.val < group.length → pos.val = 0 ∨ ByteAt group.val (pos.val - 1) 10)
    (state : GroupState gids seen)
    (extra : List Std.U32) (hext : gids.val = gids0.val ++ extra)
    (listed : ∀ x ∈ extra, ListedIn group.val who.val x) :
    add_member_groups_loop group gids seen who pos room ⦃ r => GroupState r.2.1 r.2.2 ∧
      ∃ extra, r.2.1.val = gids0.val ++ extra ∧ ∀ x ∈ extra, ListedIn group.val who.val x ⦄ := by
  unfold add_member_groups_loop
  apply loop.spec_decr_nat
    (fun (q : (alloc.vec.Vec Std.U32) × (alloc.vec.Vec Std.U32) × Std.Usize × Bool) =>
      group.length + 1 - q.2.2.1.val)
    (fun (q : (alloc.vec.Vec Std.U32) × (alloc.vec.Vec Std.U32) × Std.Usize × Bool) =>
      q.2.2.1.val ≤ group.length + 1 ∧
      (q.2.2.1.val < group.length → q.2.2.1.val = 0 ∨ ByteAt group.val (q.2.2.1.val - 1) 10) ∧
      GroupState q.1 q.2.1 ∧
      ∃ extra, q.1.val = gids0.val ++ extra ∧ ∀ x ∈ extra, ListedIn group.val who.val x)
  · rintro ⟨gids1, seen1, pos1, room1⟩ ⟨h1, h2, h3, extra1, hext1, listed1⟩
    simp only at h1 h2 h3 hext1 listed1 ⊢
    unfold add_member_groups_loop.body
    step*
    have below := ‹pos1 < group.len›
    have lt : pos1.val < group.length := by scalar_tac
    step with line_at_spec group pos1 (by omega) (h2 lt) as ⟨ fin, stop, hline, hsf, hfin_le, hfin_nl ⟩
    step with group_line_spec group pos1 stop hline.1 hline.2.1 as ⟨ o, o_post ⟩
    have hps : pos1.val ≤ stop.val := hline.1
    have noovf : fin.val + 1 ≤ Std.Usize.max := by scalar_tac
    have finish : ∀ (gids2 seen2 : alloc.vec.Vec Std.U32) (pos2 : Std.Usize), pos2.val = fin.val + 1 →
        GroupState gids2 seen2 → (∃ extra, gids2.val = gids0.val ++ extra ∧
          ∀ x ∈ extra, ListedIn group.val who.val x) →
        pos2.val ≤ group.length + 1 ∧
        (pos2.val < group.length → pos2.val = 0 ∨ ByteAt group.val (pos2.val - 1) 10) ∧
        GroupState gids2 seen2 ∧ (∃ extra, gids2.val = gids0.val ++ extra ∧
          ∀ x ∈ extra, ListedIn group.val who.val x) ∧
        group.length + 1 - pos2.val < group.length + 1 - pos1.val := by
      intro gids2 seen2 pos2 pos2_post st2 ex2
      refine ⟨by omega, ?_, st2, ex2, by omega⟩
      intro lt2
      right
      have := hfin_nl (by omega)
      rw [pos2_post]; simpa using this
    rcases o with _ | g
    · simp only [bind_ok]
      step as ⟨ pos2, pos2_post ⟩
      exact finish gids1 seen1 pos2 pos2_post h3 ⟨extra1, hext1, listed1⟩
    · have entry := o_post g rfl
      have ⟨_, name_lt, mem_le, mem_in⟩ := group_entry_bounds _ _ _ g entry
      have mem_in' : g.members.2.val ≤ group.length := by omega
      simp only []
      step with is_member_spec group g.members who mem_le mem_in' short as ⟨ b, hb ⟩
      by_cases hbt : b = true
      · rw [if_yes hbt]
        have small : g.gid.val < NoId := by
          obtain ⟨_, c0, c1, c2, rest, _, _, _, parsed, _⟩ := entry
          exact parsed.2.2
        simp only [Std.bind_assoc]
        step with add_gid_spec gids1 seen1 g.gid h3 small as ⟨ r, st2, grew ⟩
        obtain ⟨room2, gids2, seen2⟩ := r
        simp
        step as ⟨ pos2, pos2_post ⟩
        refine finish gids2 seen2 pos2 pos2_post st2 ?_
        have here : ListedIn group.val who.val g.gid := ⟨pos1.val, stop.val, g, hline, entry, rfl, hb hbt⟩
        rcases grew with h | h
        · exact ⟨extra1, by rw [h]; exact hext1, listed1⟩
        · refine ⟨extra1 ++ [g.gid], by rw [h, hext1]; simp, ?_⟩
          intro x hx
          rcases List.mem_append.mp hx with hx | hx
          · exact listed1 x hx
          · simp at hx; subst hx; exact here
      · rw [if_no hbt]
        simp only [bind_ok]
        step as ⟨ pos2, pos2_post ⟩
        exact finish gids1 seen1 pos2 pos2_post h3 ⟨extra1, hext1, listed1⟩
  · exact ⟨hpos, starts, state, extra, hext, listed⟩

/-- `add_member_groups` returns, keeps `GroupState`, and adds only gids of lines that list the name of the entry. -/
theorem add_member_groups_spec (group passwd : Slice Std.U8) (entry : Option Passwd)
    (gids seen : alloc.vec.Vec Std.U32) (short : group.length < Std.Usize.max)
    (state : GroupState gids seen)
    (hent : ∀ e, entry = some e → e.name.1.val ≤ e.name.2.val ∧ e.name.2.val ≤ passwd.length) :
    add_member_groups group passwd entry gids seen ⦃ r => GroupState r.2.1 r.2.2 ∧
      ∃ extra, r.2.1.val = gids.val ++ extra ∧
        ∀ x ∈ extra, ∃ e, entry = some e ∧ e.name.1.val < e.name.2.val ∧
          ListedIn group.val (List.slice e.name.1.val e.name.2.val passwd.val) x ⦄ := by
  unfold add_member_groups
  rcases entry with _ | e
  · exact (WP.spec_ok _).mpr ⟨state, [], by simp, by simp⟩
  · obtain ⟨hab, hb⟩ := hent e rfl
    obtain ⟨⟨n1, n2⟩, uid, gid, gecos, home⟩ := e
    simp only at hab hb ⊢
    by_cases empty : n1 ≥ n2
    · simp
      have e' : n2.val ≤ n1.val := by scalar_tac
      rw [if_yes e']
      exact (WP.spec_ok _).mpr ⟨state, [], by simp, by simp⟩
    · simp
      have e' : ¬ (n2.val ≤ n1.val) := by scalar_tac
      rw [if_no e']
      step as ⟨ who, who_post, who_len ⟩
      step with member_groups_loop_spec group who gids short gids seen 0#usize true (by simp) (by simp)
        state [] (by simp) (by simp) as ⟨ r, st, extra, hext, hl ⟩
      refine ⟨st, extra, hext, ?_⟩
      intro x hx
      refine ⟨by scalar_tac, ?_⟩
      have := hl x hx
      rw [who_post] at this
      exact this

end UserCore
