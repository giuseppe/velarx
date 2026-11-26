-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `resolve_user` does once it knows the uid, the gid and the home: it adds the groups.
-- Why it is needed: the same text ends every way of reaching an answer.
-- Read before this file: MemberGroups.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` is the number a
--    machine integer is.
import UserCore.MemberGroups
open Aeneas Aeneas.Std Result velarx_user_core
namespace UserCore

/-- What the groups of an answer are, once the uid, the gid and the home are known. -/
def TailPost (passwd group : Slice Std.U8) (ga : Slice (alloc.vec.Vec Std.U8)) (strict own_group : Bool)
    (entry : Option Passwd) (uid gid : Std.U32) (home : Option (Std.Usize × Std.Usize))
    (r : core.result.Result Resolved Refusal) : Prop :=
  (∀ res, r = core.result.Result.Ok res → res.uid = uid ∧ res.gid = gid ∧ res.home = home ∧
    res.gids.val.head? = some gid ∧ res.gids.val.Nodup ∧ res.gids.val.length ≤ 65536 ∧
    (∀ x ∈ res.gids.val, x.val < NoId) ∧
    ∀ x ∈ res.gids.val, x = gid ∨
      (∃ (k : Nat) (s : alloc.vec.Vec Std.U8), ga.val[k]? = some s ∧ NamesGroup group.val s.val x) ∨
      (own_group = true ∧ strict = false ∧ ∃ e, entry = some e ∧ e.name.1.val < e.name.2.val ∧
        ListedIn group.val (List.slice e.name.1.val e.name.2.val passwd.val) x)) ∧
  (∀ ref, r = core.result.Result.Err ref → GroupRefusal ref)

/-- Once the uid, gid and home are known, `resolve_user` adds the groups and answers: the groups are those of the claims, a refusal is for the groups. -/
theorem tail_spec (passwd group : Slice Std.U8) (ga : Slice (alloc.vec.Vec Std.U8)) (strict own_group : Bool)
    (entry : Option Passwd) (uid gid : Std.U32) (home : Option (Std.Usize × Std.Usize))
    (short : group.length < Std.Usize.max)
    (small : gid.val < NoId)
    (hent : ∀ e, entry = some e → e.name.1.val ≤ e.name.2.val ∧ e.name.2.val ≤ passwd.length) :
    (do
      let y ← lift (Std.Array.to_slice (Array.make 1#usize [ gid ] : Array Std.U32 1#usize))
      let ret := alloc.slice.Slice.into_vec y
      let y1 ← lift (Std.Array.to_slice (Array.make 1#usize [ gid ] : Array Std.U32 1#usize))
      let ret1 := alloc.slice.Slice.into_vec y1
      let (o, ret2, ret3) ← add_groups group ga ret ret1
      match o with
      | none =>
        if own_group = true then
          if strict = true then
            ok (core.result.Result.Ok { uid := uid, gid := gid, home := home, gids := ret2 })
          else do
            let (b3, ret4, _) ← add_member_groups group passwd entry ret2 ret3
            if b3 = true then
              ok (core.result.Result.Ok { uid := uid, gid := gid, home := home, gids := ret4 })
            else ok (core.result.Result.Err Refusal.TooManyGroups)
        else ok (core.result.Result.Ok { uid := uid, gid := gid, home := home, gids := ret2 })
      | some r => ok (core.result.Result.Err r) : Result (core.result.Result Resolved Refusal)) ⦃ r =>
      TailPost passwd group ga strict own_group entry uid gid home r ⦄ := by
  step*
  have hv : (alloc.slice.Slice.into_vec y).val = [gid] := by simp [y_post, alloc.slice.Slice.into_vec, alloc.vec.Vec.val, Std.Array.to_slice]
  have hv1 : (alloc.slice.Slice.into_vec y1).val = [gid] := by
    simp [y1_post, alloc.slice.Slice.into_vec, alloc.vec.Vec.val, Std.Array.to_slice]
  have state0 : GroupState (alloc.slice.Slice.into_vec y) (alloc.slice.Slice.into_vec y1) := by
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩ <;> simp [hv, hv1, small]
  step with add_groups_spec group ga _ _ short state0
    as ⟨ o, gids2, seen2, st, extra, hext, hsrc, hrefs ⟩
  unfold TailPost
  rw [hv] at hext
  have heads : gids2.val.head? = some gid := by
    cases extra <;> simp [hext]
  have from_ga : ∀ x ∈ gids2.val, x = gid ∨
      (∃ (k : Nat) (s : alloc.vec.Vec Std.U8), ga.val[k]? = some s ∧ NamesGroup group.val s.val x) := by
    intro x hx
    rw [hext] at hx
    simp only [List.mem_append, List.mem_singleton] at hx
    rcases hx with hx | hx
    · exact Or.inl hx
    · obtain ⟨k, s, hk, hn⟩ := hsrc x hx
      exact Or.inr ⟨k, s, hk, hn⟩
  rcases o with _ | refusal
  · simp only []
    by_cases own : own_group = true
    · rw [if_yes own]
      by_cases hs : strict = true
      · rw [if_yes hs]
        refine (WP.spec_ok _).mpr ⟨?_, by simp⟩
        intro res hres; cases hres
        refine ⟨rfl, rfl, rfl, heads, st.1, st.2.1, st.2.2.1, ?_⟩
        intro x hx
        rcases from_ga x hx with h | h
        · exact Or.inl h
        · exact Or.inr (Or.inl h)
      · rw [if_no hs]
        step with add_member_groups_spec group passwd entry gids2 seen2 short st hent
          as ⟨ b3, gids4, seen4, st4, extra4, hext4, hsrc4 ⟩
        by_cases hb : b3 = true
        · rw [if_yes hb]
          refine (WP.spec_ok _).mpr ⟨?_, by simp⟩
          intro res hres; cases hres
          refine ⟨rfl, rfl, rfl, ?_, st4.1, st4.2.1, st4.2.2.1, ?_⟩
          · rw [hext4, hext]; cases extra <;> simp
          · intro x hx
            rw [hext4] at hx
            rcases List.mem_append.mp hx with hx | hx
            · rcases from_ga x hx with h | h
              · exact Or.inl h
              · exact Or.inr (Or.inl h)
            · obtain ⟨e, he, hlt, hl⟩ := hsrc4 x hx
              exact Or.inr (Or.inr ⟨own, by simpa using hs, e, he, hlt, hl⟩)
        · rw [if_no hb]
          refine (WP.spec_ok _).mpr ⟨by simp, ?_⟩
          intro ref href; cases href; exact Or.inl rfl
    · rw [if_no own]
      refine (WP.spec_ok _).mpr ⟨?_, by simp⟩
      intro res hres; cases hres
      refine ⟨rfl, rfl, rfl, heads, st.1, st.2.1, st.2.2.1, ?_⟩
      intro x hx
      rcases from_ga x hx with h | h
      · exact Or.inl h
      · exact Or.inr (Or.inl h)
  · simp only []
    refine (WP.spec_ok _).mpr ⟨by simp, ?_⟩
    intro ref href; cases href
    exact hrefs _ rfl

end UserCore
