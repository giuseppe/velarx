-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `add_gid`, the list of the gids with no gid twice (the list `seen` is its copy in order of value, searched by halves).
-- Why it is needed: the claims on the groups of an answer follow from `GroupState` being kept.
-- Read before this file: Members.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` is the number a
--    machine integer is.
import UserCore.Members
open Aeneas Aeneas.Std Result velarx_user_core
namespace UserCore

/-- The list of the gids and its copy in order of value: no gid twice, at most `MAX_GROUPS`, all
below `NoId`, and the same gids in both. -/
def GroupState (gids seen : alloc.vec.Vec Std.U32) : Prop :=
  gids.val.Nodup ∧ gids.val.length ≤ 65536 ∧ (∀ g ∈ gids.val, g.val < NoId) ∧
    seen.val.Pairwise (fun a b => a.val < b.val) ∧ (∀ x, x ∈ seen.val ↔ x ∈ gids.val) ∧
    seen.val.length = gids.val.length

/-- Inserting at a place is cutting the list there and putting the element between the two parts. -/
theorem insertIdx_eq_take_drop {α : Type _} (l : List α) (i : Nat) (x : α) (h : i ≤ l.length) :
    l.insertIdx i x = l.take i ++ x :: l.drop i := by
  induction l generalizing i with
  | nil => simp at h; subst h; simp
  | cons a l ih =>
    cases i with
    | zero => simp
    | succ i => simp [List.insertIdx_succ_cons, ih i (by simpa using h)]

/-- Putting a gid where the binary search of `add_gid` stopped keeps the list in order of value. -/
theorem insert_sorted (l : List Std.U32) (sorted : l.Pairwise (fun a b => a.val < b.val)) (lo : Nat)
    (hlo : lo ≤ l.length) (x : Std.U32)
    (before : ∀ j, j < lo → ∀ y, l[j]? = some y → y.val < x.val)
    (after : ∀ j, lo ≤ j → ∀ y, l[j]? = some y → x.val < y.val) :
    (l.insertIdx lo x).Pairwise (fun a b => a.val < b.val) := by
  rw [insertIdx_eq_take_drop l lo x hlo]
  have split : l = l.take lo ++ l.drop lo := (List.take_append_drop lo l).symm
  rw [split] at sorted
  have ⟨sa, sb, sab⟩ := List.pairwise_append.mp sorted
  rw [List.pairwise_append]
  refine ⟨sa, ?_, ?_⟩
  · rw [List.pairwise_cons]
    refine ⟨?_, sb⟩
    intro b hb
    obtain ⟨j, hj, rfl⟩ := List.getElem_of_mem hb
    exact after (lo + j) (by omega) _ (by simp)
  · intro a ha b hb
    obtain ⟨j, hj, rfl⟩ := List.getElem_of_mem ha
    simp only [List.mem_cons] at hb
    rcases hb with rfl | hb
    · exact before j (by simp at hj; omega) _ (by simp)
    · exact sab _ (List.getElem_mem hj) b hb

/-- `MAX_GROUPS` is 65536. -/
theorem max_groups : MAX_GROUPS = 65536#usize := by unfold MAX_GROUPS; rfl

/-- In a list in order of value, a gid at an earlier place is the smaller one. -/
theorem sorted_get (l : List Std.U32) (sorted : l.Pairwise (fun a b => a.val < b.val))
    (i j : Nat) (hij : i < j) (x y : Std.U32) (hx : l[i]? = some x) (hy : l[j]? = some y) :
    x.val < y.val := by
  rw [List.pairwise_iff_getElem] at sorted
  have hi : i < l.length := by
    by_contra h; rw [List.getElem?_eq_none (by omega)] at hx; cases hx
  have hj : j < l.length := by
    by_contra h; rw [List.getElem?_eq_none (by omega)] at hy; cases hy
  rw [List.getElem?_eq_getElem hi] at hx
  rw [List.getElem?_eq_getElem hj] at hy
  cases hx; cases hy
  exact sorted i j hi hj hij

/-- The binary search of `add_gid` returns the place where the gid is or would go: the gids before it are smaller, those from it are not. -/
theorem search_loop_spec (seen : alloc.vec.Vec Std.U32) (gid : Std.U32) (lo hi : Std.Usize)
    (sorted : seen.val.Pairwise (fun a b => a.val < b.val)) (hlo : lo.val ≤ hi.val)
    (hhi : hi.val ≤ seen.val.length)
    (before : ∀ j, j < lo.val → ∀ x, seen.val[j]? = some x → x.val < gid.val)
    (after : ∀ j, hi.val ≤ j → ∀ x, seen.val[j]? = some x → gid.val ≤ x.val) :
    add_gid_loop seen gid lo hi ⦃ r =>
      (∀ j, j < r.val → ∀ x, seen.val[j]? = some x → x.val < gid.val) ∧
      (∀ j, r.val ≤ j → ∀ x, seen.val[j]? = some x → gid.val ≤ x.val) ∧ r.val ≤ seen.val.length ⦄ := by
  unfold add_gid_loop
  apply loop.spec_decr_nat (fun (q : Std.Usize × Std.Usize) => q.2.val - q.1.val)
    (fun (q : Std.Usize × Std.Usize) => q.1.val ≤ q.2.val ∧ q.2.val ≤ seen.val.length ∧
      (∀ j, j < q.1.val → ∀ x, seen.val[j]? = some x → x.val < gid.val) ∧
      (∀ j, q.2.val ≤ j → ∀ x, seen.val[j]? = some x → gid.val ≤ x.val))
  · rintro ⟨lo0, hi1⟩ ⟨h0, h1, h2, h3⟩
    simp only at h0 h1 h2 h3 ⊢
    unfold add_gid_loop.body
    step*
    · have small := ‹i2 < gid›
      have below : mid.val < seen.val.length := by scalar_tac
      have byte : seen.val[mid.val]? = some i2 := by
        rw [i2_post]; simp [below]
      have small' : i2.val < gid.val := by scalar_tac
      refine ⟨by scalar_tac, h1, ?_, h3, by scalar_tac⟩
      intro j hj x hx
      by_cases old : j < lo0.val
      · exact h2 j old x hx
      · by_cases e : j = mid.val
        · subst e; rw [byte] at hx; cases hx; exact small'
        · have := sorted_get _ sorted j mid.val (by scalar_tac) x i2 hx byte
          omega
    · have big := ‹¬ i2 < gid›
      have below : mid.val < seen.val.length := by scalar_tac
      have byte : seen.val[mid.val]? = some i2 := by
        rw [i2_post]; simp [below]
      have big' : gid.val ≤ i2.val := by scalar_tac
      refine ⟨by scalar_tac, by scalar_tac, h2, ?_, by scalar_tac⟩
      intro j hj x hx
      by_cases e : j = mid.val
      · subst e; rw [byte] at hx; cases hx; exact big'
      · have := sorted_get _ sorted mid.val j (by scalar_tac) i2 x byte hx
        omega
    · have done := ‹¬ lo0 < hi1›
      refine ⟨h2, ?_, by omega⟩
      have : lo0.val = hi1.val := by scalar_tac
      rw [this]; exact h3
  · exact ⟨hlo, hhi, before, after⟩

/-- Adding to the list a gid that is not in it, at the place the search found, keeps `GroupState`. -/
theorem state_push (gids seen : List Std.U32) (gid : Std.U32) (lo : Nat)
    (nodup : gids.Nodup) (glen : gids.length < 65536) (gsmall : ∀ g ∈ gids, g.val < NoId)
    (sorted : seen.Pairwise (fun a b => a.val < b.val)) (same : ∀ x, x ∈ seen ↔ x ∈ gids)
    (samelen : seen.length = gids.length) (small : gid.val < NoId)
    (hlo : lo ≤ seen.length)
    (hb : ∀ j, j < lo → ∀ x, seen[j]? = some x → x.val < gid.val)
    (ha : ∀ j, lo ≤ j → ∀ x, seen[j]? = some x → gid.val ≤ x.val)
    (absent : gid ∉ seen) :
    (gids ++ [gid]).Nodup ∧ (gids ++ [gid]).length ≤ 65536 ∧
    (∀ g ∈ gids ++ [gid], g.val < NoId) ∧
    (seen.insertIdx lo gid).Pairwise (fun a b => a.val < b.val) ∧
    (∀ x, x ∈ seen.insertIdx lo gid ↔ x ∈ gids ++ [gid]) ∧
    (seen.insertIdx lo gid).length = (gids ++ [gid]).length := by
  have ne : ∀ y : Nat, seen[y]? ≠ some gid := by
    intro y h; exact absent (List.mem_of_getElem? h)
  refine ⟨?_, by simp; omega, ?_, ?_, ?_, ?_⟩
  · rw [List.nodup_append]
    refine ⟨nodup, by simp, ?_⟩
    intro a ha' b hb' hab
    simp at hb'; subst hb'; subst hab
    exact absent ((same _).mpr ha')
  · intro g hg
    simp at hg
    rcases hg with hg | rfl
    · exact gsmall g hg
    · exact small
  · refine insert_sorted seen sorted lo hlo gid hb ?_
    intro j hj x hx
    have := ha j hj x hx
    have : x.val ≠ gid.val := fun h => ne j (by rw [hx]; congr; exact (Std.UScalar.eq_of_val_eq h))
    omega
  · intro x
    rw [List.mem_insertIdx hlo, List.mem_append, List.mem_singleton, same]
    tauto
  · simp [List.length_insertIdx_of_le_length hlo, samelen]

/-- What `add_gid` does for a gid that is not in the list: refuse when the list is full, else add it at the end of one list and in order in the other. -/
theorem add_gid_rest (gids seen : alloc.vec.Vec Std.U32) (gid : Std.U32) (lo : Std.Usize)
    (state : GroupState gids seen) (small : gid.val < NoId) (hlo : lo.val ≤ seen.val.length)
    (hb : ∀ j, j < lo.val → ∀ x, seen.val[j]? = some x → x.val < gid.val)
    (ha : ∀ j, lo.val ≤ j → ∀ x, seen.val[j]? = some x → gid.val ≤ x.val)
    (absent : gid ∉ seen.val) :
    (do
      let i1 := alloc.vec.Vec.len gids
      if i1 >= MAX_GROUPS then ok (false, gids, seen)
      else do
        let gids1 ← alloc.vec.Vec.push gids gid
        let i2 := alloc.vec.Vec.len seen
        if lo = i2 then do
            let seen1 ← alloc.vec.Vec.push seen gid
            ok (true, gids1, seen1)
          else do
            let seen1 ← alloc.vec.Vec.insert seen lo gid
            ok (true, gids1, seen1)) ⦃ r => GroupState r.2.1 r.2.2 ∧
      (r.2.1.val = gids.val ∨ r.2.1.val = gids.val ++ [gid]) ⦄ := by
  obtain ⟨nodup, glen, gsmall, sorted, same, samelen⟩ := state
  have hl1 : (alloc.vec.Vec.len gids).val = gids.val.length := alloc.vec.Vec.len_val gids
  have hl2 : (alloc.vec.Vec.len seen).val = seen.val.length := alloc.vec.Vec.len_val seen
  by_cases full : alloc.vec.Vec.len gids >= MAX_GROUPS
  · rw [if_yes full]
    refine (WP.spec_ok _).mpr ⟨⟨nodup, glen, gsmall, sorted, same, samelen⟩, Or.inl rfl⟩
  · rw [if_no full]
    have room : gids.val.length < 65536 := by
      have : ¬ (alloc.vec.Vec.len gids).val ≥ MAX_GROUPS.val := by scalar_tac
      rw [max_groups] at this; simp at this; omega
    have seen_small : seen.val.length < Std.Usize.max := by scalar_tac
    have gids_small : gids.val.length < Std.Usize.max := by scalar_tac
    have pushed := state_push gids.val seen.val gid lo.val nodup room gsmall sorted same samelen small
      hlo hb ha absent
    step as ⟨ gids1, gids1_post ⟩
    by_cases at_end : lo = alloc.vec.Vec.len seen
    · rw [if_yes at_end]
      step as ⟨ seen1, seen1_post ⟩
      have lo_eq : lo.val = seen.val.length := by scalar_tac
      have seen1_eq : seen1.val = seen.val.insertIdx lo.val gid := by
        rw [seen1_post, lo_eq, List.insertIdx_length_self]
      refine ⟨?_, Or.inr gids1_post⟩
      unfold GroupState
      rw [gids1_post, seen1_eq]; exact pushed
    · rw [if_no at_end]
      have lo_lt : lo.val < seen.val.length := by scalar_tac
      step as ⟨ seen1, seen1_post ⟩
      refine ⟨?_, Or.inr gids1_post⟩
      unfold GroupState
      rw [gids1_post, seen1_post]; exact pushed

/-- `add_gid` returns, keeps `GroupState`, and leaves the list as it was or adds the gid at its end. -/
theorem add_gid_spec (gids seen : alloc.vec.Vec Std.U32) (gid : Std.U32)
    (state : GroupState gids seen) (small : gid.val < NoId) :
    add_gid gids seen gid ⦃ r => GroupState r.2.1 r.2.2 ∧
      (r.2.1.val = gids.val ∨ r.2.1.val = gids.val ++ [gid]) ⦄ := by
  have state0 := state
  obtain ⟨nodup, glen, gsmall, sorted, same, samelen⟩ := state
  unfold add_gid
  have hlen : (alloc.vec.Vec.len seen).val = seen.val.length := alloc.vec.Vec.len_val seen
  step with search_loop_spec seen gid 0#usize (alloc.vec.Vec.len seen) sorted (by simp)
    (by omega) (by simp) (fun j hj x hx => by
      rw [List.getElem?_eq_none (by omega)] at hx; cases hx) as ⟨ lo, hb, ha, hl ⟩
  have present : gid ∈ seen.val → lo.val < seen.val.length ∧ seen.val[lo.val]? = some gid := by
    intro hm
    obtain ⟨j, hj, hjx⟩ := List.getElem_of_mem hm
    have hjx' : seen.val[j]? = some gid := by simp [hj, hjx]
    have jl : lo.val ≤ j := by
      by_contra h
      have := hb j (by omega) gid hjx'; omega
    have lo_lt : lo.val < seen.val.length := by omega
    obtain ⟨y, hy⟩ : ∃ y, seen.val[lo.val]? = some y := ⟨_, List.getElem?_eq_getElem lo_lt⟩
    have gy := ha lo.val (le_refl _) y hy
    have jy : j = lo.val := by
      by_contra h
      have := sorted_get _ sorted lo.val j (by omega) y gid hy hjx'
      omega
    subst jy
    exact ⟨lo_lt, hjx'⟩
  by_cases inl : lo < alloc.vec.Vec.len seen
  · have inl' : lo.val < seen.val.length := by scalar_tac
    rw [if_yes inl]
    step as ⟨ i1, i1_post ⟩
    by_cases same_gid : i1 = gid
    · rw [if_yes same_gid]
      exact (WP.spec_ok _).mpr ⟨state0, Or.inl rfl⟩
    · rw [if_no same_gid]
      have absent : gid ∉ seen.val := by
        intro hm
        obtain ⟨_, h2⟩ := present hm
        apply same_gid
        have : seen.val[lo.val]? = some i1 := by rw [i1_post]; simp [inl']
        rw [h2] at this; cases this; rfl
      exact add_gid_rest gids seen gid lo state0 small (by omega) hb ha absent
  · have absent : gid ∉ seen.val := by
      intro hm
      obtain ⟨h1, _⟩ := present hm
      apply inl; scalar_tac
    rw [if_no inl]
    exact add_gid_rest gids seen gid lo state0 small (by omega) hb ha absent

end UserCore

