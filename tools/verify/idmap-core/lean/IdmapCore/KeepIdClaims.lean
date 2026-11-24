-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what follows from the shape of what `keep_id` returns (KeepId.lean): the
-- pairs it maps are exactly those of the layout, it uses only the parent ids 0 to `sub`, and,
-- for ids that are not too large, it is a valid mapping.
--
-- Read before this file: Spec.lean (`Maps`, `KeepIdLayout`, `Valid`), KeepId.lean.
import IdmapCore.KeepId

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- A list of two lists maps a pair when one of the two maps it. -/
theorem maps_of_append (first second : List Map) (c p : Nat) :
    Maps (first ++ second) c p ↔ Maps first c p ∨ Maps second c p := by
  simp only [Maps, List.mem_append]
  constructor
  · rintro ⟨e, in_first | in_second, has, is_p⟩
    · exact Or.inl ⟨e, in_first, has, is_p⟩
    · exact Or.inr ⟨e, in_second, has, is_p⟩
  · rintro (⟨e, in_first, has, is_p⟩ | ⟨e, in_second, has, is_p⟩)
    · exact ⟨e, Or.inl in_first, has, is_p⟩
    · exact ⟨e, Or.inr in_second, has, is_p⟩

/-- A list of one entry maps the pairs of the entry. -/
theorem maps_of_one_entry (e : Map) (c p : Nat) :
    Maps [e] c p ↔ (InContainers e c ∧ p = e.parent_id.val + (c - e.container_id.val)) := by
  simp [Maps]

/-- A list of at most one entry is empty, or has one entry. -/
theorem at_most_one_entry (l : List Map) (short : l.length ≤ 1) : l = [] ∨ ∃ a, l = [a] := by
  match l with
  | [] => exact Or.inl rfl
  | [a] => exact Or.inr ⟨a, rfl⟩
  | _ :: _ :: _ => simp at short

/-- **`keep_id` maps exactly the layout**: the pairs of `KeepIdLayout`, and no other. -/
theorem keep_id_maps_the_layout (id sub : U32) (size : Option U32) :
    keep_id id sub size ⦃ out => ∀ c p, Maps out.val c p ↔ KeepIdLayout id sub size c p ⦄ := by
  step with keep_id_returns_the_pieces id sub size as ⟨ out, shaped ⟩
  obtain ⟨below, above, is_out, below_facts, below_iff, below_short, above_facts, above_iff,
    above_short⟩ := shaped
  rename_i c p
  rw [is_out, maps_of_append, maps_of_append]
  unfold KeepIdLayout
  have user_maps : Maps [(⟨id, 0#u32, 1#u32⟩ : Map)] c p ↔ (c = id.val ∧ p = 0) := by
    rw [maps_of_one_entry]
    simp only [InContainers]
    simp
    omega
  have below_maps : Maps below c p ↔
      (0 < sub.val ∧ c < id.val ∧ c < KeepIdTop sub size ∧ p = c + 1) := by
    rcases at_most_one_entry below below_short with empty | ⟨a, is_a⟩
    · subst empty
      have no_sub_ids : ¬ (0 < sub.val ∧ id.val ≠ 0 ∧ 0 < min (KeepIdTop sub size) id.val) :=
        fun h => below_iff.mpr h rfl
      simp only [Maps, List.not_mem_nil]
      simp
      omega
    · subst is_a
      have facts := below_facts a (by simp)
      have exists_sub_ids := below_iff.mp (by simp)
      rw [maps_of_one_entry]
      simp only [InContainers]
      omega
  have above_maps : Maps above c p ↔ (id.val < c ∧ c ≤ KeepIdTop sub size ∧ p = c) := by
    rcases at_most_one_entry above above_short with empty | ⟨a, is_a⟩
    · subst empty
      have no_above : ¬ id.val < KeepIdTop sub size := fun h => above_iff.mpr h rfl
      simp only [Maps, List.not_mem_nil]
      simp
      omega
    · subst is_a
      have facts := above_facts a (by simp)
      have above_exist := above_iff.mp (by simp)
      rw [maps_of_one_entry]
      simp only [InContainers]
      omega
  rw [below_maps, user_maps, above_maps]
  constructor
  · rintro ((in_below | in_user) | in_above)
    · exact Or.inr (Or.inl in_below)
    · exact Or.inl in_user
    · exact Or.inr (Or.inr in_above)
  · rintro (in_user | in_below | in_above)
    · exact Or.inl (Or.inr in_user)
    · exact Or.inl (Or.inl in_below)
    · exact Or.inr in_above

/-- The top of the sub ids is at most `sub`. -/
theorem the_top_is_at_most_sub (sub : U32) (size : Option U32) : KeepIdTop sub size ≤ sub.val := by
  unfold KeepIdTop
  cases size with
  | none => simp
  | some s =>
    simp only []
    split <;> omega

/-- **`keep_id` uses only the parent ids 0 to `sub`**: 0 for the user, 1 to `sub` for the others. -/
theorem keep_id_uses_only_the_sub_ids (id sub : U32) (size : Option U32) :
    keep_id id sub size ⦃ out => ∀ c p, Maps out.val c p → p ≤ sub.val ⦄ := by
  step with keep_id_maps_the_layout id sub size as ⟨ out, maps_the_layout ⟩
  rename_i c p maps
  have := the_top_is_at_most_sub sub size
  have layout := (maps_the_layout c p).mp maps
  unfold KeepIdLayout at layout
  omega

/-- Two entries whose container ids, and whose parent ids, are one range before the other are
apart. -/
theorem entries_in_two_runs_are_apart (a b : Map)
    (containers : a.container_id.val + a.size.val ≤ b.container_id.val ∨
      b.container_id.val + b.size.val ≤ a.container_id.val)
    (parents : a.parent_id.val + a.size.val ≤ b.parent_id.val ∨
      b.parent_id.val + b.size.val ≤ a.parent_id.val) : Apart a b := by
  unfold Apart InContainers InParents
  constructor
  · rintro c ⟨⟨a_start, a_end⟩, ⟨b_start, b_end⟩⟩
    omega
  · rintro p ⟨⟨a_start, a_end⟩, ⟨b_start, b_end⟩⟩
    omega

/-- **`keep_id` is valid**, when the user's id and the number of sub ids are below the limit
(`sub = u32::MAX` would map the container id `u32::MAX`, which is past it).  The answer has at
most three entries, each of them is sane, and no two share a container id or a parent id. -/
theorem keep_id_is_valid (id sub : U32) (size : Option U32) (id_below : id.val < IdLimit)
    (sub_below : sub.val < IdLimit) :
    keep_id id sub size ⦃ out => Valid out.val ⦄ := by
  step with keep_id_returns_the_pieces id sub size as ⟨ out, shaped ⟩
  obtain ⟨below, above, is_out, below_facts, below_iff, below_short, above_facts, above_iff,
    above_short⟩ := shaped
  have top_le := the_top_is_at_most_sub sub size
  unfold IdLimit at id_below sub_below
  have user_has_ids : Sane ⟨id, 0#u32, 1#u32⟩ := by
    unfold Sane
    simp [IdLimit]
    omega
  have below_sane : ∀ a ∈ below, Sane a := by
    intro a a_in
    have facts := below_facts a a_in
    unfold Sane
    unfold IdLimit
    omega
  have above_sane : ∀ a ∈ above, Sane a := by
    intro a a_in
    have facts := above_facts a a_in
    have not_empty : above ≠ [] := List.ne_nil_of_mem a_in
    have := above_iff.mp not_empty
    unfold Sane
    unfold IdLimit
    omega
  have below_before_user : ∀ a ∈ below, Apart a ⟨id, 0#u32, 1#u32⟩ := by
    intro a a_in
    have facts := below_facts a a_in
    apply entries_in_two_runs_are_apart
    · left; simp; omega
    · right; simp; omega
  have user_before_above : ∀ a ∈ above, Apart ⟨id, 0#u32, 1#u32⟩ a := by
    intro a a_in
    have facts := above_facts a a_in
    apply entries_in_two_runs_are_apart
    · left; simp; omega
    · left; simp; omega
  have below_before_above : ∀ a ∈ below, ∀ b ∈ above, Apart a b := by
    intro a a_in b b_in
    have facts := below_facts a a_in
    have facts' := above_facts b b_in
    apply entries_in_two_runs_are_apart
    · left; omega
    · left; omega
  refine ⟨?_, ?_, ?_⟩
  · rw [is_out]
    simp
    unfold ExtentLimit
    omega
  · intro e e_in
    rw [is_out] at e_in
    simp only [List.mem_append, List.mem_singleton] at e_in
    rcases e_in with (e_in | rfl) | e_in
    · exact below_sane e e_in
    · exact user_has_ids
    · exact above_sane e e_in
  · rw [is_out, List.pairwise_append, List.pairwise_append]
    refine ⟨⟨?_, List.pairwise_singleton _ _, ?_⟩, ?_, ?_⟩
    · rcases at_most_one_entry below below_short with empty | ⟨a, is_a⟩ <;> simp [*]
    · intro a a_in y y_in
      rw [List.mem_singleton.mp y_in]
      exact below_before_user a a_in
    · rcases at_most_one_entry above above_short with empty | ⟨a, is_a⟩ <;> simp [*]
    · intro a a_in y y_in
      rcases List.mem_append.mp a_in with a_in | a_in
      · exact below_before_above a a_in y y_in
      · rw [List.mem_singleton.mp a_in]
        exact user_before_above y y_in

end IdmapCore
