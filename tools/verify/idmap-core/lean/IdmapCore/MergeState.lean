-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the loop invariant of the second half of `sort_and_merge` and how one
-- turn of the loop keeps it.  The loop goes along the sorted entries; for each one it either adds
-- it at the end of `out` or, when it continues the last entry of `out`, makes that one longer.
--
-- The invariant says: after `i` entries, `out` maps exactly what those `i` entries map; and, if the
-- sorted entries are sane and apart, so are those of `out`, where every id of an entry of `out`
-- is an id of one of the `i` entries.
--
-- Read before this file: Spec.lean, MapsFacts.lean, Lists.lean.
import IdmapCore.MapsFacts
import IdmapCore.Lists

open Aeneas Aeneas.Std velarx_idmap_core

namespace IdmapCore

/-- The state of the merge loop after `i` of the `sorted` entries. -/
def MergeState (sorted out : List Map) (i : Nat) : Prop :=
  i ≤ sorted.length ∧ out.length ≤ i ∧
  (∀ c p, Maps out c p ↔ Maps (sorted.take i) c p) ∧
  ((∀ e ∈ sorted, Sane e) → sorted.Pairwise Apart →
    (∀ e ∈ out, Sane e) ∧ out.Pairwise Apart ∧
    ∀ x ∈ out, (∀ c, InContainers x c → ∃ y ∈ sorted.take i, InContainers y c) ∧
      (∀ p, InParents x p → ∃ y ∈ sorted.take i, InParents y p))

/-- An entry of `out` is apart from the next sorted entry `m`: each of its ids is an id of an
entry before `m`, and those are apart from `m`. -/
theorem an_entry_is_apart_from_the_next (sorted : List Map) (i : Nat) (m : Map)
    (is_m : sorted[i]? = some m) (apart : sorted.Pairwise Apart) (x : Map)
    (cover_c : ∀ c, InContainers x c → ∃ y ∈ sorted.take i, InContainers y c)
    (cover_p : ∀ p, InParents x p → ∃ y ∈ sorted.take i, InParents y p) : Apart x m := by
  have inside : i < sorted.length := (List.getElem?_eq_some_iff.mp is_m).1
  have m_is : sorted[i] = m := by simpa [List.getElem?_eq_getElem inside] using is_m
  have before : ∀ y ∈ sorted.take i, Apart y m := by
    have := apart
    rw [← List.take_append_drop i sorted, List.pairwise_append] at this
    intro y y_in
    refine this.2.2 y y_in m ?_
    rw [List.drop_eq_getElem_cons inside, m_is]
    exact List.mem_cons_self
  constructor
  · intro c ⟨in_x, in_m⟩
    obtain ⟨y, y_in, in_y⟩ := cover_c c in_x
    exact (before y y_in).1 c ⟨in_y, in_m⟩
  · intro p ⟨in_x, in_m⟩
    obtain ⟨y, y_in, in_y⟩ := cover_p p in_x
    exact (before y y_in).2 p ⟨in_y, in_m⟩

/-- **A sorted entry added at the end of `out`.** -/
theorem merge_state_after_adding (sorted out : List Map) (i : Nat) (m : Map)
    (state : MergeState sorted out i) (is_m : sorted[i]? = some m) :
    MergeState sorted (out ++ [m]) (i + 1) := by
  obtain ⟨i_le, few, same_maps, rest⟩ := state
  have inside : i < sorted.length := (List.getElem?_eq_some_iff.mp is_m).1
  have take_is : sorted.take (i + 1) = sorted.take i ++ [m] := by
    rw [take_one_more sorted i inside]
    simp [List.getElem?_eq_getElem inside] at is_m
    rw [is_m]
  have m_in : m ∈ sorted := List.mem_of_getElem? is_m
  refine ⟨by omega, by simp; omega, fun c p => ?_, fun sane apart => ?_⟩
  · rw [take_is, maps_of_append, maps_of_append, same_maps]
  · obtain ⟨out_sane, out_apart, cover⟩ := rest sane apart
    refine ⟨?_, ?_, ?_⟩
    · intro e e_in
      rcases List.mem_append.mp e_in with e_in | e_in
      · exact out_sane e e_in
      · rw [List.mem_singleton.mp e_in]
        exact sane m m_in
    · rw [List.pairwise_append]
      refine ⟨out_apart, List.pairwise_singleton _ _, fun x x_in y y_in => ?_⟩
      rw [List.mem_singleton.mp y_in]
      exact an_entry_is_apart_from_the_next sorted i m is_m apart x (cover x x_in).1
        (cover x x_in).2
    · intro x x_in
      rw [take_is]
      rcases List.mem_append.mp x_in with x_in | x_in
      · exact ⟨fun c in_x => let ⟨y, y_in, in_y⟩ := (cover x x_in).1 c in_x
          ⟨y, List.mem_append_left _ y_in, in_y⟩,
          fun p in_x => let ⟨y, y_in, in_y⟩ := (cover x x_in).2 p in_x
          ⟨y, List.mem_append_left _ y_in, in_y⟩⟩
      · rw [List.mem_singleton.mp x_in]
        exact ⟨fun c in_x => ⟨m, List.mem_append_right _ (List.mem_singleton_self m), in_x⟩,
          fun p in_x => ⟨m, List.mem_append_right _ (List.mem_singleton_self m), in_x⟩⟩

/-- **A sorted entry that continues the last entry of `out` makes it longer.** -/
theorem merge_state_after_joining (sorted init : List Map) (last : Map) (i : Nat) (m joined : Map)
    (state : MergeState sorted (init ++ [last]) i) (is_m : sorted[i]? = some m)
    (continues : Continues last m joined) :
    MergeState sorted (init ++ [joined]) (i + 1) := by
  obtain ⟨i_le, few, same_maps, rest⟩ := state
  have inside : i < sorted.length := (List.getElem?_eq_some_iff.mp is_m).1
  have take_is : sorted.take (i + 1) = sorted.take i ++ [m] := by
    rw [take_one_more sorted i inside]
    simp [List.getElem?_eq_getElem inside] at is_m
    rw [is_m]
  have m_in : m ∈ sorted := List.mem_of_getElem? is_m
  refine ⟨by omega, by simp at few ⊢; omega, fun c p => ?_, fun sane apart => ?_⟩
  · rw [take_is, maps_of_append, maps_of_append, maps_of_joined_entries last m joined continues,
      ← same_maps, maps_of_append]
    tauto
  · obtain ⟨out_sane, out_apart, cover⟩ := rest sane apart
    have last_in : last ∈ init ++ [last] := List.mem_append_right _ (List.mem_singleton_self _)
    have last_sane := out_sane last last_in
    have m_sane := sane m m_in
    obtain ⟨c_end, p_end, same_c, same_p, size⟩ := continues
    have continues : Continues last m joined := ⟨c_end, p_end, same_c, same_p, size⟩
    refine ⟨?_, ?_, ?_⟩
    · intro e e_in
      rcases List.mem_append.mp e_in with e_in | e_in
      · exact out_sane e (List.mem_append_left _ e_in)
      · rw [List.mem_singleton.mp e_in]
        unfold Sane at *
        omega
    · rw [List.pairwise_append]
      refine ⟨(List.pairwise_append.mp out_apart).1, List.pairwise_singleton _ _,
        fun x x_in y y_in => ?_⟩
      rw [List.mem_singleton.mp y_in]
      have x_in_out : x ∈ init ++ [last] := List.mem_append_left _ x_in
      have apart_last : Apart x last :=
        (List.pairwise_append.mp out_apart).2.2 x x_in last (List.mem_singleton_self _)
      have apart_m := an_entry_is_apart_from_the_next sorted i m is_m apart x
        (cover x x_in_out).1 (cover x x_in_out).2
      constructor
      · intro c ⟨in_x, in_joined⟩
        rcases (containers_of_joined_entries last m joined continues c).mp in_joined with h | h
        · exact apart_last.1 c ⟨in_x, h⟩
        · exact apart_m.1 c ⟨in_x, h⟩
      · intro p ⟨in_x, in_joined⟩
        rcases (parents_of_joined_entries last m joined continues p).mp in_joined with h | h
        · exact apart_last.2 p ⟨in_x, h⟩
        · exact apart_m.2 p ⟨in_x, h⟩
    · intro x x_in
      rw [take_is]
      rcases List.mem_append.mp x_in with x_in | x_in
      · have x_in_out : x ∈ init ++ [last] := List.mem_append_left _ x_in
        exact ⟨fun c in_x => let ⟨y, y_in, in_y⟩ := (cover x x_in_out).1 c in_x
            ⟨y, List.mem_append_left _ y_in, in_y⟩,
          fun p in_x => let ⟨y, y_in, in_y⟩ := (cover x x_in_out).2 p in_x
            ⟨y, List.mem_append_left _ y_in, in_y⟩⟩
      · rw [List.mem_singleton.mp x_in]
        have m_mem : m ∈ sorted.take i ++ [m] := List.mem_append_right _ (List.mem_singleton_self m)
        refine ⟨fun c in_joined => ?_, fun p in_joined => ?_⟩
        · rcases (containers_of_joined_entries last m joined continues c).mp in_joined with h | h
          · obtain ⟨y, y_in, in_y⟩ := (cover last last_in).1 c h
            exact ⟨y, List.mem_append_left _ y_in, in_y⟩
          · exact ⟨m, m_mem, h⟩
        · rcases (parents_of_joined_entries last m joined continues p).mp in_joined with h | h
          · obtain ⟨y, y_in, in_y⟩ := (cover last last_in).2 p h
            exact ⟨y, List.mem_append_left _ y_in, in_y⟩
          · exact ⟨m, m_mem, h⟩

end IdmapCore
