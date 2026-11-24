-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `IdSet::is_empty` (no interval, so no id) and `IdSet::contains_range`
-- (looks for one interval that has the whole range).  Because the intervals of an ordered set do
-- not touch, a range of ids all in the set is all in one interval: an id just past the end of an
-- interval is not in the set.
--
-- Read before this file: Spec.lean, Lists.lean.
import IdmapCore.Spec
import IdmapCore.Lists

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- **`is_empty`**: true exactly when there is no interval, and for an ordered set that is when
no id is in it. -/
theorem is_empty_is_true_for_the_empty_set (s : IdSet) (ordered : Ordered s.intervals.val) :
    IdSet.is_empty s ⦃ answer => answer = true ↔ ∀ id, ¬ HasId s.intervals.val id ⦄ := by
  unfold IdSet.is_empty
  step as ⟨ b, is_b ⟩
  have same_length : s.intervals.length = s.intervals.val.length := rfl
  rw [is_b]
  constructor
  · intro empty id ⟨iv, iv_in, _⟩
    have : s.intervals.val = [] := List.length_eq_zero_iff.mp (by omega)
    simp [this] at iv_in
  · intro none_has
    by_contra not_empty
    have inside : 0 < s.intervals.val.length := by omega
    have has_ids := ordered.1 s.intervals.val[0] (List.getElem_mem inside)
    exact none_has s.intervals.val[0].1.val
      ⟨_, List.getElem_mem inside, by simp only [InRun]; omega⟩

/-- A range of ids all in an ordered set is in one interval of it: the interval that has its first
id has all the others, since the id just past the end of an interval is not in the set. -/
theorem a_range_in_an_ordered_set_is_in_one_interval (runs : List (U64 × U64))
    (ordered : Ordered runs) (start len : Nat) (more : 0 < len)
    (all_in : ∀ k, k < len → HasId runs (start + k)) :
    ∃ iv ∈ runs, iv.1.val ≤ start ∧ start + len ≤ iv.2.val := by
  obtain ⟨iv, iv_in, in_run⟩ := all_in 0 more
  simp only [InRun, Nat.add_zero] at in_run
  refine ⟨iv, iv_in, in_run.1, ?_⟩
  by_contra too_long
  have end_in := all_in (iv.2.val - start) (by omega)
  obtain ⟨other, other_in, other_run⟩ := end_in
  simp only [InRun] at other_run
  have has_ids := ordered.1 iv iv_in
  have other_has_ids := ordered.1 other other_in
  by_cases same : other = iv
  · subst same
    omega
  · have apart := List.pairwise_iff_getElem.mp ordered.2
    obtain ⟨i, i_lt, is_i⟩ := List.getElem_of_mem iv_in
    obtain ⟨j, j_lt, is_j⟩ := List.getElem_of_mem other_in
    have ne : i ≠ j := fun h => same (by subst h; rw [← is_i, ← is_j])
    rcases Nat.lt_or_gt_of_ne ne with lt | gt
    · have := apart i j i_lt j_lt lt
      rw [is_i, is_j] at this
      omega
    · have := apart j i j_lt i_lt gt
      rw [is_i, is_j] at this
      omega

/-- The loop of `contains_range`: it looks at the intervals one by one for one that has the whole
range, and stops at the first it finds. -/
theorem contains_range_looks_for_one_interval (s : IdSet) (start len : U64) :
    IdSet.contains_range_loop s start len (decide (len = 0#u64)) 0#usize ⦃ answer =>
      answer = true ↔ (len.val = 0 ∨ ∃ iv ∈ s.intervals.val,
        iv.1.val ≤ start.val ∧ start.val + len.val ≤ iv.2.val) ⦄ := by
  unfold IdSet.contains_range_loop
  apply loop.spec_decr_nat (fun q => s.intervals.val.length - q.2.val)
    (fun q => q.2.val ≤ s.intervals.val.length ∧
      (q.1 = true ↔ (len.val = 0 ∨ ∃ iv ∈ s.intervals.val.take q.2.val,
        iv.1.val ≤ start.val ∧ start.val + len.val ≤ iv.2.val)))
  · rintro ⟨found, i⟩ ⟨bound, seen⟩
    simp only at bound seen ⊢
    unfold IdSet.contains_range_loop.body
    have same_length : s.intervals.length = s.intervals.val.length := rfl
    have done_when_found : found = true → (found = true ↔ (len.val = 0 ∨ ∃ iv ∈ s.intervals.val,
        iv.1.val ≤ start.val ∧ start.val + len.val ≤ iv.2.val)) := by
      intro found_true
      refine ⟨fun _ => ?_, fun _ => found_true⟩
      rcases seen.mp found_true with zero | ⟨iv, iv_in, cond⟩
      · exact Or.inl zero
      · exact Or.inr ⟨iv, List.mem_of_mem_take iv_in, cond⟩
    split
    · rename_i found_true
      dsimp only
      split <;> exact (WP.spec_ok _).mpr (done_when_found found_true)
    · rename_i not_found
      have not_found : found = false := by simpa using not_found
      have nothing_before : ¬ (len.val = 0 ∨ ∃ iv ∈ s.intervals.val.take i.val,
          iv.1.val ≤ start.val ∧ start.val + len.val ≤ iv.2.val) := by
        rw [← seen, not_found]
        simp
      dsimp only
      split
      · rename_i inside
        have inside : i.val < s.intervals.val.length := by
          have := (UScalar.lt_equiv i s.intervals.len).mp inside
          have : s.intervals.len.val = s.intervals.val.length := rfl
          omega
        step as ⟨ s0, e0, is_run ⟩
        have take_is : s.intervals.val.take (i.val + 1) =
            s.intervals.val.take i.val ++ [s.intervals.val[i.val]] :=
          take_one_more s.intervals.val i.val inside
        refine WP.spec_bind (Pₘ := fun found1 : Bool =>
          found1 = true ↔ (s0.val ≤ start.val ∧ start.val + len.val ≤ e0.val)) ?_ ?_
        · split
          · rename_i starts_before
            have starts_before := (UScalar.le_equiv s0 start).mp starts_before
            split
            · rename_i inside_run
              have inside_run := (UScalar.le_equiv start e0).mp inside_run
              step as ⟨ room, is_room ⟩
              have := (UScalar.le_equiv len room)
              simp only [decide_eq_true_eq, this]
              omega
            · rename_i past
              have past := (UScalar.le_equiv start e0).not.mp past
              refine (WP.spec_ok _).mpr ?_
              simp
              omega
          · rename_i starts_after
            have starts_after := (UScalar.le_equiv s0 start).not.mp starts_after
            refine (WP.spec_ok _).mpr ?_
            simp
            omega
        · intro found1 is_found1
          step as ⟨ i2, is_i2 ⟩
          refine ⟨by omega, ?_, by omega⟩
          rw [is_i2, take_is]
          simp only [List.mem_append, List.mem_singleton]
          rw [is_found1]
          have : (s0, e0) = s.intervals.val[i.val] := is_run
          constructor
          · intro cond
            right
            refine ⟨_, Or.inr rfl, ?_⟩
            rw [← this]
            exact cond
          · rintro (zero | ⟨iv, in_before | is_iv, cond⟩)
            · exact absurd (Or.inl zero) nothing_before
            · exact absurd (Or.inr ⟨iv, in_before, cond⟩) nothing_before
            · rw [is_iv, ← this] at cond
              exact cond
      · rename_i outside
        have : i.val = s.intervals.val.length := by
          have := (UScalar.lt_equiv i s.intervals.len).not.mp outside
          have : s.intervals.len.val = s.intervals.val.length := rfl
          omega
        refine (WP.spec_ok _).mpr ?_
        rw [not_found, this] at seen ⊢
        simpa using seen
  · refine ⟨by simp, ?_⟩
    by_cases zero : len = 0#u64
    · simp [zero]
    · have : len.val ≠ 0 := fun h => zero (UScalar.eq_of_val_eq h)
      simp [zero, this]

/-- **`contains_range`**: for an ordered set it answers `true` exactly when every id of the range
is in the set. -/
theorem contains_range_is_true_for_a_range_in_the_set (s : IdSet)
    (start len : U64) (ordered : Ordered s.intervals.val) :
    IdSet.contains_range s start len ⦃ answer =>
      answer = true ↔ ∀ k, k < len.val → HasId s.intervals.val (start.val + k) ⦄ := by
  unfold IdSet.contains_range
  step with contains_range_looks_for_one_interval s start len as ⟨ answer, is_answer ⟩
  rw [is_answer]
  constructor
  · rintro (zero | ⟨iv, iv_in, from_start, to_end⟩) k below
    · omega
    · exact ⟨iv, iv_in, by simp only [InRun]; omega⟩
  · intro all_in
    by_cases zero : len.val = 0
    · exact Or.inl zero
    · exact Or.inr (a_range_in_an_ordered_set_is_in_one_interval s.intervals.val ordered
        start.val len.val (by omega) all_in)

end IdmapCore
