-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `IdSet::size`, which adds up the lengths of the intervals, and
-- `IdSet::is_empty`.  The sum cannot overflow, because the intervals are in order and none
-- overlaps another: the sum so far is never more than where the next interval begins.
--
-- Read before this file: Spec.lean, Count.lean, Lists.lean.
import IdmapCore.Count
import IdmapCore.Lists

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- The loop of `size`: from `total` and the interval `i`, it adds the length of each interval
left, and gives the sum of all of them. -/
theorem size_adds_up_the_lengths (self : IdSet) (ordered : Ordered self.intervals.val) :
    IdSet.size_loop self 0#u64 0#usize ⦃ n => n.val = Total self.intervals.val ⦄ := by
  unfold IdSet.size_loop
  apply loop.spec_decr_nat (fun q => self.intervals.length - q.2.val)
    (fun q => q.2.val ≤ self.intervals.length ∧
      q.1.val = Total (self.intervals.val.take q.2.val) ∧
      ∀ iv ∈ self.intervals.val.drop q.2.val, q.1.val ≤ iv.1.val)
  · rintro ⟨total, i⟩ ⟨bound, is_total, below_the_rest⟩
    simp only at bound is_total below_the_rest ⊢
    unfold IdSet.size_loop.body
    dsimp only
    split
    · rename_i inside
      have same : self.intervals.length = self.intervals.val.length := rfl
      have inside : i.val < self.intervals.val.length := by
        have : i.val < self.intervals.length := by scalar_tac
        omega
      step as ⟨ s, e, is_run ⟩
      have drop_is : self.intervals.val.drop i.val =
          (s, e) :: self.intervals.val.drop (i.val + 1) := by
        rw [List.drop_eq_getElem_cons inside, ← is_run]
      have run_in : (s, e) ∈ self.intervals.val := by
        rw [is_run]
        exact List.getElem_mem _
      have run_has_ids : s.val < e.val := ordered.1 (s, e) run_in
      have total_below_start : total.val ≤ s.val :=
        below_the_rest (s, e) (by rw [drop_is]; exact List.mem_cons_self)
      step as ⟨ length, is_length ⟩
      step as ⟨ total1, is_total1 ⟩
      step as ⟨ i1, is_i1 ⟩
      refine ⟨by omega, ?_, ?_, by omega⟩
      · rw [is_i1, take_one_more self.intervals.val i.val inside, ← is_run, is_total1, is_length,
          is_total]
        simp [Total]
      · intro iv iv_in
        rw [is_i1] at iv_in
        have ordered_pairs := ordered.2
        rw [← List.take_append_drop i.val self.intervals.val, drop_is, List.pairwise_append,
          List.pairwise_cons] at ordered_pairs
        have after := ordered_pairs.2.1.1 iv iv_in
        simp only at after
        omega
    · rename_i outside
      have : i.val = self.intervals.length := by scalar_tac
      refine (WP.spec_ok _).mpr ?_
      show total.val = _
      rw [is_total, this]
      simp
  · refine ⟨by simp, by simp [Total], fun iv iv_in => ?_⟩
    simp

/-- **`size`**: for an ordered set, it returns the number of ids, exactly. -/
theorem size_is_the_number_of_ids (self : IdSet) (ordered : Ordered self.intervals.val) :
    IdSet.size self ⦃ n => ExactlyIds (HasId self.intervals.val) n.val ⦄ := by
  unfold IdSet.size
  step with size_adds_up_the_lengths self ordered as ⟨ n, is_n ⟩
  rw [is_n]
  exact ordered_runs_have_total_ids _ ordered

end IdmapCore
