-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `IdSet::below`, the ids of a set that are less than a limit: it keeps each
-- interval that begins below the limit, and cuts it at the limit.
--
-- Read before this file: Spec.lean, HasIdFacts.lean, Lists.lean.
import IdmapCore.Spec
import IdmapCore.HasIdFacts
import IdmapCore.Lists

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- The loop of `below`: from the interval `i` on, it adds to `out` the part of each interval
that is below `limit`. -/
theorem below_keeps_the_ids_under_the_limit (self : IdSet) (limit : U64)
    (ordered : Ordered self.intervals.val) :
    IdSet.below_loop self limit (alloc.vec.Vec.new (U64 × U64)) 0#usize ⦃ out =>
      Ordered out.val ∧
      (∀ id, HasId out.val id ↔ (HasId self.intervals.val id ∧ id < limit.val)) ∧
      out.val.length ≤ self.intervals.val.length ⦄ := by
  unfold IdSet.below_loop
  apply loop.spec_decr_nat (fun q => self.intervals.val.length - q.2.val)
    (fun q => q.2.val ≤ self.intervals.val.length ∧ q.1.val.length ≤ q.2.val ∧ Ordered q.1.val ∧
      (∀ a ∈ q.1.val, ∀ later ∈ self.intervals.val.drop q.2.val, a.2.val < later.1.val) ∧
      ∀ id, HasId q.1.val id ↔ (HasId (self.intervals.val.take q.2.val) id ∧ id < limit.val))
  · rintro ⟨out, i⟩ ⟨bound, few, out_ordered, before_later, covers⟩
    simp only at bound few out_ordered before_later covers ⊢
    unfold IdSet.below_loop.body
    dsimp only
    split
    · rename_i more
      have same_length : self.intervals.length = self.intervals.val.length := rfl
      have more : i.val < self.intervals.val.length := by
        have : i.val < self.intervals.length := by scalar_tac
        omega
      have limit_is_big : self.intervals.val.length ≤ Usize.max := self.intervals.property
      step as ⟨ s, e, is_run ⟩
      have drop_is : self.intervals.val.drop i.val =
          (s, e) :: self.intervals.val.drop (i.val + 1) := by
        rw [List.drop_eq_getElem_cons more, ← is_run]
      have take_is : self.intervals.val.take (i.val + 1) =
          self.intervals.val.take i.val ++ [(s, e)] := by
        rw [take_one_more self.intervals.val i.val more, ← is_run]
      have run_in : (s, e) ∈ self.intervals.val := by
        rw [is_run]
        exact List.getElem_mem _
      have run_has_ids : s.val < e.val := ordered.1 (s, e) run_in
      have after_run : ∀ later ∈ self.intervals.val.drop (i.val + 1), e.val < later.1.val := by
        have := ordered.2
        rw [← List.take_append_drop i.val self.intervals.val, drop_is, List.pairwise_append,
          List.pairwise_cons] at this
        exact this.2.1.1
      have before_later_after : ∀ a ∈ out.val, ∀ later ∈ self.intervals.val.drop (i.val + 1),
          a.2.val < later.1.val := fun a a_in later later_in =>
        before_later a a_in later (by rw [drop_is]; exact List.mem_cons_of_mem _ later_in)
      have before_run : ∀ a ∈ out.val, a.2.val < s.val := fun a a_in =>
        before_later a a_in (s, e) (by rw [drop_is]; exact List.mem_cons_self)
      have room : out.val.length < Usize.max := by omega
      -- the part of the interval below the limit is written, if there is one
      refine WP.spec_bind (Pₘ := fun out1 =>
        out1.val.length ≤ i.val + 1 ∧ Ordered out1.val ∧
        (∀ a ∈ out1.val, ∀ later ∈ self.intervals.val.drop (i.val + 1), a.2.val < later.1.val) ∧
        ∀ id, HasId out1.val id ↔
          (HasId (self.intervals.val.take (i.val + 1)) id ∧ id < limit.val)) ?_ ?_
      · split
        · rename_i starts_below
          have starts_below : s.val < limit.val := by
            have := (UScalar.lt_equiv s limit).mp starts_below
            omega
          split
          · rename_i ends_below
            have ends_below : e.val < limit.val := by
              have := (UScalar.lt_equiv e limit).mp ends_below
              omega
            step as ⟨ out1, is_out1 ⟩
            refine ⟨by simp [is_out1]; omega, ⟨?_, ?_⟩, ?_, fun id => ?_⟩
            · intro iv iv_in
              rw [is_out1] at iv_in
              rcases List.mem_append.mp iv_in with iv_in | iv_in
              · exact out_ordered.1 iv iv_in
              · rw [List.mem_singleton.mp iv_in]
                exact run_has_ids
            · rw [is_out1, List.pairwise_append]
              exact ⟨out_ordered.2, List.pairwise_singleton _ _, fun a a_in y y_in => by
                rw [List.mem_singleton.mp y_in]
                exact before_run a a_in⟩
            · intro iv iv_in later later_in
              rw [is_out1] at iv_in
              rcases List.mem_append.mp iv_in with iv_in | iv_in
              · exact before_later_after iv iv_in later later_in
              · rw [List.mem_singleton.mp iv_in]
                exact after_run later later_in
            · rw [is_out1, take_is, has_id_after_adding, has_id_after_adding, covers id]
              simp only [InRun]
              constructor
              · rintro (⟨has, below⟩ | in_run)
                · exact ⟨Or.inl has, below⟩
                · exact ⟨Or.inr in_run, by omega⟩
              · rintro ⟨has | in_run, below⟩
                · exact Or.inl ⟨has, below⟩
                · exact Or.inr (by omega)
          · rename_i ends_above
            have ends_above : limit.val ≤ e.val := by
              have := (UScalar.lt_equiv e limit).not.mp ends_above
              omega
            step as ⟨ out1, is_out1 ⟩
            refine ⟨by simp [is_out1]; omega, ⟨?_, ?_⟩, ?_, fun id => ?_⟩
            · intro iv iv_in
              rw [is_out1] at iv_in
              rcases List.mem_append.mp iv_in with iv_in | iv_in
              · exact out_ordered.1 iv iv_in
              · rw [List.mem_singleton.mp iv_in]
                exact starts_below
            · rw [is_out1, List.pairwise_append]
              exact ⟨out_ordered.2, List.pairwise_singleton _ _, fun a a_in y y_in => by
                rw [List.mem_singleton.mp y_in]
                exact before_run a a_in⟩
            · intro iv iv_in later later_in
              rw [is_out1] at iv_in
              rcases List.mem_append.mp iv_in with iv_in | iv_in
              · exact before_later_after iv iv_in later later_in
              · rw [List.mem_singleton.mp iv_in]
                have := after_run later later_in
                simp only
                omega
            · rw [is_out1, take_is, has_id_after_adding, has_id_after_adding, covers id]
              simp only [InRun]
              constructor
              · rintro (⟨has, below⟩ | in_run)
                · exact ⟨Or.inl has, below⟩
                · exact ⟨Or.inr in_run.1 |>.imp_right (fun _ => by omega), by omega⟩
              · rintro ⟨has | in_run, below⟩
                · exact Or.inl ⟨has, below⟩
                · exact Or.inr (by omega)
        · rename_i starts_above
          have starts_above : limit.val ≤ s.val := by
            have := (UScalar.lt_equiv s limit).not.mp starts_above
            omega
          refine (WP.spec_ok _).mpr ⟨by omega, out_ordered, before_later_after, fun id => ?_⟩
          rw [take_is, has_id_after_adding, covers id]
          simp only [InRun]
          constructor
          · rintro ⟨has, below⟩
            exact ⟨Or.inl has, below⟩
          · rintro ⟨has | in_run, below⟩
            · exact ⟨has, below⟩
            · exact absurd below (by omega)
      · intro out1 ⟨few1, ordered1, before1, covers1⟩
        step as ⟨ i2, is_i2 ⟩
        refine ⟨by omega, by omega, ordered1, ?_, ?_, by omega⟩
        · rw [is_i2]
          exact before1
        · rw [is_i2]
          exact covers1
    · rename_i outside
      have same_length : self.intervals.length = self.intervals.val.length := rfl
      have : i.val = self.intervals.val.length := by scalar_tac
      refine (WP.spec_ok _).mpr ⟨out_ordered, fun id => ?_, by omega⟩
      rw [covers id, this]
      simp
  · exact ⟨by simp, by simp [alloc.vec.Vec.new],
      ⟨by simp [alloc.vec.Vec.new], by simp [alloc.vec.Vec.new]⟩,
      by simp [alloc.vec.Vec.new], fun id => by simp [alloc.vec.Vec.new, HasId]⟩

/-- **`below`**: for an ordered set, it returns an ordered set that has the ids of the set that
are less than the limit, and no other, in no more intervals than the set has. -/
theorem below_is_the_ids_under_the_limit (self : IdSet) (limit : U64)
    (ordered : Ordered self.intervals.val) :
    IdSet.below self limit ⦃ s =>
      Ordered s.intervals.val ∧
      (∀ id, HasId s.intervals.val id ↔ (HasId self.intervals.val id ∧ id < limit.val)) ∧
      s.intervals.val.length ≤ self.intervals.val.length ⦄ := by
  unfold IdSet.below
  step with below_keeps_the_ids_under_the_limit self limit ordered as
    ⟨ out, out_ordered, covers, few ⟩
  exact ⟨out_ordered, covers, few⟩

end IdmapCore
