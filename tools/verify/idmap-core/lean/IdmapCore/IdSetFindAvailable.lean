-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `IdSet::find_available`, the first `n` ids of a set (from several
-- intervals if needed), or nothing if the set has fewer.  It takes whole intervals while `n` is
-- not reached, and cuts the last one.
--
-- Read before this file: Spec.lean, Count.lean, HasIdFacts.lean, Lists.lean.
import IdmapCore.Count
import IdmapCore.HasIdFacts
import IdmapCore.Lists

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- The first interval of the set (if it has one) has at least `n` ids. -/
def FirstIntervalHolds (self : IdSet) (n : U64) : Prop :=
  ∀ iv, self.intervals.val[0]? = some iv → n.val ≤ iv.2.val - iv.1.val

/-- The loop of `find_available`: it takes intervals while ids are `left` to find.  When the first
interval has `n` ids, it takes that one only. -/
theorem find_available_takes_intervals_until_n (self : IdSet) (n : U64)
    (ordered : Ordered self.intervals.val) :
    IdSet.find_available_loop self n (alloc.vec.Vec.new (U64 × U64)) 0#usize ⦃ r =>
      Ordered r.2.val ∧ (∀ id, HasId r.2.val id → HasId self.intervals.val id) ∧
      Total r.2.val + r.1.val = n.val ∧
      (0 < r.1.val → Total self.intervals.val = Total r.2.val) ∧
      (FirstIntervalHolds self n → r.2.val.length ≤ 1) ⦄ := by
  unfold IdSet.find_available_loop
  apply loop.spec_decr_nat (fun q => self.intervals.val.length - q.2.2.val)
    (fun q => q.2.2.val ≤ self.intervals.val.length ∧ q.2.1.val.length ≤ q.2.2.val ∧
      Ordered q.2.1.val ∧ (∀ id, HasId q.2.1.val id → HasId self.intervals.val id) ∧
      (∀ a ∈ q.2.1.val, ∀ later ∈ self.intervals.val.drop q.2.2.val, a.2.val < later.1.val) ∧
      Total q.2.1.val + q.1.val = n.val ∧
      (0 < q.1.val → q.2.1.val = self.intervals.val.take q.2.2.val) ∧
      q.2.2.val = q.2.1.val.length ∧
      (FirstIntervalHolds self n → q.2.1.val.length ≤ 1 ∧
        (q.2.1.val.length = 0 → q.1.val = n.val) ∧ (q.2.1.val.length = 1 → q.1.val = 0)))
  · rintro ⟨left, out, i⟩ ⟨bound, few, out_ordered, from_self, before_later, total_is, all_taken,
      one_each, shape⟩
    simp only at bound few out_ordered from_self before_later total_is all_taken one_each shape ⊢
    unfold IdSet.find_available_loop.body
    dsimp only
    have same_length : self.intervals.length = self.intervals.val.length := rfl
    have intervals_fit : self.intervals.val.length ≤ Usize.max := self.intervals.property
    split
    · rename_i more
      have more : i.val < self.intervals.val.length := by
        have : i.val < self.intervals.length := by scalar_tac
        omega
      split
      · rename_i wanted
        have wanted : 0 < left.val := by
          have := (UScalar.lt_equiv 0#u64 left).mp wanted
          simpa using this
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
        have before_run : ∀ a ∈ out.val, a.2.val < s.val := fun a a_in =>
          before_later a a_in (s, e) (by rw [drop_is]; exact List.mem_cons_self)
        have before_later_after : ∀ a ∈ out.val, ∀ later ∈ self.intervals.val.drop (i.val + 1),
            a.2.val < later.1.val := fun a a_in later later_in =>
          before_later a a_in later (by rw [drop_is]; exact List.mem_cons_of_mem _ later_in)
        have out_is := all_taken wanted
        -- when the first interval has `n` ids, this is the first turn and it has them all
        have first_turn : FirstIntervalHolds self n → i.val = 0 ∧ left.val = n.val := by
          intro first
          obtain ⟨_, nothing_yet, one_yet⟩ := shape first
          have none_yet : out.val.length = 0 := by
            by_contra not_none
            have := one_yet (by omega)
            omega
          exact ⟨by omega, nothing_yet none_yet⟩
        have first_big : FirstIntervalHolds self n → n.val ≤ e.val - s.val := by
          intro first
          obtain ⟨at_start, _⟩ := first_turn first
          refine first (s, e) ?_
          have : self.intervals.val = (s, e) :: self.intervals.val.drop 1 := by
            simpa [at_start] using drop_is
          rw [this]
          rfl
        have room : out.val.length < Usize.max := by omega
        step as ⟨ length, is_length ⟩
        refine WP.spec_bind (Pₘ := fun r : U64 × alloc.vec.Vec (U64 × U64) =>
          r.2.val.length = i.val + 1 ∧ Ordered r.2.val ∧
          (∀ id, HasId r.2.val id → HasId self.intervals.val id) ∧
          (∀ a ∈ r.2.val, ∀ later ∈ self.intervals.val.drop (i.val + 1),
            a.2.val < later.1.val) ∧
          Total r.2.val + r.1.val = n.val ∧
          (0 < r.1.val → r.2.val = self.intervals.val.take (i.val + 1)) ∧
          (FirstIntervalHolds self n → i.val = 0 ∧ r.1.val = 0)) ?_ ?_
        · split
          · -- the whole interval is taken
            rename_i whole
            have whole : length.val ≤ left.val := by
              have := (UScalar.le_equiv length left).mp whole
              omega
            step as ⟨ out1, is_out1 ⟩
            step as ⟨ left2, is_left2 ⟩
            refine ⟨by simp [is_out1]; omega, ⟨?_, ?_⟩, ?_, ?_, ?_, ?_, ?_⟩
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
            · intro id has
              rw [is_out1, has_id_after_adding] at has
              rcases has with has | in_run
              · exact from_self id has
              · exact ⟨(s, e), run_in, in_run⟩
            · intro a a_in later later_in
              rw [is_out1] at a_in
              rcases List.mem_append.mp a_in with a_in | a_in
              · exact before_later_after a a_in later later_in
              · rw [List.mem_singleton.mp a_in]
                exact after_run later later_in
            · rw [is_out1]
              simp only [Total, List.map_append, List.sum_append, List.map_cons, List.map_nil,
                List.sum_cons, List.sum_nil]
              unfold Total at total_is
              omega
            · intro _
              rw [is_out1, take_is, out_is]
            · intro first
              have := first_big first
              have := (first_turn first).2
              exact ⟨(first_turn first).1, by omega⟩
          · -- the last interval is cut
            rename_i cut
            have cut : left.val < length.val := by
              have := (UScalar.le_equiv length left).not.mp cut
              omega
            step as ⟨ cut_end, is_cut_end ⟩
            step as ⟨ out1, is_out1 ⟩
            refine ⟨by simp [is_out1]; omega, ⟨?_, ?_⟩, ?_, ?_, ?_, ?_, ?_⟩
            · intro iv iv_in
              rw [is_out1] at iv_in
              rcases List.mem_append.mp iv_in with iv_in | iv_in
              · exact out_ordered.1 iv iv_in
              · rw [List.mem_singleton.mp iv_in]
                simp only
                omega
            · rw [is_out1, List.pairwise_append]
              exact ⟨out_ordered.2, List.pairwise_singleton _ _, fun a a_in y y_in => by
                rw [List.mem_singleton.mp y_in]
                exact before_run a a_in⟩
            · intro id has
              rw [is_out1, has_id_after_adding] at has
              rcases has with has | in_run
              · exact from_self id has
              · refine ⟨(s, e), run_in, ?_⟩
                simp only [InRun] at in_run ⊢
                omega
            · intro a a_in later later_in
              rw [is_out1] at a_in
              rcases List.mem_append.mp a_in with a_in | a_in
              · exact before_later_after a a_in later later_in
              · rw [List.mem_singleton.mp a_in]
                have := after_run later later_in
                simp only
                omega
            · rw [is_out1]
              simp only [Total, List.map_append, List.sum_append, List.map_cons, List.map_nil,
                List.sum_cons, List.sum_nil]
              unfold Total at total_is
              have zero : (0#u64).val = 0 := rfl
              omega
            · intro positive
              have zero : (0#u64).val = 0 := rfl
              omega
            · intro first
              have zero : (0#u64).val = 0 := rfl
              exact ⟨(first_turn first).1, by omega⟩
        · intro r ⟨few1, ordered1, from_self1, before1, total1, taken1, first1⟩
          obtain ⟨left1, out1⟩ := r
          dsimp only at few1 ordered1 from_self1 before1 total1 taken1 first1
          step as ⟨ i3, is_i3 ⟩
          refine ⟨by omega, by omega, ordered1, from_self1, ?_, total1, ?_, ?_, ?_, by omega⟩
          · rw [is_i3]
            exact before1
          · rw [is_i3]
            exact taken1
          · omega
          · intro first
            have := first1 first
            exact ⟨by omega, by omega, by omega⟩
      · -- nothing is left to find
        rename_i nothing_left
        refine (WP.spec_ok _).mpr ⟨out_ordered, from_self, total_is, ?_, fun first =>
          (shape first).1⟩
        intro positive
        have := (UScalar.lt_equiv 0#u64 left).not.mp nothing_left
        have zero : (0#u64).val = 0 := rfl
        simp only at positive
        omega
    · rename_i outside
      have : i.val = self.intervals.val.length := by scalar_tac
      refine (WP.spec_ok _).mpr ⟨out_ordered, from_self, total_is, fun positive => ?_,
        fun first => (shape first).1⟩
      rw [all_taken positive, this]
      simp
  · refine ⟨by simp, by simp [alloc.vec.Vec.new],
      ⟨by simp [alloc.vec.Vec.new], by simp [alloc.vec.Vec.new]⟩,
      by simp [alloc.vec.Vec.new, HasId], by simp [alloc.vec.Vec.new],
      by simp [alloc.vec.Vec.new, Total],
      by simp [alloc.vec.Vec.new], by simp [alloc.vec.Vec.new],
      fun _ => ⟨by simp [alloc.vec.Vec.new], fun _ => rfl, by simp [alloc.vec.Vec.new]⟩⟩

/-- **`find_available`**: for an ordered set and `n` ids wanted, it returns either an ordered set
of exactly `n` ids, all of them in the set, or nothing, and then the set has fewer than `n`
ids.  When the first interval has `n` ids, the answer is one interval. -/
theorem find_available_gives_n_ids_or_says_there_are_fewer (self : IdSet) (n : U64)
    (ordered : Ordered self.intervals.val) :
    IdSet.find_available self n ⦃ r =>
      match r with
      | some s => Ordered s.intervals.val ∧
          (∀ id, HasId s.intervals.val id → HasId self.intervals.val id) ∧
          ExactlyIds (HasId s.intervals.val) n.val ∧
          (FirstIntervalHolds self n → s.intervals.val.length ≤ 1)
      | none => Total self.intervals.val < n.val ⦄ := by
  unfold IdSet.find_available
  step with find_available_takes_intervals_until_n self n ordered as
    ⟨ left, out, out_ordered, from_self, total_is, all_taken, one_interval ⟩
  split
  · rename_i some_left
    have positive : 0 < left.val := by
      have := (UScalar.lt_equiv 0#u64 left).mp some_left
      simpa using this
    refine (WP.spec_ok _).mpr ?_
    have := all_taken positive
    omega
  · rename_i none_left
    have : left.val = 0 := by
      have := (UScalar.lt_equiv 0#u64 left).not.mp none_left
      simpa using this
    refine (WP.spec_ok _).mpr ⟨out_ordered, from_self, ?_, one_interval⟩
    have exactly := ordered_runs_have_total_ids out.val out_ordered
    rwa [show Total out.val = n.val by omega] at exactly

end IdmapCore
