-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `IdSet::subtract`, the ids of a set that another set does not have.  For
-- each interval of the first set, the inner loop (IdSetSubtractInner.lean) writes the pieces
-- that the intervals of the other set leave before the last one, and the outer loop writes what
-- is left after it.
--
-- Read before this file: Spec.lean, IdSetSubtractInner.lean, HasIdFacts.lean, Lists.lean.
import IdmapCore.IdSetSubtractInner

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- The outer loop: from the interval `i` of `self`, it writes the ids of each interval that
`other` does not have. -/
theorem subtract_goes_through_the_intervals (self other : IdSet)
    (self_ordered : Ordered self.intervals.val) (other_ordered : Ordered other.intervals.val)
    (fits : self.intervals.val.length * (other.intervals.val.length + 1) ≤ Usize.max) :
    IdSet.subtract_loop0 self other (alloc.vec.Vec.new (U64 × U64)) 0#usize ⦃ out =>
      Ordered out.val ∧
      (∀ id, HasId out.val id ↔
        (HasId self.intervals.val id ∧ ¬ HasId other.intervals.val id)) ∧
      out.val.length ≤ self.intervals.val.length * (other.intervals.val.length + 1) ⦄ := by
  unfold IdSet.subtract_loop0
  apply loop.spec_decr_nat (fun q => self.intervals.val.length - q.2.2.val)
    (fun q => q.1.intervals = other.intervals ∧
      q.2.2.val ≤ self.intervals.val.length ∧
      q.2.1.val.length ≤ q.2.2.val * (other.intervals.val.length + 1) ∧
      Ordered q.2.1.val ∧
      (∀ a ∈ q.2.1.val, ∀ later ∈ self.intervals.val.drop q.2.2.val, a.2.val < later.1.val) ∧
      ∀ id, HasId q.2.1.val id ↔
        (HasId (self.intervals.val.take q.2.2.val) id ∧ ¬ HasId other.intervals.val id))
  · rintro ⟨other1, out, i⟩ ⟨same_other, bound, few, out_ordered, before_later, covers⟩
    simp only at same_other bound few out_ordered before_later covers ⊢
    unfold IdSet.subtract_loop0.body
    dsimp only
    have same_length : self.intervals.length = self.intervals.val.length := rfl
    split
    · rename_i more
      have more : i.val < self.intervals.val.length := by
        have : i.val < self.intervals.length := by scalar_tac
        omega
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
      have run_has_ids : s.val < e.val := self_ordered.1 (s, e) run_in
      have after_run : ∀ later ∈ self.intervals.val.drop (i.val + 1), e.val < later.1.val := by
        have := self_ordered.2
        rw [← List.take_append_drop i.val self.intervals.val, drop_is, List.pairwise_append,
          List.pairwise_cons] at this
        exact this.2.1.1
      have out_before_run : ∀ a ∈ out.val, a.2.val < s.val := fun a a_in =>
        before_later a a_in (s, e) (by rw [drop_is]; exact List.mem_cons_self)
      have out_before_later : ∀ a ∈ out.val, ∀ later ∈ self.intervals.val.drop (i.val + 1),
          a.2.val < later.1.val := fun a a_in later later_in =>
        before_later a a_in later (by rw [drop_is]; exact List.mem_cons_of_mem _ later_in)
      -- the room the inner loop and the last write need
      have rows : (i.val + 1) * (other.intervals.val.length + 1) ≤
          self.intervals.val.length * (other.intervals.val.length + 1) :=
        Nat.mul_le_mul_right _ (by omega)
      have next_row : (i.val + 1) * (other.intervals.val.length + 1) =
          i.val * (other.intervals.val.length + 1) + other.intervals.val.length + 1 := by
        rw [Nat.succ_mul]
        omega
      have room : out.val.length + other.intervals.val.length < Usize.max := by omega
      have other1_is : other1 = other := by
        cases other1
        cases other
        exact congrArg IdSet.mk same_other
      rw [other1_is]
      step with subtract_writes_the_pieces_of_one_interval other s e out other_ordered out_ordered
        out_before_run room as ⟨ v, out1, start, same_v, j, done, pieces, few1, rest_free ⟩
      obtain ⟨s_le, out1_ordered, out1_before_start, out1_new_or_old, decided, undecided, _,
        _, _⟩ := pieces
      have room_for_last : out1.val.length < Usize.max := by omega
      have key : ∀ id, (HasId out1.val id ∨ (start.val ≤ id ∧ id < e.val)) ↔
          ((HasId (self.intervals.val.take i.val) id ∨ (s.val ≤ id ∧ id < e.val)) ∧
            ¬ HasId other.intervals.val id) := by
        intro id
        by_cases before_the_start : id < start.val
        · have not_piece : ¬ (start.val ≤ id ∧ id < e.val) := by omega
          rw [decided id before_the_start, covers id]
          constructor
          · rintro ((⟨has, no⟩ | ⟨has_s, lt_e, no⟩) | piece)
            · exact ⟨Or.inl has, no⟩
            · exact ⟨Or.inr ⟨has_s, lt_e⟩, no⟩
            · exact absurd piece not_piece
          · rintro ⟨has | ⟨has_s, lt_e⟩, no⟩
            · exact Or.inl (Or.inl ⟨has, no⟩)
            · exact Or.inl (Or.inr ⟨has_s, lt_e, no⟩)
        · have id_ge : start.val ≤ id := by omega
          have no_out1 := undecided id id_ge
          have no_prev : ¬ HasId (self.intervals.val.take i.val) id ∨
              HasId other.intervals.val id := by
            by_contra both
            push Not at both
            have in_out := (covers id).mpr ⟨both.1, both.2⟩
            obtain ⟨iv, iv_in, in_run⟩ := in_out
            have := out_before_run iv iv_in
            simp only [InRun] at in_run
            omega
          constructor
          · rintro (has | ⟨_, lt_e⟩)
            · exact absurd has no_out1
            · exact ⟨Or.inr ⟨by omega, lt_e⟩, rest_free id id_ge lt_e⟩
          · rintro ⟨has | ⟨_, lt_e⟩, no⟩
            · rcases no_prev with no_take | has_other
              · exact absurd has no_take
              · exact absurd has_other no
            · exact Or.inr ⟨id_ge, lt_e⟩
      refine WP.spec_bind (Pₘ := fun out2 : alloc.vec.Vec (U64 × U64) =>
        out2.val.length ≤ out.val.length + other.intervals.val.length + 1 ∧ Ordered out2.val ∧
        (∀ a ∈ out2.val, ∀ later ∈ self.intervals.val.drop (i.val + 1), a.2.val < later.1.val) ∧
        ∀ id, HasId out2.val id ↔
          (HasId (self.intervals.val.take (i.val + 1)) id ∧ ¬ HasId other.intervals.val id)) ?_ ?_
      · split
        · rename_i leftover
          have leftover : start.val < e.val := by
            have := (UScalar.lt_equiv start e).mp leftover
            omega
          step as ⟨ out2, is_out2 ⟩
          refine ⟨by simp [is_out2]; omega, ⟨?_, ?_⟩, ?_, fun id => ?_⟩
          · intro iv iv_in
            rw [is_out2] at iv_in
            rcases List.mem_append.mp iv_in with iv_in | iv_in
            · exact out1_ordered.1 iv iv_in
            · rw [List.mem_singleton.mp iv_in]
              exact leftover
          · rw [is_out2, List.pairwise_append]
            exact ⟨out1_ordered.2, List.pairwise_singleton _ _, fun a a_in y y_in => by
              rw [List.mem_singleton.mp y_in]
              exact out1_before_start a a_in⟩
          · intro a a_in later later_in
            rw [is_out2] at a_in
            rcases List.mem_append.mp a_in with a_in | a_in
            · rcases out1_new_or_old a a_in with old | new
              · exact out_before_later a old later later_in
              · have := after_run later later_in
                omega
            · rw [List.mem_singleton.mp a_in]
              exact after_run later later_in
          · rw [is_out2, take_is, has_id_after_adding]
            have := key id
            simp only [InRun] at this ⊢
            rw [has_id_after_adding, this]
            simp only [InRun]
        · rename_i no_leftover
          have no_leftover : e.val ≤ start.val := by
            have := (UScalar.lt_equiv start e).not.mp no_leftover
            omega
          refine (WP.spec_ok _).mpr ⟨by omega, out1_ordered, ?_, fun id => ?_⟩
          · intro a a_in later later_in
            rcases out1_new_or_old a a_in with old | new
            · exact out_before_later a old later later_in
            · have := after_run later later_in
              omega
          · rw [take_is, has_id_after_adding]
            have := key id
            have no_piece : ¬ (start.val ≤ id ∧ id < e.val) := by omega
            simp only [InRun] at this ⊢
            rw [← this]
            constructor
            · intro has
              exact Or.inl has
            · rintro (has | piece)
              · exact has
              · exact absurd piece no_piece
      · intro out2 ⟨few2, ordered2, before2, covers2⟩
        step as ⟨ i2, is_i2 ⟩
        refine ⟨?_, by omega, by rw [is_i2]; omega, ordered2, ?_, ?_, by omega⟩
        · exact same_v
        · rw [is_i2]
          exact before2
        · rw [is_i2]
          exact covers2
    · rename_i outside
      have : i.val = self.intervals.val.length := by scalar_tac
      refine (WP.spec_ok _).mpr ⟨out_ordered, fun id => ?_, by rw [this] at few; exact few⟩
      rw [covers id, this]
      simp
  · refine ⟨rfl, by simp, by simp [alloc.vec.Vec.new],
      ⟨by simp [alloc.vec.Vec.new], by simp [alloc.vec.Vec.new]⟩,
      by simp [alloc.vec.Vec.new], fun id => by simp [alloc.vec.Vec.new, HasId]⟩

/-- **`subtract`**: for two ordered sets (whose numbers of intervals are such that the answer fits
in the memory of a computer: the number of intervals of the first, times one more than that of
the second, is at most 2^64), it returns an ordered set that has the ids of the first that the
second does not have, and no other, in at most as many intervals as the first has, times one more
than the second has. -/
theorem subtract_has_the_ids_of_the_first_not_in_the_second (self other : IdSet)
    (self_ordered : Ordered self.intervals.val) (other_ordered : Ordered other.intervals.val)
    (fits : self.intervals.val.length * (other.intervals.val.length + 1) ≤ Usize.max) :
    IdSet.subtract self other ⦃ s =>
      Ordered s.intervals.val ∧
      (∀ id, HasId s.intervals.val id ↔
        (HasId self.intervals.val id ∧ ¬ HasId other.intervals.val id)) ∧
      s.intervals.val.length ≤ self.intervals.val.length * (other.intervals.val.length + 1) ⦄ := by
  unfold IdSet.subtract
  step with subtract_goes_through_the_intervals self other self_ordered other_ordered fits
    as ⟨ out, ordered, has_ids, few ⟩
  exact ⟨ordered, has_ids, few⟩

end IdmapCore
