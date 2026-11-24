-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the inner loop of `IdSet::subtract`.  For one interval `[s, e)` of the
-- first set, it goes along the intervals of the other set, in order, and writes the pieces of
-- `[s, e)` that no interval of the other set has, keeping in `start` the first id not yet decided.
-- What is left, `[start, e)`, is written by the outer loop.
--
-- Read before this file: Spec.lean, HasIdFacts.lean, Lists.lean.  `Pieces` is the invariant of
-- the loop: where it is in the other set (`j`, and `done` when the rest of the other set begins
-- past `e`), the pieces written so far (`out`, after `out0` of the earlier intervals), and how
-- they relate to the ids of `[s, e)` that are not in the other set.
import IdmapCore.Spec
import IdmapCore.HasIdFacts
import IdmapCore.Lists

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- What the inner loop of `subtract` has done when it is at the interval `j` of `other` with
`start` the first id of `[s, e)` it has not decided: every id before `start` is either written in
`out`, or is not wanted (it is in the other set, or `out0` has it); no id from `start` on is in
`out`; no interval of the other set that was read has an id in `[start, e)`. -/
def Pieces (other : List (U64 × U64)) (s e : U64) (out0 out : List (U64 × U64)) (start : U64)
    (j : Nat) (done : Bool) : Prop :=
  s.val ≤ start.val ∧ Ordered out ∧ (∀ a ∈ out, a.2.val < start.val) ∧
  (∀ a ∈ out, a ∈ out0 ∨ a.2.val ≤ e.val) ∧
  (∀ id, id < start.val →
    (HasId out id ↔ (HasId out0 id ∨ (s.val ≤ id ∧ id < e.val ∧ ¬ HasId other id)))) ∧
  (∀ id, start.val ≤ id → ¬ HasId out id) ∧
  (∀ id, s.val ≤ id → id < start.val → ¬ HasId (other.drop j) id) ∧
  (∀ id, start.val ≤ id → id < e.val → ¬ HasId (other.take j) id) ∧
  (done = true → ∀ o ∈ other.drop j, e.val ≤ o.1.val)

/-- The inner loop: from the first interval of `other`, with nothing decided (`start = s`), it
reaches a state that satisfies `Pieces` and in which no id of `[start, e)` is in `other` at all. -/
theorem subtract_writes_the_pieces_of_one_interval (other : IdSet) (s e : U64)
    (out0 : alloc.vec.Vec (U64 × U64)) (ordered : Ordered other.intervals.val)
    (out0_ordered : Ordered out0.val) (out0_before : ∀ a ∈ out0.val, a.2.val < s.val)
    (room : out0.val.length + other.intervals.val.length < Usize.max) :
    IdSet.subtract_loop0_loop0 other out0 e s 0#usize false ⦃ r =>
      r.1 = other.intervals ∧
      ∃ j done, Pieces other.intervals.val s e out0.val r.2.1.val r.2.2 j done ∧
        r.2.1.val.length ≤ out0.val.length + other.intervals.val.length ∧
        ∀ id, r.2.2.val ≤ id → id < e.val → ¬ HasId other.intervals.val id ⦄ := by
  unfold IdSet.subtract_loop0_loop0
  apply loop.spec_decr_nat (fun q => other.intervals.val.length - q.2.2.1.val)
    (fun q => q.2.2.1.val ≤ other.intervals.val.length ∧
      q.1.val.length ≤ out0.val.length + q.2.2.1.val ∧
      Pieces other.intervals.val s e out0.val q.1.val q.2.1 q.2.2.1.val q.2.2.2)
  · rintro ⟨out, start, j, done1⟩ ⟨bound, few, pieces⟩
    simp only at bound few pieces ⊢
    obtain ⟨s_le, out_ordered, before_start, new_or_old, decided, undecided, drop_decided,
      take_undecided, done_means⟩ := pieces
    unfold IdSet.subtract_loop0_loop0.body
    dsimp only
    have same_length : other.intervals.length = other.intervals.val.length := rfl
    split
    · rename_i more
      have more : j.val < other.intervals.val.length := by
        have : j.val < other.intervals.length := by scalar_tac
        omega
      split
      · -- the rest of the other set begins past the end: nothing more to read
        rename_i finished
        have finished : done1 = true := by simpa using finished
        have rest_is_past := done_means finished
        refine (WP.spec_ok _).mpr ⟨rfl, j.val, true, ?_, by dsimp only; omega, ?_⟩
        · exact ⟨s_le, out_ordered, before_start, new_or_old, decided, undecided, drop_decided,
            take_undecided, fun _ => rest_is_past⟩
        · intro id id_ge id_lt has
          -- some interval of the other set has the id: one that was read, or one not yet read
          obtain ⟨iv, iv_in, in_run⟩ := has
          rw [← List.take_append_drop j.val other.intervals.val, List.mem_append] at iv_in
          rcases iv_in with iv_in | iv_in
          · exact take_undecided id id_ge id_lt ⟨iv, iv_in, in_run⟩
          · have := rest_is_past iv iv_in
            simp only [InRun] at in_run
            omega
      · -- the interval `j` of the other set is read
        rename_i not_finished
        have not_finished : done1 = false := by simpa using not_finished
        step as ⟨ os, oe, is_other ⟩
        have drop_is : other.intervals.val.drop j.val =
            (os, oe) :: other.intervals.val.drop (j.val + 1) := by
          rw [List.drop_eq_getElem_cons more, ← is_other]
        have take_is : other.intervals.val.take (j.val + 1) =
            other.intervals.val.take j.val ++ [(os, oe)] := by
          rw [take_one_more other.intervals.val j.val more, ← is_other]
        have other_in : (os, oe) ∈ other.intervals.val := by
          rw [is_other]
          exact List.getElem_mem _
        have other_has_ids : os.val < oe.val := ordered.1 (os, oe) other_in
        have after_other : ∀ later ∈ other.intervals.val.drop (j.val + 1),
            oe.val < later.1.val := by
          have := ordered.2
          rw [← List.take_append_drop j.val other.intervals.val, drop_is, List.pairwise_append,
            List.pairwise_cons] at this
          exact this.2.1.1
        have drop_decided_next : ∀ id, s.val ≤ id → id < start.val →
            ¬ HasId (other.intervals.val.drop (j.val + 1)) id := fun id h1 h2 ⟨iv, iv_in, in_run⟩ =>
          drop_decided id h1 h2 ⟨iv, by rw [drop_is]; exact List.mem_cons_of_mem _ iv_in, in_run⟩
        have out0_has_no_id_from_s : ∀ id, s.val ≤ id → ¬ HasId out0.val id := by
          rintro id id_ge ⟨iv, iv_in, in_run⟩
          have := out0_before iv iv_in
          simp only [InRun] at in_run
          omega
        refine WP.spec_bind (Pₘ := fun r : alloc.vec.Vec (U64 × U64) × U64 × Bool =>
          r.1.val.length ≤ out.val.length + 1 ∧
          Pieces other.intervals.val s e out0.val r.1.val r.2.1 (j.val + 1) r.2.2) ?_ ?_
        · split
          · -- the interval of the other set begins at or past the end of `[s, e)`
            rename_i past_the_end
            have past_the_end : e.val ≤ os.val := by
              have := (UScalar.le_equiv e os).mp past_the_end
              omega
            refine (WP.spec_ok _).mpr ⟨by show out.val.length ≤ out.val.length + 1; omega, s_le,
              out_ordered, before_start, new_or_old,
              decided, undecided, ?_, ?_, ?_⟩
            · exact drop_decided_next
            · intro id id_ge id_lt ⟨iv, iv_in, in_run⟩
              rw [take_is, List.mem_append] at iv_in
              rcases iv_in with iv_in | iv_in
              · exact take_undecided id id_ge id_lt ⟨iv, iv_in, in_run⟩
              · rw [List.mem_singleton.mp iv_in] at in_run
                simp only [InRun] at in_run
                omega
            · intro _ later later_in
              have := after_other later later_in
              omega
          · rename_i before_the_end
            have before_the_end : os.val < e.val := by
              have := (UScalar.le_equiv e os).not.mp before_the_end
              omega
            split
            · -- the interval of the other set takes ids from `start` on
              rename_i takes_from_start
              have takes_from_start : start.val < oe.val := by
                have := (UScalar.lt_equiv start oe).mp takes_from_start
                omega
              -- (the ids before `os` are written, if there are some)
              refine WP.spec_bind (Pₘ := fun out2 : alloc.vec.Vec (U64 × U64) =>
                out2.val.length ≤ out.val.length + 1 ∧ Ordered out2.val ∧
                (∀ a ∈ out2.val, a.2.val < oe.val) ∧
                (∀ a ∈ out2.val, a ∈ out0.val ∨ a.2.val ≤ e.val) ∧
                (∀ id, id < oe.val → (HasId out2.val id ↔ (HasId out0.val id ∨
                  (s.val ≤ id ∧ id < e.val ∧ ¬ HasId other.intervals.val id)))) ∧
                (∀ id, oe.val ≤ id → ¬ HasId out2.val id)) ?_ ?_
              · have room_to_push : out.val.length < Usize.max := by omega
                -- whether the piece before `os` is written or not, the same facts hold
                have facts : ∀ out2 : alloc.vec.Vec (U64 × U64),
                    (out2.val = out.val ∧ os.val ≤ start.val) ∨
                    (out2.val = out.val ++ [(start, os)] ∧ start.val < os.val) →
                    out2.val.length ≤ out.val.length + 1 ∧ Ordered out2.val ∧
                    (∀ a ∈ out2.val, a.2.val < oe.val) ∧
                    (∀ a ∈ out2.val, a ∈ out0.val ∨ a.2.val ≤ e.val) ∧
                    (∀ id, id < oe.val → (HasId out2.val id ↔ (HasId out0.val id ∨
                      (s.val ≤ id ∧ id < e.val ∧ ¬ HasId other.intervals.val id)))) ∧
                    (∀ id, oe.val ≤ id → ¬ HasId out2.val id) := by
                  intro out2 which
                  have has_id_out2 : ∀ id, HasId out2.val id ↔
                      (HasId out.val id ∨ (start.val < os.val ∧ start.val ≤ id ∧ id < os.val)) := by
                    intro id
                    rcases which with ⟨same, _⟩ | ⟨wrote, below⟩
                    · rw [same]
                      constructor
                      · exact Or.inl
                      · rintro (has | ⟨_, _, _⟩)
                        · exact has
                        · omega
                    · rw [wrote, has_id_after_adding]
                      simp only [InRun]
                      constructor
                      · rintro (has | ⟨ge, lt⟩)
                        · exact Or.inl has
                        · exact Or.inr ⟨below, ge, lt⟩
                      · rintro (has | ⟨_, ge, lt⟩)
                        · exact Or.inl has
                        · exact Or.inr ⟨ge, lt⟩
                  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
                  · rcases which with ⟨same, _⟩ | ⟨wrote, _⟩
                    · rw [same]; omega
                    · rw [wrote]; simp
                  · rcases which with ⟨same, _⟩ | ⟨wrote, below⟩
                    · rw [same]; exact out_ordered
                    · rw [wrote]
                      refine ⟨fun iv iv_in => ?_, ?_⟩
                      · rcases List.mem_append.mp iv_in with iv_in | iv_in
                        · exact out_ordered.1 iv iv_in
                        · rw [List.mem_singleton.mp iv_in]
                          exact below
                      · rw [List.pairwise_append]
                        exact ⟨out_ordered.2, List.pairwise_singleton _ _, fun a a_in y y_in => by
                          rw [List.mem_singleton.mp y_in]
                          exact before_start a a_in⟩
                  · intro a a_in
                    rcases which with ⟨same, _⟩ | ⟨wrote, below⟩
                    · rw [same] at a_in
                      have := before_start a a_in
                      omega
                    · rw [wrote] at a_in
                      rcases List.mem_append.mp a_in with a_in | a_in
                      · have := before_start a a_in
                        omega
                      · rw [List.mem_singleton.mp a_in]
                        exact other_has_ids |> fun _ => by simp only; omega
                  · intro a a_in
                    rcases which with ⟨same, _⟩ | ⟨wrote, below⟩
                    · rw [same] at a_in
                      exact new_or_old a a_in
                    · rw [wrote] at a_in
                      rcases List.mem_append.mp a_in with a_in | a_in
                      · exact new_or_old a a_in
                      · rw [List.mem_singleton.mp a_in]
                        exact Or.inr (by simp only; omega)
                  · intro id id_lt
                    rw [has_id_out2 id]
                    by_cases before_the_start : id < start.val
                    · have not_piece : ¬ (start.val < os.val ∧ start.val ≤ id ∧ id < os.val) := by
                        omega
                      rw [decided id before_the_start]
                      constructor
                      · rintro (has | piece)
                        · exact has
                        · exact absurd piece not_piece
                      · exact Or.inl
                    · have id_ge : start.val ≤ id := by omega
                      have no_out := undecided id id_ge
                      have no_out0 := out0_has_no_id_from_s id (by omega)
                      have inside_other : os.val ≤ id → HasId other.intervals.val id := fun h =>
                        ⟨(os, oe), other_in, h, id_lt⟩
                      have outside_other : id < os.val → ¬ HasId other.intervals.val id := by
                        rintro below ⟨iv, iv_in, in_run⟩
                        rw [← List.take_append_drop j.val other.intervals.val, List.mem_append,
                          drop_is, List.mem_cons] at iv_in
                        rcases iv_in with iv_in | rfl | iv_in
                        · exact take_undecided id id_ge (by omega) ⟨iv, iv_in, in_run⟩
                        · simp only [InRun] at in_run
                          omega
                        · have := after_other iv iv_in
                          simp only [InRun] at in_run
                          omega
                      constructor
                      · rintro (has | ⟨_, _, lt⟩)
                        · exact absurd has no_out
                        · exact Or.inr ⟨by omega, by omega, outside_other lt⟩
                      · rintro (has | ⟨_, lt_e, not_in⟩)
                        · exact absurd has no_out0
                        · refine Or.inr ⟨?_, id_ge, ?_⟩
                          · by_contra
                            have := inside_other (by omega)
                            exact not_in this
                          · by_contra
                            exact not_in (inside_other (by omega))
                  · intro id id_ge
                    rw [has_id_out2 id]
                    rintro (has | ⟨_, _, lt⟩)
                    · exact undecided id (by omega) has
                    · omega
                split
                · rename_i writes
                  have writes : start.val < os.val := by
                    have := (UScalar.lt_equiv start os).mp writes
                    omega
                  step as ⟨ out2, is_out2 ⟩
                  exact facts out2 (Or.inr ⟨is_out2, writes⟩)
                · rename_i skips
                  have skips : os.val ≤ start.val := by
                    have := (UScalar.lt_equiv start os).not.mp skips
                    omega
                  exact (WP.spec_ok _).mpr (facts out (Or.inl ⟨rfl, skips⟩))
              · intro out2 ⟨few2, ordered2, before2, new_or_old2, decided2, undecided2⟩
                refine (WP.spec_ok _).mpr ⟨few2, by show s.val ≤ oe.val; omega, ordered2, before2,
                  new_or_old2,
                  decided2, undecided2, ?_, ?_, ?_⟩
                · intro id _ (id_lt : id < oe.val) ⟨iv, iv_in, in_run⟩
                  have := after_other iv iv_in
                  simp only [InRun] at in_run
                  omega
                · intro id (id_ge : oe.val ≤ id) id_lt ⟨iv, iv_in, in_run⟩
                  rw [take_is, List.mem_append] at iv_in
                  rcases iv_in with iv_in | iv_in
                  · exact take_undecided id (by omega) id_lt ⟨iv, iv_in, in_run⟩
                  · rw [List.mem_singleton.mp iv_in] at in_run
                    simp only [InRun] at in_run
                    omega
                · intro finished_now later later_in
                  have := after_other later later_in
                  have : e.val ≤ oe.val := by
                    have := (UScalar.le_equiv e oe).mp (by simpa using finished_now)
                    omega
                  omega
            · -- the interval of the other set ends before `start`: nothing changes
              rename_i before_start_oe
              have before_start_oe : oe.val ≤ start.val := by
                have := (UScalar.lt_equiv start oe).not.mp before_start_oe
                omega
              refine (WP.spec_ok _).mpr ⟨by show out.val.length ≤ out.val.length + 1; omega, s_le,
              out_ordered, before_start, new_or_old,
                decided, undecided, drop_decided_next, ?_, ?_⟩
              · intro id (id_ge : start.val ≤ id) id_lt ⟨iv, iv_in, in_run⟩
                rw [take_is, List.mem_append] at iv_in
                rcases iv_in with iv_in | iv_in
                · exact take_undecided id id_ge id_lt ⟨iv, iv_in, in_run⟩
                · rw [List.mem_singleton.mp iv_in] at in_run
                  simp only [InRun] at in_run
                  omega
              · intro done_now later later_in
                exact done_means done_now later
                  (by rw [drop_is]; exact List.mem_cons_of_mem _ later_in)
        · intro r ⟨few1, pieces1⟩
          obtain ⟨out1, start1, done2⟩ := r
          step as ⟨ j1, is_j1 ⟩
          refine ⟨by omega, by simp only at few1; omega, ?_, by omega⟩
          rw [is_j1]
          exact pieces1
    · -- every interval of the other set was read
      rename_i all_read
      have j_is : j.val = other.intervals.val.length := by scalar_tac
      refine (WP.spec_ok _).mpr ⟨rfl, j.val, done1, ?_, by dsimp only; omega, ?_⟩
      · exact ⟨s_le, out_ordered, before_start, new_or_old, decided, undecided, drop_decided,
          take_undecided, done_means⟩
      · intro id id_ge id_lt has
        apply take_undecided id id_ge id_lt
        rw [j_is, List.take_length]
        exact has
  · refine ⟨by simp, by simp, le_refl _, out0_ordered, out0_before, fun a a_in => Or.inl a_in,
      ?_, ?_, fun id (_ : s.val ≤ id) (id_lt : id < s.val) => by omega,
      fun id _ _ => by simp [no_id_in_the_empty_list],
      fun h => by simp at h⟩
    · intro id (id_lt : id < s.val)
      constructor
      · exact Or.inl
      · rintro (has | ⟨ge, _⟩)
        · exact has
        · omega
    · rintro id (id_ge : s.val ≤ id) ⟨iv, iv_in, in_run⟩
      have := out0_before iv iv_in
      simp only [InRun] at in_run
      omega

end IdmapCore
