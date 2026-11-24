-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `range_to_parent`: it looks for the first entry that has the container id
-- `start`, and answers its parent id for `start` when the whole range `[start, start + len)` is in
-- that entry (and the parent id fits in 32 bits).  What the loop knows at the entry `i` is
-- `Found`: no entry before it has `start`, or the first one that has it is known, with the answer
-- that it gives.
--
-- Read before this file: Spec.lean (`InContainers`, `ParentOf`), Lists.lean.
import IdmapCore.Spec
import IdmapCore.Lists
import IdmapCore.ValidMeansFunction

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- The answer that the entry `e` gives for the range, if the whole range is in it and its parent
id for `start` fits in 32 bits. -/
def AnswerOf (e : Map) (start len : U32) : Option Nat :=
  if start.val + len.val ≤ e.container_id.val + e.size.val ∧ ParentOf e start.val ≤ U32Max then
    some (ParentOf e start.val)
  else none

/-- What the loop knows after reading the entries `entries` (the first ones of the list): `done`
is false and nothing was found while no entry has `start`; once one has it, `done` is true, it is
the first, and `found` is its answer. -/
def Found (entries : List Map) (start len : U32) (found : Option U32) (done : Bool) : Prop :=
  (done = false ∧ found = none ∧ ∀ e ∈ entries, ¬ InContainers e start.val) ∨
  (done = true ∧ ∃ before e after, entries = before ++ e :: after ∧
    (∀ x ∈ before, ¬ InContainers x start.val) ∧ InContainers e start.val ∧
    (found.map (fun q => q.val)) = AnswerOf e start len)

/-- What is known of the answer when all the entries are read, or one that has `start` was found:
nothing has `start`, or the first entry that has it gave this answer. -/
def Finished (entries : List Map) (start len : U32) (found : Option U32) : Prop :=
  (found = none ∧ ∀ e ∈ entries, ¬ InContainers e start.val) ∨
  (∃ before e after, entries = before ++ e :: after ∧
    (∀ x ∈ before, ¬ InContainers x start.val) ∧ InContainers e start.val ∧
    (found.map (fun q => q.val)) = AnswerOf e start len)

/-- The loop of `range_to_parent`, from the first entry: at the end, the first entry that has
`start`, if there is one, has given its answer. -/
theorem range_to_parent_finds_the_first_entry (maps : Slice Map) (start len : U32) :
    range_to_parent_loop maps start len none false 0#usize ⦃ found =>
      Finished maps.val start len found ⦄ := by
  unfold range_to_parent_loop
  apply loop.spec_decr_nat (fun q => maps.length - q.2.2.val)
    (fun q => q.2.2.val ≤ maps.length ∧ Found (maps.val.take q.2.2.val) start len q.1 q.2.1)
  · rintro ⟨found, done1, i⟩ ⟨bound, known⟩
    simp only at bound known ⊢
    unfold range_to_parent_loop.body
    dsimp only [Slice.len]
    split
    · rename_i more
      have more : i.val < maps.length := by scalar_tac
      split
      · -- an entry was found before: the loop ends
        rename_i finished
        have finished : done1 = true := by simpa using finished
        refine (WP.spec_ok _).mpr ?_
        rcases known with ⟨not_done, _⟩ | ⟨_, before, e, after, is_take, no_before, has, answer⟩
        · simp [finished] at not_done
        · refine Or.inr ⟨before, e, after ++ maps.val.drop i.val, ?_, no_before, has, answer⟩
          calc maps.val = maps.val.take i.val ++ maps.val.drop i.val :=
                (List.take_append_drop _ _).symm
            _ = _ := by rw [is_take]; simp
      · rename_i not_finished
        have not_finished : done1 = false := by simpa using not_finished
        obtain ⟨found_none, none_before⟩ : found = none ∧ ∀ e ∈ maps.val.take i.val,
            ¬ InContainers e start.val := by
          rcases known with ⟨_, found_none, none_before⟩ | ⟨is_done, _⟩
          · exact ⟨found_none, none_before⟩
          · simp [not_finished] at is_done
        step as ⟨ m, is_m ⟩
        have take_is : maps.val.take (i.val + 1) = maps.val.take i.val ++ [m] := by
          rw [take_one_more maps.val i.val more, is_m]
        have hc := core.convert.num.FromU64U32.from_val_eq m.container_id
        have hs := core.convert.num.FromU64U32.from_val_eq m.size
        have hp := core.convert.num.FromU64U32.from_val_eq m.parent_id
        have hstart := core.convert.num.FromU64U32.from_val_eq start
        have hlen := core.convert.num.FromU64U32.from_val_eq len
        simp only [Std.lift, Std.bind_ok]
        step as ⟨ end_, is_end ⟩
        refine WP.spec_bind (Pₘ := fun r : Option U32 × Bool =>
          Found (maps.val.take (i.val + 1)) start len r.1 r.2) ?_ ?_
        · split
          · rename_i starts_before
            have starts_before : m.container_id.val ≤ start.val := by
              have := (UScalar.le_equiv m.container_id start).mp starts_before
              omega
            split
            · rename_i inside
              have inside : start.val < end_.val := by
                have := (UScalar.lt_equiv (core.convert.num.FromU64U32.from start) end_).mp inside
                omega
              have has : InContainers m start.val := by
                unfold InContainers
                omega
              step as ⟨ diff, is_diff ⟩
              have hdiff := core.convert.num.FromU64U32.from_val_eq diff
              step as ⟨ parent, is_parent ⟩
              step as ⟨ range_end, is_range_end ⟩
              refine WP.spec_bind (Pₘ := fun o : Option U32 =>
                o.map (fun q => q.val) = AnswerOf m start len) ?_ ?_
              · split
                · rename_i fits_in_entry
                  have fits_in_entry : start.val + len.val ≤ m.container_id.val + m.size.val := by
                    have := (UScalar.le_equiv range_end end_).mp fits_in_entry
                    omega
                  have u32_max : (core.convert.num.FromU64U32.from core.num.U32.MAX).val =
                      U32Max := by
                    rw [core.convert.num.FromU64U32.from_val_eq]
                    exact (by decide : core.num.U32.MAX.val = 4294967295)
                  split
                  · rename_i parent_fits
                    have parent_fits : parent.val ≤ U32Max := by
                      have := (UScalar.le_equiv parent _).mp parent_fits
                      omega
                    refine (WP.spec_ok _).mpr ?_
                    have small_is : (UScalar.cast UScalarTy.U32 parent).val = parent.val := by
                      rw [UScalar.cast_val_eq]
                      simp
                      unfold U32Max at parent_fits
                      omega
                    have holds : start.val + len.val ≤ m.container_id.val + m.size.val ∧
                        ParentOf m start.val ≤ U32Max := ⟨fits_in_entry, by unfold ParentOf; omega⟩
                    simp only [AnswerOf, holds, and_self, ite_true, Option.map_some,
                      Option.some.injEq]
                    unfold ParentOf at *
                    omega
                  · rename_i parent_too_big
                    have parent_too_big : ¬ parent.val ≤ U32Max := by
                      have := (UScalar.le_equiv parent _).not.mp parent_too_big
                      omega
                    refine (WP.spec_ok _).mpr ?_
                    have fails : ¬ (start.val + len.val ≤ m.container_id.val + m.size.val ∧
                        ParentOf m start.val ≤ U32Max) := by
                      unfold ParentOf
                      omega
                    simp [AnswerOf, fails, found_none]
                · rename_i too_long
                  have too_long : ¬ start.val + len.val ≤ m.container_id.val + m.size.val := by
                    have := (UScalar.le_equiv range_end end_).not.mp too_long
                    omega
                  refine (WP.spec_ok _).mpr ?_
                  have fails : ¬ (start.val + len.val ≤ m.container_id.val + m.size.val ∧
                      ParentOf m start.val ≤ U32Max) := by omega
                  simp [AnswerOf, fails, found_none]
              · intro o answer
                refine (WP.spec_ok _).mpr (Or.inr ⟨rfl, maps.val.take i.val, m, [],
                  by simp [take_is],
                  none_before, has, answer⟩)
            · rename_i outside
              have outside : ¬ start.val < end_.val := by
                have := (UScalar.lt_equiv (core.convert.num.FromU64U32.from start) end_).not.mp
                  outside
                omega
              refine (WP.spec_ok _).mpr (Or.inl ⟨not_finished, found_none, ?_⟩)
              rw [take_is]
              intro e e_in
              rcases List.mem_append.mp e_in with e_in | e_in
              · exact none_before e e_in
              · rw [List.mem_singleton.mp e_in]
                unfold InContainers
                omega
          · rename_i starts_after
            have starts_after : start.val < m.container_id.val := by
              have := (UScalar.le_equiv m.container_id start).not.mp starts_after
              omega
            refine (WP.spec_ok _).mpr (Or.inl ⟨not_finished, found_none, ?_⟩)
            rw [take_is]
            intro e e_in
            rcases List.mem_append.mp e_in with e_in | e_in
            · exact none_before e e_in
            · rw [List.mem_singleton.mp e_in]
              unfold InContainers
              omega
        · intro r known_next
          obtain ⟨found1, done2⟩ := r
          step as ⟨ i2, is_i2 ⟩
          refine ⟨by omega, ?_, by omega⟩
          rw [is_i2]
          exact known_next
    · rename_i outside
      have : i.val = maps.length := by scalar_tac
      refine (WP.spec_ok _).mpr ?_
      rw [this, List.take_length] at known
      rcases known with ⟨_, found_none, none_have⟩ | ⟨_, finished⟩
      · exact Or.inl ⟨found_none, none_have⟩
      · exact Or.inr finished
  · exact ⟨by simp, Or.inl ⟨rfl, rfl, by simp⟩⟩

/-- **`range_to_parent`**: the loop gives `Finished`. -/
theorem range_to_parent_is_finished (maps : Slice Map) (start len : U32) :
    range_to_parent maps start len ⦃ found => Finished maps.val start len found ⦄ := by
  unfold range_to_parent
  exact range_to_parent_finds_the_first_entry maps start len

/-- If `range_to_parent` answers `q`, an entry has the range and `q` is what it gives. -/
theorem an_answer_comes_from_an_entry (maps : Slice Map) (start len : U32) :
    range_to_parent maps start len ⦃ r =>
      ∀ q, r = some q → ∃ e ∈ maps.val, InContainers e start.val ∧
        start.val + len.val ≤ e.container_id.val + e.size.val ∧ q.val = ParentOf e start.val ∧
        ∀ k, k < len.val → Maps maps.val (start.val + k) (q.val + k) ⦄ := by
  step with range_to_parent_is_finished maps start len as ⟨ found, finished ⟩
  rename_i q is_q
  rcases finished with ⟨found_none, _⟩ | ⟨before, e, after, is_maps, _, has, answer⟩
  · simp [found_none] at is_q
  · subst is_q
    simp only [Option.map_some] at answer
    unfold AnswerOf at answer
    split at answer
    · rename_i fits
      simp only [Option.some.injEq] at answer
      have e_in : e ∈ maps.val := by rw [is_maps]; simp
      refine ⟨e, e_in, has, fits.1, answer, fun k below => ?_⟩
      unfold InContainers at has
      refine ⟨e, e_in, ?_, ?_⟩
      · unfold InContainers
        omega
      · unfold ParentOf at answer
        omega
    · simp at answer

/-- For a valid list, an entry that has `start` and the whole range gives the answer. -/
theorem an_entry_with_the_range_gives_the_answer (maps : Slice Map) (start len : U32)
    (valid : Valid maps.val) (e : Map) (e_in : e ∈ maps.val) (has : InContainers e start.val)
    (fits : start.val + len.val ≤ e.container_id.val + e.size.val) :
    range_to_parent maps start len ⦃ r => ∃ q, r = some q ∧ q.val = ParentOf e start.val ⦄ := by
  step with range_to_parent_is_finished maps start len as ⟨ found, finished ⟩
  rcases finished with ⟨_, none_has⟩ | ⟨before, first, after, is_maps, _, first_has, answer⟩
  · exact absurd has (none_has e e_in)
  · have first_in : first ∈ maps.val := by rw [is_maps]; simp
    have same : first = e := by
      by_contra different
      have apart := entries_of_a_valid_list_are_apart maps.val valid first e first_in e_in different
      exact apart.1 start.val ⟨first_has, has⟩
    subst same
    have sane := valid.2.1 first first_in
    unfold Sane IdLimit at sane
    unfold AnswerOf at answer
    have holds : start.val + len.val ≤ first.container_id.val + first.size.val ∧
        ParentOf first start.val ≤ U32Max := by
      refine ⟨fits, ?_⟩
      unfold ParentOf U32Max
      unfold InContainers at first_has
      omega
    simp only [holds, and_self, ite_true] at answer
    cases found with
    | none => simp at answer
    | some q => exact ⟨q, rfl, by simpa using answer⟩

end IdmapCore
