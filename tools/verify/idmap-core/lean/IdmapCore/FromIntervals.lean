-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `IdSet::from_intervals` (crates/idmap-core) builds an ordered set that has
-- exactly the ids of the intervals it is given.  It has three loops: the first puts each interval
-- that is not empty into a list in order of its start (an insertion sort: the new interval is
-- written at the end, and moved down while the one before it begins later), the second goes along
-- that list and joins each interval to the last one kept when it begins at or before where that
-- one ends.
--
-- Why it is needed: every `IdSet` of the crate is made by this function (the other functions that
-- make one call it, or cut one that it made), so its answer being `Ordered` is what the others
-- rely on.
--
-- Read before this file: Spec.lean (`Ordered`, `HasId`, `InRun`), Insertion.lean, HasIdFacts.lean,
-- Lists.lean.
--
-- Notation: as in Validate.lean; `before ++ spare :: after` is a list of the elements `before`,
-- then `spare`, then `after`.
import IdmapCore.Spec
import IdmapCore.Insertion
import IdmapCore.Lists
import IdmapCore.HasIdFacts

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- The inner loop of the first loop of `from_intervals`: the list is `before ++ spare :: after`
with the new interval at the end of `after`'s place; it moves the spare place down while the
interval before it begins after the new one, and ends with the place where the new interval goes:
the intervals before begin at or before it, those after begin after it. -/
theorem from_intervals_moves_the_new_interval_down (s : U64)
    (sorted : alloc.vec.Vec (U64 × U64)) (j : Usize) (before after : List (U64 × U64))
    (spare : U64 × U64) (is_sorted : sorted.val = before ++ spare :: after)
    (is_j : j.val = before.length)
    (all_after_start_later : ∀ a ∈ after, s.val < a.1.val) :
    IdSet.from_intervals_loop0_loop0 sorted s j ⦃ r =>
      ∃ before' after' spare', r.1.val = before' ++ spare' :: after' ∧
        before' ++ after' = before ++ after ∧ r.2.val = before'.length ∧
        (∀ a ∈ after', s.val < a.1.val) ∧
        (before' = [] ∨ ∃ init last, before' = init ++ [last] ∧ last.1.val ≤ s.val) ⦄ := by
  unfold IdSet.from_intervals_loop0_loop0
  apply loop.spec_decr_nat (fun q => q.2.val)
    (fun q => ∃ before' after' spare', q.1.val = before' ++ spare' :: after' ∧
        before' ++ after' = before ++ after ∧ q.2.val = before'.length ∧
        (∀ a ∈ after', s.val < a.1.val))
  · rintro ⟨sorted1, j1⟩ ⟨before1, after1, spare1, is_sorted1, same, is_j1, later⟩
    simp only at is_sorted1 same is_j1 later ⊢
    unfold IdSet.from_intervals_loop0_loop0.body
    split
    · rename_i positive
      have positive : 0 < j1.val := by scalar_tac
      step as ⟨ i, hi ⟩
      obtain ⟨init, last, is_before1⟩ : ∃ init last, before1 = init ++ [last] := by
        rcases List.eq_nil_or_concat before1 with empty | ⟨init, last, is_before1⟩
        · simp [empty] at is_j1; omega
        · exact ⟨init, last, by simpa using is_before1⟩
      have last_is_before : sorted1.val[i.val]'(by simp [is_sorted1]; scalar_tac) = last :=
        the_element_before_the_spare init last spare1 after1 sorted1.val
          (by rw [is_sorted1, is_before1]) i.val (by simp [is_before1] at is_j1; omega)
          (by simp [is_sorted1]; scalar_tac)
      step as ⟨ start_before, end_before, is_before ⟩
      have start_is_last : start_before = last.1 := by
        rw [last_is_before] at is_before
        rw [← is_before]
      split
      · -- the interval before is greater: it is copied over the spare place
        rename_i greater
        have greater : s.val < last.1.val := by
          have : s < start_before := by scalar_tac
          rw [start_is_last] at this
          scalar_tac
        step as ⟨ copy, is_copy ⟩
        step as ⟨ spare_place, put, is_spare, put_is ⟩
        have copy_is_last : copy = last := by rw [is_copy]; exact last_is_before
        have sorted_is : sorted1.val = (init ++ [last]) ++ spare1 :: after1 := by
          rw [is_sorted1, is_before1]
        refine ⟨⟨init, last :: after1, last, ?_, ?_, ?_, ?_⟩, by omega⟩
        · rw [put_is, copy_is_last, alloc.vec.Vec.set_val_eq, sorted_is]
          have j1_is : j1.val = (init ++ [last]).length := by rw [is_j1, is_before1]
          rw [j1_is, copy_the_last_one_over_the_spare]
          simp
        · rw [is_before1] at same
          simpa using same
        · simp [hi, is_j1, is_before1]
        · intro a a_in
          rcases List.mem_cons.mp a_in with rfl | a_in
          · exact greater
          · exact later a a_in
      · -- it is not: this is the place
        rename_i not_greater
        have not_greater : last.1.val ≤ s.val := by
          have : ¬ s < start_before := by scalar_tac
          rw [start_is_last] at this
          scalar_tac
        exact (WP.spec_ok _).mpr ⟨before1, after1, spare1, is_sorted1, same, is_j1, later,
          Or.inr ⟨init, last, is_before1, not_greater⟩⟩
    · -- the new interval is at the front
      rename_i not_positive
      have : j1.val = 0 := by scalar_tac
      have empty : before1 = [] := List.length_eq_zero_iff.mp (by omega)
      exact (WP.spec_ok _).mpr ⟨before1, after1, spare1, is_sorted1, same, is_j1, later,
        Or.inl empty⟩
  · exact ⟨before, after, spare, is_sorted, rfl, is_j, all_after_start_later⟩

/-- The first loop of `from_intervals`: it adds each interval of the list that is not empty to
`sorted`, in its place, so that the starts stay in order. -/
theorem from_intervals_sorts_the_intervals (list : Slice (U64 × U64)) :
    IdSet.from_intervals_loop0 list (alloc.vec.Vec.new (U64 × U64)) 0#usize ⦃ sorted =>
      sorted.val.Pairwise (fun a b => a.1.val ≤ b.1.val) ∧
      (∀ iv, iv ∈ sorted.val ↔ (iv ∈ list.val ∧ iv.1.val < iv.2.val)) ∧
      sorted.val.length ≤ list.val.length ⦄ := by
  unfold IdSet.from_intervals_loop0
  apply loop.spec_decr_nat (fun q => list.length - q.2.val)
    (fun q => q.2.val ≤ list.length ∧
      q.1.val.length ≤ q.2.val ∧
      q.1.val.Pairwise (fun a b => a.1.val ≤ b.1.val) ∧
      ∀ iv, iv ∈ q.1.val ↔ (iv ∈ list.val.take q.2.val ∧ iv.1.val < iv.2.val))
  · rintro ⟨sorted, i⟩ ⟨bound, few, in_order, members⟩
    simp only at bound few in_order members ⊢
    unfold IdSet.from_intervals_loop0.body
    dsimp only [Slice.len]
    split
    · rename_i inside
      have inside : i.val < list.length := by scalar_tac
      step as ⟨ p, hp ⟩
      obtain ⟨s, e⟩ := p
      have next_members : ∀ iv, iv ∈ list.val.take (i.val + 1) ↔
          (iv ∈ list.val.take i.val ∨ iv = (s, e)) := by
        intro iv
        rw [take_one_more list.val i.val inside, ← hp]
        simp
      simp only [Std.uncurry_apply_pair]
      split
      · -- the interval has ids: it is put in its place
        rename_i has_ids
        have has_ids : s.val < e.val := by scalar_tac
        have room : sorted.val.length < Usize.max := by scalar_tac
        step as ⟨ sorted1, is_sorted1 ⟩
        have sorted1_has_one_more : sorted1.val.length = sorted.val.length + 1 := by
          simp [is_sorted1]
        step as ⟨ j, is_j ⟩
        step with from_intervals_moves_the_new_interval_down s sorted1 j sorted.val []
          (s, e) (by simp [is_sorted1]) (by simp [is_j, is_sorted1]) (by simp)
          as ⟨ sorted2, j1, front, back, spare, is_sorted2, same_list, is_j1, later_start,
            place ⟩
        have front_back : front ++ back = sorted.val := by simpa using same_list
        have j1_inside : j1.val < sorted2.length := by
          simp [is_sorted2, is_j1]
        step as ⟨ spare_place, put, is_spare, put_is ⟩
        step as ⟨ i3, is_i3 ⟩
        have written : (put (s, e)).val = front ++ (s, e) :: back := by
          rw [put_is, alloc.vec.Vec.set_val_eq, is_sorted2, is_j1]
          exact write_over_the_spare front spare back (s, e)
        refine ⟨by omega, ?_, ?_, ?_, by omega⟩
        · rw [written]
          have := congrArg List.length front_back
          simp at this ⊢
          omega
        · rw [written]
          refine sorted_after_inserting (fun a => a.1.val) front back (s, e)
            (by rw [front_back]; exact in_order) ?_
            (fun a a_in => Nat.le_of_lt (later_start a a_in))
          rcases place with empty | ⟨init, last, is_front, last_le⟩
          · simp [empty]
          · have sorted_front : (init ++ [last]).Pairwise (fun a b => a.1.val ≤ b.1.val) := by
              rw [is_front] at front_back
              rw [← front_back] at in_order
              exact List.Pairwise.sublist (List.sublist_append_left _ _) in_order
            rw [is_front]
            intro b b_in
            have := every_key_is_at_most_the_last (fun a => a.1.val) init last sorted_front
            rcases List.mem_append.mp b_in with b_in | b_in
            · exact Nat.le_trans (this b b_in) last_le
            · rw [List.mem_singleton.mp b_in]; exact last_le
        · intro iv
          rw [written, is_i3, next_members iv]
          simp only [List.mem_append, List.mem_cons]
          constructor
          · rintro (in_front | rfl | in_back)
            · have := (members iv).mp (by rw [← front_back]; exact List.mem_append_left _ in_front)
              exact ⟨Or.inl this.1, this.2⟩
            · exact ⟨Or.inr rfl, has_ids⟩
            · have := (members iv).mp (by rw [← front_back]; exact List.mem_append_right _ in_back)
              exact ⟨Or.inl this.1, this.2⟩
          · rintro ⟨in_take | rfl, nonempty⟩
            · have := (members iv).mpr ⟨in_take, nonempty⟩
              rw [← front_back] at this
              rcases List.mem_append.mp this with h | h
              · exact Or.inl h
              · exact Or.inr (Or.inr h)
            · exact Or.inr (Or.inl rfl)
      · -- the interval is empty: it is left out
        rename_i no_ids
        have no_ids : e.val ≤ s.val := by scalar_tac
        step as ⟨ i2, is_i2 ⟩
        refine ⟨by omega, by omega, in_order, ?_, by omega⟩
        intro iv
        rw [is_i2, next_members iv, members iv]
        constructor
        · exact fun in_take => ⟨Or.inl in_take.1, in_take.2⟩
        · rintro ⟨in_take | rfl, nonempty⟩
          · exact ⟨in_take, nonempty⟩
          · simp only at nonempty
            omega
    · -- every interval was read
      rename_i outside
      have : i.val = list.length := by scalar_tac
      have same_length : list.length = list.val.length := rfl
      refine (WP.spec_ok _).mpr ⟨in_order, ?_, by omega⟩
      rw [this] at members
      simpa using members
  · exact ⟨by simp, by simp [alloc.vec.Vec.new], by simp [alloc.vec.Vec.new],
      by simp [alloc.vec.Vec.new]⟩

/-- The second loop of `from_intervals`: it goes along the intervals in order of start, and joins
each to the last interval kept when it begins at or before where that one ends. -/
theorem from_intervals_joins_the_intervals (sorted : alloc.vec.Vec (U64 × U64))
    (in_order : sorted.val.Pairwise (fun a b => a.1.val ≤ b.1.val))
    (have_ids : ∀ iv ∈ sorted.val, iv.1.val < iv.2.val) :
    IdSet.from_intervals_loop1 sorted (alloc.vec.Vec.new (U64 × U64)) 0#usize ⦃ out =>
      Ordered out.val ∧ (∀ id, HasId out.val id ↔ HasId sorted.val id) ∧
      out.val.length ≤ sorted.val.length ⦄ := by
  unfold IdSet.from_intervals_loop1
  apply loop.spec_decr_nat (fun q => sorted.length - q.2.val)
    (fun q => q.2.val ≤ sorted.length ∧ q.1.val.length ≤ q.2.val ∧ Ordered q.1.val ∧
      (∀ iv ∈ q.1.val, ∀ later ∈ sorted.val.drop q.2.val, iv.1.val ≤ later.1.val) ∧
      ∀ id, HasId q.1.val id ↔ HasId (sorted.val.take q.2.val) id)
  · rintro ⟨out, i⟩ ⟨bound, few, ordered, starts_before, covers⟩
    simp only at bound few ordered starts_before covers ⊢
    unfold IdSet.from_intervals_loop1.body
    dsimp only [Slice.len]
    split
    · rename_i inside
      have inside : i.val < sorted.length := by scalar_tac
      step as ⟨ s, e, is_cur ⟩
      have has_ids : s.val < e.val :=
        have_ids (s, e) (by rw [is_cur]; exact List.getElem_mem _)
      have drop_is : sorted.val.drop i.val = (s, e) :: sorted.val.drop (i.val + 1) := by
        rw [List.drop_eq_getElem_cons inside, ← is_cur]
      have take_is : sorted.val.take (i.val + 1) = sorted.val.take i.val ++ [(s, e)] := by
        rw [take_one_more sorted.val i.val inside, ← is_cur]
      have start_after_out : ∀ iv ∈ out.val, iv.1.val ≤ s.val := fun iv iv_in =>
        starts_before iv iv_in (s, e) (by rw [drop_is]; exact List.mem_cons_self)
      have starts_after_out : ∀ iv ∈ out.val, ∀ later ∈ sorted.val.drop (i.val + 1),
          iv.1.val ≤ later.1.val := fun iv iv_in later later_in =>
        starts_before iv iv_in later (by rw [drop_is]; exact List.mem_cons_of_mem _ later_in)
      have later_start : ∀ later ∈ sorted.val.drop (i.val + 1), s.val ≤ later.1.val := by
        have := in_order
        rw [← List.take_append_drop i.val sorted.val, drop_is, List.pairwise_append,
          List.pairwise_cons] at this
        exact this.2.1.1
      refine WP.spec_bind (Pₘ := fun out1 =>
        out1.val.length ≤ i.val + 1 ∧ Ordered out1.val ∧
        (∀ iv ∈ out1.val, ∀ later ∈ sorted.val.drop (i.val + 1), iv.1.val ≤ later.1.val) ∧
        ∀ id, HasId out1.val id ↔ HasId (sorted.val.take (i.val + 1)) id) ?_ ?_
      · have : sorted.val.length ≤ Usize.max := sorted.property
        have same_length : sorted.length = sorted.val.length := rfl
        have room : out.val.length < Usize.max := by scalar_tac
        have out_has_nothing_else : ∀ id, HasId out.val id ↔ HasId (sorted.val.take i.val) id :=
          covers
        split
        · -- some interval is kept: the new one is joined to the last, or follows it
          rename_i kept
          obtain ⟨init, last, is_out⟩ : ∃ init last, out.val = init ++ [last] := by
            rcases List.eq_nil_or_concat out.val with empty | ⟨init, last, is_out⟩
            · simp [alloc.vec.Vec.len, empty] at kept
            · exact ⟨init, last, by simpa using is_out⟩
          step as ⟨ i2, is_i2 ⟩
          step as ⟨ start_last, end_last, is_last ⟩
          have len_is : out.len.val = init.length + 1 := by
            have : out.len.val = out.val.length := rfl
            rw [this, is_out]
            simp
          have is_i2' : i2.val = init.length := by omega
          have i2_inside : i2.val < out.val.length := by
            rw [is_out]
            simp [is_i2']
          have last_is : (start_last, end_last) = last := by
            rw [is_last]
            exact the_element_before_the_spare_at_the_end init last out.val is_out i2.val is_i2'
              i2_inside
          have start_last_is : start_last.val = last.1.val := by rw [← last_is]
          have end_last_is : end_last.val = last.2.val := by rw [← last_is]
          have ordered_out := ordered
          obtain ⟨init_have_ids, ordered_pairs⟩ := ordered
          rw [is_out] at init_have_ids ordered_pairs
          have last_has_ids : last.1.val < last.2.val :=
            init_have_ids last (List.mem_append_right _ (List.mem_singleton_self last))
          have init_before_last : ∀ a ∈ init, a.2.val < last.1.val := by
            have := (List.pairwise_append.mp ordered_pairs).2.2
            exact fun a a_in => this a a_in last (List.mem_singleton_self last)
          have init_pairs : init.Pairwise (fun a b => a.2.val < b.1.val) :=
            (List.pairwise_append.mp ordered_pairs).1
          have init_have_ids' : ∀ iv ∈ init, iv.1.val < iv.2.val :=
            fun iv iv_in => init_have_ids iv (List.mem_append_left _ iv_in)
          have last_in_out : last ∈ out.val := by
            rw [is_out]
            exact List.mem_append_right init (List.mem_singleton_self last)
          have last_start_before : last.1.val ≤ s.val := start_after_out last last_in_out
          have covers_init_last : ∀ id, HasId (sorted.val.take i.val) id ↔
              HasId init id ∨ InRun last id := by
            intro id
            rw [← covers id, is_out, has_id_after_adding]
          split
          · -- the new interval begins where the last one is, or before its end
            rename_i touches_raw
            have touches : s.val ≤ last.2.val := by
              have := (UScalar.le_equiv s end_last).mp touches_raw
              omega
            step as ⟨ start_again, end_again, is_again ⟩
            have end_again_is : end_again.val = last.2.val := by
              have : (start_again, end_again) = last :=
                is_again.trans (is_last.symm.trans last_is).symm.symm
              rw [← this]
            split
            · -- it goes on past the end of the last: the last is made longer
              rename_i longer_raw
              have longer : last.2.val < e.val := by
                have := (UScalar.lt_equiv end_again e).mp longer_raw
                omega
              step as ⟨ extended_start, extended_end, extended_back, is_extended, is_back ⟩
              have extended_is_last : (extended_start, extended_end) = last :=
                is_extended.trans (is_last.symm.trans last_is).symm.symm
              have extended_start_is : extended_start = last.1 := by
                have := congrArg Prod.fst extended_is_last
                exact this
              have new_is : (extended_back (extended_start, e)).val = init ++ [(last.1, e)] := by
                rw [is_back, alloc.vec.Vec.set_val_eq, is_out, is_i2', extended_start_is]
                exact write_over_the_spare init last [] (last.1, e)
              rw [new_is]
              refine ⟨?_, ⟨?_, ?_⟩, ?_, ?_⟩
              · have := congrArg List.length is_out
                simp at this ⊢
                omega
              · intro iv iv_in
                rcases List.mem_append.mp iv_in with iv_in | iv_in
                · exact init_have_ids' iv iv_in
                · rw [List.mem_singleton.mp iv_in]
                  simp only
                  omega
              · rw [List.pairwise_append]
                exact ⟨init_pairs, List.pairwise_singleton _ _, fun a a_in y y_in => by
                  rw [List.mem_singleton.mp y_in]
                  exact init_before_last a a_in⟩
              · intro iv iv_in later later_in
                rcases List.mem_append.mp iv_in with iv_in | iv_in
                · exact starts_after_out iv (by rw [is_out]; exact List.mem_append_left _ iv_in)
                    later later_in
                · rw [List.mem_singleton.mp iv_in]
                  exact starts_after_out last last_in_out later later_in
              · intro id
                rw [take_is, has_id_after_adding, has_id_after_adding, covers_init_last]
                have same_ids : InRun (last.1, e) id ↔ InRun last id ∨ InRun (s, e) id := by
                  simp only [InRun]
                  omega
                rw [same_ids]
                tauto
            · rename_i not_longer_raw
              have not_longer : e.val ≤ last.2.val := by
                have := (UScalar.lt_equiv end_again e).not.mp (by simpa using not_longer_raw)
                omega
              refine (WP.spec_ok _).mpr ⟨by omega, ordered_out, starts_after_out, ?_⟩
              intro id
              rw [take_is, has_id_after_adding, ← covers id]
              have covers_last : InRun (s, e) id → HasId out.val id := by
                intro in_run
                refine ⟨last, last_in_out, ?_⟩
                simp only [InRun] at in_run ⊢
                omega
              constructor
              · intro has
                exact Or.inl has
              · rintro (has | in_run)
                · exact has
                · exact covers_last in_run
          · -- the new interval begins after the end of the last: it is added
            rename_i apart_raw
            have apart : last.2.val < s.val := by
              have := (UScalar.le_equiv s end_last).not.mp apart_raw
              omega
            step as ⟨ out1, is_out1 ⟩
            rw [is_out1]
            refine ⟨?_, ⟨?_, ?_⟩, ?_, ?_⟩
            · simp
              omega
            · intro iv iv_in
              rcases List.mem_append.mp iv_in with iv_in | iv_in
              · exact init_have_ids iv (by rw [← is_out]; exact iv_in)
              · rw [List.mem_singleton.mp iv_in]
                exact has_ids
            · rw [List.pairwise_append]
              refine ⟨by rw [is_out]; exact ordered_pairs, List.pairwise_singleton _ _, ?_⟩
              intro a a_in y y_in
              rw [List.mem_singleton.mp y_in]
              rw [is_out] at a_in
              rcases List.mem_append.mp a_in with a_in | a_in
              · have := init_before_last a a_in
                simp only
                omega
              · rw [List.mem_singleton.mp a_in]
                simp only
                omega
            · intro iv iv_in later later_in
              rcases List.mem_append.mp iv_in with iv_in | iv_in
              · exact starts_after_out iv iv_in later later_in
              · rw [List.mem_singleton.mp iv_in]
                exact later_start later later_in
            · intro id
              rw [take_is, has_id_after_adding, has_id_after_adding, covers id]
        · -- nothing is kept yet: the new interval is the first
          rename_i nothing
          have empty : out.val = [] := by
            have not_positive := (UScalar.lt_equiv 0#usize out.len).not.mp nothing
            have : out.val.length = 0 := by
              have : out.len.val = out.val.length := rfl
              have zero : (0#usize).val = 0 := rfl
              omega
            exact List.length_eq_zero_iff.mp this
          step as ⟨ out1, is_out1 ⟩
          refine ⟨by simp [is_out1, empty], ?_, ?_, ?_⟩
          · refine ⟨?_, ?_⟩
            · intro iv iv_in
              simp [is_out1, empty] at iv_in
              rw [iv_in]
              exact has_ids
            · simp [is_out1, empty]
          · intro iv iv_in later later_in
            simp [is_out1, empty] at iv_in
            rw [iv_in]
            exact later_start later later_in
          · intro id
            have no_ids_before := (covers id).mp
            rw [empty] at no_ids_before
            rw [take_is, is_out1, empty, has_id_after_adding, has_id_after_adding]
            constructor
            · rintro (in_empty | in_run)
              · exact absurd in_empty (no_id_in_the_empty_list id)
              · exact Or.inr in_run
            · rintro (in_take | in_run)
              · have := (covers id).mpr in_take
                rw [empty] at this
                exact absurd this (no_id_in_the_empty_list id)
              · exact Or.inr in_run
      · intro out1 ⟨few1, ordered1, starts1, covers1⟩
        step as ⟨ i2, is_i2 ⟩
        refine ⟨by omega, by omega, ordered1, ?_, ?_, by omega⟩
        · rw [is_i2]
          exact starts1
        · rw [is_i2]
          exact covers1
    · -- every interval was read
      rename_i outside
      have : i.val = sorted.length := by scalar_tac
      have same_length : sorted.length = sorted.val.length := rfl
      refine (WP.spec_ok _).mpr ⟨ordered, ?_, by omega⟩
      have := covers
      rw [‹i.val = sorted.length›] at this
      simpa using this
  · refine ⟨by simp, by simp [alloc.vec.Vec.new],
      ⟨by simp [alloc.vec.Vec.new], by simp [alloc.vec.Vec.new]⟩,
      by simp [alloc.vec.Vec.new], fun id => by simp [alloc.vec.Vec.new, HasId]⟩

/-- An interval that has an id is not empty. -/
theorem an_interval_with_an_id_is_not_empty (iv : U64 × U64) (id : Nat) (has_id : InRun iv id) :
    iv.1.val < iv.2.val := by
  unfold InRun at has_id
  omega

/-- **`from_intervals`**: it returns an ordered list of intervals that has exactly the ids of the
intervals it is given, and no more intervals than it is given. -/
theorem from_intervals_is_the_union_with_few_intervals (list : Slice (U64 × U64)) :
    IdSet.from_intervals list ⦃ s =>
      Ordered s.intervals.val ∧ (∀ id, HasId s.intervals.val id ↔ HasId list.val id) ∧
      s.intervals.val.length ≤ list.val.length ⦄ := by
  unfold IdSet.from_intervals
  step with from_intervals_sorts_the_intervals list as ⟨ sorted, in_order, members, few ⟩
  step with from_intervals_joins_the_intervals sorted in_order
    (fun iv iv_in => ((members iv).mp iv_in).2) as ⟨ out, ordered, covers, few_out ⟩
  refine ⟨ordered, fun id => ?_, by omega⟩
  rw [covers id]
  constructor
  · rintro ⟨iv, iv_in, in_run⟩
    exact ⟨iv, ((members iv).mp iv_in).1, in_run⟩
  · rintro ⟨iv, iv_in, in_run⟩
    exact ⟨iv, (members iv).mpr ⟨iv_in, an_interval_with_an_id_is_not_empty iv id in_run⟩, in_run⟩

/-- **`from_intervals`**: it returns an ordered list of intervals that has exactly the ids of the
intervals it is given. -/
theorem from_intervals_is_the_union (list : Slice (U64 × U64)) :
    IdSet.from_intervals list ⦃ s =>
      Ordered s.intervals.val ∧ ∀ id, HasId s.intervals.val id ↔ HasId list.val id ⦄ :=
  WP.spec_mono (from_intervals_is_the_union_with_few_intervals list)
    (fun _ h => ⟨h.1, h.2.1⟩)

end IdmapCore
