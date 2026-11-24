-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `IdSet::zip`, which pairs the parent ids of one set with the container
-- ids of another, both in order, and writes each run of ids that go together as one entry.  The
-- loop keeps a cursor in each set (Cursor.lean); each turn it takes as many ids as both
-- intervals have left, writes one entry for them, and moves the cursors on.
--
-- What is proved: every entry has ids and ends before the limit, the entries are apart (no
-- container id and no parent id twice), every id the entries map is an id of the sets, and, when
-- the second set has no more ids than the first, every id of the second set is mapped.
--
-- Read before this file: Spec.lean, Cursor.lean, IdSetBelow.lean.
import IdmapCore.Cursor
import IdmapCore.IdSetBelow
import IdmapCore.Limits

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- How many ids the entries have in all (the sum of their sizes). -/
def Weight (maps : List Map) : Nat := (maps.map (fun e => e.size.val)).sum

/-- What `zip` makes is made of entries that have ids, end before the limit, and are apart; it
maps only ids of the two sets, and, when the second has no more ids than the first, every id of
the second set. -/
def ZipResult (hosts ctrs : List (U64 × U64)) (out : List Map) : Prop :=
  (∀ e ∈ out, Sane e) ∧ out.Pairwise Apart ∧
  (∀ c p, Maps out c p → HasId hosts p ∧ HasId ctrs c) ∧
  (Total ctrs ≤ Total hosts → ∀ c, HasId ctrs c → ∃ p, Maps out c p) ∧ out.length ≤ IdLimit ∧
  out.length ≤ hosts.length + ctrs.length

/-- The state of the loop of `zip` at any turn.  `out` is what is written; each cursor
(`i`, `hs` for the parent ids and `j`, `cs` for the container ids) has handed out exactly the ids
of the entries written, and as many; every entry written is before both cursors (so there are
no more entries than the container id the cursor is at: the list can grow), and no more than
the intervals the two cursors have left behind (each entry uses up an interval of one of the
sets). -/
def ZipState (hosts ctrs : List (U64 × U64)) (out : List Map) (i j : Nat) (hs cs : Nat) : Prop :=
  i ≤ hosts.length ∧ j ≤ ctrs.length ∧ Within hosts i hs ∧ Within ctrs j cs ∧
  hs ≤ IdLimit ∧ cs ≤ IdLimit ∧
  (∀ e ∈ out, 0 < e.size.val ∧ e.container_id.val + e.size.val ≤ cs ∧
    e.parent_id.val + e.size.val ≤ hs) ∧
  out.Pairwise Apart ∧
  (∀ p, (∃ e ∈ out, InParents e p) ↔ Reached hosts i hs p) ∧
  (∀ c, (∃ e ∈ out, InContainers e c) ↔ Reached ctrs j cs c) ∧
  Weight out = Passed hosts i hs ∧ Weight out = Passed ctrs j cs ∧ out.length ≤ cs ∧
  out.length ≤ i + j

/-- **One more entry.**  The entry `new` takes the `n` (at least one) next ids of both cursors,
which are both in an interval that has them, and one of which it ends (`n` is the smaller of
what the two intervals have left); the cursors move on (`advance_cursor`).  The loop is
then in a state again, and the cursor of the parent ids has handed out more ids than before. -/
theorem zip_state_after_one_more_entry (hosts ctrs : List (U64 × U64))
    (hosts_ordered : Ordered hosts) (ctrs_ordered : Ordered ctrs)
    (hosts_below : ∀ x ∈ hosts, x.2.val ≤ IdLimit) (ctrs_below : ∀ x ∈ ctrs, x.2.val ≤ IdLimit)
    (out : List Map) (i j hs cs : Nat) (state : ZipState hosts ctrs out i j hs cs)
    (host_run ctr_run : U64 × U64) (is_host_run : hosts[i]? = some host_run)
    (is_ctr_run : ctrs[j]? = some ctr_run) (n : Nat) (more : 0 < n)
    (fits_host : hs + n ≤ host_run.2.val) (fits_ctr : cs + n ≤ ctr_run.2.val)
    (ends : hs + n = host_run.2.val ∨ cs + n = ctr_run.2.val)
    (i' j' hs' cs' : Nat)
    (moved_host : (hs + n = host_run.2.val ∧ i' = i + 1 ∧ hs' = StartOfNext hosts i (hs + n)) ∨
      (hs + n < host_run.2.val ∧ i' = i ∧ hs' = hs + n))
    (moved_ctr : (cs + n = ctr_run.2.val ∧ j' = j + 1 ∧ cs' = StartOfNext ctrs j (cs + n)) ∨
      (cs + n < ctr_run.2.val ∧ j' = j ∧ cs' = cs + n))
    (new : Map) (new_container : new.container_id.val = cs) (new_parent : new.parent_id.val = hs)
    (new_size : new.size.val = n) :
    ZipState hosts ctrs (out ++ [new]) i' j' hs' cs' ∧
    Total hosts - Passed hosts i' hs' < Total hosts - Passed hosts i hs := by
  obtain ⟨i_le, j_le, within_h, within_c, hs_le, cs_le, before, apart, host_ids, ctr_ids,
    weight_h, weight_c, few, entries_few⟩ := state
  obtain ⟨reach_h, within_h', passed_h, hs_le', bound_h⟩ := advance_cursor hosts hosts_ordered i
    hs n host_run is_host_run within_h fits_host i' hs' moved_host
  obtain ⟨reach_c, within_c', passed_c, cs_le', bound_c⟩ := advance_cursor ctrs ctrs_ordered j cs n
    ctr_run is_ctr_run within_c fits_ctr j' cs' moved_ctr
  have hs'_le : hs' ≤ IdLimit := bound_h IdLimit hosts_below
  have cs'_le : cs' ≤ IdLimit := bound_c IdLimit ctrs_below
  have weight : Weight (out ++ [new]) = Weight out + n := by simp [Weight, new_size]
  have inside_host := a_cursor_inside_has_not_passed_the_interval hosts i hs host_run
    is_host_run within_h
  have host_len : i' ≤ hosts.length := by
    rcases moved_host with ⟨_, rfl, _⟩ | ⟨_, rfl, _⟩
    · exact (List.getElem?_eq_some_iff.mp is_host_run).1
    · exact i_le
  have ctr_len : j' ≤ ctrs.length := by
    rcases moved_ctr with ⟨_, rfl, _⟩ | ⟨_, rfl, _⟩
    · exact (List.getElem?_eq_some_iff.mp is_ctr_run).1
    · exact j_le
  have passed_le := a_cursor_has_not_passed_the_set hosts i' hs' within_h'
  refine ⟨⟨host_len, ctr_len, within_h', within_c', hs'_le, cs'_le, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_⟩, ?_⟩
  · intro e e_in
    rcases List.mem_append.mp e_in with e_in | e_in
    · have := before e e_in
      exact ⟨this.1, by omega, by omega⟩
    · rw [List.mem_singleton.mp e_in]
      exact ⟨by omega, by omega, by omega⟩
  · rw [List.pairwise_append]
    refine ⟨apart, List.pairwise_singleton _ _, fun e e_in y y_in => ?_⟩
    rw [List.mem_singleton.mp y_in]
    have := before e e_in
    constructor
    · intro id ⟨in_e, in_new⟩
      unfold InContainers at in_e in_new
      omega
    · intro id ⟨in_e, in_new⟩
      unfold InParents at in_e in_new
      omega
  · intro p
    rw [reach_h p, ← host_ids p]
    simp only [List.mem_append, List.mem_singleton, or_and_right, exists_or,
      exists_eq_left]
    unfold InParents
    rw [new_parent, new_size]
  · intro c
    rw [reach_c c, ← ctr_ids c]
    simp only [List.mem_append, List.mem_singleton, or_and_right, exists_or,
      exists_eq_left]
    unfold InContainers
    rw [new_container, new_size]
  · rw [weight, passed_h, weight_h]
  · rw [weight, passed_c, weight_c]
  · simp
    omega
  · simp
    omega
  · omega

/-- **The end of the loop.**  When one of the two cursors has no interval left, the entries
written are the result: ids that go together, apart, and mapping only ids of the two sets, and
mapping all the ids of the second one when it has no more ids than the first. -/
theorem zip_state_at_the_end_is_the_result (hosts ctrs : List (U64 × U64))
    (out : List Map) (i j hs cs : Nat) (state : ZipState hosts ctrs out i j hs cs)
    (exit : hosts.length ≤ i ∨ ctrs.length ≤ j) : ZipResult hosts ctrs out := by
  obtain ⟨i_le, j_le, within_h, within_c, hs_le, cs_le, before, apart, host_ids, ctr_ids,
    weight_h, weight_c, few, entries_few⟩ := state
  have in_hosts : ∀ e ∈ out, ∀ p, InParents e p → HasId hosts p := fun e e_in p in_e =>
    a_reached_id_is_in_the_set hosts i hs within_h p ((host_ids p).mp ⟨e, e_in, in_e⟩)
  have in_ctrs : ∀ e ∈ out, ∀ c, InContainers e c → HasId ctrs c := fun e e_in c in_e =>
    a_reached_id_is_in_the_set ctrs j cs within_c c ((ctr_ids c).mp ⟨e, e_in, in_e⟩)
  refine ⟨fun e e_in => ?_, apart, ?_, fun fewer c has => ?_, by omega, by omega⟩
  · have := before e e_in
    exact ⟨this.1, by omega, by omega⟩
  · rintro c p ⟨e, e_in, in_e, is_p⟩
    refine ⟨in_hosts e e_in p ?_, in_ctrs e e_in c in_e⟩
    unfold InParents InContainers at *
    omega
  · -- the second set is used up: if it were not, the first would have fewer ids
    have used_up : ctrs.length ≤ j := by
      by_contra not_used_up
      have inside : j < ctrs.length := Nat.lt_of_not_le not_used_up
      have hosts_end : hosts.length ≤ i := by
        rcases exit with at_end | at_end
        · exact at_end
        · exact absurd at_end not_used_up
      have all_passed := a_cursor_at_the_end_has_passed_all hosts i hs hosts_end
      have is_run : ctrs[j]? = some ctrs[j] := List.getElem?_eq_getElem inside
      have := a_cursor_inside_has_not_passed_the_interval ctrs j cs ctrs[j] is_run within_c
      omega
    obtain ⟨e, e_in, in_e⟩ := (ctr_ids c).mpr
      ((a_cursor_at_the_end_has_reached_all ctrs j cs used_up c).mpr has)
    exact ⟨e.parent_id.val + (c - e.container_id.val), e, e_in, in_e, rfl⟩

/-- **The loop of `zip`.**  From a state, it writes entries until one of the two cursors has no
interval left, and gives the result. -/
theorem zip_loop_writes_the_entries (v v1 : alloc.vec.Vec (U64 × U64))
    (hosts_ordered : Ordered v.val) (ctrs_ordered : Ordered v1.val)
    (hosts_below : ∀ x ∈ v.val, x.2.val ≤ IdLimit) (ctrs_below : ∀ x ∈ v1.val, x.2.val ≤ IdLimit)
    (out : alloc.vec.Vec Map) (i j : Usize) (hs cs : U64)
    (state : ZipState v.val v1.val out.val i.val j.val hs.val cs.val) :
    IdSet.zip_loop v v1 out i j hs cs ⦃ r => ZipResult v.val v1.val r.val ⦄ := by
  unfold IdSet.zip_loop
  apply loop.spec_decr_nat (fun q => Total v.val - Passed v.val q.2.1.val q.2.2.2.1.val)
    (fun q => ZipState v.val v1.val q.1.val q.2.1.val q.2.2.1.val q.2.2.2.1.val q.2.2.2.2.val)
  · rintro ⟨out, i, j, hs, cs⟩ state
    simp only at state ⊢
    unfold IdSet.zip_loop.body
    dsimp only
    have same_hosts : v.length = v.val.length := rfl
    have same_ctrs : v1.length = v1.val.length := rfl
    split
    · rename_i more_hosts
      have inside_h : i.val < v.val.length := by scalar_tac
      split
      · rename_i more_ctrs
        have inside_c : j.val < v1.val.length := by scalar_tac
        step as ⟨ hs0, he, is_host_run ⟩
        step as ⟨ cs0, ce, is_ctr_run ⟩
        have is_host_run' : v.val[i.val]? = some (hs0, he) := by
          rw [List.getElem?_eq_getElem inside_h, is_host_run]
        have is_ctr_run' : v1.val[j.val]? = some (cs0, ce) := by
          rw [List.getElem?_eq_getElem inside_c, is_ctr_run]
        have host_in : (hs0, he) ∈ v.val := List.mem_of_getElem? is_host_run'
        have ctr_in : (cs0, ce) ∈ v1.val := List.mem_of_getElem? is_ctr_run'
        have he_le : he.val ≤ IdLimit := hosts_below _ host_in
        have ce_le : ce.val ≤ IdLimit := ctrs_below _ ctr_in
        have within_h := state.2.2.1 (hs0, he) is_host_run'
        have within_c := state.2.2.2.1 (cs0, ce) is_ctr_run'
        simp only at within_h within_c
        step as ⟨ i3, is_i3 ⟩
        step as ⟨ i4, is_i4 ⟩
        refine WP.spec_bind (Pₘ := fun n : U64 => n.val = min (he.val - hs.val) (ce.val - cs.val))
          ?_ ?_
        · split
          · rename_i smaller
            have := (UScalar.lt_equiv i3 i4).mp smaller
            refine (WP.spec_ok _).mpr ?_
            omega
          · rename_i not_smaller
            have := (UScalar.lt_equiv i3 i4).not.mp not_smaller
            refine (WP.spec_ok _).mpr ?_
            omega
        intro n is_n
        simp only [Std.lift, Std.bind_ok]
        have cs_cast : (UScalar.cast UScalarTy.U32 cs).val = cs.val := by
          rw [UScalar.cast_val_eq]
          simp
          have := state.2.2.2.2.2.1
          unfold IdLimit at this
          omega
        have hs_cast : (UScalar.cast UScalarTy.U32 hs).val = hs.val := by
          rw [UScalar.cast_val_eq]
          simp
          have := state.2.2.2.2.1
          unfold IdLimit at this
          omega
        have n_cast : (UScalar.cast UScalarTy.U32 n).val = n.val := by
          rw [UScalar.cast_val_eq]
          simp
          unfold IdLimit at he_le
          omega
        have room : out.val.length < Usize.max := by
          have few := state.2.2.2.2.2.2.2.2.2.2.2.2.1
          have cs_le := state.2.2.2.2.2.1
          unfold IdLimit at ce_le
          scalar_tac
        step as ⟨ out1, is_out1 ⟩
        step as ⟨ hs1, is_hs1 ⟩
        step as ⟨ cs1, is_cs1 ⟩
        have n_le_host : n.val ≤ he.val - hs.val := by rw [is_n]; exact Nat.min_le_left _ _
        have n_le_ctr : n.val ≤ ce.val - cs.val := by rw [is_n]; exact Nat.min_le_right _ _
        have n_pos : 0 < n.val := by
          rw [is_n]
          exact Nat.lt_min.mpr ⟨by omega, by omega⟩
        have finish : ∀ (i8 j1 : Usize) (hs2 cs2 : U64),
            ((hs.val + n.val = he.val ∧ i8.val = i.val + 1 ∧
                hs2.val = StartOfNext v.val i.val (hs.val + n.val)) ∨
              (hs.val + n.val < he.val ∧ i8.val = i.val ∧ hs2.val = hs.val + n.val)) →
            ((cs.val + n.val = ce.val ∧ j1.val = j.val + 1 ∧
                cs2.val = StartOfNext v1.val j.val (cs.val + n.val)) ∨
              (cs.val + n.val < ce.val ∧ j1.val = j.val ∧ cs2.val = cs.val + n.val)) →
            ZipState v.val v1.val (out1.val) i8.val j1.val hs2.val cs2.val ∧
            Total v.val - Passed v.val i8.val hs2.val <
              Total v.val - Passed v.val i.val hs.val := by
          intro i8 j1 hs2 cs2 moved_h moved_c
          have := zip_state_after_one_more_entry v.val v1.val hosts_ordered ctrs_ordered
            hosts_below ctrs_below out.val i.val j.val hs.val cs.val state (hs0, he) (cs0, ce)
            is_host_run' is_ctr_run' n.val n_pos (by show hs.val + n.val ≤ he.val; omega)
            (by show cs.val + n.val ≤ ce.val; omega)
            (by show hs.val + n.val = he.val ∨ cs.val + n.val = ce.val; omega) i8.val j1.val
            hs2.val cs2.val moved_h moved_c
            ⟨UScalar.cast UScalarTy.U32 cs, UScalar.cast UScalarTy.U32 hs,
              UScalar.cast UScalarTy.U32 n⟩
            cs_cast hs_cast n_cast
          rw [is_out1]
          exact this
        refine WP.spec_bind (Pₘ := fun r : Usize × U64 =>
          (hs.val + n.val = he.val ∧ r.1.val = i.val + 1 ∧
            r.2.val = StartOfNext v.val i.val (hs.val + n.val)) ∨
          (hs.val + n.val < he.val ∧ r.1.val = i.val ∧ r.2.val = hs.val + n.val)) ?_ ?_
        · split
          · -- the interval of the parent ids is used up: the cursor goes to the next one
            rename_i used_up
            have used_up : hs.val + n.val = he.val := by
              have := congrArg UScalar.val used_up
              omega
            step as ⟨ i9, is_i9 ⟩
            split
            · rename_i has_next
              step as ⟨ next, e3 ⟩
              obtain ⟨hs3, he3⟩ := next
              have next_inside : i.val + 1 < v.val.length := by
                have := (UScalar.lt_equiv i9 v.len).mp has_next
                have same : v.len.val = v.val.length := rfl
                omega
              have is_next : v.val[i.val + 1]? = some (hs3, he3) := by
                rw [List.getElem?_eq_getElem next_inside]
                have : (hs3, he3) = v.val[i9.val] := e3
                simp only [is_i9] at this
                rw [this]
              refine WP.spec_bind (Pₘ := fun x : U64 => x = hs3) ((WP.spec_ok _).mpr rfl) ?_
              intro i11 is_i11
              refine (WP.spec_ok _).mpr ?_
              left
              exact ⟨used_up, is_i9, by simp [StartOfNext, is_next, is_i11]⟩
            · rename_i no_next
              simp only [Std.bind_ok]
              refine (WP.spec_ok _).mpr ?_
              left
              have : v.val[i.val + 1]? = none := List.getElem?_eq_none (by
                have := (UScalar.lt_equiv i9 v.len).not.mp no_next
                have same : v.len.val = v.val.length := rfl
                omega)
              refine ⟨used_up, is_i9, ?_⟩
              simp [StartOfNext, this]
              omega
          · rename_i not_used_up
            refine (WP.spec_ok _).mpr ?_
            right
            have : hs1.val ≠ he.val := fun same => not_used_up (UScalar.eq_of_val_eq same)
            exact ⟨by omega, rfl, by omega⟩
        intro ⟨i8, hs2⟩ moved_h
        simp only at moved_h
        split
        · rename_i ctr_used_up
          have ctr_used_up : cs.val + n.val = ce.val := by
            have := congrArg UScalar.val ctr_used_up
            omega
          step as ⟨ j1, is_j1 ⟩
          split
          · rename_i has_next
            step as ⟨ cs2, ce2, e2 ⟩
            have next_inside : j.val + 1 < v1.val.length := by
              have := (UScalar.lt_equiv j1 v1.len).mp has_next
              have same : v1.len.val = v1.val.length := rfl
              omega
            have is_next : v1.val[j.val + 1]? = some (cs2, ce2) := by
              rw [List.getElem?_eq_getElem next_inside]
              have : (cs2, ce2) = v1.val[j1.val] := e2
              simp only [is_j1] at this
              rw [this]
            exact finish i8 j1 hs2 cs2 moved_h
              (Or.inl ⟨ctr_used_up, is_j1, by simp [StartOfNext, is_next]⟩)
          · rename_i no_next
            refine (WP.spec_ok _).mpr
              (finish i8 j1 hs2 cs1 moved_h (Or.inl ⟨ctr_used_up, is_j1, ?_⟩))
            have : v1.val[j.val + 1]? = none := List.getElem?_eq_none (by
              have := (UScalar.lt_equiv j1 v1.len).not.mp no_next
              have same : v1.len.val = v1.val.length := rfl
              omega)
            simp [StartOfNext, this]
            omega
        · rename_i not_used_up
          have : cs1.val ≠ ce.val := fun same => not_used_up (UScalar.eq_of_val_eq same)
          exact (WP.spec_ok _).mpr (finish i8 j hs2 cs1 moved_h (Or.inr ⟨by omega, rfl, by omega⟩))
      · rename_i no_more_ctrs
        refine (WP.spec_ok _).mpr ?_
        exact zip_state_at_the_end_is_the_result _ _ _ _ _ _ _ state (Or.inr (by scalar_tac))
    · rename_i no_more_hosts
      refine (WP.spec_ok _).mpr ?_
      exact zip_state_at_the_end_is_the_result _ _ _ _ _ _ _ state (Or.inl (by scalar_tac))
  · exact state

/-- Ids that satisfy `P` exactly when they satisfy `Q` are as many. -/
theorem exactly_ids_are_the_same_for_equivalent_properties (P Q : Nat → Prop) (n : Nat)
    (same : ∀ id, P id ↔ Q id) (exactly : ExactlyIds P n) : ExactlyIds Q n := by
  obtain ⟨ids, nodup, has, len⟩ := exactly
  exact ⟨ids, nodup, fun id => by rw [has, same], len⟩

/-- Every interval of an ordered set whose ids are all below `IdLimit` ends at `IdLimit` at
most. -/
theorem intervals_of_a_set_below_the_limit_end_below_it (runs : List (U64 × U64))
    (ordered : Ordered runs) (below : ∀ id, HasId runs id → id < IdLimit) :
    ∀ x ∈ runs, x.2.val ≤ IdLimit := by
  intro x x_in
  have has_ids := ordered.1 x x_in
  have := below (x.2.val - 1) ⟨x, x_in, by simp only [InRun]; omega⟩
  omega

/-- Where a cursor starts: at the start of the first interval of the set, when it has one (and
at 0 when it has none: it is then never used). -/
theorem a_cursor_starts_at_the_first_interval (runs : alloc.vec.Vec (U64 × U64))
    (ordered : Ordered runs.val) (below : ∀ x ∈ runs.val, x.2.val ≤ IdLimit) (b : Bool)
    (is_b : (b = true) = (runs.length = 0)) :
    (if b = true then ok 0#u64 else do
      let (s, _) ← runs.index_usize 0#usize
      ok s) ⦃ cur =>
      Within runs.val 0 cur.val ∧ cur.val ≤ IdLimit ∧
      ∀ iv, runs.val[0]? = some iv → cur.val = iv.1.val ⦄ := by
  have same_length : runs.length = runs.val.length := rfl
  split
  · rename_i empty
    have empty : runs.val = [] := by
      have : runs.length = 0 := by rw [← is_b]; exact empty
      exact List.length_eq_zero_iff.mp (by omega)
    refine (WP.spec_ok _).mpr ⟨fun iv is_iv => by simp [empty] at is_iv, by simp [IdLimit],
      fun iv is_iv => by simp [empty] at is_iv⟩
  · rename_i not_empty
    have inside : 0 < runs.val.length := by
      have : ¬ runs.length = 0 := by rw [← is_b]; exact not_empty
      omega
    step as ⟨ s, e, is_first ⟩
    have is_run : runs.val[0]? = some (s, e) := by
      rw [List.getElem?_eq_getElem inside]
      have : (s, e) = runs.val[(0#usize).val] := is_first
      rw [this]
      rfl
    have in_runs : (s, e) ∈ runs.val := List.mem_of_getElem? is_run
    have has_ids := ordered.1 _ in_runs
    have end_le := below _ in_runs
    refine ⟨fun iv is_iv => ?_, ?_, fun iv is_iv => ?_⟩
    · have : iv = (s, e) := by simpa [is_run] using is_iv.symm
      subst this
      simp only at *
      omega
    · simp only at *
      omega
    · have : iv = (s, e) := by simpa [is_run] using is_iv.symm
      subst this
      rfl

/-- **`zip`**: for two ordered sets, it returns entries that have ids, end before the limit and
are apart, and map only ids that are below the limit and of the first set (the parent ids) and of
the second (the container ids).  When all the ids of both are below the limit, and the second
has no more ids than the first, every id of the second is mapped.  It has no more entries than
the two sets have intervals. -/
theorem zip_pairs_the_ids_in_order (self container : IdSet)
    (self_ordered : Ordered self.intervals.val)
    (container_ordered : Ordered container.intervals.val) :
    IdSet.zip self container ⦃ out =>
      (∀ e ∈ out.val, Sane e) ∧ out.val.Pairwise Apart ∧
      (∀ c p, Maps out.val c p →
        (HasId self.intervals.val p ∧ p < IdLimit) ∧
        (HasId container.intervals.val c ∧ c < IdLimit)) ∧
      ((∀ k m, ExactlyIds (fun id => HasId self.intervals.val id ∧ id < IdLimit) k →
          ExactlyIds (fun id => HasId container.intervals.val id ∧ id < IdLimit) m → m ≤ k) →
        ∀ c, HasId container.intervals.val c → c < IdLimit → ∃ p, Maps out.val c p) ∧
      out.val.length ≤ IdLimit ∧
      out.val.length ≤ self.intervals.val.length + container.intervals.val.length ⦄ := by
  unfold IdSet.zip
  rw [id_limit_is_the_largest_u32]
  step with below_is_the_ids_under_the_limit self 4294967295#u64 self_ordered as
    ⟨ hosts, hosts_ordered, hosts_ids, hosts_few ⟩
  step with below_is_the_ids_under_the_limit container 4294967295#u64 container_ordered as
    ⟨ ctrs, ctrs_ordered, ctrs_ids, ctrs_few ⟩
  have hosts_ids' : ∀ id, HasId hosts.intervals.val id ↔
      HasId self.intervals.val id ∧ id < IdLimit := hosts_ids
  have ctrs_ids' : ∀ id, HasId ctrs.intervals.val id ↔
      HasId container.intervals.val id ∧ id < IdLimit := ctrs_ids
  have hosts_below := intervals_of_a_set_below_the_limit_end_below_it hosts.intervals.val
    hosts_ordered (fun id has => ((hosts_ids' id).mp has).2)
  have ctrs_below := intervals_of_a_set_below_the_limit_end_below_it ctrs.intervals.val
    ctrs_ordered (fun id has => ((ctrs_ids' id).mp has).2)
  step as ⟨ b, is_b ⟩
  refine WP.spec_bind (a_cursor_starts_at_the_first_interval hosts.intervals hosts_ordered
    hosts_below b is_b) ?_
  intro hs ⟨within_h, hs_le, hs_start⟩
  step as ⟨ b1, is_b1 ⟩
  refine WP.spec_bind (a_cursor_starts_at_the_first_interval ctrs.intervals ctrs_ordered
    ctrs_below b1 is_b1) ?_
  intro cs ⟨within_c, cs_le, cs_start⟩
  have start_state : ZipState hosts.intervals.val ctrs.intervals.val
      (alloc.vec.Vec.new Map).val (0#usize).val (0#usize).val hs.val cs.val := by
    refine ⟨by simp, by simp, within_h, within_c, hs_le, cs_le, by simp [alloc.vec.Vec.new],
      by simp [alloc.vec.Vec.new], fun p => ?_, fun c => ?_, ?_, ?_, by simp [alloc.vec.Vec.new],
      by simp [alloc.vec.Vec.new]⟩
    · constructor
      · rintro ⟨e, e_in, _⟩
        simp [alloc.vec.Vec.new] at e_in
      · rintro (⟨iv, iv_in, _⟩ | ⟨iv, is_iv, from_start, below⟩)
        · simp at iv_in
        · have := hs_start iv is_iv
          omega
    · constructor
      · rintro ⟨e, e_in, _⟩
        simp [alloc.vec.Vec.new] at e_in
      · rintro (⟨iv, iv_in, _⟩ | ⟨iv, is_iv, from_start, below⟩)
        · simp at iv_in
        · have := cs_start iv is_iv
          omega
    · rcases h : hosts.intervals.val[0]? with _ | iv
      · simp [Weight, Passed, alloc.vec.Vec.new, Total, h]
      · have := hs_start iv h
        simp [Weight, Passed, alloc.vec.Vec.new, Total, h, this]
    · rcases h : ctrs.intervals.val[0]? with _ | iv
      · simp [Weight, Passed, alloc.vec.Vec.new, Total, h]
      · have := cs_start iv h
        simp [Weight, Passed, alloc.vec.Vec.new, Total, h, this]
  step with zip_loop_writes_the_entries hosts.intervals ctrs.intervals hosts_ordered
    ctrs_ordered hosts_below ctrs_below _ _ _ _ _ start_state as ⟨ out, result ⟩
  obtain ⟨sane, apart, maps_ids, covers, few_entries, few_pieces⟩ := result
  refine ⟨sane, apart, fun c p is_map => ?_, fun fewer c has below => ?_, few_entries, ?_⟩
  · obtain ⟨in_hosts, in_ctrs⟩ := maps_ids c p is_map
    have in_hosts' := (hosts_ids' p).mp in_hosts
    have in_ctrs' := (ctrs_ids' c).mp in_ctrs
    exact ⟨in_hosts'.1, in_hosts'.2, in_ctrs'.1, in_ctrs'.2⟩
  · have hosts_exactly := exactly_ids_are_the_same_for_equivalent_properties _ _ _
      (fun id => hosts_ids' id) (ordered_runs_have_total_ids _ hosts_ordered)
    have ctrs_exactly := exactly_ids_are_the_same_for_equivalent_properties _ _ _
      (fun id => ctrs_ids' id) (ordered_runs_have_total_ids _ ctrs_ordered)
    exact covers (fewer _ _ hosts_exactly ctrs_exactly) c ((ctrs_ids' c).mpr ⟨has, below⟩)
  · omega

end IdmapCore
