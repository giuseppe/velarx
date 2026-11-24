-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `pick` answers, loop by loop: it keeps, for the records read so
-- far, the first of the latest time (`best`), and the last record of that time whose digest
-- differs from its digest (`other`, when `tied`); at the end of the list that is `Named`
-- (Spec.lean).
--
-- Why it is needed: the claims about `pick` in Spec.lean are about every list.  The invariant
-- `PickState` says what the three variables of the loop mean for the first `i` records; four
-- lemmas (`state_next`) say what it becomes when record `i` is later than `best`, of the same
-- time with another digest, of the same time with the same digest, or earlier.
--
-- Read before this file: Spec.lean (`Named`, `FirstOfLatest`), Scope.lean (`same_is_equal`).
--
-- Notation: as in Select.lean; `records[k]? = some s` is "record `k` of the list is `s`";
-- `s.time.val` is the time of `s` as a whole number.
import PolicyCore.Scope
open Aeneas Aeneas.Std Result velarx_policy_core
namespace PolicyCore

/-- What the loop of `pick` knows after reading the first `i` records: `best` is the first of
the latest time among them (it names the record `r`), and when `tied` is false every one of that
time has the digest of `r`, and when it is true `other` is one of them with another digest. -/
def PickState (records : List Signed) (i : Nat) (best other : Nat) (tied : Bool) : Prop :=
  ∃ r, best < i ∧ records[best]? = some r ∧
    (∀ k < i, ∀ s, records[k]? = some s → s.time.val ≤ r.time.val) ∧
    (∀ k < best, ∀ s, records[k]? = some s → s.time.val < r.time.val) ∧
    (tied = false → ∀ k < i, ∀ s, records[k]? = some s → s.time.val = r.time.val →
      s.digest.val = r.digest.val) ∧
    (tied = true → other < i ∧ ∃ s, records[other]? = some s ∧ s.time.val = r.time.val ∧
      s.digest.val ≠ r.digest.val)

/-- Reading record `i` (`s`) with the best so far (`r`): what `PickState` becomes in each of the
four cases of the loop body. -/
theorem state_next (records : List Signed) (i best other : Nat) (tied : Bool)
    (state : PickState records i best other tied) (s r : Signed)
    (s_at : records[i]? = some s) (r_at : records[best]? = some r) :
    (r.time.val < s.time.val → PickState records (i + 1) i other false) ∧
    (s.time.val = r.time.val → s.digest.val ≠ r.digest.val →
      PickState records (i + 1) best i true) ∧
    (s.time.val = r.time.val → s.digest.val = r.digest.val →
      PickState records (i + 1) best other tied) ∧
    (s.time.val < r.time.val → PickState records (i + 1) best other tied) := by
  obtain ⟨r', before, r'_at, latest, first, agree, differs⟩ := state
  have same_r : r = r' := by
    rw [r_at] at r'_at; exact Option.some.inj r'_at
  subst same_r
  -- the position `k` is before `i`, or it is `i`
  have split : ∀ k, k < i + 1 → k < i ∨ k = i := fun k below => by omega
  refine ⟨fun later => ?_, fun same_time other_digest => ?_, fun same_time same_digest => ?_,
    fun earlier => ?_⟩
  · -- `s` is the new best: nothing before it is as late
    refine ⟨s, by omega, s_at, fun k below t t_at => ?_, fun k below t t_at => ?_,
      fun _ k below t t_at same_time => ?_, fun tied_now => by cases tied_now⟩
    · rcases split k below with before_i | at_i
      · have := latest k before_i t t_at; omega
      · rw [at_i, s_at] at t_at; cases Option.some.inj t_at; omega
    · have := latest k (by omega) t t_at; omega
    · rcases split k below with before_i | at_i
      · have := latest k before_i t t_at; omega
      · rw [at_i, s_at] at t_at; cases Option.some.inj t_at; rfl
  · -- `s` is of the time of `best` with another digest: the tie is `s`
    refine ⟨r, by omega, r'_at, fun k below t t_at => ?_, first, fun no_tie => ?_,
      fun _ => ⟨by omega, s, s_at, same_time, other_digest⟩⟩
    · rcases split k below with before_i | at_i
      · exact latest k before_i t t_at
      · rw [at_i, s_at] at t_at; cases Option.some.inj t_at; omega
    · cases no_tie
  · refine ⟨r, by omega, r'_at, fun k below t t_at => ?_, first, fun no_tie k below t t_at
      same_time_t => ?_, fun tied_now => ?_⟩
    · rcases split k below with before_i | at_i
      · exact latest k before_i t t_at
      · rw [at_i, s_at] at t_at; cases Option.some.inj t_at; omega
    · rcases split k below with before_i | at_i
      · exact agree no_tie k before_i t t_at same_time_t
      · rw [at_i, s_at] at t_at; cases Option.some.inj t_at; exact same_digest
    · exact ⟨by have := (differs tied_now).1; omega, (differs tied_now).2⟩
  · refine ⟨r, by omega, r'_at, fun k below t t_at => ?_, first, fun no_tie k below t t_at
      same_time_t => ?_, fun tied_now => ?_⟩
    · rcases split k below with before_i | at_i
      · exact latest k before_i t t_at
      · rw [at_i, s_at] at t_at; cases Option.some.inj t_at; omega
    · rcases split k below with before_i | at_i
      · exact agree no_tie k before_i t t_at same_time_t
      · rw [at_i, s_at] at t_at; cases Option.some.inj t_at; omega
    · exact ⟨by have := (differs tied_now).1; omega, (differs tied_now).2⟩

/-- `same_digest` says whether the digests of two records are the same bytes. -/
@[step]
theorem same_digest_is (records : Slice Signed) (i j : Std.Usize) (a b : Signed)
    (a_at : records.val[i.val]? = some a) (b_at : records.val[j.val]? = some b) :
    same_digest records i j ⦃ r => r = true ↔ a.digest.val = b.digest.val ⦄ := by
  have inside_i : i.val < records.length := (List.getElem?_eq_some_iff.mp a_at).1
  have inside_j : j.val < records.length := (List.getElem?_eq_some_iff.mp b_at).1
  unfold same_digest
  step as ⟨ x, hx ⟩
  step as ⟨ y, hy ⟩
  step as ⟨ r, hr ⟩
  simp_all [alloc.vec.Vec.deref]

/-- The loop of `pick`: starting from what is known before the position `i`, it ends knowing it
for the whole list. -/
theorem pick_loop_is (records : Slice Signed) (best other : Std.Usize) (tied : Bool)
    (i : Std.Usize) (read : i.val ≤ records.length)
    (state : PickState records.val i.val best.val other.val tied) :
    pick_loop records best other tied i ⦃ r =>
      PickState records.val records.length r.1.val r.2.1.val r.2.2 ⦄ := by
  unfold pick_loop
  apply loop.spec_decr_nat (fun q => records.length - q.2.2.2.val)
    (fun q => q.2.2.2.val ≤ records.length ∧
      PickState records.val q.2.2.2.val q.1.val q.2.1.val q.2.2.1)
  · rintro ⟨best, other, tied, i⟩ ⟨read, state⟩
    simp only at read state ⊢
    unfold pick_loop.body
    dsimp only [Slice.len]
    split
    · rename_i below
      have inside : i.val < records.length := by scalar_tac
      obtain ⟨r, before, r_at, _⟩ := id state
      -- record `i` and the best record so far are read
      step as ⟨ s, hs ⟩
      step as ⟨ s1, hs1 ⟩
      have s_at : records.val[i.val]? = some s := by simp [hs]
      have s1_at : records.val[best.val]? = some s1 := by simp [hs1]
      have next := state_next records.val i.val best.val other.val tied state s s1 s_at s1_at
      -- the record is later than the best (it is the new best), or of the same time (it is a
      -- tie when its digest differs), or earlier
      refine WP.spec_bind (Pₘ := fun r : Std.Usize × Std.Usize × Bool =>
        PickState records.val (i.val + 1) r.1.val r.2.1.val r.2.2) ?_ (fun r kept => ?_)
      · by_cases later : s.time > s1.time
        · simp only [eq_true later, ↓reduceIte]
          refine (WP.spec_ok _).mpr (next.1 ?_)
          simpa [GT.gt, IScalar.lt_equiv] using later
        · simp only [eq_false later, ↓reduceIte]
          refine WP.spec_bind (Pₘ := fun q : Std.Usize × Bool =>
            PickState records.val (i.val + 1) best.val q.1.val q.2) ?_ (fun q kept2 => ?_)
          · by_cases same_time : s.time = s1.time
            · simp only [eq_true same_time, ↓reduceIte]
              have time_eq : s.time.val = s1.time.val := by rw [same_time]
              refine WP.spec_bind (same_digest_is records i best s s1 s_at s1_at)
                (fun alike halike => ?_)
              by_cases digests : alike = true
              · simp only [eq_true digests, ↓reduceIte]
                exact (WP.spec_ok _).mpr (next.2.2.1 time_eq (halike.mp digests))
              · simp only [eq_false digests, ↓reduceIte]
                exact (WP.spec_ok _).mpr
                  (next.2.1 time_eq (fun equal => digests (halike.mpr equal)))
            · simp only [eq_false same_time, ↓reduceIte]
              refine (WP.spec_ok _).mpr (next.2.2.2 ?_)
              simp only [GT.gt, IScalar.lt_equiv, not_lt] at later
              have different : s.time.val ≠ s1.time.val := fun equal =>
                same_time (IScalar.eq_equiv .. |>.mpr equal)
              omega
          · exact (WP.spec_ok _).mpr kept2
      · obtain ⟨best1, other1, tied1⟩ := r
        step as ⟨ next_i, hnext ⟩
        exact ⟨by omega, by simpa [hnext] using kept, by omega⟩
    · rename_i past_end
      have at_end : i.val = records.length := by scalar_tac
      simp only [WP.spec_ok]
      rw [at_end] at state
      exact state
  · exact ⟨read, state⟩

/-- With no record the loop does not turn: it answers what it was given. -/
theorem pick_loop_of_empty (records : Slice Signed) (best other : Std.Usize) (tied : Bool)
    (i : Std.Usize) (empty : records.length = 0) :
    pick_loop records best other tied i ⦃ r => r = (best, other, tied) ⦄ := by
  unfold pick_loop
  apply loop.spec_decr_nat (fun q => records.length - q.2.2.2.val)
    (fun q => q = (best, other, tied, i))
  · rintro ⟨best, other, tied, i⟩ same
    unfold pick_loop.body
    dsimp only [Slice.len]
    split
    · rename_i below
      exfalso
      scalar_tac
    · simp only [WP.spec_ok, Prod.mk.injEq] at same ⊢
      exact ⟨same.1, same.2.1, same.2.2.1⟩
  · rfl

/-- At the end of the list, with no tie, the best record is named: it is the first of the latest
time and every record of that time has its digest. -/
theorem state_is_one (records : List Signed) (best other : Nat)
    (state : PickState records records.length best other false) :
    ∃ r, FirstOfLatest records best r ∧
      ∀ s ∈ records, s.time.val = r.time.val → s.digest.val = r.digest.val := by
  obtain ⟨r, _, r_at, latest, first, agree, _⟩ := state
  refine ⟨r, ⟨r_at, fun s member => ?_, first⟩, fun s member same_time => ?_⟩
  · obtain ⟨k, k_at⟩ := List.mem_iff_getElem?.mp member
    exact latest k (List.getElem?_eq_some_iff.mp k_at).1 s k_at
  · obtain ⟨k, k_at⟩ := List.mem_iff_getElem?.mp member
    exact agree rfl k (List.getElem?_eq_some_iff.mp k_at).1 s k_at same_time

/-- At the end of the list, with a tie, the best record is the first of the latest time and
`other` is a record of that time with another digest. -/
theorem state_is_tie (records : List Signed) (best other : Nat)
    (state : PickState records records.length best other true) :
    ∃ r s, FirstOfLatest records best r ∧ records[other]? = some s ∧
      s.time.val = r.time.val ∧ s.digest.val ≠ r.digest.val := by
  obtain ⟨r, _, r_at, latest, first, _, differs⟩ := state
  obtain ⟨_, s, s_at, same_time, other_digest⟩ := differs rfl
  refine ⟨r, s, ⟨r_at, fun t member => ?_, first⟩, s_at, same_time, other_digest⟩
  obtain ⟨k, k_at⟩ := List.mem_iff_getElem?.mp member
  exact latest k (List.getElem?_eq_some_iff.mp k_at).1 t k_at

/-- `pick` names what the latest records say. -/
theorem pick_is (records : Slice Signed) : pick records ⦃ answer => Named records.val answer ⦄ := by
  unfold pick
  by_cases empty : records.length = 0
  · refine WP.spec_bind (pick_loop_of_empty records 0#usize 0#usize false 1#usize empty)
      (fun _ _ => ?_)
    refine WP.spec_bind (core.slice.Slice.is_empty_spec records) (fun is_empty his => ?_)
    have no_records : records.val = [] := List.length_eq_zero_iff.mp empty
    simp [his, Named, no_records]
  · have some_record : 1 ≤ records.length := by omega
    refine WP.spec_bind (pick_loop_is records 0#usize 0#usize false 1#usize
      (by simpa using some_record) ?_) (fun r state => ?_)
    · -- the first record is the best of the first one
      obtain ⟨first, first_at⟩ : ∃ first, records.val[0]? = some first :=
        ⟨_, List.getElem?_eq_getElem (by scalar_tac)⟩
      refine ⟨first, by simp, by simpa using first_at, fun k below t t_at => ?_,
        fun k below => by simp at below, fun _ k below t t_at same_time => ?_,
        fun tied_now => by simp at tied_now⟩
      · have : k = 0 := by simp at below; omega
        subst this; rw [first_at] at t_at; cases Option.some.inj t_at; omega
      · have : k = 0 := by simp at below; omega
        subst this; rw [first_at] at t_at; cases Option.some.inj t_at; rfl
    · obtain ⟨best, other, tied⟩ := r
      refine WP.spec_bind (core.slice.Slice.is_empty_spec records) (fun is_empty his => ?_)
      simp only [his, empty, ↓reduceIte]
      cases tied
      · simp only [Bool.false_eq_true, ↓reduceIte]
        exact (WP.spec_ok _).mpr (state_is_one records.val best other state)
      · simp only [↓reduceIte]
        exact (WP.spec_ok _).mpr (state_is_tie records.val best other state)

/-- A record strictly later than every other is the one `Named` names: not nothing (it is in the
list), and when it is the first of the latest time it is that record; a tie would need another
record of its time. -/
theorem later_record_is_named (records : List Signed) (answer : Picked)
    (named : Named records answer) (i : Nat) (r : Signed) (r_at : records[i]? = some r)
    (later : ∀ k s, records[k]? = some s → k ≠ i → s.time.val < r.time.val) :
    ∃ i', answer = Picked.One i' ∧ i'.val = i := by
  have r_member : r ∈ records := List.mem_of_getElem? r_at
  -- the first of the latest time is `r`
  have is_r : ∀ (i' : Std.Usize) (r' : Signed),
      FirstOfLatest records i'.val r' → i'.val = i ∧ r' = r := by
    rintro i' r' ⟨r'_at, r'_max, _⟩
    have r_le := r'_max r r_member
    by_cases same_place : i'.val = i
    · rw [same_place, r_at] at r'_at
      exact ⟨same_place, (Option.some.inj r'_at).symm⟩
    · have := later i'.val r' r'_at same_place
      omega
  cases answer with
  | Nothing =>
    simp only [Named] at named
    simp [named] at r_at
  | One i' =>
    obtain ⟨r', first, _⟩ := named
    exact ⟨i', rfl, (is_r i' r' first).1⟩
  | Tie i' j =>
    obtain ⟨r', s, first, s_at, same_time, different⟩ := named
    obtain ⟨_, same_record⟩ := is_r i' r' first
    subst same_record
    by_cases same_place : j.val = i
    · rw [same_place, r_at] at s_at
      cases Option.some.inj s_at
      exact absurd rfl different
    · have := later j.val s s_at same_place
      omega

/-- When the records are the same in another order, an answer that names one record and an
answer that names a tie cannot both be right: the latest time, and the digests at it, are the
same for both. -/
theorem one_is_not_tie (records reordered : List Signed) (order : records.Perm reordered)
    (i j k : Std.Usize) (one : Named records (Picked.One i))
    (tie : Named reordered (Picked.Tie j k)) : False := by
  obtain ⟨r, ⟨r_at, r_latest, _⟩, r_agree⟩ := one
  obtain ⟨r', s, ⟨r'_at, r'_latest, _⟩, s_at, s_time, s_digest⟩ := tie
  have r_in : r ∈ reordered := order.mem_iff.mp (List.mem_of_getElem? r_at)
  have r'_in : r' ∈ records := order.mem_iff.mpr (List.mem_of_getElem? r'_at)
  have s_in : s ∈ records := order.mem_iff.mpr (List.mem_of_getElem? s_at)
  have r_le := r'_latest r r_in
  have r'_le := r_latest r' r'_in
  have s_same := r_agree s s_in (by omega)
  have r'_same := r_agree r' r'_in (by omega)
  exact s_digest (by rw [s_same, r'_same])

/-- Reordered records are named the same: the same time and digest, or a tie again. -/
theorem order_does_not_matter (records reordered : List Signed) (order : records.Perm reordered)
    (answer again : Picked) (named : Named records answer) (named_again : Named reordered again) :
    SameNaming records answer reordered again := by
  cases answer with
  | Nothing =>
    have no_records : records = [] := named
    rw [no_records] at order
    have none_again : reordered = [] := order.symm.eq_nil
    cases again with
    | Nothing => exact Or.inl ⟨rfl, rfl⟩
    | One j => obtain ⟨s, ⟨s_at, _⟩, _⟩ := named_again; simp [none_again] at s_at
    | Tie j k => obtain ⟨r, s, ⟨r_at, _⟩, _⟩ := named_again; simp [none_again] at r_at
  | One i =>
    obtain ⟨r, ⟨r_at, r_latest, _⟩, r_agree⟩ := id named
    cases again with
    | Nothing =>
      have none_again : reordered = [] := named_again
      rw [none_again] at order
      have no_records : records = [] := order.eq_nil
      simp [no_records] at r_at
    | One j =>
      obtain ⟨s, ⟨s_at, s_latest, _⟩, _⟩ := named_again
      have r_in : r ∈ reordered := order.mem_iff.mp (List.mem_of_getElem? r_at)
      have s_in : s ∈ records := order.mem_iff.mpr (List.mem_of_getElem? s_at)
      have r_le := s_latest r r_in
      have s_le := r_latest s s_in
      exact Or.inr (Or.inr ⟨i, j, r, s, rfl, rfl, r_at, s_at, by omega,
        (r_agree s s_in (by omega)).symm⟩)
    | Tie j k =>
      exact (one_is_not_tie records reordered order i j k named named_again).elim
  | Tie i j =>
    cases again with
    | Nothing =>
      obtain ⟨r, s, ⟨r_at, _⟩, _⟩ := named
      have none_again : reordered = [] := named_again
      rw [none_again] at order
      have no_records : records = [] := order.eq_nil
      simp [no_records] at r_at
    | One j' => exact (one_is_not_tie reordered records order.symm j' i j named_again named).elim
    | Tie i' j' => exact Or.inr (Or.inl ⟨i, j, i', j', rfl, rfl⟩)

end PolicyCore
