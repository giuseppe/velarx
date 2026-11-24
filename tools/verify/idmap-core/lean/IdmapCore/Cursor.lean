-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: how a cursor that walks along the intervals of an ordered set behaves.
-- `IdSet::zip` keeps, for each of its two sets, the number `i` of the interval it is in and the
-- next id `cur` of that interval to hand out.  The ids before the cursor are the ids it has
-- handed out so far.  This file says what that is (`Reached`), how many they are (`Passed`), and
-- that taking `n` more ids from the interval, and moving to the next interval when the interval
-- is used up, is the same as handing out those `n` ids (`advance_cursor`).
--
-- Why it is needed: `zip` does the same for the parent ids and for the container ids; the proof
-- is written once, here, and used twice.
--
-- Read before this file: Spec.lean (`HasId`, `Ordered`), Count.lean (`Total`).
-- Notation: `runs[i]?` is the interval `i` of the list, or `none` when there is no such interval;
-- `runs.take i` is the first `i` intervals.
import IdmapCore.Count
import IdmapCore.HasIdFacts
import IdmapCore.Lists

open Aeneas Aeneas.Std

namespace IdmapCore

/-- The ids a cursor has handed out: those of the intervals before the interval `i`, and those of
the interval `i` below `cur`. -/
def Reached (runs : List (U64 × U64)) (i cur id : Nat) : Prop :=
  HasId (runs.take i) id ∨ ∃ iv, runs[i]? = some iv ∧ iv.1.val ≤ id ∧ id < cur

/-- The cursor is in the interval `i` (when there is one): `cur` is one of its ids. -/
def Within (runs : List (U64 × U64)) (i cur : Nat) : Prop :=
  ∀ iv, runs[i]? = some iv → iv.1.val ≤ cur ∧ cur < iv.2.val

/-- How many ids a cursor has handed out: the ids of the intervals before the interval `i`, and
those of the interval `i` below `cur`. -/
def Passed (runs : List (U64 × U64)) (i cur : Nat) : Nat :=
  Total (runs.take i) + (match runs[i]? with | some iv => cur - iv.1.val | none => 0)

/-- An id the cursor has handed out is an id of the set, when the cursor is inside its
interval. -/
theorem a_reached_id_is_in_the_set (runs : List (U64 × U64)) (i cur : Nat)
    (within : Within runs i cur) (id : Nat) (reached : Reached runs i cur id) :
    HasId runs id := by
  rcases reached with ⟨iv, iv_in, in_run⟩ | ⟨iv, is_iv, from_start, below_cur⟩
  · exact ⟨iv, List.mem_of_mem_take iv_in, in_run⟩
  · have := within iv is_iv
    exact ⟨iv, List.mem_of_getElem? is_iv, from_start, by omega⟩

/-- When there is no interval `i` left, the cursor has handed out all the ids. -/
theorem a_cursor_at_the_end_has_reached_all (runs : List (U64 × U64)) (i cur : Nat)
    (at_end : runs.length ≤ i) (id : Nat) : Reached runs i cur id ↔ HasId runs id := by
  have none_left : runs[i]? = none := List.getElem?_eq_none at_end
  simp [Reached, none_left, List.take_of_length_le at_end]

/-- When there is no interval `i` left, the cursor has handed out all the ids, and they are as
many as the ids of the set. -/
theorem a_cursor_at_the_end_has_passed_all (runs : List (U64 × U64)) (i cur : Nat)
    (at_end : runs.length ≤ i) : Passed runs i cur = Total runs := by
  have none_left : runs[i]? = none := List.getElem?_eq_none at_end
  simp [Passed, none_left, List.take_of_length_le at_end]

/-- The ids of the first `i + 1` intervals are those of the first `i` and those of the interval
`i`: so are their numbers. -/
theorem total_of_one_more_interval (runs : List (U64 × U64)) (i : Nat) (iv : U64 × U64)
    (is_iv : runs[i]? = some iv) :
    Total (runs.take (i + 1)) = Total (runs.take i) + (iv.2.val - iv.1.val) := by
  have inside : i < runs.length := (List.getElem?_eq_some_iff.mp is_iv).1
  have is_iv' : runs[i] = iv := by simpa [List.getElem?_eq_getElem inside] using is_iv
  rw [take_one_more runs i inside, is_iv']
  simp [Total]

/-- The ids of the first intervals are no more than those of all of them. -/
theorem total_of_a_prefix_is_at_most_the_total (runs : List (U64 × U64)) (i : Nat) :
    Total (runs.take i) ≤ Total runs := by
  have := congrArg (fun l => (l.map (fun iv : U64 × U64 => iv.2.val - iv.1.val)).sum)
    (List.take_append_drop i runs)
  simp only [List.map_append, List.sum_append] at this
  unfold Total
  omega

/-- A cursor inside the interval `i` has handed out fewer ids than the intervals up to `i`
have. -/
theorem a_cursor_inside_has_not_passed_the_interval (runs : List (U64 × U64)) (i cur : Nat)
    (iv : U64 × U64) (is_iv : runs[i]? = some iv) (within : Within runs i cur) :
    Passed runs i cur < Total runs := by
  have := within iv is_iv
  have one_more := total_of_one_more_interval runs i iv is_iv
  have prefix_le := total_of_a_prefix_is_at_most_the_total runs (i + 1)
  simp only [Passed, is_iv]
  obtain ⟨s_le, lt_e⟩ := this
  generalize iv.1.val = s at *
  generalize iv.2.val = e at *
  have key : cur - s < e - s := by omega
  omega

/-- A cursor never has handed out more ids than the set has. -/
theorem a_cursor_has_not_passed_the_set (runs : List (U64 × U64)) (i cur : Nat)
    (within : Within runs i cur) : Passed runs i cur ≤ Total runs := by
  rcases h : runs[i]? with _ | iv
  · exact Nat.le_of_eq (a_cursor_at_the_end_has_passed_all runs i cur (by
      by_contra inside
      simp [List.getElem?_eq_getElem (Nat.lt_of_not_le inside)] at h))
  · exact Nat.le_of_lt (a_cursor_inside_has_not_passed_the_interval runs i cur iv h within)

/-- Where the cursor goes when interval `i` is used up: the start of the next interval, and
`fallback` when there is none. -/
def StartOfNext (runs : List (U64 × U64)) (i fallback : Nat) : Nat :=
  match runs[i + 1]? with
  | some next => next.1.val
  | none => fallback

/-- In an ordered list an interval ends before the next one begins. -/
theorem an_interval_ends_before_the_next (runs : List (U64 × U64)) (ordered : Ordered runs)
    (i : Nat) (iv next : U64 × U64) (is_iv : runs[i]? = some iv)
    (is_next : runs[i + 1]? = some next) : iv.2.val < next.1.val := by
  have inside : i < runs.length := (List.getElem?_eq_some_iff.mp is_iv).1
  have inside_next : i + 1 < runs.length := (List.getElem?_eq_some_iff.mp is_next).1
  have is_iv' : runs[i] = iv := by simpa [List.getElem?_eq_getElem inside] using is_iv
  have is_next' : runs[i + 1] = next := by
    simpa [List.getElem?_eq_getElem inside_next] using is_next
  have := List.pairwise_iff_getElem.mp ordered.2 i (i + 1) inside inside_next (by omega)
  rwa [is_iv', is_next'] at this

/-- **Handing out `n` more ids.**  The cursor is in the interval `i`, which ends at `iv.2`, and
the `n` (at least one) ids from `cur` are all in it.  The cursor then goes to `cur + n`, or to the
start of the next interval when that is the end of the interval.  It has then handed out the same
ids as before and the `n` ids more, it is again in an interval (or past the last), it has handed
out `n` more ids in number, it is at `cur + n` or later, and it is not past a bound that all the
ids of the set are below. -/
theorem advance_cursor (runs : List (U64 × U64)) (ordered : Ordered runs) (i cur n : Nat)
    (iv : U64 × U64) (is_iv : runs[i]? = some iv) (within : Within runs i cur)
    (fits : cur + n ≤ iv.2.val) (i' cur' : Nat)
    (moved : (cur + n = iv.2.val ∧ i' = i + 1 ∧ cur' = StartOfNext runs i (cur + n)) ∨
      (cur + n < iv.2.val ∧ i' = i ∧ cur' = cur + n)) :
    (∀ id, Reached runs i' cur' id ↔ Reached runs i cur id ∨ (cur ≤ id ∧ id < cur + n)) ∧
    Within runs i' cur' ∧ Passed runs i' cur' = Passed runs i cur + n ∧ cur + n ≤ cur' ∧
    (∀ bound, (∀ x ∈ runs, x.2.val ≤ bound) → cur' ≤ bound) := by
  have iv_in : iv ∈ runs := List.mem_of_getElem? is_iv
  have has_ids := ordered.1 iv iv_in
  have here := within iv is_iv
  have one_more := total_of_one_more_interval runs i iv is_iv
  have inside : i < runs.length := (List.getElem?_eq_some_iff.mp is_iv).1
  rcases moved with ⟨at_end, rfl, rfl⟩ | ⟨before_end, rfl, rfl⟩
  · -- the interval is used up: the cursor is at the start of the next one, if there is one
    have taken : ∀ id, HasId (runs.take (i + 1)) id ↔ HasId (runs.take i) id ∨ InRun iv id := by
      intro id
      rw [take_one_more runs i inside, has_id_after_adding]
      have : runs[i] = iv := by simpa [List.getElem?_eq_getElem inside] using is_iv
      rw [this]
    have same_ids : ∀ id,
        (InRun iv id ↔ (iv.1.val ≤ id ∧ id < cur) ∨ (cur ≤ id ∧ id < cur + n)) := by
      intro id
      simp only [InRun]
      omega
    have passed_now : Total (runs.take (i + 1)) = Total (runs.take i) + (cur - iv.1.val) + n := by
      rw [one_more]
      generalize iv.1.val = s at *
      generalize iv.2.val = e at *
      subst at_end
      have key : cur + n - s = cur - s + n := by omega
      omega
    rcases h : runs[i + 1]? with _ | next
    · have no_next : StartOfNext runs i (cur + n) = cur + n := by simp [StartOfNext, h]
      refine ⟨fun id => ?_, fun other is_other => by simp [h] at is_other, ?_, by omega, ?_⟩
      · simp only [Reached, taken, h, is_iv]
        have := same_ids id
        simp only [Option.some.injEq, exists_eq_left', reduceCtorEq, false_and, exists_false,
          or_false]
        tauto
      · simp [Passed, h, is_iv, passed_now]
      · intro bound below
        rw [no_next]
        have := below iv iv_in
        omega
    · have next_in : next ∈ runs := List.mem_of_getElem? h
      have next_has_ids := ordered.1 next next_in
      have after := an_interval_ends_before_the_next runs ordered i iv next is_iv h
      have next_start : StartOfNext runs i (cur + n) = next.1.val := by simp [StartOfNext, h]
      rw [next_start]
      refine ⟨fun id => ?_, ?_, ?_, by omega, ?_⟩
      · simp only [Reached, taken, h, is_iv]
        have := same_ids id
        have empty : ¬ (next.1.val ≤ id ∧ id < next.1.val) := by omega
        simp only [Option.some.injEq, exists_eq_left']
        tauto
      · intro other is_other
        have : other = next := by simpa [h] using is_other.symm
        subst this
        omega
      · simp [Passed, h, is_iv, passed_now]
      · intro bound below
        have := below next next_in
        omega
  · -- the interval is not used up: the cursor goes on in it
    refine ⟨fun id => ?_, fun other is_other => ?_, ?_, by omega, ?_⟩
    · simp only [Reached, is_iv, Option.some.injEq, exists_eq_left']
      have : (iv.1.val ≤ id ∧ id < cur + n) ↔
          (iv.1.val ≤ id ∧ id < cur) ∨ (cur ≤ id ∧ id < cur + n) := by omega
      tauto
    · have : other = iv := by simpa [is_iv] using is_other.symm
      subst this
      omega
    · simp only [Passed, is_iv]
      have key : cur + n - iv.1.val = cur - iv.1.val + n := by
        generalize iv.1.val = s at *
        omega
      omega
    · intro bound below
      have := below iv iv_in
      omega

end IdmapCore
