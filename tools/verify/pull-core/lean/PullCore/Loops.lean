-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the calls of the Rust standard library that
-- crates/pull-core makes do, each as a fact about the list inside the vector:
-- `Vec::index` and `Vec::index_mut` give the element at a place (and the way
-- to put another there), `Vec::push` adds one at the end, `Iter::position`
-- finds the first element a predicate says yes to, `Vec::retain` keeps the
-- elements its predicate says yes to, and a loop over a slice takes the
-- elements in order (`slice_next`).
--
-- Why it is needed: the proofs of Table.lean, Ends.lean, Claims.lean and
-- Phases.lean follow the Rust functions line by line, and a line is often one
-- of these calls.  The facts do not mention a pull.  `position` and `retain`
-- are the two functions of Models.lean: loops written there as recursive
-- functions, whose facts are proved by induction on the list.
--
-- Read before this file: ../../Ok.lean and ../Models.lean.
--
-- Notation: `Ok m P` is "if `m` returns, its result satisfies `P`"; `v.val`
-- is the list inside a Rust `Vec`; `l[i]?` is the element `i` of the list
-- `l` if there is one; `l.filter keep` is the elements of `l` that `keep`
-- says yes to; `keep`, a function of an element to `true` or `false`, is what
-- the predicate of the Rust closure says.
import Ok
import Models

open Aeneas Aeneas.Std Result

namespace PullCore

/-- `v[i]` of a vector: the element, when `i` is inside. -/
theorem vec_index {T : Type} (v : alloc.vec.Vec T) (i : Std.Usize) (inside : i.val < v.val.length) :
    Ok (alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice T) v i)
      (fun x => x = v.val[i.val]) := by
  rw [alloc.vec.Vec.index_slice_index]
  exact Ok.of_spec (alloc.vec.Vec.index_usize_spec v i inside)

/-- `Vec::index_mut`: the element at `i` and the way to put another back. -/
theorem vec_index_mut {T : Type} (v : alloc.vec.Vec T) (i : Std.Usize)
    (inside : i.val < v.val.length) :
    Ok (alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice T) v i)
      (fun r => r.1 = v.val[i.val] ∧ ∀ x, (r.2 x).val = v.val.set i.val x) := by
  rw [alloc.vec.Vec.index_mut_slice_index]
  refine Ok.mono (Ok.of_spec (alloc.vec.Vec.index_mut_usize_spec v i inside)) ?_
  rintro ⟨x, back⟩ ⟨hx, rfl⟩
  exact ⟨hx, fun y => by simp⟩

/-- `Vec::push` returns the vector with `x` added at the end. -/
theorem push_spec {α : Type} (v : alloc.vec.Vec α) (x : α) :
    Ok (v.push x) (fun v1 => v1.val = v.val ++ [x]) := by
  unfold alloc.vec.Vec.push
  dsimp only
  split
  · apply Ok.ok.mpr; simp
  · exact Ok.fail

attribute [local irreducible] Ok

/-- One turn of a loop over a slice: the next element, if any. -/
theorem slice_next {T : Type} (it : core.slice.iter.Iter T) :
    Ok (core.slice.iter.IteratorSliceIter.next it) (fun r =>
      (∃ h : it.i < it.slice.val.length,
        r.1 = some it.slice.val[it.i] ∧ r.2 = { it with i := it.i + 1 }) ∨
      (it.slice.val.length ≤ it.i ∧ r.1 = none ∧ r.2 = it)) := by
  unfold core.slice.iter.IteratorSliceIter.next
  split
  · rename_i h
    apply Ok.ok.mpr
    have h' : it.i < it.slice.val.length := by simpa using h
    exact Or.inl ⟨h', congrArg some (Slice.getElem_Nat_eq _ _ h'), rfl⟩
  · rename_i h
    apply Ok.ok.mpr
    exact Or.inr ⟨by simpa using h, rfl, rfl⟩

/-- `positionFrom` with a predicate that is a function of the element alone finds the first
element from `i` that it says yes to. -/
theorem positionFrom_first {T P : Type} (inst : core.ops.function.FnMut P T Bool) (keep : T → Bool)
    (f : P) (stateless : ∀ x, inst.call_mut f x = ok (keep x, f)) (s : Slice T) :
    ∀ n i, s.val.length - i = n →
    Ok (positionFrom inst s f i) (fun r =>
      (r.1 = none ∧ ∀ j x, i ≤ j → s.val[j]? = some x → keep x = false) ∨
      (∃ k, r.1 = some k ∧ i ≤ k.val ∧ ∃ x, s.val[k.val]? = some x ∧ keep x = true ∧
        ∀ j y, i ≤ j → j < k.val → s.val[j]? = some y → keep y = false)) := by
  intro n
  induction n with
  | zero =>
    intro i hn
    unfold positionFrom
    have outside : ¬ i < s.val.length := by omega
    simp only [outside, ↓reduceDIte]
    apply Ok.ok.mpr
    exact Or.inl ⟨rfl, fun j x hj hx => by
      have := (List.getElem?_eq_some_iff.mp hx).1; omega⟩
  | succ n ih =>
    intro i hn
    unfold positionFrom
    have inside : i < s.val.length := by omega
    simp only [inside, ↓reduceDIte, stateless, bind_ok]
    by_cases hk : keep s.val[i] = true
    · simp only [hk]
      apply Ok.ok.mpr
      exact Or.inr ⟨_, rfl, by simp, s.val[i], by simp, hk,
        fun j y hj hjk _ => by simp at hjk; omega⟩
    · simp only [hk]
      refine Ok.mono (ih (i + 1) (by omega)) ?_
      rintro r (⟨hnone, hrest⟩ | ⟨k, hk', hik, x, hx, hkeep, hbefore⟩)
      · refine Or.inl ⟨hnone, fun j x hj hx => ?_⟩
        by_cases hji : j = i
        · subst hji
          rw [List.getElem?_eq_getElem (by omega), Option.some.injEq] at hx
          rw [← hx]; simpa using hk
        · exact hrest j x (by omega) hx
      · refine Or.inr ⟨k, hk', by omega, x, hx, hkeep, fun j y hj hjk hy => ?_⟩
        by_cases hji : j = i
        · subst hji
          rw [List.getElem?_eq_getElem (by omega), Option.some.injEq] at hy
          rw [← hy]; simpa using hk
        · exact hbefore j y (by omega) hjk hy

/-- `Iter::position` with such a predicate, from the first element: the place of the first
element it says yes to, or none if there is not one. -/
theorem position_first {T P : Type} (inst : core.ops.function.FnMut P T Bool) (keep : T → Bool)
    (f : P) (stateless : ∀ x, inst.call_mut f x = ok (keep x, f)) (s : Slice T) :
    Ok (core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.position inst ⟨s, 0⟩ f)
      (fun r => (r.1 = none ∧ ∀ x ∈ s.val, keep x = false) ∨
        (∃ k, r.1 = some k ∧ ∃ x, s.val[k.val]? = some x ∧ keep x = true ∧
          ∀ j y, j < k.val → s.val[j]? = some y → keep y = false)) := by
  unfold core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.position
  refine Ok.bind (positionFrom_first inst keep f stateless s _ 0 rfl) ?_
  rintro ⟨o, it⟩ (⟨hnone, hrest⟩ | ⟨k, hk, -, x, hx, hkeep, hbefore⟩)
  · dsimp only at hnone
    subst hnone
    apply Ok.ok.mpr
    refine Or.inl ⟨rfl, fun x hx => ?_⟩
    obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hx
    exact hrest j x (Nat.zero_le _) hj
  · dsimp only at hk
    subst hk
    apply Ok.ok.mpr
    refine Or.inr ⟨_, rfl, x, by simpa using hx, hkeep,
      fun j y hj hy => hbefore j y (Nat.zero_le _) hj hy⟩

/-- `retainFrom` with a predicate that is a function of the element alone keeps
the elements it says yes to. -/
theorem retainFrom_filter {T F : Type} (inst : core.ops.function.FnMut F T Bool) (keep : T → Bool)
    (f : F) (stateless : ∀ x, inst.call_mut f x = ok (keep x, f)) (l : List T) :
    Ok (retainFrom inst l f) (fun r => r.val = l.filter keep) := by
  induction l with
  | nil => exact Ok.ok.mpr (by simp)
  | cons x rest ih =>
    unfold retainFrom
    rw [stateless x]
    simp only [bind_ok]
    refine Ok.bind ih ?_
    intro kept hkept
    apply Ok.ok.mpr
    cases h : keep x <;> simp [h, hkept]

/-- `Vec::retain` with such a predicate keeps the elements it says yes to. -/
theorem retain_filter {T F : Type} (inst : core.ops.function.FnMut F T Bool) (keep : T → Bool)
    (f : F) (stateless : ∀ x, inst.call_mut f x = ok (keep x, f)) (v : alloc.vec.Vec T) :
    Ok (alloc.vec.Vec.retain alloc.alloc.Global inst v f)
      (fun v1 => v1.val = v.val.filter keep) := by
  unfold alloc.vec.Vec.retain
  refine Ok.bind (retainFrom_filter inst keep f stateless v.val) ?_
  intro kept hkept
  exact Ok.ok.mpr (by simpa using hkept)

end PullCore
