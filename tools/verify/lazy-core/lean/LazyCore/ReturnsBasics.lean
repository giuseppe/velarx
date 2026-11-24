-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what a proof that `step` of crates/lazy-core RETURNS needs to know of the
-- functions of the standard library the Rust calls: the next element of an iterator, `Vec::push`,
-- `Vec::retain`, `slice::position`, `mem::take`, a comparison of two enums, and so on.  For each it
-- says when the call returns and what is then known of what it gives (the length of a vector, the
-- place of an element).  It also defines the one-line tactic `bookkeeping`, and a few facts about a
-- `Vec` (the length of a vector with one element set, of a vector made of a slice).
--
-- Why it is needed: the proofs of the older claims say what holds IF the step returns (Ok.lean),
-- and use a function of the library as a call whose result is not known.  To say that `step`
-- returns, every call must be known to return.  The lemmas here are marked `@[step]`, so that the
-- tactic `step*` finds them by itself.  Where Aeneas has a lemma of its own (`Vec::push`,
-- `Vec::index`) it is used, and the one for `Vec::push` is given here again in the form this
-- development needs: the length of the new vector, not its contents.
--
-- Read before this file: Spec.lean (`Short`, `OnA64BitMachine`), Pulls.lean (`position_pure`,
-- `anyM_pure`), and Models.lean (the functions of the library that are written by hand).
--
-- The tactics a reader meets in the proofs.  `step*` follows the Rust function line by line: for
-- each call it uses the lemma of this development that says when the call returns and what it
-- gives (the lemmas marked `@[step]`), and leaves what is to be shown (that a `Vec` has room, that
-- an index is inside) as goals.  `step as ⟨x, hx⟩` does one line and names the result `x` and what
-- is known of it `hx`.  `loop.spec_decr_nat` proves that a loop returns because a number goes down
-- at each turn (here, the elements left to read) while a fact (the invariant) is kept.
-- `bookkeeping` (ReturnsBasics.lean) closes the goals that are only sums of lengths.
--
-- Notation: `m ⦃ r => P r ⦄` is "the call `m` returns, and its result `r` satisfies `P r`" (the
-- notation of Aeneas); `v.val` is the list inside a Rust `Vec`; `(↑v)` is the same.
-- `unseal Result` below makes `Result` (the type of what a Rust function returns) an ordinary type
-- for this file, so that a call that is known to return can be split into its value
-- (`spec_imp_ok`).
import LazyCore.Pulls

open Aeneas Aeneas.Std Result velarx_lazy_core
open Aeneas.Data.Coinductive

unseal Result
attribute [local implicit_reducible] Result

namespace LazyCore

/-- `next` of a slice iterator: at the end it says `none`, before it says the element and moves. -/
@[step] theorem slice_next_spec {T : Type} (it : core.slice.iter.Iter T) :
    core.slice.iter.IteratorSliceIter.next it ⦃ o it1 =>
      (it.i < it.slice.val.length ∧ ∃ x, o = some x ∧ it1.slice = it.slice ∧ it1.i = it.i + 1) ∨
      (¬ it.i < it.slice.val.length ∧ o = none ∧ it1 = it) ⦄ := by
  unfold core.slice.iter.IteratorSliceIter.next
  by_cases h : it.i < it.slice.len
  · have h' : it.i < it.slice.val.length := by simpa using h
    simp [h', WP.spec_ok]
  · have h' : ¬ it.i < it.slice.val.length := by simpa using h
    simp [h', WP.spec_ok]

/-- `next` of a mutable slice iterator. -/
@[step] theorem iter_mut_next_spec {T : Type} (it : core.slice.iter.IterMut T) :
    core.slice.iter.IteratorIterMut.next it ⦃ o it1 back =>
      it1.slice = it.slice ∧
      (∀ it' o', (back it' o').slice.val.length = it'.slice.val.length) ∧
      ((it.i < it.slice.val.length ∧ ∃ x, o = some x ∧ it1.i = it.i + 1) ∨
      (¬ it.i < it.slice.val.length ∧ o = none ∧ it1.i = it.i)) ⦄ := by
  unfold core.slice.iter.IteratorIterMut.next
  by_cases h : it.i < it.slice.len
  · have h' : it.i < it.slice.val.length := by simpa using h
    simp only [h, ↓reduceDIte, WP.spec_ok]
    refine ⟨rfl, ?_, Or.inl ⟨h', _, rfl, rfl⟩⟩
    intro it' o'
    cases o' <;> simp [Slice.setAtNat]
  · have h' : ¬ it.i < it.slice.val.length := by simpa using h
    simp only [h, ↓reduceDIte, WP.spec_ok]
    exact ⟨rfl, fun _ _ => rfl, Or.inr ⟨h', rfl, rfl⟩⟩

/-- `next` of the iterator of a vector. -/
@[step] theorem into_iter_next_spec {T : Type} (it : alloc.vec.into_iter.IntoIter T) :
    alloc.vec.into_iter.IteratorIntoIter.next it ⦃ o it1 =>
      (it.val = [] ∧ o = none ∧ it1 = it) ∨
      (∃ x l, it.val = x :: l ∧ o = some x ∧ it1.val = l) ⦄ := by
  unfold alloc.vec.into_iter.IteratorIntoIter.next
  split
  · rename_i h
    simp [WP.spec_ok, h]
  · rename_i hd tl h
    simp [WP.spec_ok, WP.uncurry', h]

/-- The comparison of two steps (`==` on `Step`) returns. -/
@[step] theorem step_eq_returns (a b : Step) :
    Step.Insts.CoreCmpPartialEqStep.eq a b ⦃ _ => True ⦄ := by
  cases a <;> cases b <;> simp [Step.Insts.CoreCmpPartialEqStep.eq, Step.read_discriminant,
    WP.spec_ok]

/-- The comparison of two phases (`==` on `Phase`) returns. -/
@[step] theorem phase_eq_returns (a b : Phase) :
    Phase.Insts.CoreCmpPartialEqPhase.eq a b ⦃ _ => True ⦄ := by
  unfold Phase.Insts.CoreCmpPartialEqPhase.eq
  cases a <;> cases b <;> simp [Phase.read_discriminant, WP.spec_ok]
  · exact step_eq_returns _ _
  · simp [lift, WP.spec_ok]

/-- The comparison of two states of a group returns. -/
@[step] theorem group_state_eq_returns (a b : GroupState) :
    GroupState.Insts.CoreCmpPartialEqGroupState.eq a b ⦃ _ => True ⦄ := by
  unfold GroupState.Insts.CoreCmpPartialEqGroupState.eq
  cases a <;> cases b <;> simp [GroupState.read_discriminant, WP.spec_ok]
  simp [lift, WP.spec_ok]

/-- The comparison of two states of a layer returns. -/
@[step] theorem layer_state_eq_returns (a b : LayerState) :
    LayerState.Insts.CoreCmpPartialEqLayerState.eq a b ⦃ _ => True ⦄ := by
  unfold LayerState.Insts.CoreCmpPartialEqLayerState.eq
  cases a <;> cases b <;> simp [LayerState.read_discriminant, WP.spec_ok]

/-- A call that returns, with a result that satisfies `P`, is `ok` of such a result. -/
theorem spec_imp_ok {α : Type} {m : Result α} {P : α → Prop} (h : m ⦃ r => P r ⦄) :
    ∃ x, m = ok x ∧ P x := by
  cases m using ITree.cases with
  | ret x => exact ⟨x, rfl, (WP.spec_ok x).mp h⟩
  | vis e k => exact ((WP.spec_vis e k).mp h).elim
  | div => exact (WP.spec_div.mp h).elim

/-- The test of a closure returns, given by what `step` proves of it. -/
theorem answers_of_spec {T P : Type} {inst : core.ops.function.FnMut P T Bool}
    (h : ∀ p x, inst.call_mut p x ⦃ _ _ => True ⦄) :
    ∀ p x, ∃ b p', inst.call_mut p x = ok (b, p') := by
  intro p x
  obtain ⟨⟨b, p'⟩, found, _⟩ := spec_imp_ok (h p x)
  exact ⟨b, p', found⟩

/-- The search of `position`, from the `i`th element on, returns when the test of its closure
returns for every element. -/
theorem positionFrom_total {T P : Type} (inst : core.ops.function.FnMut P T Bool) (s : Slice T)
    (answers : ∀ p x, ∃ b p', inst.call_mut p x = ok (b, p')) :
    ∀ k i (pred : P), s.val.length - i = k → ∃ r, positionFrom inst s pred i = ok r := by
  intro k
  induction k with
  | zero =>
    intro i pred left
    rw [positionFrom]
    have : ¬ i < s.val.length := by omega
    simp only [this, ↓reduceDIte]
    exact ⟨_, rfl⟩
  | succ k ih =>
    intro i pred left
    rw [positionFrom]
    have in_range : i < s.val.length := by omega
    obtain ⟨b, p', is_b⟩ := answers pred s.val[i]
    simp only [in_range, ↓reduceDIte, is_b, bind_ok]
    cases b
    · exact ih (i + 1) p' (by omega)
    · exact ⟨_, rfl⟩

/-- `position` returns when the test of its closure returns for every element. -/
theorem position_total {T P : Type} (inst : core.ops.function.FnMut P T Bool)
    (it : core.slice.iter.Iter T) (pred : P)
    (answers : ∀ p x, ∃ b p', inst.call_mut p x = ok (b, p')) :
    ∃ r, core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.position inst it pred
      = ok r := by
  obtain ⟨⟨o, it1⟩, found⟩ := positionFrom_total inst it.slice answers _ it.i pred rfl
  unfold core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.position
  simp only [found, bind_ok]
  cases o <;> exact ⟨_, rfl⟩

/-- `any` returns when the test of its closure returns for every element. -/
theorem any_total {T P : Type} (inst : core.ops.function.FnMut P T Bool)
    (it : core.slice.iter.Iter T) (pred : P)
    (answers : ∀ p x, ∃ b p', inst.call_mut p x = ok (b, p')) :
    ∃ r, core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.any inst it pred
      = ok r := by
  obtain ⟨r, found⟩ := position_total inst it pred answers
  unfold core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.any
  simp only [found, bind_ok]
  exact ⟨_, rfl⟩

/-- The search `retain` makes (the model of Models.lean) returns when the test of its closure
returns for every element. -/
theorem retainFrom_total {T F : Type} (inst : core.ops.function.FnMut F T Bool)
    (answers : ∀ p x, ∃ b p', inst.call_mut p x = ok (b, p')) :
    ∀ (l : List T) (f : F), ∃ r, retainFrom inst l f = ok r := by
  intro l
  induction l with
  | nil => intro f; exact ⟨_, rfl⟩
  | cons x rest ih =>
    intro f
    obtain ⟨b, f1, is_b⟩ := answers f x
    obtain ⟨kept, is_kept⟩ := ih f1
    refine ⟨if b then ⟨x :: kept.val, kept.property.cons_cons x⟩
      else ⟨kept.val, kept.property.cons x⟩, ?_⟩
    simp [retainFrom, is_b, is_kept]

/-- `Vec::retain` returns when the test of its closure returns for every element, and keeps no more
than it had. -/
theorem retain_total {T F : Type} (A : Type) (inst : core.ops.function.FnMut F T Bool)
    (v : alloc.vec.Vec T) (f : F)
    (answers : ∀ p x, ∃ b p', inst.call_mut p x = ok (b, p')) :
    alloc.vec.Vec.retain A inst v f ⦃ r => r.val.length ≤ v.val.length ⦄ := by
  obtain ⟨kept, found⟩ := retainFrom_total inst answers v.val f
  unfold alloc.vec.Vec.retain
  simp only [found, bind_ok]
  exact (WP.spec_ok _).mpr (by simpa using kept.property.length_le)

/-- `slice.iter()` makes an iterator over the slice, at its first element. -/
@[step] theorem slice_iter_spec {T : Type} (s : Slice T) :
    core.slice.Slice.iter s ⦃ it => it.slice = s ∧ it.i = 0 ⦄ := by
  simp [core.slice.Slice.iter, WP.spec_ok]

/-- `slice.iter_mut()` makes an iterator over the slice, at its first element, and gives the
function that turns the iterator back into the slice. -/
@[step] theorem slice_iter_mut_spec {T : Type} (s : Slice T) :
    core.slice.Slice.iter_mut s ⦃ it back => it.slice = s ∧ it.i = 0 ∧
      ∀ it', back it' = it'.slice ⦄ := by
  simp [core.slice.Slice.iter_mut, WP.spec_ok, WP.uncurry']

/-- `contains` on a slice of `u32` returns. -/
@[step] theorem contains_u32_returns (s : Slice Std.U32) (x : Std.U32) :
    core.slice.Slice.contains core.cmp.PartialEqU32 s x ⦃ _ => True ⦄ := by
  unfold core.slice.Slice.contains
  rw [anyM_pure (core.cmp.PartialEqU32.eq x) (fun y => x = y) (fun _ => rfl) s.val]
  exact (WP.spec_ok _).mpr trivial

/-- `a != b` on the states of a layer returns. -/
@[step] theorem ne_layer_state_returns (a b : LayerState) :
    core.cmp.PartialEq.ne.trait_default LayerState.Insts.CoreCmpPartialEqLayerState a b
      ⦃ _ => True ⦄ := by
  unfold core.cmp.PartialEq.ne.trait_default core.cmp.PartialEq.ne.default
  step*

/-- `a != b` on the states of a group returns. -/
@[step] theorem ne_group_state_returns (a b : GroupState) :
    core.cmp.PartialEq.ne.trait_default GroupState.Insts.CoreCmpPartialEqGroupState a b
      ⦃ _ => True ⦄ := by
  unfold core.cmp.PartialEq.ne.trait_default core.cmp.PartialEq.ne.default
  step*

@[simp] theorem deref_val {T : Type} (v : alloc.vec.Vec T) : (alloc.vec.Vec.deref v).val = v.val :=
by
  simp [alloc.vec.Vec.deref]

/-- A call of a function that cannot fail (Aeneas writes `lift f`) returns what the function gives.
-/
@[step] theorem lift_spec {α : Type} (x : α) : lift x ⦃ r => r = x ⦄ := by
  simp [lift, WP.spec_ok]

/-- `u64::checked_shl` (Models.lean) returns. -/
@[step] theorem checked_shl_returns (x : Std.U64) (n : Std.U32) :
    core.num.U64.checked_shl x n ⦃ _ => True ⦄ := by
  simp [core.num.U64.checked_shl, WP.spec_ok]

/-- `u64::saturating_mul` (Models.lean) returns. -/
@[step] theorem saturating_mul_returns (x y : Std.U64) :
    core.num.U64.saturating_mul x y ⦃ _ => True ⦄ := by
  simp [core.num.U64.saturating_mul, WP.spec_ok]

/-- `mem::take` of the list of the layers of a pull: it gives the old list and leaves an empty one.
-/
@[step] theorem take_layers_spec (d : alloc.vec.Vec Std.U32) :
    core.mem.take (alloc.vec.Vec.Insts.CoreDefaultDefault Std.U32) d ⦃ old new =>
      old = d ∧ new.val = [] ⦄ := by
  unfold core.mem.take alloc.vec.Vec.Insts.CoreDefaultDefault
  simp [alloc.vec.Vec.Insts.CoreDefaultDefault.default, alloc.vec.Vec.new, WP.spec_ok]

@[simp] theorem deref_mut_eq {T : Type} (v : alloc.vec.Vec T) :
    alloc.vec.Vec.deref_mut v = (v.slice, fun s => ⟨s⟩) := rfl

@[simp] theorem vec_slice_val {T : Type} (v : alloc.vec.Vec T) : v.slice.val = v.val := rfl

@[simp] theorem vec_mk_val {T : Type} (s : Slice T) :
    (({ slice := s } : alloc.vec.Vec T)).val = s.val := rfl

/-- `Vec::remove` of a place inside the vector gives back a vector with one less. -/
@[step] theorem vec_remove_spec {T : Type} (A : Type) (v : alloc.vec.Vec T) (i : Std.Usize)
    (inside : i.val < v.val.length) :
    alloc.vec.Vec.remove A v i ⦃ _ v1 => v1.val.length + 1 = v.val.length ⦄ := by
  unfold alloc.vec.Vec.remove
  simp only [inside, ↓reduceDIte, WP.spec_ok, WP.uncurry']
  simp [List.length_eraseIdx, inside]
  omega

/-- What a proof that `step` returns knows of `Vec::push`: the vector is one longer. -/
@[step] theorem push_length_spec {α : Type} (v : alloc.vec.Vec α) (x : α)
    (room : v.val.length < Usize.max) :
    v.push x ⦃ r => r.val.length = v.val.length + 1 ⦄ := by
  have := alloc.vec.Vec.push_spec v x room
  exact WP.spec_mono this (fun r h => by simp [h])

@[simp] theorem vec_set_val_length {T : Type} (v : alloc.vec.Vec T) (i : Std.Usize) (x : T) :
    (v.set i x).val.length = v.val.length := by
  simp [alloc.vec.Vec.set]

/-- Closes the bookkeeping goals a proof that a function returns leaves: lengths of lists and
numbers, by arithmetic after the facts known of the calls are put in. -/
macro "bookkeeping" : tactic =>
  `(tactic| first
    | omega
    | (simp only [Short, vec_set_val_length] at *; omega)
    | (simp_all [Short] <;> omega))

/-- Cloning a vector of `u32` gives the same vector. -/
@[step] theorem clone_u32_vec_spec (v : alloc.vec.Vec Std.U32) :
    alloc.vec.CloneVec.clone core.clone.CloneU32 v ⦃ r => r.val = v.val ⦄ := by
  unfold alloc.vec.CloneVec.clone
  have := Slice.clone_spec (clone := core.clone.CloneU32.clone) (s := v.slice) (by
    intro x _
    rfl)
  refine WP.spec_bind this ?_
  intro s h
  simp only [WP.spec_ok]
  rw [← h]

/-- The iterator of a vector goes over the elements of the vector. -/
@[step] theorem vec_into_iter_spec {T : Type} (v : alloc.vec.Vec T) :
    alloc.vec.IntoIteratorVec.into_iter v ⦃ it => it.val = v.val ⦄ := by
  unfold alloc.vec.IntoIteratorVec.into_iter
  exact (WP.spec_ok _).mpr rfl

@[simp] theorem into_vec_val {T : Type} (s : Slice T) : (alloc.slice.Slice.into_vec s).val = s.val
:=
  rfl

@[simp] theorem single_to_slice_val {T : Type} (x : T) :
    (Array.to_slice (Array.make 1#usize [x])).val = [x] := by
  simp [Array.to_slice, Array.make]

/-- Closes a bookkeeping goal that needs every fact known of the calls: `simp_all`, then
arithmetic if there is some left. -/
macro "settle" : tactic => `(tactic| (simp_all [Short] <;> omega))

end LazyCore
