-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the functions that end a try do to the
-- pulls and to `out`, as small facts the two proofs (Cancel.lean and
-- Verdict.lean) use as bricks:
--   - `let_go` changes only the layers of the pull it is called for;
--   - `begin_try` and the loop of `leave` keep the names of the pulls;
--   - `leave` removes the pull it ends from the pulls, and pushes
--     `End` of it to `out`;
--   - `pull_at` finds a pull that is there (it is a search over the
--     pulls, `slice::Iter::position`, modelled in Models.lean).  The search is proved
--     once, for any test that is a pure function of the element (`positionFrom_pure`,
--     `position_pure`, `any_iff`): `pull_at`, `layer_at`, `lacking` and `goes` follow;
--   - `Vec::retain` keeps the elements a test says yes to (`retain_filter`), which gives the
--     layers `prepared` takes as new (`fresh_layers`).
-- Along the way: small lemmas on `Vec::index`, `Vec::set` and on lists that these proofs
-- need (the lemma on `Vec::push` is in Grows.lean).
--
-- Why it is needed: the two theorems speak of "the pull `p`" and of
-- the actions in `out`.  The Rust looks the pull up by name (`pull_at`),
-- changes it in place (`index_mut`) and calls these functions; a
-- proof must say what each of them leaves of the rest.
--
-- Read before this file: Ok.lean and Grows.lean.  Spec.lean is imported
-- for `asked`.
--
-- Notation met here (more in Ok.lean and Grows.lean):
--   - `v.val` is the list inside a Rust `Vec`; `c.pulls.val` the list of
--     the pulls of the core `c`;
--   - `∃ h : i < n, P` is "`i < n`, and `P` (which may use that fact)":
--     the proof of `i < n` is kept because a list is indexed with it;
--     `l[i]` is the `i`th element, `l.set i x` the list with `x` there;
--   - `l.eraseIdx i` is the list without its `i`th element;
--   - `(·.id)` is "the id of" and `l.map (·.id)` the list of the names
--     of the pulls in `l`;
--   - `x ∈ l` is "x is an element of l".
import LazyCore.Grows
import LazyCore.Spec

open Aeneas Aeneas.Std Result velarx_lazy_core

namespace LazyCore

attribute [local irreducible] let_go leave_loop

/-- `v[i]` (reading), of any vector (the pulls, the layers, the groups), returns the `i`th element
when `i` is in range. -/
theorem index_in_range {T : Type} (v : alloc.vec.Vec T) (i : Std.Usize)
    (in_range : i.val < v.val.length) :
    alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice T) v i = ok v.val[i.val] := by
  simp [alloc.vec.Vec.index_slice_index, alloc.vec.Vec.index_usize, in_range]

/-- `v[i]` (reading), of any vector, returns the `i`th element; out of range it panics, which is
not spoken of. -/
theorem index_result {T : Type} (v : alloc.vec.Vec T) (i : Std.Usize) :
    Ok (alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice T) v i)
      (fun r => ∃ h : i.val < v.val.length, r = v.val[i.val]) := by
  by_cases in_range : i.val < v.val.length
  · rw [index_in_range _ _ in_range]; exact Ok.ok.mpr ⟨in_range, rfl⟩
  · have : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice T) v i
        = fail Error.arrayOutOfBounds := by
      simp [alloc.vec.Vec.index_slice_index, alloc.vec.Vec.index_usize, in_range]
    rw [this]; exact Ok.fail

/-- `&mut v[i]` returns the `i`th element, and the way to write it back
(`Vec::set`), when `i` is in range. -/
theorem index_mut_in_range {T : Type} (v : alloc.vec.Vec T) (i : Std.Usize)
    (in_range : i.val < v.val.length) :
    alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice T) v i =
      ok (v.val[i.val], alloc.vec.Vec.set v i) := by
  simp [alloc.vec.Vec.index_mut_slice_index, alloc.vec.Vec.index_mut_usize,
    alloc.vec.Vec.index_usize, in_range]

/-- `&mut v[i]`: if it returns, `i` was in range and it gives the `i`th element and
the way to write it back; out of range it panics, which is not spoken of. -/
theorem index_mut_result {T : Type} (v : alloc.vec.Vec T) (i : Std.Usize) :
    Ok (alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice T) v i)
      (fun r => ∃ h : i.val < v.val.length, r = (v.val[i.val], alloc.vec.Vec.set v i)) := by
  by_cases in_range : i.val < v.val.length
  · rw [index_mut_in_range _ _ in_range]; exact Ok.ok.mpr ⟨in_range, rfl⟩
  · have : alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice T) v i
        = fail Error.arrayOutOfBounds := by
      simp [alloc.vec.Vec.index_mut_slice_index, alloc.vec.Vec.index_mut_usize,
        alloc.vec.Vec.index_usize, in_range]
    rw [this]; exact Ok.fail

/-- Writing back with `Vec::set` puts the element at its place in the list. -/
theorem set_val {T : Type} (v : alloc.vec.Vec T) (i : Std.Usize) (x : T) :
    (alloc.vec.Vec.set v i x).val = v.val.set i.val x := by
  simp [alloc.vec.Vec.set]

/-- Putting back an element of the same name at `i` leaves the list of the names as it was. -/
theorem map_set_of_same {α β : Type} (f : α → β) (l : List α) (i : Nat) (y : α)
    (in_range : i < l.length) (same : f y = f l[i]) : (l.set i y).map f = l.map f := by
  apply List.ext_getElem
  · simp
  · intro j _ _
    simp only [List.getElem_map, List.getElem_set]
    split
    · subst_vars; exact same
    · rfl

/-- A list is its element at `i` and the others. -/
theorem mem_iff_here_or_erased {α : Type} (l : List α) (i : Nat) (in_range : i < l.length)
    (x : α) : x ∈ l ↔ x = l[i] ∨ x ∈ l.eraseIdx i := by
  rw [List.eraseIdx_eq_take_drop_succ]
  conv_lhs => rw [← List.take_append_drop i l, List.drop_eq_getElem_cons in_range]
  simp only [List.mem_append, List.mem_cons]
  tauto

/-- The same, for a list that had its element at `i` replaced: it is the new element and the
others. -/
theorem mem_set_iff {α : Type} (l : List α) (i : Nat) (in_range : i < l.length) (y x : α) :
    x ∈ l.set i y ↔ x = y ∨ x ∈ l.eraseIdx i := by
  rw [List.eraseIdx_eq_take_drop_succ, List.set_eq_take_append_cons_drop]
  simp only [in_range, ↓reduceIte, List.mem_append, List.mem_cons]
  tauto

/-- An element that differs from the one at `i` in `f` (for example in its name) is still there
when another is put at `i`. -/
theorem mem_set_of_other {α β : Type} (f : α → β) {l : List α} {i : Nat} (y : α)
    (in_range : i < l.length) {x : α} (in_l : x ∈ l) (other : f x ≠ f l[i]) : x ∈ l.set i y :=
  (mem_set_iff l i in_range y x).mpr (Or.inr
    (((mem_iff_here_or_erased l i in_range x).mp in_l).resolve_left
      fun same => other (by rw [same])))

/-- What the search of `position`, from the `i`th element on, returns when its test is a pure
function of the element (it answers `f x` for each `x` and gives the state back unchanged): `none`
when no element from `i` on satisfies `f`; `some n` when `n` is in range, not before `i`, the
element at `n` satisfies `f`, and none between `i` and `n` does.  Proved by induction on what is
left to search; it is the only proof of that search: `pull_at`, `layer_at`, `lacking` and `goes`
are corollaries. -/
theorem positionFrom_pure {T P : Type} (inst : core.ops.function.FnMut P T Bool) (f : T → Prop)
    [DecidablePred f] (s : Slice T) (pred : P)
    (answers : ∀ x, inst.call_mut pred x = ok (decide (f x), pred)) :
    ∀ k i, s.val.length - i = k → ∃ o it, positionFrom inst s pred i = ok (o, it) ∧
      match o with
      | none => ∀ j (hj : j < s.val.length), i ≤ j → ¬ f (s.val[j])
      | some n => ∃ hn : n.val < s.val.length, i ≤ n.val ∧ f (s.val[n.val]) ∧
          ∀ j (hj : j < s.val.length), i ≤ j → j < n.val → ¬ f (s.val[j]) := by
  intro k
  induction k with
  | zero =>
    intro i left
    -- nothing is left to search: no element from `i` on, as none is there
    rw [positionFrom]
    have : ¬ i < s.val.length := by omega
    simp only [this, ↓reduceDIte]
    exact ⟨_, _, rfl, fun j hj ij => absurd hj (by omega)⟩
  | succ k ih =>
    intro i left
    have in_range : i < s.val.length := by omega
    rw [positionFrom]
    simp only [in_range, ↓reduceDIte, answers, bind_ok, uncurry_eq]
    by_cases here : f (s.val[i])
    · -- the element at `i` satisfies `f`: the search stops there
      simp only [here, decide_true, ↓reduceIte]
      refine ⟨_, _, rfl, by simpa using in_range, by simp, by simpa using here, ?_⟩
      intro j _ ij before
      have : j < i := before
      omega
    · -- it does not: the search goes on with `i + 1`
      simp only [here, decide_false]
      obtain ⟨o, it, found, result⟩ := ih (i + 1) (by omega)
      refine ⟨o, it, found, ?_⟩
      cases o with
      | none =>
        intro j hj ij
        rcases Nat.lt_or_eq_of_le ij with ahead | same
        · exact result j hj ahead
        · subst same; exact here
      | some n =>
        obtain ⟨hn, after_i, satisfies, before⟩ := result
        refine ⟨hn, by omega, satisfies, fun j hj ij before_n => ?_⟩
        rcases Nat.lt_or_eq_of_le ij with ahead | same
        · exact before j hj ahead before_n
        · subst same; exact here

/-- `position` over a whole slice, with a test that is a pure function of the element: it returns
`none` when no element satisfies `f`, and `some n` when the element at `n` does and none
before it. -/
theorem position_pure {T P : Type} (inst : core.ops.function.FnMut P T Bool) (f : T → Prop)
    [DecidablePred f] (s : Slice T) (pred : P)
    (answers : ∀ x, inst.call_mut pred x = ok (decide (f x), pred)) :
    ∃ o it, core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.position inst
        ⟨s, 0⟩ pred = ok (o, it) ∧
      match o with
      | none => ∀ x ∈ s.val, ¬ f x
      | some n => ∃ hn : n.val < s.val.length, f (s.val[n.val]) ∧
          ∀ j (hj : j < n.val), ¬ f (s.val[j]'(hj.trans hn)) := by
  obtain ⟨o, it, found, result⟩ := positionFrom_pure inst f s pred answers _ 0 rfl
  unfold core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.position
  simp only [found, bind_ok]
  cases o with
  | none =>
    refine ⟨none, it, rfl, fun x in_s => ?_⟩
    obtain ⟨j, hj, rfl⟩ := List.getElem_of_mem in_s
    exact result j hj (Nat.zero_le _)
  | some n =>
    obtain ⟨hn, _, satisfies, before⟩ := result
    refine ⟨_, it, rfl, by simpa using hn, by simpa using satisfies, fun j hj => ?_⟩
    simpa using before j (by simp at hj; omega) (Nat.zero_le _) (by simpa using hj)

/-- `any` over a whole slice, with a test that is a pure function of the element: it says whether
`f` holds of an element of the slice. -/
theorem any_iff {T P : Type} (inst : core.ops.function.FnMut P T Bool) (f : T → Prop)
    [DecidablePred f] (s : Slice T) (pred : P)
    (answers : ∀ x, inst.call_mut pred x = ok (decide (f x), pred)) :
    ∃ it, core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.any inst ⟨s, 0⟩ pred
      = ok (decide (∃ x ∈ s.val, f x), it) := by
  obtain ⟨o, it, found, result⟩ := position_pure inst f s pred answers
  unfold core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.any
  simp only [found, bind_ok]
  cases o with
  | none => exact ⟨it, by simpa using result⟩
  | some n =>
    obtain ⟨hn, satisfies, _⟩ := result
    exact ⟨it, by simpa using ⟨_, List.getElem_mem hn, satisfies⟩⟩

/-- What `pull_at` returns (the first pull named `p`, by `slice::Iter::position`): `none` when
no pull of the core is named `p`; `some n` when `n` is in range, the pull at `n` is named `p`,
and no pull before it is. -/
theorem pull_at_result (c : Core) (p : Std.U32) :
    Ok (Core.pull_at c p) (fun o => match o with
      | none => ∀ q ∈ c.pulls.val, q.id ≠ p
      | some n => ∃ hn : n.val < c.pulls.val.length, (c.pulls.val[n.val]).id = p ∧
          ∀ j (hj : j < n.val), (c.pulls.val[j]'(hj.trans hn)).id ≠ p) := by
  obtain ⟨o, it, found, result⟩ := position_pure
    Core.pull_at.closure.Insts.CoreOpsFunctionFnMutTupleShared0PullBool (fun q : Pull => q.id = p)
    c.pulls.deref p (fun _ => rfl)
  have deref : (c.pulls.deref).val = c.pulls.val := by simp [alloc.vec.Vec.deref]
  unfold Core.pull_at
  simp only [core.slice.Slice.iter, found, bind_ok]
  cases o with
  | none =>
    exact Ok.ok.mpr fun q in_c => by simpa [deref] using result q (by simpa [deref] using in_c)
  | some n =>
    obtain ⟨hn, named, before⟩ := result
    exact Ok.ok.mpr ⟨by simpa [deref] using hn, by simpa [deref] using named, fun j hj => by
      simpa [deref] using before j hj⟩

/-- `pull_at` returns only a place whose pull is named as asked. -/
theorem pull_at_sound (c : Core) (p : Std.U32) :
    Ok (Core.pull_at c p)
      (fun o => ∀ n, o = some n →
        ∃ hn : n.val < c.pulls.val.length, (c.pulls.val[n.val]).id = p) := by
  refine (pull_at_result c p).mono ?_
  intro o result n found
  subst found
  obtain ⟨hn, named, _⟩ := result
  exact ⟨hn, named⟩

/-- `pull_at` finds no pull of a name that the core holds: if it returns `none`, the core
holds no pull of that name. -/
theorem pull_at_none (c : Core) (pull : Std.U32) :
    Ok (Core.pull_at c pull) (fun o => o = none → ¬ held c pull) := by
  refine (pull_at_result c pull).mono ?_
  rintro o result rfl ⟨q, hq, named⟩
  exact result q hq named

/-- When the names are distinct, `pull_at` of the name of the pull at `j` returns `j`
(and not another place). -/
theorem pull_at_unique (c : Core) (p : Std.U32) (distinct : (c.pulls.val.map (·.id)).Nodup)
    (j : Nat) (in_range : j < c.pulls.val.length) (named_p : (c.pulls.val[j]).id = p) :
    Ok (Core.pull_at c p) (fun o => ∃ n : Std.Usize, o = some n ∧ n.val = j) := by
  refine (pull_at_result c p).mono ?_
  intro o result
  cases o with
  | none => exact absurd named_p (result _ (List.getElem_mem in_range))
  | some n =>
    obtain ⟨hn, named_n, _⟩ := result
    refine ⟨n, rfl, ?_⟩
    exact (List.Nodup.getElem_inj_iff distinct (i := n.val) (j := j)
      (hi := by simpa using hn) (hj := by simpa using in_range)).mp (by simp [named_n, named_p])

/-- Two steps with the same discriminant are the same step. -/
theorem step_eq_of_discriminant (s1 s2 : Step) :
    s1.read_discriminant = s2.read_discriminant → s1 = s2 := by
  cases s1 <;> cases s2 <;> simp [Step.read_discriminant]

/-- `a == b` on phases says yes only for equal phases. -/
theorem phase_eq_true (a b : Phase) :
    Ok (Phase.Insts.CoreCmpPartialEqPhase.eq a b) (fun r => r = true → a = b) := by
  unfold Phase.Insts.CoreCmpPartialEqPhase.eq
  cases a <;> cases b <;>
    simp [Phase.read_discriminant, Step.Insts.CoreCmpPartialEqStep.eq]
  all_goals first
    | exact Ok.ok.mpr trivial
    | exact Ok.ok.mpr rfl
    | exact Ok.ok.mpr (fun same => step_eq_of_discriminant _ _ (by simpa using same) ▸ rfl)
    | exact Ok.ok.mpr (fun same => by simpa using same)

/-- `x - 1` for a length of at least one is the length of what is before the last. -/
theorem pred_len (x : Std.Usize) :
    Ok (x - 1#usize) (fun z => z.val + 1 = x.val) := by
  show Ok (UScalar.sub x 1#usize) _
  unfold UScalar.sub
  by_cases small : x.val < (1#usize).val
  · simp only [small, ↓reduceIte]; exact Ok.fail
  · simp only [small, ↓reduceIte]
    apply Ok.ok.mpr
    have one : (1#usize).val = 1 := rfl
    rw [one] at small
    show (BitVec.ofNat _ (x.val - (1#usize).val)).toNat + 1 = x.val
    rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt (by scalar_tac), one]
    omega

/-- `next` of the iterator of a vector: it gives the first element and the rest, or nothing
when the vector is empty. -/
theorem into_iter_next {T : Type} (it : alloc.vec.into_iter.IntoIter T) :
    Ok (alloc.vec.into_iter.IteratorIntoIter.next it) (fun r =>
      (r.1 = none ∧ it.val = []) ∨ ∃ hd tl, r.1 = some hd ∧ it.val = hd :: tl ∧ r.2.val = tl) := by
  unfold alloc.vec.into_iter.IteratorIntoIter.next
  split
  · rename_i empty; exact Ok.ok.mpr (Or.inl ⟨rfl, empty⟩)
  · rename_i hd tl cons; exact Ok.ok.mpr (Or.inr ⟨hd, tl, rfl, cons, alloc.vec.Vec.from_val _ _⟩)

/-- The core holds a pull named `p` exactly when `p` is among the names of its pulls. -/
theorem held_iff_name {c : Core} {p : Std.U32} :
    held c p ↔ p ∈ c.pulls.val.map (·.id) := by
  simp [held]

/-- `Option::filter` of the place `pull_at` found, in `prepared`, keeps a place only if the pull
there is at `Running Preparing`. -/
theorem filter_preparing (c : Core) (o : Option Std.Usize) :
    Ok (core.option.Option.filter
        prepared.closure.Insts.CoreOpsFunctionFnOnceTupleShared1UsizeBool o c.pulls)
      (fun r => ∀ n, r = some n →
        ∃ h : n.val < c.pulls.val.length,
          (c.pulls.val[n.val]).phase = Phase.Running Step.Preparing) := by
  unfold core.option.Option.filter
  cases o with
  | none => exact Ok.ok.mpr (fun n found => by simp at found)
  | some t =>
    show Ok (do
      let b ← prepared.closure.Insts.CoreOpsFunctionFnOnceTupleShared1UsizeBool.call_once c.pulls t
      ok (if b then some t else none)) _
    unfold prepared.closure.Insts.CoreOpsFunctionFnOnceTupleShared1UsizeBool.call_once
    simp only [Std.bind_assoc]
    refine Ok.bind (index_result _ _) ?_
    rintro _ ⟨in_range, rfl⟩
    refine Ok.bind (phase_eq_true _ _) ?_
    intro b preparing
    refine Ok.ok.mpr fun n found => ?_
    by_cases b_true : b = true
    · simp only [b_true, ↓reduceIte, Option.some.injEq] at found
      subst found
      exact ⟨in_range, preparing b_true⟩
    · simp [b_true] at found

/-- `Option::filter` keeps the place `pull_at` found, in `prepared`, if the pull there is at
`Running Preparing`. -/
theorem filter_keeps_preparing (c : Core) (n : Std.Usize) (in_range : n.val < c.pulls.val.length)
    (preparing : (c.pulls.val[n.val]).phase = Phase.Running Step.Preparing) :
    Ok (core.option.Option.filter
        prepared.closure.Insts.CoreOpsFunctionFnOnceTupleShared1UsizeBool (some n) c.pulls)
      (fun r => r = some n) := by
  unfold core.option.Option.filter
  show Ok (do
    let b ← prepared.closure.Insts.CoreOpsFunctionFnOnceTupleShared1UsizeBool.call_once c.pulls n
    ok (if b then some n else none)) _
  unfold prepared.closure.Insts.CoreOpsFunctionFnOnceTupleShared1UsizeBool.call_once
  simp only [Std.bind_assoc]
  refine Ok.bind (index_result _ _) ?_
  rintro _ ⟨_, rfl⟩
  rw [preparing]
  simp [Phase.Insts.CoreCmpPartialEqPhase.eq, Phase.read_discriminant,
    Step.Insts.CoreCmpPartialEqStep.eq, Step.read_discriminant]
  exact Ok.ok.mpr rfl

/-- `Vec::retain` with a predicate that answers `keep x` for each `x`, whatever it has seen
before, keeps the elements `keep` says yes to. -/
theorem retain_filter {T F : Type} (A : Type) (inst : core.ops.function.FnMut F T Bool)
    (keep : T → Bool) (f : F) (answers : ∀ x, inst.call_mut f x = ok (keep x, f))
    (v : alloc.vec.Vec T) :
    Ok (alloc.vec.Vec.retain A inst v f) (fun w => w.val = v.val.filter keep) := by
  have each : ∀ l : List T, ∃ r : { r : List T // r.Sublist l },
      retainFrom inst l f = ok r ∧ r.val = l.filter keep := by
    intro l
    induction l with
    | nil => exact ⟨⟨[], .slnil⟩, rfl, rfl⟩
    | cons x rest ih =>
      obtain ⟨r, found, is_filter⟩ := ih
      by_cases yes : keep x = true
      · refine ⟨⟨x :: r.val, r.property.cons_cons x⟩, ?_, by simp [yes, is_filter]⟩
        simp [retainFrom, answers, found, yes]
      · refine ⟨⟨r.val, r.property.cons x⟩, ?_, by simp [yes, is_filter]⟩
        simp [retainFrom, answers, found, yes]
  obtain ⟨r, found, is_filter⟩ := each v.val
  unfold alloc.vec.Vec.retain
  rw [found]
  simp only [bind_ok]
  exact Ok.ok.mpr (by rw [alloc.vec.Vec.from_val]; exact is_filter)

/-- `Vec::retain` keeps some of the elements, in order, whatever the predicate does. -/
theorem retain_sublist {T F : Type} (A : Type) (inst : core.ops.function.FnMut F T Bool)
    (f : F) (v : alloc.vec.Vec T) :
    Ok (alloc.vec.Vec.retain A inst v f) (fun w => w.val.Sublist v.val) := by
  unfold alloc.vec.Vec.retain
  refine Ok.bind (Q := fun _ => True) (Ok.any _) ?_
  intro kept _
  exact Ok.ok.mpr (by rw [alloc.vec.Vec.from_val]; exact kept.property)

/-- `layer_at` finds a layer exactly when the layer is in the table. -/
theorem layer_at_isSome (c : Core) (l : Std.U32) :
    ∃ o, Core.layer_at c l = ok o ∧ (o.isSome = true ↔ ∃ x ∈ c.layers.val, x.id = l) := by
  obtain ⟨o, it, found, result⟩ := position_pure
    Core.layer_at.closure.Insts.CoreOpsFunctionFnMutTupleShared0LayerBool
    (fun x : Layer => x.id = l) (alloc.vec.Vec.deref c.layers) l (fun _ => rfl)
  unfold Core.layer_at
  simp only [core.slice.Slice.iter, found, bind_ok]
  refine ⟨o, rfl, ?_⟩
  cases o with
  | none => simpa [alloc.vec.Vec.deref] using result
  | some n =>
    obtain ⟨hn, named, _⟩ := result
    simp only [Option.isSome_some, true_iff]
    have in_range : n.val < c.layers.val.length := by simpa [alloc.vec.Vec.deref] using hn
    exact ⟨_, List.getElem_mem in_range, by simpa [alloc.vec.Vec.deref] using named⟩

/-- The layers `prepared` takes from the event as new: those that are not in the table.  The test
`retain` makes is `layer_at(l).is_none()`. -/
theorem fresh_layers (c : Core) (layers : alloc.vec.Vec Std.U32) :
    Ok (alloc.vec.Vec.retain alloc.alloc.Global
      prepared.closure_1.Insts.CoreOpsFunctionFnMutTupleShared1U32Bool layers c)
      (fun w => w.val = layers.val.filter fun l => decide (l ∉ c.layers.val.map (·.id))) := by
  have answers : ∀ l : Std.U32,
      prepared.closure_1.Insts.CoreOpsFunctionFnMutTupleShared1U32Bool.call_mut c l =
        ok (decide (l ∉ c.layers.val.map (·.id)), c) := by
    intro l
    obtain ⟨o, found, iff⟩ := layer_at_isSome c l
    simp only [prepared.closure_1.Insts.CoreOpsFunctionFnMutTupleShared1U32Bool.call_mut, found,
      bind_ok, core.option.Option.is_none]
    congr 2
    cases o <;> simp_all
  exact retain_filter alloc.alloc.Global
    prepared.closure_1.Insts.CoreOpsFunctionFnMutTupleShared1U32Bool _ c answers layers

/-- `let_go` of the pull at `at_` changes only the layers of that pull: `out` grows, by
actions that say nothing of a pull, the settings are the same, and the pulls are the same
but for the layers of the pull at `at_`. -/
theorem let_go_changes_layers (c : Core) (at_ : Std.Usize) (out : alloc.vec.Vec Action) :
    Ok (let_go c at_ out) (fun r => AppendsAboutNoPull out.val r.2.val ∧ r.1.cfg = c.cfg ∧
      ∃ (h : at_.val < c.pulls.val.length) (ls : alloc.vec.Vec Std.U32),
        r.1.pulls = c.pulls.set at_ { c.pulls.val[at_.val] with layers := ls }) := by
  unfold let_go
  by_cases in_range : at_.val < c.pulls.val.length
  swap
  · refine Ok.bind (index_mut_result _ _) ?_
    rintro _ ⟨h, _⟩
    exact absurd h in_range
  -- `let_go` takes the pull at `at_` (`&mut c.pulls[at]`) and its layers (`mem::take`)
  rw [index_mut_in_range _ _ in_range]
  simp only [bind_ok, uncurry_eq]
  refine Ok.bind (Ok.any _) ?_; intro x _
  simp only [uncurry_eq]
  refine Ok.bind (Ok.any _) ?_; intro p1 _
  refine Ok.bind (Ok.any _) ?_; intro iter _
  -- the loop over the layers only pushes to `out`
  refine Ok.bind ((let_go_loop0_kinds _ _ _ _).appends.mono fun _ h => h.noPull) ?_;
      intro out1 grew_layers
  refine Ok.bind (Ok.any _) ?_; intro layers _
  refine Ok.bind (Ok.any _) ?_; intro y _
  simp only [uncurry_eq]
  refine Ok.bind (Ok.any _) ?_; intro z _
  simp only [uncurry_eq]
  -- so does the loop over the groups; they do not touch the pulls
  refine Ok.bind ((let_go_loop1_kinds _ _ _ _ _).appends.mono fun _ h => grew_layers.trans h.noPull)
    ?_; intro w grew_groups
  simp only [uncurry_eq]
  refine Ok.bind (Ok.any _) ?_; intro groups1 _
  -- what is returned: the core with the pull put back, with other layers
  apply Ok.ok.mpr
  exact ⟨grew_groups, rfl, in_range, _, rfl⟩

/-- `begin_try` of the pull at `at_` pushes to `out`, among other actions, `Prepare` of the pull,
keeps the settings, the layers and the groups, and puts the pull back at `at_` at
`Running Preparing`, with `progressed` off: the other pulls, and the name and the other fields of
that one, are as they were. -/
theorem begin_try_prepares (c : Core) (at_ : Std.Usize) (out : alloc.vec.Vec Action) :
    Ok (begin_try c at_ out) (fun r => r.1.cfg = c.cfg ∧ r.1.layers = c.layers ∧
      r.1.groups = c.groups ∧ ∃ h : at_.val < c.pulls.val.length,
        (∃ t, r.2.val = out.val ++ t ∧ Action.Prepare (c.pulls.val[at_.val]).id ∈ t) ∧
        r.1.pulls.val = c.pulls.val.set at_.val { c.pulls.val[at_.val] with
          phase := Phase.Running Step.Preparing, progressed := false }) := by
  unfold begin_try
  -- the pull at `at_` is changed (phase, `progressed`)
  refine Ok.bind (index_mut_result _ _) ?_
  rintro _ ⟨in_range, rfl⟩
  simp only [uncurry_eq]
  -- the two pushes: `Record` and `Prepare`
  refine Ok.bind (push_appends _ _) ?_; intro out1 pushed_record
  refine Ok.bind (push_appends _ _) ?_; intro out2 pushed_prepare
  apply Ok.ok.mpr
  refine ⟨rfl, rfl, rfl, in_range, ⟨out2.val.drop out.val.length, ?_, ?_⟩,
    by simp [alloc.vec.Vec.set]⟩
  · rw [pushed_prepare, pushed_record]; simp
  · rw [pushed_prepare, pushed_record]; simp

/-- `begin_try` of the pull at `at_` pushes to `out` (`Record`, `Prepare`), keeps the
settings, and the pulls keep their names. -/
theorem begin_try_keeps_names (c : Core) (at_ : Std.Usize) (out : alloc.vec.Vec Action) :
    Ok (begin_try c at_ out) (fun r => out.val <+: r.2.val ∧ r.1.cfg = c.cfg ∧
      r.1.pulls.val.map (·.id) = c.pulls.val.map (·.id)) := by
  refine (begin_try_prepares c at_ out).mono ?_
  rintro r ⟨same_cfg, _, _, in_range, ⟨t, pushed, _⟩, pulls⟩
  refine ⟨by rw [pushed]; exact List.prefix_append _ _, same_cfg, ?_⟩
  rw [pulls]
  refine map_set_of_same (·.id) _ _ _ in_range ?_
  rfl

/-- The loop of `leave` that gives the freed place to the pulls that wait (it calls
`begin_try`) pushes to `out` and keeps the names of the pulls. -/
theorem leave_loop_keeps_names (iter : core.ops.range.Range Std.Usize) (c : Core)
    (out : alloc.vec.Vec Action) (old : List Action) (old_first : old <+: out.val) :
    Ok (leave_loop iter c out) (fun r => old <+: r.2.val ∧
      r.1.pulls.val.map (·.id) = c.pulls.val.map (·.id)) := by
  unfold leave_loop
  refine Ok.loop (I := fun x => old <+: x.2.2.val ∧
    x.2.1.pulls.val.map (·.id) = c.pulls.val.map (·.id)) ?_ ⟨old_first, rfl⟩
  rintro ⟨iter, c1, out1⟩ ⟨grown, same_names⟩
  dsimp only at grown same_names
  unfold leave_loop.body
  -- the next index of the range: `for at in 0..c.pulls.len()`
  refine Ok.bind (Ok.any _) ?_; rintro ⟨o, iter1⟩ _
  simp only [uncurry_eq]
  cases o with
  | none => exact Ok.ok.mpr ⟨grown, same_names⟩
  | some at_ =>
    simp only []
    -- `if slots_held(c) >= completers { break }`
    refine Ok.bind (Ok.any _) ?_; intro i _
    split
    · exact Ok.ok.mpr ⟨grown, same_names⟩
    · -- `if c.pulls[at].phase == Phase::Queued`
      refine Ok.bind (Ok.any _) ?_; intro p _
      refine Ok.bind (Ok.any _) ?_; intro queued _
      split
      · -- it is queued: it gets the place (`slot = true`), and `begin_try` runs for it
        refine Ok.bind (index_mut_result _ _) ?_
        rintro _ ⟨in_range, rfl⟩
        simp only [uncurry_eq]
        refine Ok.bind (begin_try_keeps_names _ _ _) ?_
        rintro ⟨c2, out2⟩ ⟨grown2, _, names2⟩
        apply Ok.ok.mpr
        refine ⟨grown.trans grown2, ?_⟩
        rw [names2, ← same_names]
        simp [alloc.vec.Vec.set, map_set_of_same (·.id) _ _ _ in_range]
      · exact Ok.ok.mpr ⟨grown, same_names⟩

/-- Taking the `i`th element out of a list that had another element put at `i` gives
the same list as taking it out of the original. -/
theorem eraseIdx_set {α : Type} (l : List α) (i : Nat) (q : α) :
    (l.set i q).eraseIdx i = l.eraseIdx i := by
  induction l generalizing i with
  | nil => simp
  | cons a l ih => cases i <;> simp [ih]

/-- `Vec::remove` of an index in range returns the element there and the vector without it. -/
theorem remove_returns_and_erases (v : alloc.vec.Vec Pull) (i : Std.Usize)
    (in_range : i.val < v.val.length) :
    ∃ rest, alloc.vec.Vec.remove alloc.alloc.Global v i = ok (v.val[i.val], rest) ∧
      rest.val = v.val.eraseIdx i.val := by
  unfold alloc.vec.Vec.remove
  simp [in_range]

/-- `leave` ends the pull at `at_`: from `out` it pushes some actions and then `End` of
the pull, and the pulls that are left are the others, in the same order. -/
theorem leave_removes_the_pull (c : Core) (at_ : Std.Usize) (out : alloc.vec.Vec Action) :
    Ok (leave c at_ out) (fun r => ∃ (h : at_.val < c.pulls.val.length) (t : List Action),
      (out.val ++ t ++ [Action.End (c.pulls.val[at_.val]).id]) <+: r.2.val ∧
      r.1.pulls.val.map (·.id) = (c.pulls.val.eraseIdx at_.val).map (·.id)) := by
  unfold leave
  -- `let_go` first: it pushes `t`, and changes only the layers of the pull
  refine Ok.bind (let_go_changes_layers c at_ out) ?_
  rintro ⟨c1, out1⟩ ⟨⟨⟨t, pushed_t⟩, _⟩, _, in_range, ls, pulls1⟩
  dsimp only at pulls1 pushed_t
  simp only [uncurry_eq]
  have in_range1 : at_.val < c1.pulls.val.length := by
    rw [pulls1]; simpa [alloc.vec.Vec.set] using in_range
  have same_name : (c1.pulls.val[at_.val]).id = (c.pulls.val[at_.val]).id := by
    simp [pulls1, alloc.vec.Vec.set]
  -- then `c.pulls.remove(at)`
  obtain ⟨rest, removed, rest_is⟩ := remove_returns_and_erases c1.pulls at_ in_range1
  rw [removed]
  simp only [bind_ok, uncurry_eq]
  -- then `End` of the pull is pushed
  refine Ok.bind (push_appends _ _) ?_
  intro out2 pushed_end
  -- and the loop that gives the place away only pushes, and keeps the names
  refine (leave_loop_keeps_names _ _ _ out2.val (List.prefix_refl _)).mono ?_
  rintro r ⟨grown, same_names⟩
  refine ⟨in_range, t, ?_, ?_⟩
  · rw [pushed_end, ← pushed_t, same_name] at grown
    simpa using grown
  · rw [same_names]
    simp [rest_is, pulls1, alloc.vec.Vec.set, eraseIdx_set]

/-- `List.anyM` (by which Aeneas models `Slice::contains`) of a test that answers whether `P` holds
of its argument says yes exactly when `P` holds of one of the elements. -/
theorem anyM_pure {α : Type} (f : α → Result Bool) (P : α → Prop) [DecidablePred P]
    (answers : ∀ x, f x = ok (decide (P x))) (l : List α) :
    List.anyM f l = ok (decide (∃ x ∈ l, P x)) := by
  induction l with
  | nil => exact rfl
  | cons a rest ih =>
    simp only [List.anyM, answers, ih]
    by_cases here : P a <;> simp [here]; rfl

/-- `Pull::lacks` says yes exactly when the layer is among the layers of the pull
(`self.layers.contains(&layer)`). -/
theorem lacks_iff (p : Pull) (layer : Std.U32) :
    Pull.lacks p layer = ok (decide (layer ∈ p.layers.val)) := by
  unfold Pull.lacks core.slice.Slice.contains
  have contains := anyM_pure (core.cmp.PartialEqU32.eq layer) (fun y => layer = y)
    (fun x => rfl) (alloc.vec.Vec.deref p.layers).val
  simp [alloc.vec.Vec.deref] at contains ⊢
  exact contains

/-- `Pull::has_all` (a loop over the layers, stopping at the first the pull lacks that `done`
refuses) says yes exactly when `done` accepts the state of every layer of the slice that the pull
lacks, if the closure `done` answers whether `accepts` holds of the state it is given. -/
theorem has_all_iff {T0 : Type} (inst : core.ops.function.Fn T0 LayerState Bool) (p : Pull)
    (layers : Slice Layer) (done : T0) (accepts : LayerState → Prop) [DecidablePred accepts]
    (answers : ∀ s, inst.call done s = ok (decide (accepts s))) :
    Ok (Pull.has_all inst p layers done)
      (fun b => b = true ↔ ∀ x ∈ layers.val, x.id ∈ p.layers.val → accepts x.state) := by
  unfold Pull.has_all
  simp only [core.slice.Slice.iter, bind_ok]
  unfold Pull.has_all_loop
  refine Ok.loop (I := fun it : core.slice.iter.Iter Layer =>
     it.slice = layers ∧ it.i ≤ layers.val.length ∧
       ∀ x ∈ layers.val.take it.i, x.id ∈ p.layers.val → accepts x.state) ?_ ⟨rfl, by simp, by simp⟩
  rintro it ⟨same, in_range, seen⟩
  unfold Pull.has_all_loop.body core.slice.iter.IteratorSliceIter.next
  dsimp only
  by_cases more : it.i < it.slice.len
  · have more' : it.i < layers.val.length := by subst same; simpa using more
    simp only [more, ↓reduceDIte, bind_ok]
    generalize hg : it.slice[it.i] = x
    have current : it.slice.val[it.i] = x := hg
    refine Ok.bind (Q := fun b => b = decide (x.id ∈ p.layers.val))
      (by rw [lacks_iff]; exact Ok.ok.mpr rfl) ?_
    intro b is_b
    subst is_b
    have more'' : it.i < it.slice.val.length := by simpa [same] using more'
    -- the layers seen after this round: those before, and this one
    have seen_next : (x.id ∈ p.layers.val → accepts x.state) →
        ∀ y ∈ List.take (it.i + 1) layers.val, y.id ∈ p.layers.val → accepts y.state := by
      intro ok_x y hy lacked
      rw [List.take_succ_eq_append_getElem (by simpa [same] using more'')] at hy
      rcases List.mem_append.mp hy with before | here
      · exact seen y before lacked
      · have : y = x := by rw [List.mem_singleton.mp here, ← current]; simp [same]
        subst this; exact ok_x lacked
    by_cases lacked : x.id ∈ p.layers.val
    · simp only [decide_eq_true_eq, lacked, ↓reduceIte, answers, bind_ok]
      by_cases accepted : accepts x.state
      · simp only [accepted, ↓reduceIte]
        exact Ok.ok.mpr ⟨same, by show it.i + 1 ≤ _; omega, seen_next fun _ => accepted⟩
      · simp only [accepted, ↓reduceIte]
        refine Ok.ok.mpr ⟨by simp, fun all => absurd (all x ?_ lacked) accepted⟩
        rw [← same, ← current]; exact List.getElem_mem more''
    · simp only [decide_eq_true_eq, lacked, ↓reduceIte]
      exact Ok.ok.mpr ⟨same, by show it.i + 1 ≤ _; omega,
        seen_next fun h => absurd h lacked⟩
  · -- no more layers: all of them were seen
    simp only [more, ↓reduceDIte, bind_ok]
    refine Ok.ok.mpr ⟨fun _ x hx => ?_, fun _ => rfl⟩
    have : layers.val.length ≤ it.i := by simpa [same] using more
    exact seen x (by rwa [List.take_of_length_le this]) 
/-- A layer state has the discriminant of `Stored` exactly when it is `Stored`.  (Aeneas has the
comparison `s == LayerState::Stored` compare the discriminants of the two states.) -/
theorem stored_iff (s : LayerState) :
    s.read_discriminant = LayerState.Stored.read_discriminant ↔ s = LayerState.Stored := by
  cases s <;> simp [LayerState.read_discriminant]

/-- The test of the closure `|s| s == LayerState::Stored` of `advance` answers whether the
discriminant of the state is that of `Stored`. -/
theorem stored_test (s : LayerState) :
    advance.closure.Insts.CoreOpsFunctionFnTupleLayerStateBool.call () s =
      ok (decide (s.read_discriminant = LayerState.Stored.read_discriminant)) := by
  unfold advance.closure.Insts.CoreOpsFunctionFnTupleLayerStateBool.call
    LayerState.Insts.CoreCmpPartialEqLayerState.eq
  rfl

/-- Two layer states are equal or not (the Rust `LayerState` derives `PartialEq`). -/
instance : DecidableEq LayerState := fun a b => by
  cases a <;> cases b <;> first | exact isTrue rfl | exact isFalse (by intro h; cases h)

/-- The test of the closure `|s| matches!(s, Ready | Stored)` of `advance` answers whether the
state is `Ready` or `Stored`. -/
theorem ready_test (s : LayerState) :
    advance.closure_1.Insts.CoreOpsFunctionFnTupleLayerStateBool.call () s =
      ok (decide (s = LayerState.Ready ∨ s = LayerState.Stored)) := by
  cases s <;> rfl

/-- An action that is in what was pushed (`out.val ++ l` is the beginning of the new
`out'`) was asked for by the step: it is in what `out'` has more than `out`. -/
theorem asked_if_appended {out out' : alloc.vec.Vec Action} {l : List Action} {a : Action}
    (appended : (out.val ++ l) <+: out'.val) (a_in_l : a ∈ l) : asked out out' a := by
  obtain ⟨t, ht⟩ := appended
  simp [asked, ← ht, a_in_l]

end LazyCore
