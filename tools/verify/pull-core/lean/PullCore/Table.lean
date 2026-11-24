-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: how the table of the core is read and written by
-- the functions of crates/pull-core: the pulls are found by their place
-- (`pull_at_spec`), the phase of a pull is `phaseOf` (`phase_spec`), and a
-- phase is changed by `Retag` (the phase of the first pull named `p`, and
-- nothing else of the pulls).  It is what the proofs of the four claims
-- have in common.
--
-- Why it is needed: every function that changes a pull finds it with
-- `pull_at`, reads it with `Vec::index` and writes it back with
-- `Vec::index_mut`.  These lines are proved here once (`found_index`,
-- `found_set`), so that a proof of a function (Ends.lean, Claims.lean,
-- Phases.lean) follows only what the function does besides.  The facts of
-- `phaseOf` after a retag say what the others of the pulls do not.
--
-- Read before this file: Spec.lean, Loops.lean, and lib.rs of crates/pull-core.
--
-- Notation: `Ok m P` is "if `m` returns, its result satisfies `P`"; `pre ++ q :: post` is
-- the list `pre`, then `q`, then the list `post`; `∃`/`∀` as in Spec.lean.
import Ok
import Models
import PullCore.Spec
import PullCore.Loops

open Aeneas Aeneas.Std Result velarx_pull_core

namespace PullCore

/-- `c'` is `c` with the phase of the first pull named `p` set to `ph`: the pulls are
the same but for that phase, in the same places, and the last number is the same.  (`pre` are
the pulls before it, none of them named `p`; `q` the pull; `post` those after.) -/
def Retag (c c' : Core) (p : Std.U32) (ph : Phase) : Prop :=
  ∃ pre q post, c.pulls.val = pre ++ q :: post ∧ q.id = p ∧ (∀ x ∈ pre, x.id ≠ p) ∧
    c'.pulls.val = pre ++ { q with phase := ph } :: post ∧ c'.last = c.last

/-- What `pull_at` says when it finds a pull: `i` is the place of the first pull named
`p`, it is `q`, and `pre` are the pulls before it. -/
def Found (c : Core) (p : Std.U32) (i : Std.Usize) : Prop :=
  ∃ pre q post, c.pulls.val = pre ++ q :: post ∧ q.id = p ∧ (∀ x ∈ pre, x.id ≠ p) ∧
    i.val = pre.length

/-- The phase of the pull `q`, when it is the first one named `p`. -/
theorem phaseOf_found {c : Core} {p : Std.U32} {pre : List Pull} {q : Pull}
    {post : List Pull} (hc : c.pulls.val = pre ++ q :: post) (hq : q.id = p)
    (hpre : ∀ x ∈ pre, x.id ≠ p) : phaseOf c p = some q.phase := by
  have none_before : pre.find? (fun x => x.id = p) = none :=
    List.find?_eq_none.mpr (by simpa using hpre)
  simp [phaseOf, hc, List.find?_append, none_before, hq]

/-- No pull is named `p`: the core holds none. -/
theorem phaseOf_absent {c : Core} {p : Std.U32} (none_named : ∀ q ∈ c.pulls.val, q.id ≠ p) :
    phaseOf c p = none := by
  have none_found : c.pulls.val.find? (fun x => x.id = p) = none :=
    List.find?_eq_none.mpr (by simpa using none_named)
  simp [phaseOf, none_found]

/-- Two cores with the same pulls give a pull the same phase. -/
theorem phaseOf_congr {c c' : Core} (same : c'.pulls = c.pulls) (q : Std.U32) :
    phaseOf c' q = phaseOf c q := by simp [phaseOf, same]

/-- After a retag, the pull has the new phase and the others have the phase they had. -/
theorem phaseOf_retag {c c' : Core} {p : Std.U32} {ph : Phase} (retagged : Retag c c' p ph)
    (r : Std.U32) : phaseOf c' r = if r = p then some ph else phaseOf c r := by
  obtain ⟨pre, q, post, hc, hq, hpre, hc', -⟩ := retagged
  by_cases hr : r = p
  · subst hr
    simpa using phaseOf_found hc' hq hpre
  · have other : ¬ q.id = r := by rw [hq]; exact fun same => hr same.symm
    simp [phaseOf, hc, hc', List.find?_append, hr, other]

/-- A retag moves the phase of the one pull it is about, and no other. -/
theorem retag_cases {c c' : Core} {p : Std.U32} {ph : Phase} (retagged : Retag c c' p ph)
    (q : Std.U32) :
    phaseOf c' q = phaseOf c q ∨ (q = p ∧ phaseOf c' q = some ph) := by
  by_cases hq : q = p
  · exact Or.inr ⟨hq, by subst hq; simp [phaseOf_retag retagged]⟩
  · exact Or.inl (by simp [phaseOf_retag retagged q, hq])

/-- The derived `==` of a phase with a phase with no field.  (Only such: `==` of two
`Over` calls `Option::eq`, which Aeneas has no model of, and the crate makes no such
comparison.) -/
theorem phase_eq (x b : Phase) (hb : b = Phase.Waiting ∨ b = Phase.Fetching) :
    Ok (Phase.Insts.CoreCmpPartialEqPhase.eq x b) (fun r => r = true ↔ x = b) := by
  rcases hb with rfl | rfl <;> cases x <;>
    simp [Phase.Insts.CoreCmpPartialEqPhase.eq, Phase.read_discriminant, Ok.ok]

/-- The derived `!=` of a phase with a phase with no field. -/
theorem phase_ne (x b : Phase) (hb : b = Phase.Waiting ∨ b = Phase.Fetching) :
    Ok (core.cmp.PartialEq.ne.trait_default Phase.Insts.CoreCmpPartialEqPhase x b)
      (fun r => r = true ↔ x ≠ b) := by
  unfold core.cmp.PartialEq.ne.trait_default core.cmp.PartialEq.ne.default
  refine Ok.bind (phase_eq x b hb) ?_
  intro e he
  apply Ok.ok.mpr
  cases e <;> simp_all

/-- `U32` plus one is one more, or panics. -/
theorem add_one (x : Std.U32) : Ok (x + 1#u32) (fun z => z.val = x.val + 1) := by
  show Ok (UScalar.tryMk UScalarTy.U32 (x.val + (1#u32).val)) _
  unfold UScalar.tryMk UScalar.tryMkOpt
  split
  · apply Ok.ok.mpr; simp_all
  · exact Ok.fail

attribute [local irreducible] Ok

/-- `Vec::index` at the place `pull_at` found gives the pull found. -/
theorem found_index {c : Core} {i : Std.Usize} {pre post : List Pull} {q : Pull}
    (hc : c.pulls.val = pre ++ q :: post) (hi : i.val = pre.length) :
    Ok (alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Pull) c.pulls i)
      (fun x => x = q) := by
  refine Ok.mono (vec_index c.pulls i (by simp [hc, hi])) ?_
  intro x hx
  simp [hx, hc, hi]

/-- `Vec::index_mut` at that place gives the pull, and its way back, given the pull with another
phase, gives the retagged core. -/
theorem found_set {c : Core} {p : Std.U32} {i : Std.Usize} {pre post : List Pull} {q : Pull}
    (hc : c.pulls.val = pre ++ q :: post) (hq : q.id = p) (hpre : ∀ x ∈ pre, x.id ≠ p)
    (hi : i.val = pre.length) (ph : Phase) :
    Ok (alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice Pull) c.pulls i)
      (fun r => r.1 = q ∧ Retag c { c with pulls := r.2 { q with phase := ph } } p ph) := by
  refine Ok.mono (vec_index_mut c.pulls i (by simp [hc, hi])) ?_
  rintro ⟨y, back⟩ ⟨hy, hback⟩
  have is_q : y = q := by simpa [hc, hi] using hy
  refine ⟨is_q, pre, q, post, hc, hq, hpre, ?_, rfl⟩
  simp [hback, hc, hi]

/-- `pull_at`: the place of the first pull named `p`, as `Found` says, and no pull is
named `p` if it says there is none. -/
theorem pull_at_spec (c : Core) (p : Std.U32) :
    Ok (Core.pull_at c p) (fun o => match o with
      | none => ∀ q ∈ c.pulls.val, q.id ≠ p
      | some i => Found c p i) := by
  unfold Core.pull_at
  simp only [alloc.vec.Vec.deref, core.slice.Slice.iter, bind_ok]
  refine Ok.bind (position_first Core.pull_at.closure.Insts.CoreOpsFunctionFnMutTupleShared0PullBool
    (fun x => decide (x.id = p)) p (fun x => rfl) _) ?_
  rintro ⟨o, it⟩ (⟨hnone, hall⟩ | ⟨k, hk, x, hx, hkeep, hbefore⟩)
  · dsimp only at hnone
    subst hnone
    apply Ok.ok.mpr
    intro q hq
    simpa using hall q (by simpa using hq)
  · dsimp only at hk
    subst hk
    apply Ok.ok.mpr
    have hx' : c.pulls.val[k.val]? = some x := by simpa using hx
    have inside := (List.getElem?_eq_some_iff.mp hx').1
    have before : ∀ y ∈ c.pulls.val.take k.val, y.id ≠ p := by
      intro y hy
      obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hy
      rw [List.getElem?_take] at hj
      split at hj
      · simpa using hbefore j y (by omega) (by simpa using hj)
      · simp at hj
    refine ⟨c.pulls.val.take k.val, x, c.pulls.val.drop (k.val + 1), ?_, by simpa using hkeep,
      before, by simp; omega⟩
    rw [List.getElem?_eq_getElem inside, Option.some.injEq] at hx'
    rw [← hx', List.getElem_cons_drop inside, List.take_append_drop]

/-- `phase` is `phaseOf` of Spec.lean: the phase of the first pull named `p`. -/
theorem phase_spec (c : Core) (p : Std.U32) : Ok (Core.phase c p) (fun o => o = phaseOf c p) := by
  unfold Core.phase
  refine Ok.bind (pull_at_spec c p) ?_
  rintro (_ | i) found
  · simp only [core.option.Option.map]
    exact Ok.ok.mpr (phaseOf_absent found).symm
  · obtain ⟨pre, q, post, hc, hq, hpre, hi⟩ := found
    have inside : i.val < c.pulls.val.length := by simp [hc, hi]
    simp only [core.option.Option.map,
      Core.phase.closure.Insts.CoreOpsFunctionFnOnceTupleUsizePhase.call_once]
    have at_i : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Pull) c.pulls i =
        ok q := by
      rw [alloc.vec.Vec.index_slice_index]
      simp [alloc.vec.Vec.index_usize, hc, hi]
    rw [at_i]
    refine Ok.bind (Q := fun ph => ph = q.phase) ?_ ?_
    · refine Ok.bind (Q := fun x => x = q) (Ok.ok.mpr rfl) ?_
      intro x hx
      exact Ok.ok.mpr (by rw [hx])
    · intro ph hph
      apply Ok.ok.mpr
      rw [hph, phaseOf_found hc hq hpre]

end PullCore
