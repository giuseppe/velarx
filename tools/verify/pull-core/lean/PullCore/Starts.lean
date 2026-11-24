-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the functions of crates/pull-core that start a pull, give it
-- layers or drop it do (`begin_spec`, `claim_spec`, `forget_spec`), and what the loops they
-- call do (`held`, `free`, and the loop of `claim` that pushes a claim for each layer).
--
-- Why it is needed: they are the functions that add pulls and claims, and `forget` drops
-- them.  The claims of Spec.lean about the phases of the pulls (Phases.lean) and about the
-- claims (Claims.lean) are read off what they do, so it is said once, here, in terms of the
-- list of the pulls and the list of the claims.  What `forget` and the push of `begin` do to
-- the phase of a pull is `phaseOf_forget` and `phaseOf_push`.
--
-- How a lemma is proved: it follows the Rust function line by line: `Ok.bind` goes through a
-- line (the lemma of the call, from Loops.lean or Table.lean), a `cases` or a `split` goes
-- through a `match` or an `if`.  A loop is proved with `Ok.loop` and an invariant: what the
-- turns so far did (for `held`: "no claim before the place `i` is of the layer").
--
-- Read before this file: Spec.lean, Table.lean and lib.rs of crates/pull-core.
--
-- Notation: `Ok m P` is "if `m` returns, its result satisfies `P`"; `r.2` is the core a call
-- gives back (`r.1` is its answer); `l.map f` is the list of the `f` of the elements of `l`;
-- `l1 ++ l2` joins two lists; `∃`/`∀` as in Spec.lean.
import Ok
import Models
import PullCore.Spec
import PullCore.Loops
import PullCore.Table

open Aeneas Aeneas.Std Result velarx_pull_core

namespace PullCore

attribute [local irreducible] Ok

/-- `held`: whether a claim is of the layer. -/
theorem held_spec (c : Core) (l : Std.U32) :
    Ok (Core.held c l) (fun b => b = true ↔ ∃ h ∈ c.claims.val, h.layer = l) := by
  unfold Core.held Core.held_loop
  simp only [alloc.vec.Vec.deref, core.slice.Slice.iter, bind_ok]
  refine Ok.loop (I := fun it => it.slice.val = c.claims.val ∧ it.i ≤ c.claims.val.length ∧
    ∀ j h, c.claims.val[j]? = some h → j < it.i → h.layer ≠ l) ?_
    ⟨by simp, by simp, by intro j h _ hj; simp at hj⟩
  intro it ⟨hslice, hle, hbefore⟩
  unfold Core.held_loop.body
  refine Ok.bind (slice_next it) ?_
  rintro ⟨o, it1⟩ (⟨inside, hnext⟩ | ⟨outside, hnext⟩)
  · obtain ⟨rfl, rfl⟩ := hnext
    show Ok (if (it.slice.val[it.i]'inside).layer = l then ok (ControlFlow.done true)
      else ok (ControlFlow.cont ({ slice := it.slice, i := it.i + 1 } :
        core.slice.iter.Iter Held))) _
    split
    · rename_i same
      apply Ok.ok.mpr
      refine ⟨fun _ => ⟨_, ?_, same⟩, fun _ => rfl⟩
      rw [← hslice]; exact List.getElem_mem _
    · rename_i different
      apply Ok.ok.mpr
      have inside' : it.i < c.claims.val.length := by rw [← hslice]; exact inside
      refine ⟨hslice, by simp; omega, ?_⟩
      intro j h hh hj
      by_cases old : j < it.i
      · exact hbefore j h hh old
      · have : j = it.i := by simp at hj; omega
        subst this
        rw [← hslice, List.getElem?_eq_getElem inside, Option.some.injEq] at hh
        rw [← hh]
        exact different
  · obtain ⟨rfl, rfl⟩ := hnext
    rw [hslice] at outside
    apply Ok.ok.mpr
    refine ⟨fun no => by simp at no, ?_⟩
    rintro ⟨h, hmem, hl⟩
    obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hmem
    exact absurd hl (hbefore j h hj (by have := (List.getElem?_eq_some_iff.mp hj).1; omega))

/-- `free`: whether no claim is of any of the layers. -/
theorem free_spec (c : Core) (layers : Slice Std.U32) :
    Ok (Core.free c layers) (fun b =>
      b = true ↔ ∀ l ∈ layers.val, ∀ h ∈ c.claims.val, h.layer ≠ l) := by
  unfold Core.free SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter
  simp only [bind_ok]
  unfold Core.free_loop
  refine Ok.loop (I := fun it => it.slice = layers ∧ it.i ≤ layers.val.length ∧
    ∀ j l, layers.val[j]? = some l → j < it.i → ∀ h ∈ c.claims.val, h.layer ≠ l) ?_
    ⟨rfl, by simp, by intro j l _ hj; simp at hj⟩
  intro it ⟨hslice, hle, hbefore⟩
  subst hslice
  unfold Core.free_loop.body
  refine Ok.bind (slice_next it) ?_
  rintro ⟨o, it1⟩ (⟨inside, hnext⟩ | ⟨outside, hnext⟩)
  · obtain ⟨rfl, rfl⟩ := hnext
    refine Ok.bind (held_spec c _) ?_
    intro b hb
    split
    · rename_i held
      apply Ok.ok.mpr
      refine ⟨fun no => by simp at no, ?_⟩
      intro all
      obtain ⟨h, hmem, hl⟩ := hb.mp held
      exact absurd hl (all _ (List.getElem_mem _) h hmem)
    · rename_i not_held
      apply Ok.ok.mpr
      refine ⟨rfl, by simp; omega, ?_⟩
      intro j l hl hj
      by_cases old : j < it.i
      · exact hbefore j l hl old
      · have : j = it.i := by simp at hj; omega
        subst this
        rw [List.getElem?_eq_getElem inside, Option.some.injEq] at hl
        intro h hmem hh
        exact not_held (hb.mpr ⟨h, hmem, by rw [hh, ← hl]⟩)
  · obtain ⟨rfl, rfl⟩ := hnext
    apply Ok.ok.mpr
    refine ⟨fun _ => ?_, fun _ => rfl⟩
    intro l hl
    obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hl
    exact hbefore j l hj (by have := (List.getElem?_eq_some_iff.mp hj).1; omega)

/-- The loop of `claim`: a claim of `p` for each layer is pushed, in order. -/
theorem claim_loop_spec (layers : Slice Std.U32) (v : alloc.vec.Vec Held) (p : Std.U32) :
    Ok (Core.claim_loop ⟨layers, 0⟩ v p) (fun v1 =>
      v1.val = v.val ++ layers.val.map (fun l => ({ layer := l, pull := p } : Held))) := by
  unfold Core.claim_loop
  refine Ok.loop (I := fun x => x.1.slice = layers ∧ x.1.i ≤ layers.val.length ∧
    x.2.val = v.val ++ (layers.val.take x.1.i).map (fun l => ({ layer := l, pull := p } : Held))) ?_
    ⟨rfl, by simp, by simp⟩
  rintro ⟨it, v1⟩ ⟨hslice, hle, hpushed⟩
  dsimp only at hslice hle hpushed
  subst hslice
  unfold Core.claim_loop.body
  refine Ok.bind (slice_next it) ?_
  rintro ⟨o, it1⟩ (⟨inside, hnext⟩ | ⟨outside, hnext⟩)
  · obtain ⟨rfl, rfl⟩ := hnext
    refine Ok.bind (push_spec v1 _) ?_
    intro v2 hv2
    apply Ok.ok.mpr
    refine ⟨rfl, inside, ?_⟩
    rw [hv2, hpushed, List.take_add_one, List.getElem?_eq_getElem inside]
    simp only [Option.toList_some, List.map_append, List.map_cons, List.map_nil, List.append_assoc]
  · obtain ⟨rfl, rfl⟩ := hnext
    apply Ok.ok.mpr
    simpa [List.take_of_length_le outside] using hpushed

/-- `c'` is `c` without the pull `p` and the claims of `p` (`Core::forget`). -/
def ForgetOf (c : Core) (p : Std.U32) (c' : Core) : Prop :=
  c'.pulls.val = c.pulls.val.filter (fun q => q.id != p) ∧
  c'.claims.val = c.claims.val.filter (fun h => h.pull != p) ∧ c'.last = c.last

/-- `forget` drops the pulls named `p` and the claims of `p`, and leaves the last number. -/
theorem forget_spec (c : Core) (p : Std.U32) : Ok (Core.forget c p) (ForgetOf c p) := by
  unfold Core.forget
  refine Ok.bind (retain_filter _ (fun q => q.id != p) p (fun q => rfl) c.pulls) ?_
  intro pulls hpulls
  refine Ok.bind (retain_filter _ (fun h => h.pull != p) p (fun h => rfl) c.claims) ?_
  intro claims hclaims
  exact Ok.ok.mpr ⟨hpulls, hclaims, rfl⟩

/-- What `begin` does to the table before it starts the new pull: nothing, or the
forgetting of the old pull `o` the engine began before under the same name. -/
def Dropped (c : Core) (old : Option Std.U32) (c1 : Core) : Prop :=
  c1 = c ∨ ∃ o, old = some o ∧ ForgetOf c o c1

/-- The end of `begin`: the new pull, numbered one more than the last, is pushed
at the end of the pulls, waiting, and the claims are the claims of the core. -/
theorem push_new_spec (c1 : Core) :
    Ok (do
        let i ← c1.last + 1#u32
        let v ← alloc.vec.Vec.push c1.pulls ({ id := i, phase := Phase.Waiting } : Pull)
        ok (Begin.Started i, { c1 with pulls := v, last := i }))
      (fun r => ∃ i : Std.U32, i.val = c1.last.val + 1 ∧
        r.2.pulls.val = c1.pulls.val ++ [{ id := i, phase := Phase.Waiting }] ∧
        r.2.claims = c1.claims ∧ r.2.last = i) := by
  refine Ok.bind (add_one c1.last) ?_
  intro i hi
  refine Ok.bind (push_spec c1.pulls _) ?_
  intro v hv
  exact Ok.ok.mpr ⟨i, hi, hv, rfl, rfl⟩

/-- What `begin` leaves: `c'` is the core as it was (`Resumed`, `Busy`), or the old pull of the name
was dropped if it was over or absent (`Dropped`: the core `c1`), and the new pull, numbered one more
than the last, waiting, is pushed at the end, with no claim. -/
def Begun (c : Core) (old : Option Std.U32) (c' : Core) : Prop :=
  c' = c ∨ ∃ (c1 : Core) (i : Std.U32), Dropped c old c1 ∧ i.val = c.last.val + 1 ∧
    c'.pulls.val = c1.pulls.val ++ [{ id := i, phase := Phase.Waiting }] ∧
    c'.claims = c1.claims ∧ c'.last = i

/-- `begin` leaves the core as `Begun` says. -/
theorem begin_spec (c : Core) (old : Option Std.U32) :
    Ok (Core.begin c old) (fun r => Begun c old r.2) := by
  unfold Core.begin
  -- the new pull is pushed after `c1`, the core as the old pull left it
  have started : ∀ c1, Dropped c old c1 → c1.last = c.last →
      Ok (do
          let i ← c1.last + 1#u32
          let v ← alloc.vec.Vec.push c1.pulls ({ id := i, phase := Phase.Waiting } : Pull)
          ok (Begin.Started i, { c1 with pulls := v, last := i }))
        (fun r => Begun c old r.2) := by
    intro c1 dropped same
    refine Ok.mono (push_new_spec c1) ?_
    rintro r ⟨i, hi, hpulls, hclaims, hlast⟩
    exact Or.inr ⟨c1, i, dropped, by rw [hi, same], hpulls, hclaims, hlast⟩
  have forgotten : ∀ o, old = some o → Ok (do
        let c1 ← Core.forget c o
        let i ← c1.last + 1#u32
        let v ← alloc.vec.Vec.push c1.pulls ({ id := i, phase := Phase.Waiting } : Pull)
        ok (Begin.Started i, { c1 with pulls := v, last := i }))
      (fun r => Begun c old r.2) := by
    intro o hold
    refine Ok.bind (forget_spec c o) ?_
    intro c1 hc1
    exact started c1 (Or.inr ⟨o, hold, hc1⟩) hc1.2.2
  cases old with
  | none => exact started c (Or.inl rfl) rfl
  | some o =>
    refine Ok.bind (phase_spec c o) ?_
    intro ph hph
    subst hph
    rcases phaseOf c o with _ | ph
    · exact forgotten o rfl
    · cases ph <;> first
        | exact Ok.ok.mpr (Or.inl rfl)
        | exact forgotten o rfl

/-- `claim`: it leaves the core as it was (the pull is not there, or does not wait, or a
layer is held), or the pull waits, no layer asked for is held, the pull is fetching and its
claims, one for each layer, come after the others. -/
theorem claim_spec (c : Core) (p : Std.U32) (layers : Slice Std.U32) :
    Ok (Core.claim c p layers) (fun r =>
      r.2 = c ∨ (phaseOf c p = some Phase.Waiting ∧
        (∀ l ∈ layers.val, ∀ h ∈ c.claims.val, h.layer ≠ l) ∧ Retag c r.2 p Phase.Fetching ∧
        r.2.claims.val =
          c.claims.val ++ layers.val.map (fun l => ({ layer := l, pull := p } : Held)))) := by
  unfold Core.claim
  refine Ok.bind (pull_at_spec c p) ?_
  rintro (_ | i) found
  · exact Ok.ok.mpr (Or.inl rfl)
  · obtain ⟨pre, q, post, hc, hq, hpre, hi⟩ := found
    refine Ok.bind (found_index hc hi) ?_
    intro x hx
    subst hx
    refine Ok.bind (phase_ne x.phase Phase.Waiting (Or.inl rfl)) ?_
    intro b hb
    split
    · exact Ok.ok.mpr (Or.inl rfl)
    · rename_i not_other
      have waiting : x.phase = Phase.Waiting := by
        by_contra other
        exact not_other (hb.mpr other)
      refine Ok.bind (free_spec c layers) ?_
      intro free hfree
      split
      · rename_i isfree
        simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
        refine Ok.bind (claim_loop_spec layers c.claims p) ?_
        intro v hv
        refine Ok.bind (found_set hc hq hpre hi Phase.Fetching) ?_
        rintro ⟨y, back⟩ ⟨hy, retagged⟩
        dsimp only at hy retagged
        subst hy
        exact Ok.ok.mpr (Or.inr ⟨by rw [phaseOf_found hc hq hpre, waiting],
          hfree.mp isfree, retagged, hv⟩)
      · exact Ok.ok.mpr (Or.inl rfl)

/-- Dropping the pulls named `p` from a list leaves the first pull named `q` (not `p`). -/
theorem find_filter_other (l : List Pull) {p q : Std.U32} (h : q ≠ p) :
    (l.filter (fun x => x.id != p)).find? (fun x => x.id = q) = l.find? (fun x => x.id = q) := by
  rw [List.find?_filter]
  congr 1
  funext x
  by_cases hx : x.id = q
  · subst hx
    simpa [bne_iff_ne] using h
  · simp [hx]

/-- After a forget of `p`, no pull is named `p`, and the others have the phase they had. -/
theorem phaseOf_forget {c c1 : Core} {p : Std.U32} (h : ForgetOf c p c1) (q : Std.U32) :
    phaseOf c1 q = if q = p then none else phaseOf c q := by
  obtain ⟨hpulls, -, -⟩ := h
  by_cases hq : q = p
  · subst hq
    have : (c.pulls.val.filter (fun x => x.id != q)).find? (fun x => x.id = q) = none :=
      List.find?_eq_none.mpr (by simp)
    simp [phaseOf, hpulls, this]
  · simp [phaseOf, hpulls, hq, find_filter_other _ hq]

/-- After a pull is pushed at the end, a pull that was held has the phase it had, and the new
one, numbered `i`, is waiting (if no pull was named `i`). -/
theorem phaseOf_push {c1 c' : Core} {i : Std.U32}
    (h : c'.pulls.val = c1.pulls.val ++ [{ id := i, phase := Phase.Waiting }]) (q : Std.U32) :
    phaseOf c' q = match phaseOf c1 q with
      | some ph => some ph
      | none => if i = q then some Phase.Waiting else none := by
  simp only [phaseOf, h, List.find?_append]
  cases found : c1.pulls.val.find? (fun x => x.id = q) <;> by_cases hiq : i = q <;> simp [hiq]

end PullCore
