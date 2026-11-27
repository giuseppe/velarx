-- SPDX-License-Identifier: Apache-2.0
-- What this file is: the one notion the proofs of the crates are written in
-- (lazy-core; ./run copies it next to Proved.lean).
--
-- Aeneas turns each Rust function into a Lean function that returns a
-- `Result`: either `ok x` (the function returned `x`) or `fail e` (it
-- panicked; a loop that never ends is a third case).  The statements we
-- prove are of the kind "if the function returns, then ...", so we need
-- a way to say that about a `Result`.  That is `Ok`:
--
--     Ok m P    "if `m` returns, what it returns satisfies `P`"
--
-- A `fail` satisfies every `Ok` (`Ok.fail`), so `Ok` says nothing of a
-- panic or of a loop that does not end.  This is on purpose: the
-- functions of the standard library that have no model (Models.lean) may
-- do either, and the statements of Spec.lean only speak of runs that
-- return (`step c now event out = ok (c', out')` for lazy-core).
--
-- Why it is needed: the proofs follow a Rust function line by line, and
-- a line is a `bind` (`let x <- m; rest`).  `Ok.bind` is the rule to go
-- through a line: prove `Ok m Q` for the call, then `Ok (rest x) P`
-- for every `x` that satisfies `Q`.  `Ok.loop` does the same for a loop
-- (the invariant is kept by the body).  `Ok.mono` weakens the claim, `Ok.and`
-- joins two claims of one call, `Ok.any` is the claim "nothing" (for a call
-- whose result does not matter), `Ok.ok` and `Ok.eq` read an `Ok` of a known
-- result, `Ok.of_spec` turns a fact of the Aeneas library, said in its own
-- notation (`m ⦃ r => P r ⦄`), into an `Ok`.
--
-- Read before this file: nothing.
--
-- Notation: `Ok m P` as above; `fun x => P x` is the function that takes
-- `x` and gives `P x`; `m >>= f` is "run `m`, then `f` of its result".
-- `DWLP`, `EffectWP` and `RustEffect` belong to Aeneas: `Ok` is
-- `DWLP` for an effect in which every panic is allowed, and the two
-- `instance`s below are the two small facts Aeneas asks of that effect.
import Aeneas

open Aeneas Aeneas.Std Aeneas.Data.Coinductive Result Lean.Order

unseal Result
attribute [local implicit_reducible] Result

/-- The effect of a panic: it is allowed, whatever the claim. -/
@[reducible] def okWP : EffectWP RustEffect where
  State := Unit
  wp _ _ _ := True

/-- A condition Aeneas asks of the effect above; trivial, since every panic is allowed. -/
instance : EffectWP.Monotonic okWP where
  wp_monotonic _ _ _ := trivial

/-- The other condition Aeneas asks of the effect above; trivial too. -/
instance : EffectWP.Conjunctive okWP where
  wp_conj _ _ _ := trivial

/-- `Ok m P`: if the Rust function behind `m` returns, its result satisfies `P`;
if it panics or does not end, nothing is claimed. -/
def Ok {α : Type} (m : Result α) (P : α → Prop) : Prop :=
  DWLP okWP m (fun v _ => P v) ()

variable {α β : Type}

/-- A function that returns `x` satisfies `P` exactly when `x` does. -/
theorem Ok.ok {x : α} {P : α → Prop} : Ok (Result.ok x) P ↔ P x :=
  DWLP.ret_iff

/-- If `m` satisfies `P` and is known to return `x`, then `x` satisfies `P`. -/
theorem Ok.eq {m : Result α} {P : α → Prop} {x : α} (h : Ok m P) (hm : m = Result.ok x) :
    P x := by
  subst hm; exact Ok.ok.mp h

/-- A panic satisfies every claim: only runs that return are spoken of. -/
theorem Ok.fail {e : Error} {P : α → Prop} : Ok (Result.fail e) P :=
  DWLP.vis trivial

/-- The empty claim: every call satisfies it, for a call whose result does not matter. -/
theorem Ok.any (m : Result α) : Ok m (fun _ => True) := by
  refine DWLP.coinduction (fun _ _ => True) ?_ trivial
  intro t s _
  cases t using ITree.cases <;>
    simp [FunctionalWP.ret, FunctionalWP.div, FunctionalWP.vis]

/-- What Aeneas proves of a function of its library, in its notation `m ⦃ r => P r ⦄` (`m`
returns, and its result satisfies `P`), is more than `Ok m P`. -/
theorem Ok.of_spec {m : Result α} {P : α → Prop} (h : m ⦃ r => P r ⦄) : Ok m P := by
  cases m using ITree.cases with
  | ret x => exact Ok.ok.mpr ((WP.spec_ok x).mp h)
  | vis e k => exact ((WP.spec_vis e k).mp h).elim
  | div => exact (WP.spec_div.mp h).elim

/-- Going through one line `let x <- m; f x` of a function: the call `m` satisfies `Q`,
and the rest satisfies `P` for each result that satisfies `Q`. -/
theorem Ok.bind {m : Result α} {f : α → Result β} {Q : α → Prop} {P : β → Prop}
    (hm : Ok m Q) (hf : ∀ x, Q x → Ok (f x) P) : Ok (m >>= f) P :=
  DWLP.bind hm (fun v _ hv => hf v hv)

/-- A claim may be weakened: if `m` satisfies `P` and `P` gives `Q`, then `m` satisfies `Q`. -/
theorem Ok.mono {m : Result α} {P Q : α → Prop} (h : Ok m P) (hPQ : ∀ x, P x → Q x) :
    Ok m Q :=
  DWLP.mono h (fun v _ hv => hPQ v hv)

/-- A call that satisfies two claims satisfies both together. -/
theorem Ok.and {m : Result α} {P Q : α → Prop} (hP : Ok m P) (hQ : Ok m Q) :
    Ok m (fun x => P x ∧ Q x) :=
  DWLP.and_iff.mpr ⟨hP, hQ⟩

/-- A technical fact Lean needs to prove things of a loop by induction on its unfoldings. -/
theorem Ok.admissible (P : α → Prop) : admissible (fun m : Result α => Ok m P) :=
  DWLP.admissible okWP _ ()

/-- A loop keeps an invariant `I` if its body does: whenever the body is given a state
that satisfies `I`, it either goes round again with a state that satisfies `I` or
ends with a result that satisfies `P`; then the loop satisfies `P`. -/
theorem Ok.loop {body : α → Result (ControlFlow α β)} {I : α → Prop} {P : β → Prop}
    (hBody : ∀ x, I x → Ok (body x) (fun r => match r with
      | .cont y => I y
      | .done z => P z))
    {x : α} (hx : I x) : Ok (Aeneas.Std.loop body x) P := by
  refine Aeneas.Std.loop.fixpoint_induct body (fun f => ∀ x, I x → Ok (f x) P) ?_ ?_ x hx
  · apply admissible_pi_apply (P := fun x m => I x → Ok m P)
    intro x
    by_cases hI : I x
    · simpa [hI] using Ok.admissible P
    · simpa [hI] using (admissible_const_true : Lean.Order.admissible (fun (_ : Result β) => True))
  · intro f hf x hx
    apply Ok.bind (hBody x hx)
    intro r hr
    cases r with
    | cont y => exact hf y hr
    | done z => exact Ok.ok.mpr hr
