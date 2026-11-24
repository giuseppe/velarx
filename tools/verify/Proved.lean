-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the two commands that end a run of ./run, and
-- the mark `@[not_a_claim]`.
--
-- `#proved T` (one line for each claim, in the Theorems.lean of each
-- crate) fails unless `T` is a theorem whose statement is, by its name, a
-- claim: a definition of a `Prop` declared in a module `….Spec` and not
-- marked `@[not_a_claim]`; unless no other `#proved` already proved that
-- claim; and unless what `T` rests on is the three axioms of Lean and
-- functions of the standard library nothing is assumed of (the axioms of
-- Extracted/*External.lean, which ./run makes).  It prints
-- "proved: CLAIM by T" and those axioms, for a reader, and records the
-- pair in the environment.  So a `sorry` or an axiom written in a proof
-- fails the run (`native_decide` too: it rests on the axiom
-- `Lean.ofReduceBool`), and so does naming the claim instead of its proof
-- (the axioms of a statement say nothing of its proof) or a claim made up
-- outside Spec.lean.
--
-- `#all_claims_proved M` is not written by a crate: ./run reads it after
-- Theorems.lean, in a file that imports it.  It lists the claims of the
-- module M (the Spec of the crate) from the environment: every constant
-- declared there whose type is `Prop`, except those marked
-- `@[not_a_claim]`.  It checks each `#proved` again (so that a record
-- made by other means proves nothing), and fails, naming them, unless
-- every claim of M is proved and no claim of another module is.  Its last
-- line, "all N claims of M are proved", is the one ./run checks.
--
-- `@[not_a_claim]` marks a `Prop` of Spec.lean that the claims take as a
-- hypothesis (the 64-bit machine of bpf-core and lazy-core) and that is
-- not itself claimed.  A `Prop` of Spec.lean with neither a proof nor the
-- mark fails the run: a claim cannot be skipped by the way it is written
-- (`abbrev`, `private`, a namespace, an attribute).
--
-- ProvedTest.lean checks each refusal.
--
-- Why it is needed: Lean accepts a theorem that uses `sorry` or an
-- `axiom` with only a warning, and nothing says which statements were
-- meant to be proved; here both are errors, and what each theorem rests
-- on is shown, so a reader can see that every claim of Spec.lean is
-- proved from the code and the models alone.
--
-- Read before this file: nothing.  Notation: an `axiom` is a statement
-- Lean takes as true without proof; `collectAxioms T` lists those that
-- `T` uses, directly or through lemmas.  The three of Lean (`propext`,
-- `Classical.choice`, `Quot.sound`) are part of ordinary mathematics in
-- Lean.  `initialize` makes, once for every file that imports this one,
-- the table of the marks and the one of the proved claims.
import Lean

open Lean Elab Command Meta

/-- The mark of a `Prop` of Spec.lean that is not a claim. -/
initialize notAClaim : TagAttribute ←
  registerTagAttribute `not_a_claim
    "a Prop of Spec.lean that the claims assume and that is not claimed"

/-- The pairs (claim, theorem) of the `#proved` read so far, in this file
and in the files it imports. -/
initialize provedClaims : SimplePersistentEnvExtension (Name × Name) (Array (Name × Name)) ←
  registerSimplePersistentEnvExtension {
    addEntryFn := Array.push
    addImportedFn := fun modules => modules.foldl (· ++ ·) #[] }

/-- The module a constant is declared in (none: the file being read). -/
def moduleOf (env : Environment) (name : Name) : Option Name :=
  (env.getModuleIdxFor? name).map (env.header.moduleNames[·]!)

/-- A type is `Prop`, once its definitions are unfolded (all of them, as
the kernel does, so that no way of writing `Prop` hides a claim). -/
def isPropType (type : Expr) : CommandElabM Bool :=
  liftTermElabM do return (← withTransparency .all (whnf type)).isProp

/-- The checks of `#proved T`, but the one of a second proof: returns the
claim `T` proves and the axioms it rests on (those of Lean, then the
functions of the library). -/
def checkProof (name : Name) : CommandElabM (Name × Array Name × Array Name) := do
  let env ← getEnv
  -- `T` is a theorem, and its statement is a claim named as it is
  let some (.thmInfo proof) := env.find? name
    | throwError "{name} is NOT a theorem"
  let .const claim [] := proof.type
    | throwError "{name} does NOT state a claim by its name"
  -- (its type is `Prop`: Lean checked that the statement of a theorem is)
  let some (.defnInfo _) := env.find? claim
    | throwError "{name} does NOT state a claim: {claim} is not a definition"
  match moduleOf env claim with
  | some module@(.str _ "Spec") =>
    if notAClaim.hasTag env claim then
      throwError "{name} does NOT state a claim: {claim} is marked not_a_claim in {module}"
  | some module =>
    throwError "{name} does NOT state a claim: {claim} is declared in {module}, not in a Spec"
  | none =>
    throwError "{name} does NOT state a claim: {claim} is declared in this file, not in a Spec"
  -- what it rests on
  let lean := [``propext, ``Classical.choice, ``Quot.sound]
  let external (axiom_ : Name) : Bool :=
    moduleOf env axiom_ ∈ [some `Extracted.FunsExternal, some `Extracted.TypesExternal]
  let axioms := (← collectAxioms name).qsort Name.lt
  let (known, assumed) := axioms.partition fun a => lean.contains a || external a
  unless assumed.isEmpty do
    throwError "{name} is NOT proved: it assumes {assumed}"
  let (lean, unknown) := known.partition lean.contains
  return (claim, lean, unknown)

elab "#proved " theorem_:ident : command => do
  let name ← liftCoreM <| realizeGlobalConstNoOverloadWithInfo theorem_
  let (claim, lean, unknown) ← checkProof name
  if let some (_, other) := (provedClaims.getState (← getEnv)).find? (·.1 == claim) then
    throwError "{name} proves {claim} again: {other} already does"
  modifyEnv (provedClaims.addEntry · (claim, name))
  logInfo m!"proved: {claim} by {name}\n  with the axioms of Lean {lean}\n  whatever these {unknown.size} functions and types of the standard library are: {unknown}"

elab "#all_claims_proved " spec:ident : command => do
  let spec := spec.getId
  let env ← getEnv
  let some index := env.getModuleIdx? spec
    | throwError "{spec} is not imported"
  -- the claims of the Spec, from what it declares
  let mut claims := #[]
  for (name, info) in env.header.moduleData[index.toNat]!.constants.map (fun c => (c.name, c)) do
    if !notAClaim.hasTag env name && (← isPropType info.type) then
      claims := claims.push name
  -- what the `#proved` recorded, checked again
  let mut proved := #[]
  for (_, theorem_) in provedClaims.getState env do
    let (claim, _, _) ← checkProof theorem_
    unless moduleOf env claim == some spec do
      throwError "{theorem_} proves {claim}, which is not a claim of {spec}"
    if proved.contains claim then
      throwError "{claim} is proved twice"
    proved := proved.push claim
  let unproved := claims.filter (!proved.contains ·)
  unless unproved.isEmpty do
    throwError "NOT proved: {unproved.size} claims of {spec}: {unproved.qsort Name.lt}"
  logInfo m!"all {claims.size} claims of {spec} are proved"
