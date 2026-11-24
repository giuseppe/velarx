-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that `#proved` and `#all_claims_proved`
-- (Proved.lean) refuse what is not a proof of every claim: a theorem
-- that rests on `sorry`, on `native_decide` or on an axiom written for
-- it, the claim itself instead of its proof, a theorem whose statement
-- is not a claim by its name, a statement that is not a definition or is
-- made up outside the Spec, a claim proved twice, a Spec with a claim
-- left unproved, and a record of a proof not made by `#proved`.  The
-- claims are those of ProvedTest/Spec.lean.  ./run checks this file
-- before the theorems of every crate.
--
-- Why it is needed: a `#proved` that accepts too much passes every run
-- and nothing shows it; here each refusal is expected, and the run fails
-- if one goes missing, and so does the line printed for an honest proof.
--
-- Read before this file: Proved.lean, ProvedTest/Spec.lean.  Notation:
-- `#guard_msgs in C` fails unless the messages of the command C are the
-- ones written in the comment above it.
import Proved
import ProvedTest.Spec
import ProvedTest.Fake

open ProvedTest

/-- An honest proof of a claim is accepted, and says what it rests on. -/
theorem honest : Claim := rfl

/--
info: proved: ProvedTest.Claim by honest
  with the axioms of Lean []
  whatever these 0 functions and types of the standard library are: []
-/
#guard_msgs in
#proved honest

/-- A second proof of the same claim. -/
theorem honest_again : Claim := rfl

/-- error: honest_again proves ProvedTest.Claim again: honest already does -/
#guard_msgs in
#proved honest_again

/-- warning: declaration uses `sorry` -/
#guard_msgs in
theorem by_sorry : Short := sorry

/-- error: by_sorry is NOT proved: it assumes [sorryAx] -/
#guard_msgs in
#proved by_sorry

/-- A proof that trusts the compiler instead of the kernel: `native_decide`
rests on an axiom it writes for the proof (this version of Lean has no
`Lean.ofReduceBool` any more). -/
theorem by_native_decide : Short := by native_decide

/-- error: by_native_decide is NOT proved: it assumes [by_native_decide._native.native_decide.ax_1_1] -/
#guard_msgs in
#proved by_native_decide

/-- An axiom written for the proof. -/
axiom made_up : Short

theorem by_axiom : Short := made_up

/-- error: by_axiom is NOT proved: it assumes [made_up] -/
#guard_msgs in
#proved by_axiom

/-- error: ProvedTest.Short is NOT a theorem -/
#guard_msgs in
#proved Short

/-- A theorem of the right content whose statement does not name the claim. -/
theorem unnamed : 2 + 2 = 4 := rfl

/-- error: unnamed does NOT state a claim by its name -/
#guard_msgs in
#proved unnamed

/-- A statement that is not a definition. -/
inductive Built : Prop
  | made

theorem of_built : Built := .made

/-- error: of_built does NOT state a claim: Built is not a definition -/
#guard_msgs in
#proved of_built

/-- A statement made up in this file. -/
def Here : Prop := True

theorem of_here : Here := trivial

/-- error: of_here does NOT state a claim: Here is declared in this file, not in a Spec -/
#guard_msgs in
#proved of_here

/-- A statement made up in a proof file, with the name of a claim. -/
theorem of_fake : Fake.NoNameAgainstTheMeasure := trivial

/--
error: of_fake does NOT state a claim: Fake.NoNameAgainstTheMeasure is declared in ProvedTest.Fake, not in a Spec
-/
#guard_msgs in
#proved of_fake

/-- What the claims assume is not proved as a claim. -/
theorem of_assumption : Assumption := rfl

/--
error: of_assumption does NOT state a claim: ProvedTest.Assumption is marked not_a_claim in ProvedTest.Spec
-/
#guard_msgs in
#proved of_assumption

-- A claim (`Short`, an `abbrev`) is not proved yet.
/-- error: NOT proved: 1 claims of ProvedTest.Spec: [ProvedTest.Short] -/
#guard_msgs in
#all_claims_proved ProvedTest.Spec

-- The claims proved are not those of the module named.
/-- error: honest proves ProvedTest.Claim, which is not a claim of ProvedTest.Fake -/
#guard_msgs in
#all_claims_proved ProvedTest.Fake

theorem short : Short := rfl

/--
info: proved: ProvedTest.Short by short
  with the axioms of Lean []
  whatever these 0 functions and types of the standard library are: []
-/
#guard_msgs in
#proved short

-- Every claim is proved; the marked `Assumption` is not a claim.
/-- info: all 2 claims of ProvedTest.Spec are proved -/
#guard_msgs in
#all_claims_proved ProvedTest.Spec

-- A record made by other means than `#proved` is checked again.
run_cmd Lean.modifyEnv (provedClaims.addEntry · (``Short, ``by_sorry))

/-- error: by_sorry is NOT proved: it assumes [sorryAx] -/
#guard_msgs in
#all_claims_proved ProvedTest.Spec
