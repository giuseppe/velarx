-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/bpf-core.
-- The statements are in BpfCore/Spec.lean, the proofs in BpfCore/Claims.lean (which uses the files
-- before it in BpfCore/).
-- ../../run ends on this file: it fails unless every line `#proved T` below prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean
-- and the library functions the crate has no model of (the run prints none for this crate).
--
-- Read before this file: BpfCore/Spec.lean.
import Proved
import BpfCore.Claims

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean checks the type of each
-- line below, so Theorems.lean and Spec.lean suffice.
example : BpfCore.ValidNeverFails :=
  BpfCore.valid_never_fails
example : BpfCore.DenyProgramNeverFails :=
  BpfCore.deny_program_never_fails
example : BpfCore.RunNeverFails :=
  BpfCore.run_never_fails
example : BpfCore.ValidIsExactlyTheConditions :=
  BpfCore.valid_is_exactly_the_conditions
example : BpfCore.DenyProgramRefusesExactlyTheInvalidTables :=
  BpfCore.deny_program_refuses_exactly_the_invalid_tables
example : BpfCore.ProgramIsWellFormed :=
  BpfCore.program_is_well_formed
example : BpfCore.ProgramAnswersEveryCall :=
  BpfCore.program_answers_every_call
example : BpfCore.ProgramAnswersWhatTheTableSays :=
  BpfCore.program_answers_what_the_table_says

#proved BpfCore.valid_never_fails
#proved BpfCore.deny_program_never_fails
#proved BpfCore.run_never_fails
#proved BpfCore.valid_is_exactly_the_conditions
#proved BpfCore.deny_program_refuses_exactly_the_invalid_tables
#proved BpfCore.program_is_well_formed
#proved BpfCore.program_answers_every_call
#proved BpfCore.program_answers_what_the_table_says
