-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean, from the files before it in
-- BpfCore/: `valid`, `deny_program` and `run` return; `valid` accepts exactly the valid tables and
-- `deny_program` gives an error exactly for the others; the program is well formed; `run` of it
-- answers something to every call, and what `Expected` says.
--
-- Why it is needed: Theorems.lean lists these theorems and asks Lean what each rests on.
--
-- Read before this file: Spec.lean, then the other files in this directory.
--
-- Notation: `refine WP.spec_mono h ?_` is "use the result `h` about the function, and show that
-- what it says is enough"; `rintro ⟨a, b⟩` takes a statement "a and b" apart.
import BpfCore.WellFormed

open Aeneas Aeneas.Std Result velarx_bpf_core

namespace BpfCore

/-- The program of a valid small table is far shorter than the interpreter needs it to be. -/
theorem program_length_fits (on64 : OnA64BitMachine) (table : Table) (target : Target)
    (small : IsSmall table) (valid : IsValid table) :
    (programInsns table target).length + 4294967296 ≤ Usize.max := by
  obtain ⟨small_denied, small_rules, -⟩ := small
  have rules_len := rulesInsns_length_le table.«only».val
    (fun rule member => (valid.2 rule member).2.2)
  have prelude_len : (preludeInsns target.arch.val target.x32).length ≤ 6 := by
    unfold preludeInsns; split <;> simp
  have clone_len : (cloneInsns target.clone3.val target.clone.val).length = 8 := by
    simp [cloneInsns]
  have denied_len : table.denied.length = table.denied.val.length := rfl
  have rules_count : table.«only».length = table.«only».val.length := rfl
  have max_is := usize_max_is on64
  simp only [programInsns, List.length_append, deniedInsns_length]
  omega

/-- **`valid` returns on every table.** -/
theorem valid_never_fails : ValidNeverFails := by
  intro on64 table small
  exact WP.spec_mono (valid_is on64 table small) (fun _ _ => trivial)

/-- **`deny_program` returns on every table and target.** -/
theorem deny_program_never_fails : DenyProgramNeverFails := by
  intro on64 table target small
  exact WP.spec_mono (deny_program_cases on64 table target small) (fun _ _ => trivial)

/-- **`run` returns on every list of instructions.** -/
theorem run_never_fails : RunNeverFails := by
  intro on64 program nr arch args short
  have max_is := usize_max_is on64
  have : program.length + 2 ^ 32 ≤ Usize.max := by omega
  exact WP.spec_mono (run_is program nr arch args this) (fun _ _ => trivial)

/-- **`valid` accepts exactly the valid tables.** -/
theorem valid_is_exactly_the_conditions : ValidIsExactlyTheConditions := by
  intro on64 table small
  exact valid_is on64 table small

/-- **`deny_program` gives an error exactly for the tables that are not valid.** -/
theorem deny_program_refuses_exactly_the_invalid_tables :
    DenyProgramRefusesExactlyTheInvalidTables := by
  intro on64 table target small
  refine WP.spec_mono (deny_program_cases on64 table target small) ?_
  rintro r ⟨when_valid, when_invalid⟩
  constructor
  · rintro ⟨e, is_error⟩ valid
    obtain ⟨program, is_ok, -⟩ := when_valid valid
    rw [is_ok] at is_error
    cases is_error
  · exact when_invalid

/-- **The program of a valid table is well formed.** -/
theorem program_is_well_formed : ProgramIsWellFormed := by
  intro on64 table target small valid
  refine WP.spec_mono (deny_program_cases on64 table target small) ?_
  rintro r ⟨when_valid, -⟩
  obtain ⟨program, is_ok, same⟩ := when_valid valid
  exact ⟨program, is_ok, by rw [same]; exact program_well_formed table target valid⟩

/-- **The program of a valid table answers what the table says.** -/
theorem program_answers_what_the_table_says : ProgramAnswersWhatTheTableSays := by
  intro on64 table target small valid
  refine WP.spec_mono (deny_program_cases on64 table target small) ?_
  rintro r ⟨when_valid, -⟩
  obtain ⟨program, is_ok, same⟩ := when_valid valid
  refine ⟨program, is_ok, fun nr arch args => ?_⟩
  have fits := program_length_fits on64 table target small valid
  have length_is : (alloc.vec.Vec.deref program).length = (programInsns table target).length := by
    simp [alloc.vec.Vec.deref, Slice.length, same]
  refine WP.spec_mono (run_is (alloc.vec.Vec.deref program) nr arch args (by omega)) ?_
  intro answer is_exec
  rw [is_exec]
  have : (alloc.vec.Vec.deref program).val = programInsns table target := by
    simp [alloc.vec.Vec.deref, same]
  rw [this, exec_program table target nr arch args valid]

/-- **`run` of the program of a valid table answers something to every call.** -/
theorem program_answers_every_call : ProgramAnswersEveryCall := by
  intro on64 table target small valid
  refine WP.spec_mono (deny_program_cases on64 table target small) ?_
  rintro r ⟨when_valid, -⟩
  obtain ⟨program, is_ok, same⟩ := when_valid valid
  refine ⟨program, is_ok, fun nr arch args => ?_⟩
  have fits := program_length_fits on64 table target small valid
  refine WP.spec_mono (run_is (alloc.vec.Vec.deref program) nr arch args ?_) ?_
  · have : (alloc.vec.Vec.deref program).length = (programInsns table target).length := by
      simp [alloc.vec.Vec.deref, Slice.length, same]
    omega
  · intro answer is_exec is_none
    have : (alloc.vec.Vec.deref program).val = programInsns table target := by
      simp [alloc.vec.Vec.deref, same]
    rw [is_none, this, exec_program table target nr arch args valid] at is_exec
    simp at is_exec

end BpfCore
