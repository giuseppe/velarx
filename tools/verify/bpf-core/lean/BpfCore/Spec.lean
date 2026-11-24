-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/bpf-core, the seccomp program of the confined
-- threads, in words and in statements, with no proof.  This file is what a reviewer reads; Lean
-- checks the rest (the proofs are in Interpreter.lean, Generated.lean, Segments.lean, Machine.lean,
-- Valid.lean, Security.lean, WellFormed.lean and Claims.lean).
--
-- Why it is needed: a proof is worth what its statement says.  Each statement here is a
-- `def ... : Prop`: a claim, which `Theorems.lean` asks Lean to prove.  Each has a comment of
-- what it claims and of what it does NOT.  The definitions before the claims are their
-- vocabulary.  The main one is `Expected`: what a program must answer to a call, written as
-- plain rules from the documentation of the crate (the header of lib.rs) and not from the code of
-- the generator.  It is the same statement as `expected` of src/check.rs, which the tests run on
-- small tables; here the claim is for EVERY table.
--
-- Total correctness: a claim of the form `f x ⦃ r => P r ⦄` says that the Rust function `f`
-- RETURNS on `x` (no panic, no index outside a slice, no overflow, every loop ends) and that its
-- result `r` satisfies `P r`.  Every claim says it for every input, with the only conditions that
-- are named in the claim: the tables are smaller than 2^32 entries (a real one has a few
-- dozen; the condition is there so that the length of the program, which is a few instructions
-- per call and per rule, cannot overflow a `usize`, and it excludes no table that fits in
-- memory) and the machine has 64-bit words (`OnA64BitMachine`; `usize` is 32 bits on others, and
-- a jump of 2^32 instructions could then overflow the counter of the interpreter).  `run` is
-- claimed for programs shorter than 2^60 instructions: this excludes nothing, because an
-- instruction is 8 bytes and Rust never makes a slice larger than `isize::MAX` bytes (2^63).
--
-- `WellFormed` is weaker than `well_formed` of src/check.rs, which also wants only known opcodes;
-- `ProgramAnswersEveryCall` covers the gap: `run` answers `none` on an unknown opcode.
--
-- Claimed:
--   - `valid`, `deny_program` and `run` return on every input (the interpreter on every list of
--     instructions, hostile ones too);
--   - `deny_program` refuses a table exactly when it is not valid (`IsValid`: a call number that
--     does not fit 32 bits, an argument above 5, a rule with so many values that a jump does not
--     fit a byte);
--   - the program it makes is well formed (`WellFormed`: it ends with a return and every jump
--     lands on an instruction of it), and so `run` answers something to every call;
--   - THE SECURITY CLAIM: for every valid table, every target and every call (number,
--     architecture, arguments), `run` of the program answers exactly `Expected`.
--
-- Not claimed (and not proved):
--   - what `velarx-sys` does around the program: which tables it gives, that it turns the
--     instructions into `sock_filter`s faithfully, that the kernel runs them as `run` does (the
--     meaning of an instruction is that of classic BPF, as `run` has it; the test
--     `the_kernel_answers_what_the_interpreter_says` of crates/sys/src/confine.rs compares the
--     kernel with the interpreter for one kernel on x86_64 only; the aarch64 numbers and the
--     conversion to `sock_filter` are not tested against a kernel), that it installs the filter;
--   - that the tables are the right ones (which calls a thread needs): only that the program says
--     what the table says;
--   - the instructions `run` knows and the program never makes (`JA`, `ALU_AND_K`, `JGT_K`):
--     they are in the interpreter for the programs of seccompiler; `run` returns on them too, but
--     no claim is about what they answer;
--   - the `check` feature (`expected`, `agrees` of src/check.rs) is not translated: `Expected`
--     here is its statement written again, and the proof is that of the program against it;
--   - that the kernel accepts the program: it refuses one longer than `BPF_MAXINSNS` (4096
--     instructions) when it is installed, and then the install fails; no claim here bounds the
--     length (the tables the engine gives are short lists of calls);
--   - that the offsets the program loads are those of the fields of `seccomp_data`, and that
--     the low word of an argument is at the offset it reads (lib.rs: the targets are little
--     endian).
--
-- Trusted: Charon and Aeneas (../../pins) and the models of the standard library Aeneas itself
-- has (`Vec::push`, slice indexing, the integer operations and casts); no model is written by
-- hand.
--
-- Read before this file: lib.rs of crates/bpf-core (its header says what a program answers) and
-- check.rs next to it.
--
-- Index.  The claims, in the order below:
--
--   `valid`, `deny_program` and `run` return
--     ValidNeverFails                  `valid` returns on every table
--     DenyProgramNeverFails            `deny_program` returns on every table and target
--     RunNeverFails                    `run` returns on every list of instructions
--   Which tables make a program
--     ValidIsExactlyTheConditions      `valid` accepts exactly the tables of `IsValid`
--     DenyProgramRefusesExactlyTheInvalidTables
--                                      `deny_program` gives an error exactly for those that are not
--   What the program is
--     ProgramIsWellFormed              it ends with a return and every jump lands inside it
--     ProgramAnswersEveryCall          `run` of it answers something to every call
--   What the program answers
--     ProgramAnswersWhatTheTableSays   THE SECURITY CLAIM: `run` of the program is `Expected`
--
-- Notation:
--   - `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns and its result `r`
--     satisfies `P r`.
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and", `∨`
--     is "or", `→` is "if ... then", `↔` is "exactly when", `¬` is "not", `≠` is "is not",
--     `∈` is "is an element of"; `[]` is the empty list.
--   - `v.val` is the list inside a vector or a slice, `xs[i]?` is the element `i` of the list
--     `xs` if there is one, `x.val` is the number a `u32`, `u64` or `i64` holds; `l.length` is
--     the length; `l.find? p` is the first element of `l` for which `p` holds, if there is one;
--     `l.map f` applies `f` to every element.
--   - `table.«only»` is the field `only` of the table (the word `only` is a keyword of Lean).
--   - `core.result.Result.Ok x` and `core.result.Result.Err e` are the two answers of a Rust
--     `Result`; `alloc.vec.Vec.deref v` is the vector `v` as a slice (what `&v` is in Rust).
import Proved
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_bpf_core

namespace BpfCore

/-! ## The conditions on the sizes -/

/-- The machine has 64-bit words (the engine is built for x86_64 and aarch64): `usize` holds up to
2^64 - 1.  A hypothesis of the claims, not a claim (`@[not_a_claim]`, ../../../Proved.lean). -/
@[not_a_claim] abbrev OnA64BitMachine : Prop :=
  System.Platform.numBits = 64

/-- The sizes a real table has, by a very large margin: fewer than 2^32 denied calls, fewer than
2^32 rules, fewer than 2^32 values in each rule. -/
def IsSmall (table : Table) : Prop :=
  table.denied.length < 2 ^ 32 ∧ table.«only».length < 2 ^ 32 ∧
    ∀ rule ∈ table.«only».val, rule.values.length < 2 ^ 32

/-! ## Which tables make a program -/

/-- A call number the program can name: it is not negative and fits 32 bits (the number of a
call is a `u32` to the kernel). -/
def IsCallNumber (nr : Std.I64) : Prop :=
  0 ≤ nr.val ∧ nr.val ≤ 4294967295

/-- The table can be made a program (what `valid` of lib.rs says): every call number fits 32 bits,
every argument of a rule is 0 to 5 (a call has six), and the rule has at most 252 values (a jump
of the program skips the block of a rule, which has the values and four more instructions, and a
jump is a byte). -/
def IsValid (table : Table) : Prop :=
  (∀ nr ∈ table.denied.val, IsCallNumber nr) ∧
  ∀ rule ∈ table.«only».val, IsCallNumber rule.nr ∧ rule.arg.val ≤ 5 ∧ rule.values.length + 3 ≤ 255

/-! ## What a program must answer -/

/-- What a call is answered: allowed, or refused with an errno (a number below 2^16). -/
inductive Verdict where
  | allow
  | errno (e : Nat)

/-- The value the kernel is given for a verdict: `SECCOMP_RET_ALLOW`, or `SECCOMP_RET_ERRNO`
with the errno in its low 16 bits. -/
def Verdict.code : Verdict → Nat
  | Verdict.allow => RET_ALLOW.val
  | Verdict.errno e => RET_ERRNO.val ||| e

/-- The low 32 bits of the argument `i` of the call (0 to 5): what a rule or `clone` looks at.
The high 32 bits are never looked at. -/
def lowWord (args : Std.Array Std.U64 6#usize) (i : Nat) : Nat :=
  (args.val.getD i 0#u64).val % 2 ^ 32

/-- The call is one the table denies. -/
def IsDenied (table : Table) (nr : Std.U32) : Prop :=
  ∃ denied ∈ table.denied.val, denied.val = nr.val

/-- The first rule of the table that is about the call, if there is one. -/
def ruleOf (table : Table) (nr : Std.U32) : Option OnlyIf :=
  table.«only».val.find? (fun rule => decide (rule.nr.val = nr.val))

open Classical in
/-- **What the program of `table` for `target` must answer** to the call `nr` of the architecture
`arch` with the arguments `args`.  The rules, in this order, the first that applies decides:

1. a call of another architecture than the target: refused with `EPERM`;
2. on a target that has x32 (x86_64), a call whose number has the x32 bit or is above it:
   refused with `EPERM`;
3. a denied call: refused with the errno of the table, its low 16 bits;
4. a call that has a rule on an argument: allowed when the low word of that argument is one of
   the values of the first rule of the call, else refused with `EPERM`;
5. `clone3`: refused with `ENOSYS` (the C library falls back to `clone`);
6. `clone`: allowed when the low word of its flags (argument 0) has `CLONE_THREAD` and none of
   the flags that make a namespace (`CLONE_NEW_FLAGS`), else refused with `EPERM`;
7. any other call: allowed.

This is the header of lib.rs and the `expected` of src/check.rs, in the same order. -/
noncomputable def Expected (table : Table) (target : Target) (nr arch : Std.U32)
    (args : Std.Array Std.U64 6#usize) : Verdict :=
  if arch ≠ target.arch then Verdict.errno EPERM.val
  else if target.x32 = true ∧ X32.val ≤ nr.val then Verdict.errno EPERM.val
  else if IsDenied table nr then Verdict.errno (table.errno.val % 65536)
  else
    match ruleOf table nr with
    | some rule =>
        if lowWord args rule.arg.val ∈ rule.values.val.map (·.val) then Verdict.allow
        else Verdict.errno EPERM.val
    | none =>
        if nr = target.clone3 then Verdict.errno ENOSYS.val
        else if nr = target.clone then
          if lowWord args 0 &&& CLONE_THREAD.val ≠ 0 ∧ lowWord args 0 &&& CLONE_NEW_FLAGS.val = 0
          then Verdict.allow
          else Verdict.errno EPERM.val
        else Verdict.allow

/-! ## What a program is -/

/-- The instruction is a conditional jump (the ones the generator makes: equal, at least, some
bit set). -/
def IsConditionalJump (i : Insn) : Prop :=
  i.code = JEQ_K ∨ i.code = JGE_K ∨ i.code = JSET_K

/-- The program is well formed: every conditional jump lands on an instruction of the program
(the instruction at position `at_` goes on at `at_+1+jt` or `at_+1+jf`; both are positions of the
program), and the last instruction is a return. -/
def WellFormed (program : List Insn) : Prop :=
  (∀ (at_ : Nat) (i : Insn), program[at_]? = some i → IsConditionalJump i →
      at_ + 1 + i.jt.val < program.length ∧ at_ + 1 + i.jf.val < program.length) ∧
  ∃ last, program.getLast? = some last ∧ last.code = RET_K

/-! ## The claims -/

/-- **`valid` returns on every table.**  No panic, no overflow, no index outside a slice, the loops
end, whatever the table is (a call number that is negative or huge, an argument of 1000, a rule
with a million values).

Not said: which tables it accepts (`ValidIsExactlyTheConditions`).  Only for tables of `IsSmall`
sizes on a 64-bit machine, as the header says. -/
def ValidNeverFails : Prop :=
  OnA64BitMachine → ∀ table : Table, IsSmall table → valid table ⦃ _ => True ⦄

/-- **`deny_program` returns on every table and target.**  Valid or not: it makes a program or an
error, it never panics or loops.

Not said: which of the two (the next claims), what the program answers. -/
def DenyProgramNeverFails : Prop :=
  OnA64BitMachine → ∀ (table : Table) (target : Target), IsSmall table →
    deny_program table target ⦃ _ => True ⦄

/-- **`run` returns on every list of instructions.**  Whatever the instructions are: unknown
codes, loads at offsets that do not exist, jumps that leave the program, a program that is empty
or does not end with a return.  It answers `none` for those, it does not panic and it ends (the
jumps only go forward).  The list is shorter than 2^60 instructions, which is all that fits a
64-bit machine.

Not said: what it answers (`ProgramAnswersWhatTheTableSays`). -/
def RunNeverFails : Prop :=
  OnA64BitMachine →
  ∀ (program : Slice Insn) (nr arch : Std.U32) (args : Std.Array Std.U64 6#usize),
    program.length < 2 ^ 60 → run program nr arch args ⦃ _ => True ⦄

/-- **`valid` accepts exactly the valid tables.**  It returns `Ok` exactly when every call number
fits 32 bits, every argument is 0 to 5 and every rule has at most 252 values (`IsValid`); for any
other table it returns an error. -/
def ValidIsExactlyTheConditions : Prop :=
  OnA64BitMachine → ∀ table : Table, IsSmall table →
    valid table ⦃ r => r = core.result.Result.Ok () ↔ IsValid table ⦄

/-- **`deny_program` gives an error exactly for the tables that are not valid.**  For a table
with a call number that does not fit 32 bits, an argument above 5 or a rule with so many values
that a jump does not fit a byte, it answers an error; for every other table it answers a
program.

Not said: which error it names (`Number`, `Argument` or `Jump`), even for a table with one flaw. -/
def DenyProgramRefusesExactlyTheInvalidTables : Prop :=
  OnA64BitMachine → ∀ (table : Table) (target : Target), IsSmall table →
    deny_program table target ⦃ r => (∃ e, r = core.result.Result.Err e) ↔ ¬ IsValid table ⦄

/-- **The program of a valid table is well formed.**  It ends with a return and every conditional
jump lands on an instruction of it: a run never leaves the program. -/
def ProgramIsWellFormed : Prop :=
  OnA64BitMachine → ∀ (table : Table) (target : Target), IsSmall table → IsValid table →
    deny_program table target ⦃ r =>
      ∃ program, r = core.result.Result.Ok program ∧ WellFormed program.val ⦄

/-- **`run` of the program of a valid table answers something to every call.**  For every
number, architecture and arguments, it returns a value (never `none`: the run does not fall off
the program or meet an instruction it does not know). -/
def ProgramAnswersEveryCall : Prop :=
  OnA64BitMachine → ∀ (table : Table) (target : Target), IsSmall table → IsValid table →
    deny_program table target ⦃ r =>
      ∃ program, r = core.result.Result.Ok program ∧
        ∀ (nr arch : Std.U32) (args : Std.Array Std.U64 6#usize),
          run (alloc.vec.Vec.deref program) nr arch args ⦃ answer => answer ≠ none ⦄ ⦄

/-- **THE SECURITY CLAIM: the program answers what the table says.**  For every valid table and
every target, `deny_program` makes a program, and `run` of it, for every call (number,
architecture, arguments), answers exactly the value of `Expected table target nr arch args`:
- a call of another architecture is refused with `EPERM`, and on x86_64 so is a call with the
  x32 bit;
- a denied call is refused with the errno of the table (its low 16 bits);
- a call with a rule on an argument is allowed exactly when the low word of the argument is one
  of the values of the first rule of the call, else refused with `EPERM`;
- `clone3` is refused with `ENOSYS`; `clone` is allowed exactly when it makes a thread and no
  namespace; everything else is allowed.

Not said: that the tables are the right ones; anything about the high word of an argument (it is
never looked at: `Expected` does not look at it either); the answers for a table that is not
valid (there is no program). -/
def ProgramAnswersWhatTheTableSays : Prop :=
  OnA64BitMachine → ∀ (table : Table) (target : Target), IsSmall table → IsValid table →
    deny_program table target ⦃ r =>
      ∃ program, r = core.result.Result.Ok program ∧
        ∀ (nr arch : Std.U32) (args : Std.Array Std.U64 6#usize),
          run (alloc.vec.Vec.deref program) nr arch args ⦃ answer =>
            answer.map (·.val) = some (Expected table target nr arch args).code ⦄ ⦄

end BpfCore
