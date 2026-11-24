-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that the program of a valid table is well formed (`WellFormed` of
-- Spec.lean): every conditional jump lands on an instruction of it and the last instruction is a
-- return.
--
-- Why it is needed: the claim `ProgramIsWellFormed` says it, and a run that never leaves the
-- program is what `ProgramAnswersEveryCall` needs.  `Reaches l` says that no jump of the list
-- `l` goes past the instruction after `l`; `Lands l` that none goes past the last one of `l`.
-- A list that `Reaches` followed by one that `Lands` `Lands`, so the program is built from its
-- parts: the first instructions, the denied calls and the rules `Reach`, the last instructions
-- `Land`.
--
-- Read before this file: Spec.lean, Generated.lean.
--
-- Notation: `l[i]?` is the element `i` of the list `l`, if there is one; `a ∈ l` is "a is an
-- element of l".
import BpfCore.Security

open Aeneas Aeneas.Std Result velarx_bpf_core

namespace BpfCore

/-- Every conditional jump of the list lands at most on the instruction after the list: it
skips no more instructions than follow it. -/
def Reaches : List Insn → Prop
  | [] => True
  | i :: rest =>
      (IsConditionalJump i → i.jt.val ≤ rest.length ∧ i.jf.val ≤ rest.length) ∧ Reaches rest

/-- Every conditional jump of the list lands on an instruction of the list: it skips fewer
instructions than follow it. -/
def Lands : List Insn → Prop
  | [] => True
  | i :: rest =>
      (IsConditionalJump i → i.jt.val < rest.length ∧ i.jf.val < rest.length) ∧ Lands rest

/-- A list that `Reaches`, then another: the jumps of the first still land at most on the
instruction after it, which is now inside. -/
theorem reaches_append {first second : List Insn} (first_reaches : Reaches first)
    (second_reaches : Reaches second) : Reaches (first ++ second) := by
  induction first with
  | nil => simpa using second_reaches
  | cons i rest ih =>
    obtain ⟨jumps, rest_reaches⟩ := first_reaches
    rw [List.cons_append]
    refine ⟨fun is_jump => ?_, ih rest_reaches⟩
    have := jumps is_jump
    simp only [List.length_append]
    omega

/-- A list that `Reaches`, then a list that is not empty and `Lands`: all the jumps land on an
instruction. -/
theorem lands_append {first second : List Insn} (first_reaches : Reaches first)
    (second_lands : Lands second) (not_empty : 0 < second.length) : Lands (first ++ second) := by
  induction first with
  | nil => simpa using second_lands
  | cons i rest ih =>
    obtain ⟨jumps, rest_reaches⟩ := first_reaches
    rw [List.cons_append]
    refine ⟨fun is_jump => ?_, ih rest_reaches⟩
    have := jumps is_jump
    simp only [List.length_append]
    omega

/-- A list in which every jump lands on an instruction is well formed in the sense of the
statement, for the jumps (the position `at_` of the jump and the places it skips to). -/
theorem lands_is_inside {program : List Insn} (lands : Lands program) :
    ∀ (at_ : Nat) (i : Insn), program[at_]? = some i → IsConditionalJump i →
      at_ + 1 + i.jt.val < program.length ∧ at_ + 1 + i.jf.val < program.length := by
  induction program with
  | nil => intro at_ i h; simp at h
  | cons first rest ih =>
    intro at_ i found is_jump
    cases at_ with
    | zero =>
      simp only [List.getElem?_cons_zero, Option.some.injEq] at found
      subst found
      have := lands.1 is_jump
      simp only [List.length_cons]
      omega
    | succ at_ =>
      have := ih lands.2 at_ i (by simpa using found) is_jump
      simp only [List.length_cons]
      omega

/-- What `ins` makes of its jump offsets: they are bytes. -/
theorem ins_offsets (code : Std.U16) (jt jf k : Nat) :
    (ins code jt jf k).jt.val = jt % 256 ∧ (ins code jt jf k).jf.val = jf % 256 := by
  simp [ins]

/-- A refusal is not a conditional jump. -/
theorem errno_not_a_jump (e : Nat) : ¬ IsConditionalJump (errnoInsn e) := by
  simp [errnoInsn, ins, IsConditionalJump, RET_K, JEQ_K, JGE_K, JSET_K]

/-- A load is not a conditional jump. -/
theorem load_not_a_jump (jt jf k : Nat) : ¬ IsConditionalJump (ins LD_W_ABS jt jf k) := by
  simp [ins, IsConditionalJump, LD_W_ABS, JEQ_K, JGE_K, JSET_K]

/-- A return is not a conditional jump. -/
theorem return_not_a_jump (jt jf k : Nat) : ¬ IsConditionalJump (ins RET_K jt jf k) := by
  simp [ins, IsConditionalJump, RET_K, JEQ_K, JGE_K, JSET_K]

/-- `JEQ_K` is a conditional jump. -/
theorem jeq_is_a_jump (jt jf k : Nat) : IsConditionalJump (ins JEQ_K jt jf k) := by
  simp [ins, IsConditionalJump]

/-- `JGE_K` is a conditional jump. -/
theorem jge_is_a_jump (jt jf k : Nat) : IsConditionalJump (ins JGE_K jt jf k) := by
  simp [ins, IsConditionalJump]

/-- `JSET_K` is a conditional jump. -/
theorem jset_is_a_jump (jt jf k : Nat) : IsConditionalJump (ins JSET_K jt jf k) := by
  simp [ins, IsConditionalJump]

/-- The jumps of the first instructions (`push_prelude`) land inside them and after them. -/
theorem prelude_reaches (arch : Nat) (x32 : Bool) : Reaches (preludeInsns arch x32) := by
  unfold preludeInsns
  cases x32 <;>
    simp [Reaches, ins_offsets, errno_not_a_jump, load_not_a_jump, jeq_is_a_jump, jge_is_a_jump]

/-- The same for the denied calls. -/
theorem denied_reaches (denied : List Std.I64) (e : Nat) : Reaches (deniedInsns denied e) := by
  induction denied with
  | nil => simp [deniedInsns, Reaches]
  | cons d ds ih =>
    simp only [deniedInsns, Reaches, ins_offsets, errno_not_a_jump, List.length_cons]
    exact ⟨fun _ => ⟨by omega, by omega⟩, fun is_jump => is_jump.elim, ih⟩

/-- The values of a rule and the two instructions after them: each jump lands on the allow at
the end. -/
theorem values_reach (values : List Std.U32) (k j : Nat) (count : k = j + values.length)
    (small : values.length < 256) :
    Reaches (valueInsns values k j ++ [errnoInsn EPERM.val, ins RET_K 0 0 RET_ALLOW.val]) := by
  induction values generalizing j with
  | nil => simp [valueInsns, Reaches, errno_not_a_jump, return_not_a_jump]
  | cons v vs ih =>
    simp only [List.length_cons] at count small
    have rest := ih (j + 1) (by omega) (by omega)
    simp only [valueInsns, List.cons_append, Reaches, ins_offsets, List.length_append,
      valueInsns_length, List.length_cons, List.length_nil]
    refine ⟨fun _ => ⟨by omega, by omega⟩, ?_⟩
    simpa using rest

/-- The block of a rule: its first jump skips the block, and lands on the instruction after it. -/
theorem rule_reaches (nr : Std.I64) (arg : Nat) (values : List Std.U32)
    (small : values.length + 3 ≤ 255) : Reaches (ruleInsns nr arg values) := by
  have inner := values_reach values values.length 0 (by omega) (by omega)
  simp only [ruleInsns, List.cons_append, List.nil_append, Reaches, ins_offsets,
    List.length_append, valueInsns_length, List.length_cons, List.length_nil]
  refine ⟨fun _ => ⟨by omega, by omega⟩, fun is_jump => absurd is_jump (load_not_a_jump _ _ _), ?_⟩
  simpa using inner

/-- The blocks of all the rules. -/
theorem rules_reach (rules : List OnlyIf) (small : ∀ rule ∈ rules, rule.values.length + 3 ≤ 255) :
    Reaches (rulesInsns rules) := by
  induction rules with
  | nil => simp [rulesInsns, Reaches]
  | cons rule rules ih =>
    simp only [rulesInsns]
    exact reaches_append (rule_reaches rule.nr rule.arg.val rule.values.val
      (small rule List.mem_cons_self))
      (ih (fun r member => small r (List.mem_cons_of_mem _ member)))

/-- The last instructions (`clone3`, `clone`, the allow): every jump lands on one of them. -/
theorem clone_lands (clone3 clone : Nat) : Lands (cloneInsns clone3 clone) := by
  simp [cloneInsns, Lands, ins_offsets, errno_not_a_jump, load_not_a_jump, return_not_a_jump,
    jeq_is_a_jump, jset_is_a_jump]

/-- The program of a valid table: every jump lands on an instruction of it, and the last
instruction is the allow. -/
theorem program_well_formed (table : Table) (target : Target) (valid : IsValid table) :
    WellFormed (programInsns table target) := by
  obtain ⟨denied_words, rule_checks⟩ := valid
  have small : ∀ rule ∈ table.«only».val, rule.values.length + 3 ≤ 255 :=
    fun rule member => (rule_checks rule member).2.2
  have not_empty : 0 < (cloneInsns target.clone3.val target.clone.val).length := by
    simp [cloneInsns]
  refine ⟨lands_is_inside ?_, ?_⟩
  · unfold programInsns
    refine lands_append (prelude_reaches _ _) (lands_append (denied_reaches _ _) ?_ ?_) ?_
    · exact lands_append (rules_reach _ small) (clone_lands _ _) not_empty
    · simp only [List.length_append]; omega
    · simp only [List.length_append]; omega
  · refine ⟨ins RET_K 0 0 RET_ALLOW.val, ?_, rfl⟩
    unfold programInsns
    simp [cloneInsns]

end BpfCore
