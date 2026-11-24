-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the security claim, in two steps.  `deny_program_cases`: for a valid table
-- `deny_program` returns the program `programInsns` (the first instructions, the denied calls, the
-- rules, `clone3` and `clone`, one after the other), and for any other table an error.
-- `exec_program`: that program, run by `Exec`, answers `Expected` of Spec.lean to every call.
--
-- Why it is needed: Claims.lean turns these two into the claims about `deny_program` and
-- `run`.  The first step is Generated.lean put together with Valid.lean (the program is pushed
-- in four parts, and each fits); the second is Segments.lean put together in the order of the
-- program, and the comparison, case by case, with the rules of `Expected`.
--
-- Read before this file: Spec.lean, Generated.lean, Segments.lean, Valid.lean.
--
-- Notation: as in Interpreter.lean.
import BpfCore.Segments
import BpfCore.Valid

open Aeneas Aeneas.Std Result velarx_bpf_core

namespace BpfCore

/-- The program of a table for a target, as the lists of instructions of the parts of
`deny_program` one after the other: the architecture and x32, the denied calls, the rules, `clone3`
and `clone`. -/
def programInsns (table : Table) (target : Target) : List Insn :=
  preludeInsns target.arch.val target.x32 ++
    (deniedInsns table.denied.val table.errno.val ++
      (rulesInsns table.«only».val ++ cloneInsns target.clone3.val target.clone.val))

/-- The blocks of the rules are at most 256 instructions each (a rule has at most 252 values). -/
theorem rulesInsns_length_le (rules : List OnlyIf)
    (small : ∀ rule ∈ rules, rule.values.length + 3 ≤ 255) :
    (rulesInsns rules).length ≤ 256 * rules.length := by
  induction rules with
  | nil => simp [rulesInsns]
  | cons rule rules ih =>
    have rule_small : rule.values.val.length + 3 ≤ 255 := small rule List.mem_cons_self
    have := ih (fun r member => small r (List.mem_cons_of_mem _ member))
    simp only [rulesInsns, List.length_append, ruleInsns_length, List.length_cons]
    omega

/-- **`deny_program`**: for a valid table it makes the program `programInsns`; for any other
table it makes an error. -/
theorem deny_program_cases (on64 : OnA64BitMachine) (table : Table) (target : Target)
    (small : IsSmall table) :
    deny_program table target ⦃ r =>
      (IsValid table → ∃ program, r = core.result.Result.Ok program ∧
        program.val = programInsns table target) ∧
      (¬ IsValid table → ∃ e, r = core.result.Result.Err e) ⦄ := by
  unfold deny_program
  -- the table is checked: an invalid table gives its error
  step as ⟨ checked, h_checked ⟩
  cases checked with
  | Ok u =>
    cases u
    have valid : IsValid table := h_checked.mp rfl
    simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok]
    have max_is := usize_max_is on64
    obtain ⟨small_denied, small_rules, small_values⟩ := small
    obtain ⟨denied_words, rule_checks⟩ := valid
    have rules_len := rulesInsns_length_le table.«only».val
      (fun rule member => (rule_checks rule member).2.2)
    have denied_len : table.denied.length = table.denied.val.length := rfl
    have rules_count : table.«only».length = table.«only».val.length := rfl
    -- the four parts are pushed in turn, and each has room
    step as ⟨ p, hp ⟩
    have p_len : p.val.length ≤ 6 := by
      rw [hp]; simp only [preludeInsns]; split <;> simp
    step as ⟨ p1, hp1 ⟩
    have p1_len : p1.val.length ≤ 6 + 2 * table.denied.val.length := by
      rw [hp1, List.length_append, deniedInsns_length]; omega
    have rules_args : ∀ rule ∈ table.«only».val, rule.arg.val ≤ 5 :=
      fun rule member => (rule_checks rule member).2.1
    step as ⟨ p2, hp2 ⟩
    have p2_len : p2.val.length ≤
        6 + 2 * table.denied.val.length + 256 * table.«only».val.length := by
      rw [hp2, List.length_append]; omega
    step as ⟨ p3, hp3 ⟩
    refine ⟨fun _ => ⟨p3, rfl, ?_⟩, fun not_valid => absurd ⟨denied_words, rule_checks⟩ not_valid⟩
    rw [hp3, hp2, hp1, hp]
    simp [programInsns]
  | Err e =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
    simp only [core.convert.FromSame.from]
    refine WP.spec_bind (show (ok e : Result velarx_bpf_core.Error) ⦃ _ => True ⦄ from
      (WP.spec_ok e).mpr trivial) ?_
    intro v _
    refine (WP.spec_ok _).mpr ⟨fun valid => ?_, fun _ => ⟨v, rfl⟩⟩
    simpa using h_checked.mpr valid

/-- The word the program loads at the offset of the argument `i` (0 to 5) is its low word. -/
theorem data_word_of_argument (nr arch : Std.U32) (args : Std.Array Std.U64 6#usize) (i : Nat)
    (index : i ≤ 5) :
    DataWord nr arch args ((16 + 8 * i) % 4294967296) = some (lowWord args i) := by
  have below : (16 + 8 * i) % 4294967296 = 16 + 8 * i := by omega
  rw [below]
  unfold DataWord lowWord
  have : ¬ 16 + 8 * i = 0 := by omega
  have : ¬ 16 + 8 * i = 4 := by omega
  have : 15 < 16 + 8 * i ∧ 16 + 8 * i < 64 ∧ (16 + 8 * i) % 4 = 0 := by omega
  have : ¬ (16 + 8 * i) % 8 = 4 := by omega
  have : (16 + 8 * i - 16) / 8 = i := by omega
  simp [*]

/-- The first rule that is about the call is the same for the program (which compares the call
number modulo `2^32`) and for the statement, when the numbers fit 32 bits. -/
theorem rules_find (rules : List OnlyIf) (nr : Nat)
    (words : ∀ rule ∈ rules, IsCallNumber rule.nr) :
    rules.find? (fun rule => decide ((rule.nr.val % 4294967296).toNat = nr)) =
      rules.find? (fun rule => decide (rule.nr.val = (nr : Int))) := by
  induction rules with
  | nil => rfl
  | cons rule rules ih =>
    have number := words rule List.mem_cons_self
    have same : (rule.nr.val % 4294967296).toNat = nr ↔ rule.nr.val = (nr : Int) := by
      unfold IsCallNumber at number
      omega
    simp only [List.find?_cons, same]
    rw [ih (fun r member => words r (List.mem_cons_of_mem _ member))]

/-- **The program of a valid table does what `Expected` says**, as the interpreter model `Exec`
runs it: for every call, the answer is the value of `Expected`. -/
theorem exec_program (table : Table) (target : Target) (nr arch : Std.U32)
    (args : Std.Array Std.U64 6#usize) (valid : IsValid table) :
    Exec (DataWord nr arch args) (programInsns table target) 0 =
      some (Expected table target nr arch args).code := by
  obtain ⟨denied_words, rule_checks⟩ := valid
  have rule_words : ∀ rule ∈ table.«only».val, IsCallNumber rule.nr :=
    fun rule member => (rule_checks rule member).1
  have rule_small : ∀ rule ∈ table.«only».val, rule.values.val.length + 3 ≤ 255 :=
    fun rule member => (rule_checks rule member).2.2
  have arch_at_4 : DataWord nr arch args 4 = some arch.val := by simp [DataWord]
  have number_at_0 : DataWord nr arch args 0 = some nr.val := by simp [DataWord]
  have target_arch : target.arch.val < 4294967296 := by simpa using target.arch.hBounds
  have target_clone3 : target.clone3.val < 4294967296 := by simpa using target.clone3.hBounds
  have target_clone : target.clone.val < 4294967296 := by simpa using target.clone.hBounds
  -- the parts of the program one after the other, then the comparison with `Expected`
  unfold programInsns
  rw [exec_prelude _ _ _ _ 0 arch.val nr.val target_arch arch_at_4 number_at_0,
    exec_denied, exec_rules _ _ rule_small, exec_clone _ _ _ _ target_clone3 target_clone]
  unfold Expected
  have rules_eq := rules_find table.«only».val nr.val rule_words
  have denied_iff : (∃ d ∈ table.denied.val, (d.val % 4294967296).toNat = nr.val) ↔
      IsDenied table nr := by
    unfold IsDenied
    constructor
    · rintro ⟨d, member, same⟩
      have := denied_words d member
      unfold IsCallNumber at this
      exact ⟨d, member, by omega⟩
    · rintro ⟨d, member, same⟩
      have := denied_words d member
      unfold IsCallNumber at this
      exact ⟨d, member, by omega⟩
  have low_16 : DataWord nr arch args 16 = some (lowWord args 0) := by
    simpa using data_word_of_argument nr arch args 0 (by omega)
  have eperm : errnoCode EPERM.val = (Verdict.errno EPERM.val).code := by
    simp [errnoCode, Verdict.code, EPERM]
  have enosys : errnoCode ENOSYS.val = (Verdict.errno ENOSYS.val).code := by
    simp [errnoCode, Verdict.code, ENOSYS]
  have errno_table :
      errnoCode table.errno.val = (Verdict.errno (table.errno.val % 65536)).code := rfl
  have allow : allowCode = Verdict.allow.code := rfl
  have arch_iff : arch.val ≠ target.arch.val ↔ arch ≠ target.arch := by
    constructor
    · intro h same; exact h (by rw [same])
    · intro h same; exact h (UScalar.eq_of_val_eq same)
  have clone3_iff : nr.val = target.clone3.val ↔ nr = target.clone3 :=
    ⟨fun h => UScalar.eq_of_val_eq h, fun h => by rw [h]⟩
  have clone_iff : nr.val = target.clone.val ↔ nr = target.clone :=
    ⟨fun h => UScalar.eq_of_val_eq h, fun h => by rw [h]⟩
  simp only [ruleOf, rules_eq, low_16, eperm, enosys, errno_table, allow, arch_iff, clone3_iff,
    clone_iff,
    ]
  -- the cases of `Expected`, in its order: the architecture, x32, the denied calls, the rules,
  -- `clone3`, `clone`
  by_cases a1 : arch = target.arch
  · by_cases a2 : target.x32 = true ∧ X32.val ≤ nr.val
    · simp [a1, a2]
    · by_cases a3 : IsDenied table nr
      · simp [a1, a2, a3, denied_iff.mpr a3]
      · have a3' : ¬ ∃ d ∈ table.denied.val, (d.val % 4294967296).toNat = nr.val :=
          fun h => a3 (denied_iff.mp h)
        simp only [a1, a2, a3, a3', ne_eq, not_true_eq_false, ite_false]
        rcases hfind :
            List.find? (fun rule => decide (rule.nr.val = (nr.val : Int))) table.«only».val
          with _ | rule
        · simp only [hfind]
          by_cases b1 : nr = target.clone3
          · simp [b1]
          · by_cases b2 : nr = target.clone
            · subst b2
              simp only [b1, ite_true, ite_false]
              split_ifs <;> rfl
            · simp [b1, b2]
        · simp only [hfind]
          have rule_arg : rule.arg.val ≤ 5 :=
            (rule_checks rule (List.mem_of_find?_eq_some hfind)).2.1
          rw [data_word_of_argument nr _ args rule.arg.val rule_arg]
          by_cases member : lowWord args rule.arg.val ∈ rule.values.val.map (·.val) <;>
            simp [member]
  · simp [a1]

end BpfCore
