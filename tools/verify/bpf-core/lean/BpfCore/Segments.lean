-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what each part of the program does when it runs (`Exec`, Interpreter.lean):
-- an instruction of each kind, then the first instructions (the architecture and x32), the denied
-- calls, the blocks of the rules, the last instructions (`clone3`, `clone`, the allow).  Each is a
-- statement about `Exec word (part ++ rest) a`: what the run answers when it starts at the part
-- with the accumulator `a`, and what it does when it goes on after the part (`Exec word rest ...`).
--
-- Why it is needed: Security.lean puts these together, in the order of the program, and gets what
-- the whole program answers.  Nothing here is about the vector or the loops of the Rust: the lists
-- are those of Generated.lean.
--
-- Read before this file: Interpreter.lean, Generated.lean (`ins` and the lists).
--
-- Notation: as in Interpreter.lean.  `word k` is the word of the data at the offset `k` (`none`
-- when the offset is not one); `a` is the accumulator; the answers are numbers (`errnoCode e` is
-- the value of a refusal with the errno `e`, `allowCode` the value of the allow).
import BpfCore.Generated

open Aeneas Aeneas.Std Result velarx_bpf_core

namespace BpfCore

/-- What an instruction that loads a word does: it reads the word at its offset (modulo `2^32`,
as `ins` makes it), and goes on with it as the accumulator; or the run stops, if there is no such
word. -/
theorem exec_load (word : Nat → Option Nat) (jt jf k : Nat) (rest : List Insn) (a : Nat) :
    Exec word (ins LD_W_ABS jt jf k :: rest) a =
      match word (k % 4294967296) with
      | none => none
      | some w => Exec word rest w := by
  rw [Exec]
  simp only [ins, wordOf_val, ite_true]
  rcases word (k % 4294967296) with _ | x <;> rfl

/-- What a return does: it answers its constant. -/
theorem exec_return (word : Nat → Option Nat) (jt jf k : Nat) (rest : List Insn) (a : Nat) :
    Exec word (ins RET_K jt jf k :: rest) a = some (k % 4294967296) := by
  rw [Exec]
  simp [ins, LD_W_ABS, ALU_AND_K, JA, RET_K]

/-- What a conditional jump does: it skips the number of instructions of its side, `jt` if the
test holds (`hit`) and `jf` if not. -/
theorem exec_jump (word : Nat → Option Nat) (code : Std.U16)
    (is_jump : code = JEQ_K ∨ code = JGE_K ∨ code = JSET_K) (jt jf k : Nat) (rest : List Insn)
    (a : Nat) :
    Exec word (ins code jt jf k :: rest) a =
      Exec word (rest.drop (if hit code a (k % 4294967296) then jt % 256 else jf % 256)) a := by
  rw [Exec]
  rcases is_jump with rfl | rfl | rfl <;>
    simp [ins, LD_W_ABS, ALU_AND_K, JA, RET_K, JEQ_K, JGE_K, JSET_K, isJump]

/-- The value of the instruction that refuses with the errno `e`. -/
def errnoCode (e : Nat) : Nat := RET_ERRNO.val ||| e % 65536

/-- A refusal with an errno is a value of 32 bits. -/
theorem errnoCode_lt (e : Nat) : errnoCode e < 4294967296 := by
  unfold errnoCode
  have err : RET_ERRNO.val < 2 ^ 32 := by simp [RET_ERRNO]
  have low : e % 65536 < 2 ^ 32 := by omega
  simpa using Nat.or_lt_two_pow err low

/-- The instruction that refuses with the errno `e` returns `errnoCode e`. -/
theorem exec_errno (word : Nat → Option Nat) (e : Nat) (rest : List Insn) (a : Nat) :
    Exec word (errnoInsn e :: rest) a = some (errnoCode e) := by
  unfold errnoInsn
  rw [exec_return]
  have := errnoCode_lt e
  unfold errnoCode at this ⊢
  rw [Nat.mod_eq_of_lt this]

/-- `JEQ_K` jumps when the accumulator is the constant. -/
theorem hit_jeq (a k : Nat) : hit JEQ_K a k = decide (a = k) := by
  by_cases h : a = k <;> simp [hit, JEQ_K, h]
/-- `JGE_K` jumps when the accumulator is at least the constant. -/
theorem hit_jge (a k : Nat) : hit JGE_K a k = decide (k ≤ a) := by
  simp [hit, JGE_K, JGT_K, JEQ_K]
/-- `JSET_K` jumps when the accumulator and the constant have a bit in common. -/
theorem hit_jset (a k : Nat) : hit JSET_K a k = decide (a &&& k ≠ 0) := by
  by_cases h : a &&& k = 0 <;> simp [hit, JSET_K, JGE_K, JGT_K, JEQ_K, h]

/-- What `JEQ_K` does: it skips `jt` instructions when the accumulator is its constant (modulo
`2^32`), else `jf`. -/
theorem exec_jeq (word : Nat → Option Nat) (jt jf k : Nat) (rest : List Insn) (a : Nat) :
    Exec word (ins JEQ_K jt jf k :: rest) a =
      Exec word (rest.drop (if a = k % 4294967296 then jt % 256 else jf % 256)) a := by
  rw [exec_jump word JEQ_K (Or.inl rfl)]
  simp [hit_jeq]

/-- What `JGE_K` does: it skips `jt` instructions when the accumulator is at least its constant,
else `jf`. -/
theorem exec_jge (word : Nat → Option Nat) (jt jf k : Nat) (rest : List Insn) (a : Nat) :
    Exec word (ins JGE_K jt jf k :: rest) a =
      Exec word (rest.drop (if k % 4294967296 ≤ a then jt % 256 else jf % 256)) a := by
  rw [exec_jump word JGE_K (Or.inr (Or.inl rfl))]
  simp [hit_jge]

/-- What `JSET_K` does: it skips `jt` instructions when the accumulator has a bit of its constant,
else `jf`. -/
theorem exec_jset (word : Nat → Option Nat) (jt jf k : Nat) (rest : List Insn) (a : Nat) :
    Exec word (ins JSET_K jt jf k :: rest) a =
      Exec word (rest.drop (if a &&& k % 4294967296 ≠ 0 then jt % 256 else jf % 256)) a := by
  rw [exec_jump word JSET_K (Or.inr (Or.inr rfl))]
  simp [hit_jset]

/-- What the first instructions of the program do (`push_prelude`): the architecture is
tested, then, on a target that has x32, the number of the call.  `A` is the architecture of the
call and `N` its number. -/
theorem exec_prelude (word : Nat → Option Nat) (arch : Nat) (x32 : Bool) (rest : List Insn)
    (a A N : Nat) (arch_word : arch < 4294967296) (arch_is : word 4 = some A)
    (number_is : word 0 = some N) :
    Exec word (preludeInsns arch x32 ++ rest) a =
      if A ≠ arch then some (errnoCode EPERM.val)
      else if x32 = true ∧ X32.val ≤ N then some (errnoCode EPERM.val)
      else Exec word rest N := by
  -- the architecture is compared, then (if the target has x32) the number
  unfold preludeInsns
  have x32_val : X32.val = 1073741824 := by simp [X32]
  simp only [x32_val]
  have arch_mod : arch % 4294967296 = arch := Nat.mod_eq_of_lt (by simpa using arch_word)
  by_cases same : A = arch
  · by_cases x : x32 = true
    · simp only [x, ite_true, List.cons_append, List.nil_append]
      by_cases big : 1073741824 ≤ N
      · simp [exec_load, exec_jeq, exec_jge, exec_errno, arch_is, number_is, arch_mod, same, big]
      · simp [exec_load, exec_jeq, exec_jge, arch_is, number_is, arch_mod, same, big]
    · simp only [x, Bool.false_eq_true, ite_false, List.append_nil, List.cons_append,
        List.nil_append]
      simp [exec_load, exec_jeq, arch_is, number_is, arch_mod, same]
  · simp [exec_load, exec_jeq, exec_errno, arch_is, arch_mod, same]

/-- What the denied calls do (`push_denied`): the first denied call that is the accumulator ends
the run with the refusal; if none is, the run goes on after them, the accumulator unchanged. -/
theorem exec_denied (word : Nat → Option Nat) (denied : List Std.I64) (e : Nat) (rest : List Insn)
    (a : Nat) :
    Exec word (deniedInsns denied e ++ rest) a =
      if ∃ d ∈ denied, (d.val % 4294967296).toNat = a then some (errnoCode e)
      else Exec word rest a := by
  -- the denied calls one by one: the first that is the accumulator ends the run, else the next
  induction denied with
  | nil => simp [deniedInsns]
  | cons d ds ih =>
    have below : (d.val % 4294967296).toNat % 4294967296 = (d.val % 4294967296).toNat := by
      have : 0 ≤ d.val % 4294967296 := Int.emod_nonneg _ (by norm_num)
      have : d.val % 4294967296 < 4294967296 := Int.emod_lt_of_pos _ (by norm_num)
      omega
    by_cases is_d : (d.val % 4294967296).toNat = a
    · subst is_d
      simp [deniedInsns, exec_jeq, exec_errno, below]
    · have not_d : ¬ a = (d.val % 4294967296).toNat := fun h => is_d h.symm
      simp [deniedInsns, exec_jeq, below, not_d, is_d, ih]

/-- The value `SECCOMP_RET_ALLOW`, as the program returns it. -/
def allowCode : Nat := RET_ALLOW.val

/-- The instruction that allows the call returns `allowCode`. -/
theorem exec_allow (word : Nat → Option Nat) (rest : List Insn) (a : Nat) :
    Exec word (ins RET_K 0 0 RET_ALLOW.val :: rest) a = some allowCode := by
  rw [exec_return]
  simp [allowCode, RET_ALLOW]

/-- What the values of a rule do (`push_rule`'s loop): the first that is the accumulator jumps to
the allow that ends the block, over the values after it and the refusal; if none is, the refusal
is next.  `j` values of the `k` of the rule were before these. -/
theorem exec_values (word : Nat → Option Nat) (values : List Std.U32) (k j : Nat)
    (count : k = j + values.length) (small : values.length < 256) (rest : List Insn) (a : Nat) :
    Exec word
        (valueInsns values k j ++ errnoInsn EPERM.val :: ins RET_K 0 0 RET_ALLOW.val :: rest) a =
      if a ∈ values.map (·.val) then some allowCode else some (errnoCode EPERM.val) := by
  -- the values one by one: a value that is the accumulator jumps over the rest to the allow, else
  -- the next one is tried; after the last, the refusal
  induction values generalizing j with
  | nil => simp [valueInsns, exec_errno]
  | cons v vs ih =>
    simp only [List.length_cons] at count small
    have skip : (k - j) % 256 = vs.length + 1 := by omega
    have below : v.val % 4294967296 = v.val := Nat.mod_eq_of_lt (by simpa using v.hBounds)
    by_cases is_v : a = v.val
    · have after : (valueInsns vs k (j + 1) ++
            errnoInsn EPERM.val :: ins RET_K 0 0 RET_ALLOW.val :: rest).drop (vs.length + 1) =
          ins RET_K 0 0 RET_ALLOW.val :: rest := by
        have joined : valueInsns vs k (j + 1) ++
              errnoInsn EPERM.val :: ins RET_K 0 0 RET_ALLOW.val :: rest =
            (valueInsns vs k (j + 1) ++ [errnoInsn EPERM.val]) ++
              ins RET_K 0 0 RET_ALLOW.val :: rest := by
          simp
        rw [joined]
        exact List.drop_left' (by simp [valueInsns_length])
      simp [valueInsns, exec_jeq, skip, below, is_v, after, exec_allow]
    · have rest_small : vs.length < 256 := by omega
      have step := ih (j + 1) (by omega) rest_small
      have not_v : ¬ a = v.val := is_v
      simp [valueInsns, exec_jeq, below, not_v, step]

/-- What the block of a rule does (`push_rule`): when the accumulator is not the call of the rule,
the run goes on after the block; else the argument is loaded, and the call is allowed when its
low word is one of the values, else refused with `EPERM`. -/
theorem exec_rule (word : Nat → Option Nat) (nr : Std.I64) (arg : Nat) (values : List Std.U32)
    (small : values.length + 3 ≤ 255) (rest : List Insn) (a : Nat) :
    Exec word (ruleInsns nr arg values ++ rest) a =
      if a ≠ (nr.val % 4294967296).toNat then Exec word rest a
      else match word ((16 + 8 * arg) % 4294967296) with
        | none => none
        | some low =>
          if low ∈ values.map (·.val) then some allowCode else some (errnoCode EPERM.val) := by
  have below : (nr.val % 4294967296).toNat % 4294967296 = (nr.val % 4294967296).toNat := by
    have : 0 ≤ nr.val % 4294967296 := Int.emod_nonneg _ (by norm_num)
    have : nr.val % 4294967296 < 4294967296 := Int.emod_lt_of_pos _ (by norm_num)
    omega
  have skip : (values.length + 3) % 256 = values.length + 3 := Nat.mod_eq_of_lt (by omega)
  have shape : ruleInsns nr arg values ++ rest =
      ins JEQ_K 0 (values.length + 3) (nr.val % 4294967296).toNat ::
        ins LD_W_ABS 0 0 (16 + 8 * arg) ::
          (valueInsns values values.length 0 ++ errnoInsn EPERM.val ::
            ins RET_K 0 0 RET_ALLOW.val :: rest) := by
    simp [ruleInsns]
  -- the first instruction tests the call of the rule: a miss skips the block, a hit goes on
  rw [shape, exec_jeq]
  by_cases is_nr : a = (nr.val % 4294967296).toNat
  · simp only [below, is_nr, ite_true, Nat.zero_mod, List.drop_zero, ne_eq,
      not_true_eq_false, ite_false]
    rw [exec_load]
    rcases h : word ((16 + 8 * arg) % 4294967296) with _ | low
    · simp
    · simp only
      rw [exec_values word values values.length 0 (by simp) (by omega)]
  · have not_nr : ¬ (nr.val % 4294967296).toNat = a := fun h => is_nr h.symm
    simp only [below, is_nr, ite_false, skip, ne_eq, not_false_eq_true, ite_true]
    have joined : ins LD_W_ABS 0 0 (16 + 8 * arg) :: (valueInsns values values.length 0 ++
        errnoInsn EPERM.val :: ins RET_K 0 0 RET_ALLOW.val :: rest) =
        (ins LD_W_ABS 0 0 (16 + 8 * arg) :: valueInsns values values.length 0 ++
          [errnoInsn EPERM.val, ins RET_K 0 0 RET_ALLOW.val]) ++ rest := by simp
    rw [joined]
    exact congrArg (fun l => Exec word l a) (List.drop_left' (by simp [valueInsns_length]))

/-- What the rules do, in order (`push_rules`): the block of the first rule whose call is the
accumulator decides (the rules after it are never reached); when there is none, the run goes on
after all the blocks. -/
theorem exec_rules (word : Nat → Option Nat) (rules : List OnlyIf)
    (small : ∀ rule ∈ rules, rule.values.length + 3 ≤ 255) (rest : List Insn) (a : Nat) :
    Exec word (rulesInsns rules ++ rest) a =
      match rules.find? (fun rule => decide ((rule.nr.val % 4294967296).toNat = a)) with
      | none => Exec word rest a
      | some rule =>
          match word ((16 + 8 * rule.arg.val) % 4294967296) with
          | none => none
          | some low =>
              if low ∈ rule.values.val.map (·.val) then some allowCode
              else some (errnoCode EPERM.val) := by
  -- the rules one by one: the first whose call is the accumulator decides, the others are skipped
  induction rules with
  | nil => simp [rulesInsns]
  | cons rule rules ih =>
    have rule_small : rule.values.val.length + 3 ≤ 255 := small rule List.mem_cons_self
    have rules_small : ∀ r ∈ rules, r.values.length + 3 ≤ 255 :=
      fun r member => small r (List.mem_cons_of_mem _ member)
    simp only [rulesInsns, List.append_assoc]
    rw [exec_rule word rule.nr rule.arg.val rule.values.val rule_small]
    by_cases is_rule : a = (rule.nr.val % 4294967296).toNat
    · simp [is_rule]
    · have not_rule : ¬ (rule.nr.val % 4294967296).toNat = a := fun h => is_rule h.symm
      simp only [is_rule, ne_eq, not_false_eq_true, ite_true, List.find?_cons,
        not_rule, decide_false]
      exact ih rules_small

/-- What `clone3` and `clone` do (`push_clone`), at the end of the program: `clone3` is refused
with `ENOSYS`; `clone` is allowed when its flags (the low word of the argument 0, `flags`) have
`CLONE_THREAD` and none of `CLONE_NEW_FLAGS`; every other call is allowed. -/
theorem exec_clone (word : Nat → Option Nat) (clone3 clone : Nat) (a : Nat)
    (clone3_word : clone3 < 4294967296) (clone_word : clone < 4294967296) :
    Exec word (cloneInsns clone3 clone) a =
      if a = clone3 then some (errnoCode ENOSYS.val)
      else if a = clone then
        match word 16 with
        | none => none
        | some flags =>
            if flags &&& CLONE_THREAD.val ≠ 0 ∧ flags &&& CLONE_NEW_FLAGS.val = 0
            then some allowCode
            else some (errnoCode EPERM.val)
      else some allowCode := by
  have thread : CLONE_THREAD.val = 65536 := by simp [CLONE_THREAD]
  have new : CLONE_NEW_FLAGS.val = 2114060416 := by simp [CLONE_NEW_FLAGS]
  have below3 : clone3 % 4294967296 = clone3 := Nat.mod_eq_of_lt clone3_word
  have below : clone % 4294967296 = clone := Nat.mod_eq_of_lt clone_word
  -- `clone3` first, then `clone`, then the allow
  by_cases is_clone3 : a = clone3
  · simp [cloneInsns, exec_jeq, exec_errno, below3, is_clone3]
  · by_cases is_clone : a = clone
    · subst is_clone
      rcases h : word 16 with _ | flags
      · simp [cloneInsns, exec_jeq, exec_load, below3, below, is_clone3, h]
      · by_cases new_flag : flags &&& 2114060416 = 0
        · by_cases thread_flag : flags &&& 65536 = 0
          · simp [cloneInsns, exec_jeq, exec_load, exec_jset, exec_errno, below3, below, is_clone3,
              h, new_flag, thread_flag, thread, new]
          · simp [cloneInsns, exec_jeq, exec_load, exec_jset, exec_allow, below3, below, is_clone3,
              h, new_flag, thread_flag, thread, new]
        · simp [cloneInsns, exec_jeq, exec_load, exec_jset, exec_errno, below3, below, is_clone3,
            h, new_flag, thread, new]
    · simp [cloneInsns, exec_jeq, exec_allow, below3, below, is_clone3, is_clone]

end BpfCore
