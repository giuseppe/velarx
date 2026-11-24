-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the interpreter `run` of crates/bpf-core does, written as a function
-- on the list of instructions that is easy to reason about (`Exec`), and the theorem `run_is`: on
-- every list of instructions `run` returns (no panic, no overflow, the loop ends), and what it
-- answers is what `Exec` of the list says.
--
-- Why it is needed: `run` is a loop with a program counter, an accumulator, a flag and an answer.
-- The security claim is about what it answers to the program `deny_program` makes, and that is
-- easier to say instruction by instruction from the front: `Exec word (i :: rest) a` is "what the
-- instructions `i :: rest` answer when the accumulator is `a`", and a jump of `n` instructions is
-- `rest.drop n` (the offsets of the jumps are relative, so what is after a jump is the end of the
-- list).  `word k` is the word of the data of the call (`seccomp_data`) at the offset `k`.
--
-- Read before this file: Spec.lean, and `run` and `load` in src/lib.rs.
--
-- Notation: `m ⦃ r => P r ⦄` is "the Rust function `m` returns, and its result `r` satisfies
-- `P r`"; `step as ⟨ x, hx ⟩` runs one line of the Rust function and names its result `x` and what
-- is known of it `hx`; `loop.spec_decr_nat` proves that a loop returns because a number goes down
-- at each turn, and keeps an invariant; `l.drop n` is the list `l` without its first `n`
-- elements; `a &&& k` is the bitwise "and".
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_bpf_core

namespace BpfCore


/-- The word of `seccomp_data` that a load at offset `k` reads, as a number: the number of the
call (offset 0), its architecture (4), or the low or high half of an argument (16 and up, every 4);
nothing for any other offset. -/
def DataWord (nr arch : Std.U32) (args : Std.Array Std.U64 6#usize) (k : Nat) : Option Nat :=
  if k = 0 then some nr.val
  else if k = 4 then some arch.val
  else if 15 < k ∧ k < 64 ∧ k % 4 = 0 then
    some (if k % 8 = 4 then (args.val.getD ((k - 16) / 8) 0#u64).val / 2 ^ 32
          else (args.val.getD ((k - 16) / 8) 0#u64).val % 2 ^ 32)
  else none

/-- `load` reads `DataWord`: it returns, and gives the word of the offset, or nothing for an
offset that is not one. -/
@[step]
theorem load_is (k nr arch : Std.U32) (args : Std.Array Std.U64 6#usize) :
    load k nr arch args ⦃ r => r.map (·.val) = DataWord nr arch args k.val ⦄ := by
  unfold load
  by_cases h0 : k = 0#u32
  · simp [h0, DataWord]
  by_cases h4 : k = 4#u32
  · simp [h4, DataWord]
  have n0 : k.val ≠ 0 := fun h => h0 (by scalar_tac)
  have n4 : k.val ≠ 4 := fun h => h4 (by scalar_tac)
  simp only [h0, h4, ite_false, DataWord, n0, n4]
  by_cases hlow : k > 15#u32
  · by_cases hhigh : k < 64#u32
    · have lo : 15 < k.val := by scalar_tac
      have hi : k.val < 64 := by scalar_tac
      simp only [hlow, hhigh, ite_true, lo, hi, true_and]
      step as ⟨ i1, h1 ⟩
      have i1_is : i1.val = k.val % 4 := by
        rw [h1]; simpa using Nat.and_two_pow_sub_one_eq_mod k.val 2
      by_cases hal : i1 = 0#u32
      · have al : k.val % 4 = 0 := by
          rw [← i1_is]; simp [hal]
        simp only [hal, al, ite_true]
        step as ⟨ i2, h2 ⟩
        step as ⟨ i3, h3 ⟩
        step as ⟨ i4, h4' ⟩
        step as ⟨ arg, harg ⟩
        step as ⟨ i5, h5 ⟩
        have i5_is : i5.val = k.val % 8 := by
          rw [h5]; simpa using Nat.and_two_pow_sub_one_eq_mod k.val 3
        have idx : i4.val = (k.val - 16) / 8 := by simp [h4', h3, h2]
        have arg_is : arg = args.val.getD ((k.val - 16) / 8) 0#u64 := by
          have inside : i4.val < args.val.length := by simp; scalar_tac
          rw [harg, List.getD_eq_getElem _ _ (by rw [← idx]; exact inside)]
          congr 1
        by_cases hhalf : i5 = 4#u32
        · have eight : k.val % 8 = 4 := by rw [← i5_is]; simp [hhalf]
          simp only [hhalf, eight, ite_true, arg_is]
          step as ⟨ i6, h6, _ ⟩
          step as ⟨ i7, h7 ⟩
          have bound := ((args.val.getD ((k.val - 16) / 8) 0#u64)).hBounds
          simp only [h7, UScalar.cast_val_eq, h6, Nat.shiftRight_eq_div_pow, Option.map_some]
          simp only [UScalarTy.numBits] at bound
          simp only [UScalarTy.U32_numBits_eq]
          congr 1
          omega
        · have eight : ¬ k.val % 8 = 4 := fun h => hhalf (by scalar_tac)
          simp only [hhalf, eight, ite_false, arg_is]
          step as ⟨ i6, h6 ⟩
          simp [h6, UScalar.cast_val_eq]
      · have : ¬ k.val % 4 = 0 := fun h => hal (by scalar_tac)
        simp [hal, this]
    · have : ¬ k.val < 64 := fun h => hhigh (by scalar_tac)
      simp [hhigh, this]
  · have : ¬ 15 < k.val := fun h => hlow (by scalar_tac)
    simp [hlow, this]

/-- Whether the conditional jump with this code is taken: equal, above, at least, or some bit of
the constant `k` set in the accumulator `a`. -/
def hit (code : Std.U16) (a k : Nat) : Bool :=
  if code = JEQ_K then a == k
  else if code = JGT_K then decide (k < a)
  else if code = JGE_K then decide (k ≤ a)
  else a &&& k != 0

/-- The code is one of the four conditional jumps. -/
def isJump (code : Std.U16) : Bool :=
  code == JEQ_K || code == JGT_K || code == JGE_K || code == JSET_K

/-- **What the instructions answer**, when the accumulator is `a` and the data of the call is
`word`: the first instruction decides.  A load puts the word in the accumulator (and the run
stops if there is none), an `and` changes the accumulator, a jump drops the instructions it skips, a
return answers its constant, and an instruction of another code, or the end of the list, stops
the run with no answer.  This is `run`, one instruction at a time. -/
def Exec (word : Nat → Option Nat) : List Insn → Nat → Option Nat
  | [], _ => none
  | i :: rest, a =>
    if i.code = LD_W_ABS then
      match word i.k.val with
      | none => none
      | some w => Exec word rest w
    else if i.code = ALU_AND_K then Exec word rest (a &&& i.k.val)
    else if i.code = JA then Exec word (rest.drop i.k.val) a
    else if i.code = RET_K then some i.k.val
    else if isJump i.code then
      Exec word (rest.drop (if hit i.code a i.k.val then i.jt.val else i.jf.val)) a
    else none
termination_by l => l.length

/-- `JEQ_K` is a conditional jump. -/
theorem isJump_jeq : isJump JEQ_K = true := by simp [isJump]
/-- `JGT_K` is a conditional jump. -/
theorem isJump_jgt : isJump JGT_K = true := by simp [isJump, JEQ_K, JGT_K]
/-- `JGE_K` is a conditional jump. -/
theorem isJump_jge : isJump JGE_K = true := by simp [isJump, JEQ_K, JGT_K, JGE_K]
/-- `JSET_K` is a conditional jump. -/
theorem isJump_jset : isJump JSET_K = true := by simp [isJump, JEQ_K, JGT_K, JGE_K, JSET_K]

/-- Two `u32` are equal exactly when their numbers are. -/
theorem beq_val (a k : Std.U32) : (a.val == k.val) = decide (a = k) := by
  by_cases h : a = k
  · simp [h]
  · simp [h, UScalar.neq_to_neq_val.mp h]

/-- The end of a conditional jump in `run`: the counter goes on by the offset of the side that
is taken, `jt` or `jf`, and it cannot overflow as long as the program is shorter than the room
that is left. -/
theorem jump_tail (hb : Bool) (pc1 : Usize) (a : Std.U32) (jt jf : Std.U8)
    (room : pc1.val + 255 ≤ Usize.max) :
    (do let i2 ← (if hb = true then ok jt else ok jf)
        let i3 ← lift (core.convert.num.FromUsizeU8.from i2)
        let pc2 ← pc1 + i3
        ok (ControlFlow.cont (pc2, a, (none : Option Std.U32), true)) :
      Result (ControlFlow (Std.Usize × Std.U32 × Option Std.U32 × Bool) (Option Std.U32))) ⦃ r =>
      ∃ pc2 : Std.Usize, r = ControlFlow.cont (pc2, a, none, true) ∧
        pc2.val = pc1.val + (if hb = true then jt.val else jf.val) ⦄ := by
  have jt_bound := jt.hBounds
  have jf_bound := jf.hBounds
  have from_jt := core.convert.num.FromUsizeU8.from_val_eq jt
  have from_jf := core.convert.num.FromUsizeU8.from_val_eq jf
  simp only [UScalarTy.U8_numBits_eq] at jt_bound jf_bound
  cases hb
  · simp only [Bool.false_eq_true, ite_false, Std.bind_ok, lift]
    step as ⟨ pc2, hpc2 ⟩
    exact ⟨pc2, rfl, by simp [hpc2, from_jf]⟩
  · simp only [ite_true, Std.bind_ok, lift]
    step as ⟨ pc2, hpc2 ⟩
    exact ⟨pc2, rfl, by simp [hpc2, from_jt]⟩

/-- The loop of `run`: it returns, and what it answers is `Exec` of the program from its start. -/
theorem run_loop_is (program : Slice Insn) (nr arch : Std.U32) (args : Std.Array Std.U64 6#usize)
    (roomy : program.length + 2 ^ 32 ≤ Usize.max) :
    run_loop program nr arch args 0#usize 0#u32 none true ⦃ r =>
      r.map (·.val) = Exec (DataWord nr arch args) program.val 0 ⦄ := by
  unfold run_loop
  -- the loop keeps: no answer is given while it runs, and what the rest of the program, from the
  -- counter and with the accumulator, would answer (or the answer given) is what is wanted
  apply loop.spec_decr_nat (fun s => program.length - s.1.val)
    (fun s => (s.2.2.2 = true → s.2.2.1 = none) ∧
      (if s.2.2.2 then Exec (DataWord nr arch args) (program.val.drop s.1.val) s.2.1.val
       else s.2.2.1.map (·.val)) = Exec (DataWord nr arch args) program.val 0)
  · rintro ⟨pc, a, answer, running⟩ ⟨hnone, hres⟩
    simp only at hnone hres ⊢
    unfold run_loop.body
    by_cases hrun : running = true
    · simp only [hrun, ite_true] at hres hnone ⊢
      have answer_none : answer = none := hnone trivial
      subst answer_none
      -- the counter is inside the program: the instruction is read, and the counter moves on
      by_cases hpc : pc < Slice.len program
      · simp only [hpc, ite_true]
        have inside : pc.val < program.val.length := by simpa [Slice.len, Slice.length] using hpc
        step as ⟨ insn, hinsn ⟩
        step as ⟨ pc1, hpc1 ⟩
        have drop_eq : program.val.drop pc.val = insn :: program.val.drop pc1.val := by
          rw [List.drop_eq_getElem_cons inside, hinsn]
          simp [hpc1]
        rw [drop_eq] at hres
        have len_eq : program.length = program.val.length := rfl
        have progress : program.length - pc1.val < program.length - pc.val := by omega
        rw [Exec] at hres
        -- a load
        by_cases c_ld : insn.code = LD_W_ABS
        · simp only [c_ld, ite_true] at hres ⊢
          step as ⟨ o, ho ⟩
          cases o with
          | none =>
            simp only [Option.map_none] at ho
            simp only [← ho] at hres
            refine (WP.spec_ok _).mpr ⟨by simp, by simpa using hres, progress⟩
          | some w =>
            simp only [Option.map_some] at ho
            simp only [← ho] at hres
            refine (WP.spec_ok _).mpr ⟨by simp, by simpa using hres, progress⟩
        simp only [c_ld, ite_false] at hres ⊢
        -- an `and`
        by_cases c_and : insn.code = ALU_AND_K
        · simp only [c_and, ite_true] at hres ⊢
          step as ⟨ a1, ha1 ⟩
          refine ⟨by simp, ?_, progress⟩
          simpa [ha1] using hres
        simp only [c_and, ite_false] at hres ⊢
        -- an unconditional jump: the counter cannot overflow, the program is short
        by_cases c_ja : insn.code = JA
        · simp only [c_ja, ite_true] at hres ⊢
          step as ⟨ i2, hi2 ⟩
          have i2_is : i2.val = insn.k.val := by
            rw [hi2, UScalar.cast_val_eq]
            have := insn.k.hBounds
            cases System.Platform.numBits_eq <;> simp_all [UScalarTy.numBits]; omega
          step as ⟨ pc2, hpc2 ⟩
          refine ⟨by simp, ?_, by omega⟩
          rw [List.drop_drop] at hres
          simpa [show pc2.val = pc1.val + insn.k.val by omega] using hres
        simp only [c_ja, ite_false] at hres ⊢
        -- a return
        by_cases c_ret : insn.code = RET_K
        · simp only [c_ret, ite_true] at hres ⊢
          refine (WP.spec_ok _).mpr ⟨by simp, by simpa using hres, progress⟩
        simp only [c_ret, ite_false] at hres ⊢
        -- the four conditional jumps: the side is chosen, and the counter goes forward by it
        by_cases c_jeq : insn.code = JEQ_K
        · simp only [c_jeq, ite_true] at hres ⊢
          simp only [Std.bind_ok]
          refine WP.spec_mono (jump_tail (decide (a = insn.k)) pc1 a insn.jt insn.jf (by omega)) ?_
          rintro r ⟨pc2, rfl, hpc2⟩
          refine ⟨by simp, ?_, by show program.length - pc2.val < program.length - pc.val; omega⟩
          have taken : hit JEQ_K a.val insn.k.val = (decide (a = insn.k)) := by
            simp [hit, JEQ_K, beq_val]
          simp only [isJump_jeq, taken, ite_true] at hres
          simp only [ite_true]
          rw [← hres, List.drop_drop, hpc2]
        simp only [c_jeq, ite_false] at hres ⊢
        by_cases c_jgt : insn.code = JGT_K
        · simp only [c_jgt, ite_true] at hres ⊢
          simp only [Std.bind_ok]
          refine WP.spec_mono (jump_tail (decide (a > insn.k)) pc1 a insn.jt insn.jf (by omega)) ?_
          rintro r ⟨pc2, rfl, hpc2⟩
          refine ⟨by simp, ?_, by show program.length - pc2.val < program.length - pc.val; omega⟩
          have taken : hit JGT_K a.val insn.k.val = (decide (a > insn.k)) := by
            simp [hit, JGT_K, JEQ_K, GT.gt]
          simp only [isJump_jgt, taken, ite_true] at hres
          simp only [ite_true]
          rw [← hres, List.drop_drop, hpc2]
        simp only [c_jgt, ite_false] at hres ⊢
        by_cases c_jge : insn.code = JGE_K
        · simp only [c_jge, ite_true] at hres ⊢
          simp only [Std.bind_ok]
          refine WP.spec_mono (jump_tail (decide (a >= insn.k)) pc1 a insn.jt insn.jf (by omega)) ?_
          rintro r ⟨pc2, rfl, hpc2⟩
          refine ⟨by simp, ?_, by show program.length - pc2.val < program.length - pc.val; omega⟩
          have taken : hit JGE_K a.val insn.k.val = (decide (a >= insn.k)) := by
            simp [hit, JGE_K, JGT_K, JEQ_K, GE.ge]
          simp only [isJump_jge, taken, ite_true] at hres
          simp only [ite_true]
          rw [← hres, List.drop_drop, hpc2]
        simp only [c_jge, ite_false] at hres ⊢
        by_cases c_jset : insn.code = JSET_K
        · simp only [c_jset, ite_true] at hres ⊢
          step as ⟨ i2, hi2 ⟩
          refine WP.spec_mono (jump_tail (i2 != 0#u32) pc1 a insn.jt insn.jf (by omega)) ?_
          rintro r ⟨pc2, rfl, hpc2⟩
          refine ⟨by simp, ?_, by show program.length - pc2.val < program.length - pc.val; omega⟩
          have taken : hit JSET_K a.val insn.k.val = (i2 != 0#u32) := by
            simp [hit, JSET_K, JGE_K, JGT_K, JEQ_K, hi2, bne, UScalar.val_eq_imp_iff]
          simp only [isJump_jset, taken, ite_true] at hres
          simp only [ite_true]
          rw [← hres, List.drop_drop, hpc2]
        simp only [c_jset, ite_false] at hres ⊢
        -- any other code: the run stops with no answer
        have not_jump : isJump insn.code = false := by
          simp [isJump, c_jeq, c_jgt, c_jge, c_jset]
        simp only [not_jump, Bool.false_eq_true, ite_false] at hres ⊢
        refine (WP.spec_ok _).mpr ⟨by simp, by simpa using hres, progress⟩
      -- the counter is past the end: the run ends with no answer
      · have outside : ¬ pc.val < program.val.length := by simpa [Slice.len, Slice.length] using hpc
        simp only [hpc, ite_false]
        refine (WP.spec_ok _).mpr ?_
        rw [← hres]
        simp [List.drop_eq_nil_of_le (by omega : program.val.length ≤ pc.val), Exec]
    -- the run has stopped: the answer is the one given
    · simp only [hrun] at hres ⊢
      simp only [Bool.not_eq_true] at hrun
      refine (WP.spec_ok _).mpr ?_
      exact hres
  · simp

/-- **`run` returns on every program that leaves room for a jump, and answers what `Exec` says.**
No panic, no overflow, the loop ends, whatever the instructions are (unknown codes, loads at
offsets that do not exist, jumps that leave the program).  The room is that of a program shorter
than `2^32` instructions less than the largest `usize`. -/
theorem run_is (program : Slice Insn) (nr arch : Std.U32) (args : Std.Array Std.U64 6#usize)
    (roomy : program.length + 2 ^ 32 ≤ Usize.max) :
    run program nr arch args ⦃ r =>
      r.map (·.val) = Exec (DataWord nr arch args) program.val 0 ⦄ := by
  unfold run
  exact run_loop_is program nr arch args roomy

end BpfCore
