-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the instructions that `deny_program` of crates/bpf-core makes, written as
-- lists (`preludeInsns`, `deniedInsns`, `rulesInsns`, `cloneInsns`), and for each function that
-- pushes them (`push_prelude`, `push_denied`, `push_rules`, `push_clone`, and the loops and the
-- functions they call) that it returns and pushes exactly that list after the instructions that
-- were there.
--
-- Why it is needed: the security claim is about the instructions, and a vector that is pushed to in
-- loops is not something one can reason about.  Here each loop gets its lemma (what is pushed from
-- the position `i` on is the list of the calls from `i` on) and the rest follows by plain list
-- reasoning in Segments.lean and Security.lean.  `ins code jt jf k` is the instruction with these
-- fields, the offsets taken modulo 256 and the constant modulo `2^32` as the casts of the Rust
-- do; for a valid table nothing is cut (Valid.lean).
--
-- Read before this file: Spec.lean, Interpreter.lean (for the notation), and the functions of
-- src/lib.rs that make the program (`deny_program` and the `push_*`).
--
-- Notation: as in Interpreter.lean; `p.val` is the list inside the vector `p`; `l ++ m` is the list
-- `l` followed by `m`; `@[step]` makes a theorem one that `step` uses when it meets the function.
import BpfCore.Interpreter

open Aeneas Aeneas.Std Result velarx_bpf_core

namespace BpfCore

/-- The `u8` of this value (modulo 256). -/
def byteOf (n : Nat) : Std.U8 := ⟨BitVec.ofNat 8 n⟩

/-- The `u32` of this value (modulo `2^32`). -/
def wordOf (n : Nat) : Std.U32 := ⟨BitVec.ofNat 32 n⟩

/-- The number a `byteOf` holds. -/
@[simp] theorem byteOf_val (n : Nat) : (byteOf n).val = n % 256 := by
  show (BitVec.ofNat 8 n).toNat = _
  simp
/-- The number a `wordOf` holds. -/
@[simp] theorem wordOf_val (n : Nat) : (wordOf n).val = n % 4294967296 := by
  show (BitVec.ofNat 32 n).toNat = _
  simp

/-- The instruction with this code, these offsets and this constant. -/
def ins (code : Std.U16) (jt jf k : Nat) : Insn := ⟨code, byteOf jt, byteOf jf, wordOf k⟩

/-- An offset is taken modulo 256 by `ins`: the instruction does not change. -/
@[simp] theorem ins_jt_mod (code : Std.U16) (jt jf k : Nat) :
    ins code (jt % 256) jf k = ins code jt jf k := by
  simp only [ins, byteOf]; congr 2; apply BitVec.eq_of_toNat_eq; simp

/-- The same for the other offset. -/
@[simp] theorem ins_jf_mod (code : Std.U16) (jt jf k : Nat) :
    ins code jt (jf % 256) k = ins code jt jf k := by
  simp only [ins, byteOf]; congr 2; apply BitVec.eq_of_toNat_eq; simp

/-- An instruction is the one made of its own fields. -/
theorem ins_of_fields (i : Insn) : i = ins i.code i.jt.val i.jf.val i.k.val := by
  cases i with
  | mk code jt jf k =>
    simp only [ins]
    congr 1
    all_goals (apply UScalar.eq_of_val_eq; simp)

/-- The instruction that refuses with the errno `e`: it returns `SECCOMP_RET_ERRNO` with the low 16
bits of `e`. -/
def errnoInsn (e : Nat) : Insn := ins RET_K 0 0 (RET_ERRNO.val ||| e % 65536)

/-- `errno e` of lib.rs makes `errnoInsn e`. -/
@[step]
theorem errno_is (e : Std.U32) : errno e ⦃ i => i = errnoInsn e.val ⦄ := by
  unfold errno
  step as ⟨ i, hi ⟩
  step as ⟨ i1, hi1 ⟩
  unfold insn
  refine (WP.spec_ok _).mpr ?_
  simp only [errnoInsn, ins]
  congr 1
  apply UScalar.eq_of_val_eq
  have bound := i1.hBounds
  simp only [UScalarTy.U32_numBits_eq] at bound
  simp only [hi1, UScalar.val_or, UScalar.val_and, hi, wordOf_val] at bound ⊢
  have mask : e.val &&& 65535 = e.val % 65536 := Nat.and_two_pow_sub_one_eq_mod e.val 16
  have low : (65535#u32).val = 65535 := by simp
  simp only [low, mask] at bound ⊢
  omega

/-- `insn` of lib.rs makes the instruction of its fields. -/
@[step]
theorem insn_is (code : Std.U16) (jt jf : Std.U8) (k : Std.U32) :
    insn code jt jf k ⦃ i => i = ins code jt.val jf.val k.val ⦄ := by
  unfold insn
  refine (WP.spec_ok _).mpr ?_
  exact ins_of_fields _

/-- The first instructions of the program (`push_prelude`): the architecture of the call is
loaded and refused when it is not the target's, the number of the call is loaded, and, on a
target that has x32, a number from the x32 bit up is refused. -/
def preludeInsns (arch : Nat) (x32 : Bool) : List Insn :=
  [ins LD_W_ABS 0 0 4, ins JEQ_K 1 0 arch, errnoInsn EPERM.val, ins LD_W_ABS 0 0 0] ++
    if x32 then [ins JGE_K 0 1 X32.val, errnoInsn EPERM.val] else []

/-- `push_prelude` pushes `preludeInsns`. -/
@[step]
theorem push_prelude_is (p : alloc.vec.Vec Insn) (target : Target)
    (room : p.val.length + 6 < Usize.max) :
    push_prelude p target ⦃ q => q.val = p.val ++ preludeInsns target.arch.val target.x32 ⦄ := by
  unfold push_prelude
  step*
  all_goals simp_all [preludeInsns]
  all_goals omega

/-- The last instructions of the program (`push_clone`): `clone3` is refused with `ENOSYS`; `clone`
loads its flags and is allowed with the thread flag and none of the flags that make a namespace,
else refused with `EPERM`; the allow at the end, for every other call. -/
def cloneInsns (clone3 clone : Nat) : List Insn :=
  [ins JEQ_K 0 1 clone3, errnoInsn ENOSYS.val, ins JEQ_K 0 4 clone, ins LD_W_ABS 0 0 16,
   ins JSET_K 1 0 CLONE_NEW_FLAGS.val, ins JSET_K 1 0 CLONE_THREAD.val, errnoInsn EPERM.val,
   ins RET_K 0 0 RET_ALLOW.val]

/-- `push_clone` pushes `cloneInsns`. -/
@[step]
theorem push_clone_is (p : alloc.vec.Vec Insn) (target : Target)
    (room : p.val.length + 8 < Usize.max) :
    push_clone p target ⦃ q =>
      q.val = p.val ++ cloneInsns target.clone3.val target.clone.val ⦄ := by
  unfold push_clone
  step*
  all_goals simp_all [cloneInsns]
  all_goals omega

/-- The instructions of the denied calls (`push_denied`): for each, a test of the call number and,
when it is that call, the refusal with the errno of the table; when it is not, the refusal is
skipped. -/
def deniedInsns : List Std.I64 → Nat → List Insn
  | [], _ => []
  | d :: ds, e => ins JEQ_K 0 1 (d.val % 4294967296).toNat :: errnoInsn e :: deniedInsns ds e

/-- The denied calls make two instructions each. -/
theorem deniedInsns_length (ds : List Std.I64) (e : Nat) :
    (deniedInsns ds e).length = 2 * ds.length := by
  induction ds with
  | nil => rfl
  | cons d ds ih => simp [deniedInsns, ih]; omega

/-- The loop of `push_denied`: from the call at `i` on, it pushes the test and the refusal of each
call. -/
theorem push_denied_loop_is (denied : Slice Std.I64) (e : Std.U32) (p : alloc.vec.Vec Insn)
    (i : Std.Usize) (read : i.val ≤ denied.length)
    (room : p.val.length + 2 * (denied.length - i.val) < Usize.max) :
    push_denied_loop p denied e i ⦃ q =>
      q.val = p.val ++ deniedInsns (denied.val.drop i.val) e.val ⦄ := by
  unfold push_denied_loop
  -- the loop keeps: what is pushed so far, then the instructions of the calls still to come, is
  -- what is wanted; and the calls still to come are fewer at each turn
  apply loop.spec_decr_nat (fun s => denied.length - s.2.val)
    (fun s => s.2.val ≤ denied.length ∧
      s.1.val ++ deniedInsns (denied.val.drop s.2.val) e.val =
        p.val ++ deniedInsns (denied.val.drop i.val) e.val)
  · rintro ⟨q, j⟩ ⟨read_j, same⟩
    simp only at read_j same ⊢
    unfold push_denied_loop.body
    -- a call is left: its test and its refusal are pushed, and the position moves on
    by_cases inside : j < Slice.len denied
    · simp only [inside, ite_true]
      have inside' : j.val < denied.val.length := by simpa [Slice.len, Slice.length] using inside
      have at_j : (denied.val.drop j.val) = denied.val[j.val] :: denied.val.drop (j.val + 1) :=
        List.drop_eq_getElem_cons inside'
      have len_same : q.val.length + 2 * (denied.length - j.val) =
          p.val.length + 2 * (denied.length - i.val) := by
        have := congrArg List.length same
        simpa [deniedInsns_length, List.length_drop, Slice.length] using this
      have len_eq : denied.length = denied.val.length := rfl
      step*
      all_goals try first
        | omega
        | (rw [p1_post]; simp only [List.length_append, List.length_singleton]; omega)
      refine ⟨by omega, ?_, by omega⟩
      rw [p2_post, p1_post, i4_post, i5_post, i6_post]
      rw [at_j] at same
      simp only [deniedInsns, i3_post, i2_post, IScalar.hcast_val_eq,
        UScalarTy.U32_numBits_eq] at same ⊢
      simpa using same
    -- no call is left: what has been pushed is what is wanted
    · have outside : denied.val.length ≤ j.val := by
        simpa [Slice.len, Slice.length] using inside
      simp only [inside, ite_false]
      refine (WP.spec_ok _).mpr ?_
      rw [List.drop_eq_nil_of_le outside] at same
      simpa [deniedInsns] using same
  · exact ⟨read, rfl⟩

/-- `push_denied` pushes the test and the refusal of every denied call. -/
@[step]
theorem push_denied_is (p : alloc.vec.Vec Insn) (denied : Slice Std.I64) (e : Std.U32)
    (room : p.val.length + 2 * denied.length < Usize.max) :
    push_denied p denied e ⦃ q => q.val = p.val ++ deniedInsns denied.val e.val ⦄ := by
  unfold push_denied
  have := push_denied_loop_is denied e p 0#usize (by simp) (by simpa using room)
  simpa using this

/-- The instructions of the values of a rule, from the one at `j` of the `k` values: each jumps to
the allow at the end (`k - j` instructions on) when the accumulator is its value. -/
def valueInsns : List Std.U32 → Nat → Nat → List Insn
  | [], _, _ => []
  | v :: vs, k, j => ins JEQ_K (k - j) 0 v.val :: valueInsns vs k (j + 1)

/-- A value makes one instruction. -/
theorem valueInsns_length (vs : List Std.U32) (k j : Nat) :
    (valueInsns vs k j).length = vs.length := by
  induction vs generalizing j with
  | nil => rfl
  | cons v vs ih => simp [valueInsns, ih]

/-- The loop of `push_rule`: from the value at `j` on, it pushes one jump to the allow for each. -/
@[step]
theorem push_rule_loop_is (p : alloc.vec.Vec Insn) (values : Slice Std.U32) (k j : Std.Usize)
    (k_is : k.val = values.length) (read : j.val ≤ k.val)
    (room : p.val.length + (k.val - j.val) < Usize.max) :
    push_rule_loop p values k j ⦃ q =>
      q.val = p.val ++ valueInsns (values.val.drop j.val) k.val j.val ⦄ := by
  unfold push_rule_loop
  -- as for the denied calls: what is pushed so far, then the jumps of the values still to come
  apply loop.spec_decr_nat (fun s => k.val - s.2.val)
    (fun s => s.2.val ≤ k.val ∧
      s.1.val ++ valueInsns (values.val.drop s.2.val) k.val s.2.val =
        p.val ++ valueInsns (values.val.drop j.val) k.val j.val)
  · rintro ⟨q, l⟩ ⟨read_l, same⟩
    simp only at read_l same ⊢
    unfold push_rule_loop.body
    -- a value is left: its jump is pushed, `k - l` instructions from the allow
    by_cases inside : l < k
    · simp only [inside, ite_true]
      have inside_k : l.val < k.val := inside
      have inside' : l.val < values.val.length := by
        simp [Slice.length] at k_is; omega
      have at_l : (values.val.drop l.val) = values.val[l.val] :: values.val.drop (l.val + 1) :=
        List.drop_eq_getElem_cons inside'
      have len_same : q.val.length + (k.val - l.val) = p.val.length + (k.val - j.val) := by
        have := congrArg List.length same
        simp only [List.length_append, valueInsns_length, List.length_drop] at this
        simp [Slice.length] at k_is
        omega
      step*
      refine ⟨by omega, ?_, by omega⟩
      rw [p1_post, i3_post, i1_post, j1_post]
      rw [at_l] at same
      simp only [valueInsns, i2_post, UScalar.cast_val_eq, i_post,
        UScalarTy.U8_numBits_eq] at same ⊢
      simpa using same
    -- no value is left
    · have outside : values.val.length ≤ l.val := by
        simp [Slice.length] at k_is
        have : ¬ l.val < k.val := inside
        omega
      simp only [inside, ite_false]
      refine (WP.spec_ok _).mpr ?_
      rw [List.drop_eq_nil_of_le outside] at same
      simpa [valueInsns] using same
  · exact ⟨read, rfl⟩

/-- The instructions of a rule on an argument: the call is tested (else the block is skipped),
the argument is loaded, each value jumps to the allow, a refusal, the allow. -/
def ruleInsns (nr : Std.I64) (arg : Nat) (values : List Std.U32) : List Insn :=
  [ins JEQ_K 0 (values.length + 3) (nr.val % 4294967296).toNat, ins LD_W_ABS 0 0 (16 + 8 * arg)] ++
    valueInsns values values.length 0 ++ [errnoInsn EPERM.val, ins RET_K 0 0 RET_ALLOW.val]

/-- The block of a rule has its values and four more instructions. -/
theorem ruleInsns_length (nr : Std.I64) (arg : Nat) (values : List Std.U32) :
    (ruleInsns nr arg values).length = values.length + 4 := by
  simp [ruleInsns, valueInsns_length]

/-- `push_rule` pushes the block of a rule on an argument 0 to 5. -/
@[step]
theorem push_rule_is (p : alloc.vec.Vec Insn) (nr : Std.I64) (arg : Std.Usize)
    (values : Slice Std.U32) (arg_ok : arg.val ≤ 5)
    (room : p.val.length + values.length + 4 < Usize.max) :
    push_rule p nr arg values ⦃ q => q.val = p.val ++ ruleInsns nr arg.val values.val ⦄ := by
  unfold push_rule
  have len_eq : values.length = values.val.length := rfl
  have len_len : values.len.val = values.length := rfl
  -- each line of the function in turn; the four pushes have room
  step*
  · simp [p1_post]; omega
  · simp [p2_post, p1_post, len_len]; omega
  · simp [p3_post, p2_post, p1_post, valueInsns_length]; omega
  · simp [p4_post, p3_post, p2_post, p1_post, valueInsns_length]; omega
  -- the instructions pushed are those of `ruleInsns`: the cast of the argument does not cut it
  · have i4_val : i4.val = arg.val := by
      rw [i4_post, UScalar.cast_val_eq]
      cases System.Platform.numBits_eq <;> simp [UScalarTy.numBits, *] <;> omega
    rw [q_post, p4_post, p3_post, p2_post, p1_post, i9_post, i8_post, i7_post, i3_post, i1_post,
      i2_post]
    simp only [ruleInsns, UScalar.cast_val_eq, i_post, IScalar.hcast_val_eq,
      UScalarTy.U8_numBits_eq, UScalarTy.U32_numBits_eq, i6_post, i5_post, i4_val, List.drop_zero,
      len_len]
    simp

/-- The instructions of all the rules, in order. -/
def rulesInsns : List OnlyIf → List Insn
  | [] => []
  | rule :: rules => ruleInsns rule.nr rule.arg.val rule.values.val ++ rulesInsns rules

/-- `push_rules`, from the rule at `r` on: it pushes the block of each rule, in order.  (It walks
the rules by recursion, so this is a proof by induction on how many are left.) -/
theorem push_rules_is (rules : Slice OnlyIf) :
    ∀ (n : Nat) (p : alloc.vec.Vec Insn) (r : Std.Usize), rules.length - r.val = n →
      r.val ≤ rules.length →
      (∀ rule ∈ rules.val.drop r.val, rule.arg.val ≤ 5) →
      p.val.length + (rulesInsns (rules.val.drop r.val)).length < Usize.max →
      push_rules p rules r ⦃ q => q.val = p.val ++ rulesInsns (rules.val.drop r.val) ⦄ := by
  have len_eq : rules.length = rules.val.length := rfl
  intro n
  induction n with
  | zero =>
    -- no rule is left
    intro p r measure read args room
    unfold push_rules
    have outside : ¬ r < Slice.len rules := by simp [Slice.len]; omega
    simp only [outside, ite_false]
    refine (WP.spec_ok _).mpr ?_
    simp [List.drop_eq_nil_of_le (by omega : rules.val.length ≤ r.val), rulesInsns]
  | succ n ih =>
    -- a rule is left: its block is pushed, then the rules after it by the hypothesis of induction
    intro p r measure read args room
    unfold push_rules
    have inside : r < Slice.len rules := by
      simp [Slice.len]; omega
    simp only [inside, ite_true]
    have inside' : r.val < rules.val.length := by simp [Slice.len] at inside; omega
    have at_r : rules.val.drop r.val = rules.val[r.val] :: rules.val.drop (r.val + 1) :=
      List.drop_eq_getElem_cons inside'
    rw [at_r] at args room ⊢
    simp only [rulesInsns, List.length_append] at room
    step as ⟨ rule, h_rule ⟩
    have rule_args : rule.arg.val ≤ 5 := args rule (by rw [h_rule]; exact List.mem_cons_self)
    rw [← h_rule, ruleInsns_length] at room
    step as ⟨ p1, hp1 ⟩
    step as ⟨ r1, hr1 ⟩
    refine WP.spec_mono (ih p1 r1 (by omega) (by omega) ?_ ?_) ?_
    · intro rule' member
      rw [hr1] at member
      exact args rule' (List.mem_cons_of_mem _ member)
    · rw [hr1, hp1]
      simp only [List.length_append, ruleInsns_length]
      omega
    · intro q hq
      rw [hq, hp1, hr1, ← h_rule]
      simp [rulesInsns]

/-- `push_rules` from the first rule: it pushes the block of every rule, in order. -/
@[step]
theorem push_rules_all (p : alloc.vec.Vec Insn) (rules : Slice OnlyIf)
    (args : ∀ rule ∈ rules.val, rule.arg.val ≤ 5)
    (room : p.val.length + (rulesInsns rules.val).length < Usize.max) :
    push_rules p rules 0#usize ⦃ q => q.val = p.val ++ rulesInsns rules.val ⦄ := by
  have := push_rules_is rules rules.length p 0#usize (by simp) (by simp)
    (by simpa using args) (by simpa using room)
  simpa using this

end BpfCore
