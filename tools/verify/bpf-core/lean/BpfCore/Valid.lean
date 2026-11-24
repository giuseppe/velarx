-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `valid` of crates/bpf-core accepts: exactly the tables that
-- `IsValid` of Spec.lean says (every call number fits 32 bits, every argument of a rule is 0 to 5,
-- every rule has at most 252 values), and that `valid` returns on every table of the sizes of
-- `IsSmall`.  Each of its parts (`is_word`, `valid_rule`, the loop over the denied calls, the
-- recursion over the rules) has a lemma.
--
-- Why it is needed: `deny_program` gives an error exactly when `valid` does, and the rest of the
-- proofs use that every number and offset it makes fits where it goes (Generated.lean).
--
-- Read before this file: Spec.lean, Machine.lean.
--
-- Notation: as in Interpreter.lean; `core.result.Result.Ok ()` is the answer "valid".
import BpfCore.Spec
import BpfCore.Machine

open Aeneas Aeneas.Std Result velarx_bpf_core

namespace BpfCore

/-- `is_word` says whether a call number fits 32 bits. -/
@[step]
theorem is_word_is (nr : Std.I64) : is_word nr ⦃ b => b = true ↔ IsCallNumber nr ⦄ := by
  unfold is_word IsCallNumber
  by_cases non_negative : nr >= 0#i64
  · simp only [non_negative, ite_true]
    refine (WP.spec_ok _).mpr ?_
    have : 0 ≤ nr.val := by scalar_tac
    simp [this]
  · simp only [non_negative, ite_false]
    refine (WP.spec_ok _).mpr ?_
    have : ¬ 0 ≤ nr.val := by scalar_tac
    simp [this]

/-- `is_byte` says whether a jump of `n` instructions is a byte. -/
@[step]
theorem is_byte_is (n : Std.Usize) : is_byte n ⦃ b => b = true ↔ n.val ≤ 255 ⦄ := by
  unfold is_byte
  refine (WP.spec_ok _).mpr ?_
  simp [UScalar.le_equiv]

/-- The conditions on one rule that `valid` checks: its call number, its argument, its values. -/
def RuleIsValid (nr : Std.I64) (arg : Nat) (values : Nat) : Prop :=
  IsCallNumber nr ∧ arg ≤ 5 ∧ values + 3 ≤ 255

/-- `valid_rule` accepts a rule exactly when its call number fits 32 bits, its argument is 0 to
5 and its jump fits a byte. -/
@[step]
theorem valid_rule_is (nr : Std.I64) (arg values : Std.Usize)
    (room : values.val + 3 ≤ Usize.max) :
    valid_rule nr arg values ⦃ r =>
      r = core.result.Result.Ok () ↔ RuleIsValid nr arg.val values.val ⦄ := by
  unfold valid_rule RuleIsValid
  -- the call number is tested first: a number that does not fit is the error `Number`
  step as ⟨ word, h_word ⟩
  by_cases is_number : word = true
  · have number : IsCallNumber nr := h_word.mp is_number
    simp only [is_number, ite_true]
    -- then the argument: above 5 is the error `Argument`
    by_cases arg_ok : arg > 5#usize
    · simp only [arg_ok, ite_true]
      refine (WP.spec_ok _).mpr ?_
      have : ¬ arg.val ≤ 5 := by scalar_tac
      simp [this]
    · simp only [arg_ok, ite_false]
      have arg_le : arg.val ≤ 5 := by scalar_tac
      -- then the jump over the block: more than a byte is the error `Jump`
      step as ⟨ jump, h_jump ⟩
      step as ⟨ fits, h_fits ⟩
      by_cases fit : fits = true
      · simp only [fit, ite_true]
        refine (WP.spec_ok _).mpr ?_
        simp only [true_iff]
        have := h_fits.mp fit
        exact ⟨number, arg_le, by omega⟩
      · simp only [fit]
        refine (WP.spec_ok _).mpr ?_
        have : ¬ jump.val ≤ 255 := fun h => fit (h_fits.mpr h)
        have : ¬ values.val + 3 ≤ 255 := by omega
        simp [this]
  · have not_number : ¬ IsCallNumber nr := fun n => is_number (h_word.mpr n)
    simp only [is_number]
    refine (WP.spec_ok _).mpr ?_
    simp [not_number]

/-- The loop of `valid_denied`, from the call at `i`: `Ok` exactly when every call from there on
fits 32 bits. -/
theorem valid_denied_loop_is (denied : Slice Std.I64) (i : Std.Usize)
    (read : i.val ≤ denied.length) :
    valid_denied_loop denied i ⦃ r =>
      r = core.result.Result.Ok () ↔ ∀ nr ∈ denied.val.drop i.val, IsCallNumber nr ⦄ := by
  unfold valid_denied_loop
  -- the loop keeps: the calls from the position on are numbers exactly when the calls from where
  -- it started are (it stops at the first that is not)
  apply loop.spec_decr_nat (fun j => denied.length - j.val)
    (fun j => j.val ≤ denied.length ∧
      ((∀ nr ∈ denied.val.drop j.val, IsCallNumber nr) ↔
        ∀ nr ∈ denied.val.drop i.val, IsCallNumber nr))
  · intro j ⟨read_j, same⟩
    unfold valid_denied_loop.body
    by_cases inside : j < Slice.len denied
    -- a call is left: its number is tested
    · simp only [inside, ite_true]
      have inside' : j.val < denied.val.length := by simpa [Slice.len, Slice.length] using inside
      have at_j : denied.val.drop j.val = denied.val[j.val] :: denied.val.drop (j.val + 1) :=
        List.drop_eq_getElem_cons inside'
      step as ⟨ nr, h_nr ⟩
      step as ⟨ word, h_word ⟩
      by_cases is_number : word = true
      · simp only [is_number, ite_true]
        step as ⟨ next, h_next ⟩
        have number : IsCallNumber denied.val[j.val] := by rw [← h_nr]; exact h_word.mp is_number
        refine ⟨by simp [Slice.length] at *; omega, ?_, by simp [Slice.length] at *; omega⟩
        have step_over : (∀ nr ∈ denied.val.drop j.val, IsCallNumber nr) ↔
            ∀ nr ∈ denied.val.drop (j.val + 1), IsCallNumber nr := by
          rw [at_j, List.forall_mem_cons]
          exact ⟨fun all => all.2, fun rest => ⟨number, rest⟩⟩
        rw [h_next]
        exact step_over.symm.trans same
      · simp only [is_number]
        refine (WP.spec_ok _).mpr ?_
        have not_number : ¬ IsCallNumber denied.val[j.val] := by
          rw [← h_nr]; exact fun n => is_number (h_word.mpr n)
        simp only [reduceCtorEq, false_iff]
        intro all
        exact not_number (same.mpr all _ (by rw [at_j]; exact List.mem_cons_self))
    · have outside : denied.val.length ≤ j.val := by simpa [Slice.len, Slice.length] using inside
      simp only [inside, ite_false]
      refine (WP.spec_ok _).mpr ?_
      rw [List.drop_eq_nil_of_le outside] at same
      simp only [true_iff]
      exact same.mp (by simp)
  · exact ⟨read, Iff.rfl⟩

/-- `valid_denied`: `Ok` exactly when every denied call fits 32 bits. -/
@[step]
theorem valid_denied_is (denied : Slice Std.I64) :
    valid_denied denied ⦃ r =>
      r = core.result.Result.Ok () ↔ ∀ nr ∈ denied.val, IsCallNumber nr ⦄ := by
  unfold valid_denied
  have := valid_denied_loop_is denied 0#usize (by simp)
  simpa using this

/-- `valid_rules`, from the rule at `r`: `Ok` exactly when every rule from there on is valid. -/
theorem valid_rules_is (rules : Slice OnlyIf) :
    ∀ (n : Nat) (r : Std.Usize), rules.length - r.val = n → r.val ≤ rules.length →
      (∀ rule ∈ rules.val.drop r.val, rule.values.length + 3 ≤ Usize.max) →
      valid_rules rules r ⦃ res =>
        res = core.result.Result.Ok () ↔
          ∀ rule ∈ rules.val.drop r.val, RuleIsValid rule.nr rule.arg.val rule.values.length ⦄ := by
  have len_eq : rules.length = rules.val.length := rfl
  intro n
  induction n with
  | zero =>
    -- no rule is left
    intro r measure read room
    unfold valid_rules
    have outside : ¬ r < Slice.len rules := by simp [Slice.len]; omega
    simp only [outside, ite_false]
    refine (WP.spec_ok _).mpr ?_
    simp [List.drop_eq_nil_of_le (by omega : rules.val.length ≤ r.val)]
  | succ n ih =>
    -- a rule is left: it is checked, then the rules after it by the hypothesis of induction
    intro r measure read room
    unfold valid_rules
    have inside : r < Slice.len rules := by simp [Slice.len]; omega
    simp only [inside, ite_true]
    have inside' : r.val < rules.val.length := by simp [Slice.len] at inside; omega
    have at_r : rules.val.drop r.val = rules.val[r.val] :: rules.val.drop (r.val + 1) :=
      List.drop_eq_getElem_cons inside'
    step as ⟨ rule, h_rule ⟩
    have member : rule ∈ rules.val.drop r.val := by rw [at_r, h_rule]; exact List.mem_cons_self
    have room_rule : rule.values.len.val + 3 ≤ Usize.max := by
      simpa [Slice.len, Slice.length] using room rule member
    step as ⟨ res, h_res ⟩
    cases res with
    | Ok u =>
      cases u
      simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok]
      step as ⟨ next, h_next ⟩
      have first_valid : RuleIsValid rule.nr rule.arg.val rule.values.len.val := h_res.mp rfl
      refine WP.spec_mono (ih next (by omega) (by omega) ?_) ?_
      · intro later member
        rw [h_next] at member
        exact room later (by rw [at_r]; exact List.mem_cons_of_mem _ member)
      · intro res' h_rest
        rw [h_rest, h_next, at_r, List.forall_mem_cons]
        subst h_rule
        simp only [Slice.len] at first_valid
        exact ⟨fun rest => ⟨first_valid, rest⟩, fun both => both.2⟩
    | Err e =>
      simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
      simp only [core.convert.FromSame.from]
      refine WP.spec_bind (show (ok e : Result velarx_bpf_core.Error) ⦃ _ => True ⦄ from
        (WP.spec_ok e).mpr trivial) ?_
      intro v _
      refine (WP.spec_ok _).mpr ?_
      have first_invalid : ¬ RuleIsValid rule.nr rule.arg.val rule.values.len.val :=
        fun valid => by simpa using h_res.mpr valid
      simp only [reduceCtorEq, false_iff]
      intro all
      apply first_invalid
      have := all rule member
      simpa [h_rule, Slice.len, Slice.length] using this

/-- With a table of these sizes nothing overflows when a rule is counted. -/
theorem rule_sizes_fit (on64 : OnA64BitMachine) (table : Table) (small : IsSmall table) :
    ∀ rule ∈ table.«only».val, rule.values.length + 3 ≤ Usize.max := by
  intro rule member
  have := small.2.2 rule member
  have := usize_max_is on64
  omega

/-- **`valid`**: `Ok` exactly when the table is valid. -/
@[step]
theorem valid_is (on64 : OnA64BitMachine) (table : Table) (small : IsSmall table) :
    valid table ⦃ r => r = core.result.Result.Ok () ↔ IsValid table ⦄ := by
  unfold valid
  -- the denied calls are checked first, then the rules
  step as ⟨ denied, h_denied ⟩
  cases denied with
  | Ok u =>
    cases u
    simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok]
    refine WP.spec_mono (valid_rules_is table.«only» _ 0#usize rfl (by simp)
      (by simpa using rule_sizes_fit on64 table small)) ?_
    intro r h_rules
    rw [h_rules]
    have all_denied : ∀ nr ∈ table.denied.val, IsCallNumber nr := h_denied.mp rfl
    have zero : (0#usize).val = 0 := rfl
    simp only [IsValid, RuleIsValid, zero, List.drop_zero, Slice.length]
    exact ⟨fun rules => ⟨all_denied, rules⟩, fun both => both.2⟩
  | Err e =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
    simp only [core.convert.FromSame.from]
    refine WP.spec_bind (show (ok e : Result velarx_bpf_core.Error) ⦃ _ => True ⦄ from
      (WP.spec_ok e).mpr trivial) ?_
    intro v _
    refine (WP.spec_ok _).mpr ?_
    simp only [reduceCtorEq, false_iff]
    intro valid
    exact (by simpa using h_denied.mpr valid.1 : False)

end BpfCore
