-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the sets of categories (`Cats`): `has`, `add`, `is_empty` and `within`
--    answer what the bits of the 16 words say.
-- Why it is needed: the claims about levels speak of categories in a set; the functions of the set
--    are written with words and loops, so they are proved once to be what a reader expects of a
--    set.
-- Read before this file: Spec.lean, TheLoops.lean.
-- Notation: `f x ⦃ r => P r ⦄` reads: the Rust function `f` returns and its answer `r` satisfies
--    `P r`. `step` goes through one line of the Rust function.
import McsCore.Spec
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- The bit `k` of a word that is shifted right by `k` and cut to its lowest bit. -/
theorem bit_of_shift (x : BitVec 64) (k : Nat) (_below : k < 64) :
    ((x >>> k) &&& 1#64 = 1#64) ↔ x.getLsbD k = true := by
  constructor
  · intro h
    have := congrArg (fun v => v.getLsbD 0) h
    simpa [BitVec.getLsbD_and, BitVec.getLsbD_ushiftRight] using this
  · intro h
    apply BitVec.eq_of_getLsbD_eq
    intro j hj
    rcases Nat.eq_zero_or_pos j with rfl | pos
    · simp [BitVec.getLsbD_and, BitVec.getLsbD_ushiftRight, h]
    · simp [BitVec.getLsbD_and, BitVec.getLsbD_ushiftRight, BitVec.getLsbD_one]
      omega

/-- The category is in the set: its bit is set (and it is below 1024). -/
def Mem (s : Cats) (c : Nat) : Prop :=
  c < 1024 ∧ (s.words.val[c / 64]!).bv.getLsbD (c % 64) = true

/-- What `has` answers: true exactly when the category is in the set. -/
theorem has_spec (s : Cats) (c : Std.U16) :
    Cats.has s c ⦃ b => b = true ↔ Mem s c.val ⦄ := by
  unfold Cats.has
  step as ⟨ c1, is_c1 ⟩
  step as ⟨ i, is_i ⟩
  have is_cat : CATEGORIES.val = 1024 := by simp [CATEGORIES]
  have c1v : c1.val = c.val := by rw [is_c1]; simp
  have iv : i.val = 1024 := by rw [is_i]; simp [is_cat]
  by_cases below : c1 < i
  · simp only [below, ite_true]
    have lt : c.val < 1024 := by scalar_tac
    step as ⟨ i1, is_i1 ⟩
    have len : i1.val < s.words.val.length := by simp; omega
    step as ⟨ i2, is_i2 ⟩
    step as ⟨ i3, is_i3 ⟩
    step as ⟨ i4, is_i4, bv4 ⟩
    step as ⟨ i5, is_i5, bv5 ⟩
    have is_bv : i5.bv = (i2.bv >>> i3.val) &&& 1#64 := by
      have := bv5; rw [bv4] at this; exact this
    have word : (s.words.val[c.val / 64]!) = i2 := by
      have idx : i1.val = c.val / 64 := by rw [is_i1, c1v]
      rw [is_i2]; simp only [List.getElem!_eq_getElem?_getD]
      rw [← idx]; simp [List.getElem?_eq_getElem len]
    simp only [decide_eq_true_eq, Mem, lt, true_and, word]
    have is_one : i5 = 1#u64 ↔ i5.bv = 1#64 := by rw [UScalar.eq_equiv_bv_eq]; rfl
    have mod_eq : i3.val = c.val % 64 := by rw [is_i3, c1v]
    rw [is_one, is_bv, ← mod_eq]
    exact bit_of_shift _ _ (by omega)
  · simp only [below, ite_false]
    refine (WP.spec_ok _).mpr ?_
    have : ¬ c.val < 1024 := by scalar_tac
    simp [Mem, this]

/-- The empty set of `Cats::empty` has no category. -/
theorem empty_spec : Cats.empty ⦃ s => ∀ c, ¬ Mem s c ⦄ := by
  unfold Cats.empty
  refine (WP.spec_ok _).mpr ?_
  intro c ⟨lt, bit⟩
  have : c / 64 < 16 := by omega
  have zero : ∀ k : Nat, (List.replicate 16 (0#u64))[k]! = 0#u64 := by
    intro k
    simp only [List.getElem!_eq_getElem?_getD, List.getElem?_replicate]
    split <;> rfl
  rw [Array.repeat_val, show (16#usize).val = 16 from rfl, zero] at bit
  simp at bit

/-- After `add` of a category below 1024, the set has it and what it had. -/
theorem add_spec (s : Cats) (c : Std.U16) (lt : c.val < 1024) :
    Cats.add s c ⦃ t => ∀ d, Mem t d ↔ Mem s d ∨ d = c.val ⦄ := by
  unfold Cats.add
  step as ⟨ c1, is_c1 ⟩
  have c1v : c1.val = c.val := by rw [is_c1]; simp
  step as ⟨ i, is_i ⟩
  step as ⟨ i1, is_i1, bv1 ⟩
  step as ⟨ i2, is_i2 ⟩
  have len : i2.val < s.words.val.length := by simp; omega
  step as ⟨ i3, is_i3 ⟩
  step as ⟨ i4, is_i4, bv4 ⟩
  step as ⟨ a, is_a ⟩
  intro d
  have word_at : s.words.val[i2.val]! = i3 := by
    rw [is_i3]; simp only [List.getElem!_eq_getElem?_getD]; simp [List.getElem?_eq_getElem len]
  have bits : ∀ j, i1.bv.getLsbD j = decide (j = i.val ∧ j < 64) := by
    intro j
    have iv : i.val < 64 := by rw [is_i]; omega
    have := congrArg (fun v => v.getLsbD j) bv1
    rw [this]
    simp [BitVec.getLsbD_shiftLeft, BitVec.getLsbD_one]
    rw [Bool.eq_iff_iff]
    simp only [Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq, decide_eq_false_iff_not]
    omega
  have i2v : i2.val = c.val / 64 := by rw [is_i2, c1v]
  have iv : i.val = c.val % 64 := by rw [is_i, c1v]
  unfold Mem
  rw [is_a, Array.set_val_eq]
  have lt16 : i2.val < 16 := by simpa using len
  by_cases same : d / 64 = i2.val
  · have : (s.words.val.set i2.val i4)[d / 64]! = i4 := by
      rw [same]; simp only [List.getElem!_eq_getElem?_getD]
      simp [List.getElem?_set, lt16]
    rw [this]
    have := congrArg (fun v => v.getLsbD (d % 64)) bv4
    simp only [BitVec.getLsbD_or] at this
    rw [this, bits, same, word_at]
    have key : d % 64 = i.val ↔ d = c.val := by omega
    simp only [Bool.or_eq_true, decide_eq_true_eq]
    constructor
    · rintro ⟨h, h2⟩
      rcases h2 with h2 | ⟨h2, _⟩
      · exact Or.inl ⟨h, h2⟩
      · exact Or.inr (key.mp h2)
    · rintro (⟨h, h2⟩ | h2)
      · exact ⟨h, Or.inl h2⟩
      · exact ⟨by omega, Or.inr ⟨key.mpr h2, by omega⟩⟩
  · have : (s.words.val.set i2.val i4)[d / 64]! = s.words.val[d / 64]! := by
      simp only [List.getElem!_eq_getElem?_getD]
      rw [List.getElem?_set_ne (by omega)]
    rw [this]
    constructor
    · exact fun h => Or.inl h
    · rintro (h | h)
      · exact h
      · omega

/-- A set has 16 words. -/
theorem words_len (s : Cats) : s.words.val.length = 16 := by simp

/-- The loop of `is_empty` says true when the flag is and every word from the place is zero. -/
theorem is_empty_loop_spec (s : Cats) (i : Std.Usize) (flag : Bool) (start : i.val ≤ 16) :
    Cats.is_empty_loop s i flag ⦃ r =>
      r = true ↔ flag = true ∧ ∀ k, i.val ≤ k → k < 16 → s.words.val[k]! = 0#u64 ⦄ := by
  unfold Cats.is_empty_loop
  apply loop.spec_decr_nat (fun (q : Std.Usize × Bool) => 16 - q.1.val)
    (fun (q : Std.Usize × Bool) => q.1.val ≤ 16 ∧
      ((q.2 = true ∧ ∀ k, q.1.val ≤ k → k < 16 → s.words.val[k]! = 0#u64) ↔
        (flag = true ∧ ∀ k, i.val ≤ k → k < 16 → s.words.val[k]! = 0#u64)))
  · rintro ⟨i', flag'⟩ ⟨le', same⟩
    simp only at le' same ⊢
    unfold Cats.is_empty_loop.body
    have wv : WORDS.val = 16 := by simp [WORDS]
    by_cases below : i' < WORDS
    · simp only [below, ite_true]
      have below' : i'.val < 16 := by scalar_tac
      have len : i'.val < s.words.val.length := by rw [words_len]; exact below'
      step as ⟨ w, is_w ⟩
      have is_word : s.words.val[i'.val]! = w := by
        rw [is_w]; simp only [List.getElem!_eq_getElem?_getD]; simp [List.getElem?_eq_getElem len]
      have next : (∀ k, i'.val ≤ k → k < 16 → s.words.val[k]! = 0#u64) ↔
          s.words.val[i'.val]! = 0#u64 ∧ ∀ k, i'.val + 1 ≤ k → k < 16 → s.words.val[k]! = 0#u64 := by
        constructor
        · intro all; exact ⟨all _ (le_refl _) below', fun k a b => all k (by omega) b⟩
        · rintro ⟨here, rest⟩ k a b
          rcases Nat.eq_or_lt_of_le a with eq | lt
          · rw [← eq]; exact here
          · exact rest k lt b
      by_cases zero : w = 0#u64
      · have not_ne : ¬ (w != 0#u64) = true := by simp [zero]
        simp only [not_ne, Bool.false_eq_true, ite_false, bind_tc_ok]
        step as ⟨ i2, is_i2 ⟩
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [← same, next, is_word, is_i2]
        simp [zero]
      · have is_ne : (w != 0#u64) = true := by simpa using zero
        simp only [is_ne, ite_true]
        step as ⟨ i2, is_i2 ⟩
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [← same, next, is_word]
        simp [zero]
    · have : i'.val = 16 := by scalar_tac
      simp only [below, ite_false]
      refine (WP.spec_ok _).mpr ?_
      rw [← same]
      have nothing : ∀ k, i'.val ≤ k → k < 16 → s.words.val[k]! = 0#u64 := by intro k a b; omega
      exact ⟨fun h => ⟨h, nothing⟩, fun h => h.1⟩
  · exact ⟨start, Iff.rfl⟩

/-- A word of a set, as a number of bits. -/
theorem word_bits (s : Cats) (k : Nat) (lt : k < 16) (j : Nat) (hj : j < 64) :
    Mem s (64 * k + j) ↔ (s.words.val[k]!).bv.getLsbD j = true := by
  unfold Mem
  have a : (64 * k + j) / 64 = k := by omega
  have b : (64 * k + j) % 64 = j := by omega
  rw [a, b]
  constructor
  · exact fun h => h.2
  · exact fun h => ⟨by omega, h⟩

/-- What `is_empty` answers: true exactly when no category is in the set. -/
theorem is_empty_spec (s : Cats) : Cats.is_empty s ⦃ r => r = true ↔ ∀ c, ¬ Mem s c ⦄ := by
  unfold Cats.is_empty
  refine WP.spec_mono (is_empty_loop_spec s 0#usize true (by simp)) ?_
  intro r h
  rw [h]
  have z : (0#usize).val = 0 := rfl
  simp only [true_and, z, Nat.zero_le, true_implies]
  constructor
  · intro zero c ⟨lt, bit⟩
    have := zero (c / 64) (by omega)
    rw [this] at bit
    simp at bit
  · intro none k lt
    rw [UScalar.eq_equiv_bv_eq]
    apply BitVec.eq_of_getLsbD_eq
    intro j hj
    have := none (64 * k + j)
    rw [word_bits s k lt j hj] at this
    simpa using this

/-- The loop of `within` says true when the flag is and every word from the place has no bit that
the other has not. -/
theorem within_loop_spec (s o : Cats) (i : Std.Usize) (flag : Bool) (start : i.val ≤ 16) :
    Cats.within_loop s o i flag ⦃ r =>
      r = true ↔ flag = true ∧ ∀ k, i.val ≤ k → k < 16 →
        (s.words.val[k]!).bv &&& ~~~(o.words.val[k]!).bv = 0#64 ⦄ := by
  unfold Cats.within_loop
  apply loop.spec_decr_nat (fun (q : Std.Usize × Bool) => 16 - q.1.val)
    (fun (q : Std.Usize × Bool) => q.1.val ≤ 16 ∧
      ((q.2 = true ∧ ∀ k, q.1.val ≤ k → k < 16 →
          (s.words.val[k]!).bv &&& ~~~(o.words.val[k]!).bv = 0#64) ↔
        (flag = true ∧ ∀ k, i.val ≤ k → k < 16 →
          (s.words.val[k]!).bv &&& ~~~(o.words.val[k]!).bv = 0#64)))
  · rintro ⟨i', flag'⟩ ⟨le', same⟩
    simp only at le' same ⊢
    unfold Cats.within_loop.body
    have wv : WORDS.val = 16 := by simp [WORDS]
    by_cases below : i' < WORDS
    · simp only [below, ite_true]
      have below' : i'.val < 16 := by scalar_tac
      have len : i'.val < s.words.val.length := by rw [words_len]; exact below'
      have len' : i'.val < o.words.val.length := by rw [words_len]; exact below'
      step as ⟨ w, is_w ⟩
      step as ⟨ w', is_w' ⟩
      step as ⟨ nw', is_nw' ⟩
      step as ⟨ both, is_both, bv_both ⟩
      have is_word : s.words.val[i'.val]! = w := by
        rw [is_w]; simp only [List.getElem!_eq_getElem?_getD]; simp [List.getElem?_eq_getElem len]
      have is_word' : o.words.val[i'.val]! = w' := by
        rw [is_w']; simp only [List.getElem!_eq_getElem?_getD]; simp [List.getElem?_eq_getElem len']
      have bv_nw' : nw'.bv = ~~~w'.bv := by rw [is_nw']; rfl
      have bv_both' : both.bv = w.bv &&& ~~~w'.bv := bv_both.trans (congrArg (w.bv &&& ·) bv_nw')
      have next : (∀ k, i'.val ≤ k → k < 16 →
            (s.words.val[k]!).bv &&& ~~~(o.words.val[k]!).bv = 0#64) ↔
          (s.words.val[i'.val]!).bv &&& ~~~(o.words.val[i'.val]!).bv = 0#64 ∧
          ∀ k, i'.val + 1 ≤ k → k < 16 →
            (s.words.val[k]!).bv &&& ~~~(o.words.val[k]!).bv = 0#64 := by
        constructor
        · intro all; exact ⟨all _ (le_refl _) below', fun k a b => all k (by omega) b⟩
        · rintro ⟨here, rest⟩ k a b
          rcases Nat.eq_or_lt_of_le a with eq | lt
          · rw [← eq]; exact here
          · exact rest k lt b
      have zero_iff : (both = 0#u64) ↔ w.bv &&& ~~~w'.bv = 0#64 := by
        rw [UScalar.eq_equiv_bv_eq]
        exact ⟨fun h => bv_both'.symm.trans h, fun h => bv_both'.trans h⟩
      by_cases zero : both = 0#u64
      · have not_ne : ¬ (both != 0#u64) = true := by simp [zero]
        simp only [not_ne, Bool.false_eq_true, ite_false, bind_tc_ok]
        step as ⟨ i2, is_i2 ⟩
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        have good : (s.words.val[i'.val]!).bv &&& ~~~(o.words.val[i'.val]!).bv = 0#64 := by
          rw [is_word, is_word']; exact zero_iff.mp zero
        rw [← same, next, is_i2]
        simp only [good, true_and]
      · have is_ne : (both != 0#u64) = true := by simpa using zero
        simp only [is_ne, ite_true]
        step as ⟨ i2, is_i2 ⟩
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        have bad : ¬ (s.words.val[i'.val]!).bv &&& ~~~(o.words.val[i'.val]!).bv = 0#64 := by
          rw [is_word, is_word']; exact mt zero_iff.mpr zero
        rw [← same, next]
        simp only [bad, false_and, Bool.false_eq_true, and_false]
    · have : i'.val = 16 := by scalar_tac
      simp only [below, ite_false]
      refine (WP.spec_ok _).mpr ?_
      rw [← same]
      have nothing : ∀ k, i'.val ≤ k → k < 16 →
          (s.words.val[k]!).bv &&& ~~~(o.words.val[k]!).bv = 0#64 := by intro k a b; omega
      exact ⟨fun h => ⟨h, nothing⟩, fun h => h.1⟩
  · exact ⟨start, Iff.rfl⟩

/-- What `within` answers: true exactly when each category of the set is in the other. -/
theorem within_spec (s o : Cats) :
    Cats.within s o ⦃ r => r = true ↔ ∀ c, Mem s c → Mem o c ⦄ := by
  unfold Cats.within
  refine WP.spec_mono (within_loop_spec s o 0#usize true (by simp)) ?_
  intro r h
  rw [h]
  have z : (0#usize).val = 0 := rfl
  simp only [true_and, z, Nat.zero_le, true_implies]
  constructor
  · intro all c ⟨lt, bit⟩
    refine ⟨lt, ?_⟩
    have zero := congrArg (fun v => v.getLsbD (c % 64)) (all (c / 64) (by omega))
    have bit' := (word_bits s (c / 64) (by omega) (c % 64) (by omega)).mp (by
      have : 64 * (c / 64) + c % 64 = c := by omega
      rw [this]; exact ⟨lt, bit⟩)
    generalize (s.words.val[c / 64]!) = ws at *
    generalize (o.words.val[c / 64]!) = wo at *
    simp only [BitVec.getLsbD_and, BitVec.getLsbD_not, BitVec.getLsbD_zero] at zero
    have hj : c % 64 < 64 := by omega
    simp only [hj, bit', decide_true, Bool.true_and, Bool.and_eq_false_iff] at zero
    simp_all
  · intro sub k lt
    apply BitVec.eq_of_getLsbD_eq
    intro j hj
    have := sub (64 * k + j)
    rw [word_bits s k lt j hj, word_bits o k lt j hj] at this
    generalize (s.words.val[k]!) = ws at *
    generalize (o.words.val[k]!) = wo at *
    simp only [BitVec.getLsbD_and, BitVec.getLsbD_not, BitVec.getLsbD_zero, hj, decide_true,
      Bool.true_and]
    cases hs : ws.bv.getLsbD j <;> cases ho : wo.bv.getLsbD j <;> simp_all

end McsCore
