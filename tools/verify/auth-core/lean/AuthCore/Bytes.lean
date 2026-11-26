-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the small functions that walk bytes answer: `same a b` is `true`
-- exactly when the two lists are equal, `same_lower a lit` exactly when `a` in lower case is `lit`,
-- `has s at lit` exactly when `lit` is the beginning of `s` from the place `at`, `at_is s at b`
-- exactly when the byte at the place `at` is `b`, `find s from to b` is the place of the first `b`
-- of `s` from `from` before `to` (or `to`), and `lower b` is `LowerByte b`.  All of them return.
-- Why it is needed: `matches`, `pick`, `exact` and `normalize` compare and scan bytes with these.
-- Read before this file: Spec.lean.
-- Notation: `loop.spec_decr_nat` proves that a loop returns because a number goes down at each turn
-- while a fact (the invariant) is kept by each turn; `step as ⟨ x, hx ⟩` runs one line of a Rust
-- function and names its result `x` and what is known of it `hx`; `l.take i` is the first `i`
-- elements of `l`.
import AuthCore.Spec
import AuthCore.TakeFacts

open Aeneas Aeneas.Std Result velarx_auth_core

namespace AuthCore

/-- A vector read as a slice has the bytes of the vector. -/
@[simp] theorem deref_keeps_the_bytes {α : Type} (v : alloc.vec.Vec α) :
    (alloc.vec.Vec.deref v).val = v.val := by
  simp [alloc.vec.Vec.deref]

/-- The loop of `same`: from the place `i`, `equal` says that the lists have the same length and the
same first `i` bytes; the loop ends with `true` exactly when the lists are equal. -/
theorem same_loop_compares (a b : Slice Std.U8) (equal : Bool) (i : Std.Usize)
    (inside : i.val ≤ a.length)
    (equal_says : equal = true ↔ (a.length = b.length ∧ a.val.take i.val = b.val.take i.val)) :
    same_loop a b equal i ⦃ r => r = true ↔ a.val = b.val ⦄ := by
  unfold same_loop
  apply loop.spec_decr_nat (fun (q : Bool × Std.Usize) => a.length - q.2.val)
    (fun (q : Bool × Std.Usize) => q.2.val ≤ a.length ∧
      (q.1 = true ↔ (a.length = b.length ∧ a.val.take q.2.val = b.val.take q.2.val)))
  · rintro ⟨equal, i⟩ ⟨inside, equal_says⟩
    simp only at inside equal_says ⊢
    unfold same_loop.body
    by_cases below : i.val < a.length
    · have below' : i < Slice.len a := by scalar_tac
      simp only [below', ite_true]
      by_cases still_equal : equal = true
      · simp only [still_equal, ite_true]
        have same_length := (equal_says.mp still_equal).1
        have same_prefix := (equal_says.mp still_equal).2
        have in_b : i.val < b.val.length := by
          have : b.val.length = b.length := rfl
          omega
        step as ⟨ x, is_x ⟩
        step as ⟨ y, is_y ⟩
        step as ⟨ next, is_next ⟩
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [is_next, equal_prefixes_grow a.val b.val i.val below in_b, is_x, is_y]
        simp [same_length, same_prefix]
      · simp only [still_equal]
        refine (WP.spec_ok _).mpr ?_
        show false = true ↔ a.val = b.val
        constructor
        · intro now_equal
          exact absurd now_equal (by simp)
        · intro same
          have same_length : a.val.length = b.val.length := by rw [same]
          exact absurd (equal_says.mpr ⟨same_length, by rw [same]⟩) still_equal
    · have below' : ¬ i < Slice.len a := by scalar_tac
      simp only [below', ite_false, ite_self]
      refine (WP.spec_ok _).mpr ?_
      show equal = true ↔ a.val = b.val
      have at_end : i.val = a.length := by scalar_tac
      rw [at_end, List.take_length] at equal_says
      rw [equal_says]
      constructor
      · rintro ⟨same_length, same_bytes⟩
        have : a.length = b.val.length := same_length
        rw [same_bytes, this, List.take_length]
      · intro same
        have same_length : a.length = b.val.length := by
          show a.val.length = b.val.length
          rw [same]
        exact ⟨same_length, by rw [same_length, List.take_length]; exact same⟩
  · exact ⟨inside, equal_says⟩

/-- **`same`** answers `true` exactly when the two lists of bytes are equal. -/
@[step] theorem same_is_equality (a b : Slice Std.U8) :
    same a b ⦃ r => r = true ↔ a.val = b.val ⦄ := by
  unfold same
  have lengths_say : (a.len = b.len) ↔ a.length = b.length := by
    constructor
    · intro same
      simpa using congrArg UScalar.val same
    · intro same
      exact UScalar.eq_of_val_eq (by simpa using same)
  exact same_loop_compares a b _ 0#usize (by simp) (by simpa using lengths_say)

/-- **`lower`** is `LowerByte`. -/
@[step] theorem lower_is_lower_byte (b : Std.U8) : lower b ⦃ r => r = LowerByte b ⦄ := by
  unfold lower
  by_cases upper : 65 ≤ b.val ∧ b.val ≤ 90
  · have h1 : 65#u8 ≤ b := by scalar_tac
    have h2 : b ≤ 90#u8 := by scalar_tac
    simp [h1, h2]
    step as ⟨ r, is_r ⟩
    simp only [LowerByte, upper, and_self, ↓reduceIte]
    apply UScalar.eq_of_val_eq
    rw [is_r]
    show b.val + 32 = (BitVec.ofNat 8 (b.val + 32)).toNat
    rw [BitVec.toNat_ofNat]
    omega
  · have : ¬ (65#u8 ≤ b ∧ b ≤ 90#u8) := by scalar_tac
    by_cases h1 : 65#u8 ≤ b
    · have h2 : ¬ b ≤ 90#u8 := fun h2 => this ⟨h1, h2⟩
      simp [h1, h2, LowerByte, upper]
    · simp [h1, LowerByte, upper]

/-- The loop of `same_lower`: from the place `i`, `equal` says that the lists have the same length
and the first `i` bytes of `a` in lower case are the first `i` of `lit`. -/
theorem same_lower_loop_compares (a lit : Slice Std.U8) (equal : Bool) (i : Std.Usize)
    (inside : i.val ≤ a.length)
    (equal_says : equal = true ↔
      (a.length = lit.length ∧ (a.val.take i.val).map LowerByte = lit.val.take i.val)) :
    same_lower_loop a lit equal i ⦃ r => r = true ↔ a.val.map LowerByte = lit.val ⦄ := by
  unfold same_lower_loop
  apply loop.spec_decr_nat (fun (q : Bool × Std.Usize) => a.length - q.2.val)
    (fun (q : Bool × Std.Usize) => q.2.val ≤ a.length ∧
      (q.1 = true ↔ (a.length = lit.length ∧
        (a.val.take q.2.val).map LowerByte = lit.val.take q.2.val)))
  · rintro ⟨equal, i⟩ ⟨inside, equal_says⟩
    simp only at inside equal_says ⊢
    unfold same_lower_loop.body
    by_cases below : i.val < a.length
    · have below' : i < Slice.len a := by scalar_tac
      simp only [below', ite_true]
      by_cases still_equal : equal = true
      · simp only [still_equal, ite_true]
        have same_length := (equal_says.mp still_equal).1
        have same_prefix := (equal_says.mp still_equal).2
        have in_lit : i.val < lit.val.length := by
          have : lit.val.length = lit.length := rfl
          omega
        step as ⟨ x, is_x ⟩
        step as ⟨ y, is_y ⟩
        step as ⟨ z, is_z ⟩
        step as ⟨ next, is_next ⟩
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        have a_in : i.val < a.val.length := below
        rw [is_next, take_one_more a.val i.val a_in, take_one_more lit.val i.val in_lit,
          List.map_append, List.map_cons, List.map_nil]
        have same_len : ((a.val.take i.val).map LowerByte).length =
            (lit.val.take i.val).length := by
          rw [same_prefix]
        have : ∀ (l m : List Std.U8) (x y : Std.U8), l.length = m.length →
            (l ++ [x] = m ++ [y] ↔ l = m ∧ x = y) := by
          intro l m x y h
          constructor
          · intro e
            have := List.append_inj e h
            simpa using this
          · rintro ⟨rfl, rfl⟩; rfl
        rw [this _ _ _ _ same_len]
        simp [same_length, same_prefix, is_x, is_y, is_z]
      · simp only [still_equal]
        refine (WP.spec_ok _).mpr ?_
        show false = true ↔ a.val.map LowerByte = lit.val
        constructor
        · intro now_equal
          exact absurd now_equal (by simp)
        · intro same
          have same_length : a.length = lit.length := by
            have := congrArg List.length same
            simpa using this
          have : (a.val.take i.val).map LowerByte = lit.val.take i.val := by
            rw [← same, List.map_take]
          exact absurd (equal_says.mpr ⟨same_length, this⟩) still_equal
    · have below' : ¬ i < Slice.len a := by scalar_tac
      simp only [below', ite_false, ite_self]
      refine (WP.spec_ok _).mpr ?_
      show equal = true ↔ a.val.map LowerByte = lit.val
      have at_end : i.val = a.length := by scalar_tac
      have a_len : a.val.length = a.length := rfl
      rw [at_end] at equal_says
      have a_len' : a.length = a.val.length := rfl
      rw [a_len', List.take_length] at equal_says
      rw [equal_says]
      constructor
      · rintro ⟨same_length, same_bytes⟩
        have : a.val.length = lit.length := same_length
        rw [same_bytes, this]
        exact List.take_of_length_le (le_of_eq rfl)
      · intro same
        have same_length : a.length = lit.length := by
          have := congrArg List.length same
          simpa using this
        refine ⟨same_length, ?_⟩
        rw [same, ← a_len', same_length]
        exact (List.take_of_length_le (le_of_eq rfl)).symm
  · exact ⟨inside, equal_says⟩

/-- **`same_lower`** answers `true` exactly when `a` in lower case is `lit`. -/
@[step] theorem same_lower_is_lower_case_equality (a lit : Slice Std.U8) :
    same_lower a lit ⦃ r => r = true ↔ a.val.map LowerByte = lit.val ⦄ := by
  unfold same_lower
  have lengths_say : (a.len = lit.len) ↔ a.length = lit.length := by
    constructor
    · intro same
      simpa using congrArg UScalar.val same
    · intro same
      exact UScalar.eq_of_val_eq (by simpa using same)
  exact same_lower_loop_compares a lit _ 0#usize (by simp) (by simpa using lengths_say)

/-- The loop of `has`: from the place `i`, `ok1` says that the place `at` is inside `s`, that `lit`
fits from there, and that the first `i` bytes of `lit` are those of `s` from `at`. -/
theorem has_loop_compares (s : Slice Std.U8) («at» : Std.Usize) (lit : Slice Std.U8) (ok1 : Bool)
    (i : Std.Usize) (inside : i.val ≤ lit.length)
    (ok_says : ok1 = true ↔ («at».val ≤ s.length ∧ lit.length ≤ s.length - «at».val ∧
      lit.val.take i.val = (s.val.drop «at».val).take i.val)) :
    has_loop s «at» lit ok1 i ⦃ r => r = true ↔ («at».val ≤ s.length ∧ lit.val <+: s.val.drop «at».val) ⦄ := by
  unfold has_loop
  apply loop.spec_decr_nat (fun (q : Bool × Std.Usize) => lit.length - q.2.val)
    (fun (q : Bool × Std.Usize) => q.2.val ≤ lit.length ∧
      (q.1 = true ↔ («at».val ≤ s.length ∧ lit.length ≤ s.length - «at».val ∧
        lit.val.take q.2.val = (s.val.drop «at».val).take q.2.val)))
  · rintro ⟨ok1, i⟩ ⟨inside, ok_says⟩
    simp only at inside ok_says ⊢
    unfold has_loop.body
    have s_len : s.val.length = s.length := rfl
    have lit_len : lit.val.length = lit.length := rfl
    by_cases below : i.val < lit.length
    · have below' : i < Slice.len lit := by scalar_tac
      by_cases still : ok1 = true
      · simp only [still, below', ite_true]
        obtain ⟨at_in, fits, same_prefix⟩ := ok_says.mp still
        have in_drop : i.val < (s.val.drop «at».val).length := by
          simp only [List.length_drop]; omega
        step as ⟨ j, is_j ⟩
        step as ⟨ x, is_x ⟩
        step as ⟨ y, is_y ⟩
        step as ⟨ next, is_next ⟩
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [is_next, equal_prefixes_grow lit.val _ i.val (by omega) in_drop]
        simp only [List.getElem_drop]
        have : j.val = «at».val + i.val := is_j
        have x' : x = s.val[«at».val + i.val]'(by omega) := by
          simp [is_x, this]
        have y' : y = lit.val[i.val]'(by omega) := by simp [is_y]
        simp [at_in, fits, same_prefix, x', y', eq_comm]
      · simp only [still]
        refine (WP.spec_ok _).mpr ?_
        show false = true ↔ _
        constructor
        · intro h; exact absurd h (by simp)
        · rintro ⟨at_in, begins⟩
          have fits : lit.length ≤ s.length - «at».val := by
            have := begins.length_le
            simp only [List.length_drop] at this
            omega
          have same_prefix : lit.val.take i.val = (s.val.drop «at».val).take i.val := by
            rw [List.prefix_iff_eq_take] at begins
            rw [begins, List.take_take]
            congr 1
            omega
          exact absurd (ok_says.mpr ⟨at_in, fits, same_prefix⟩) still
    · have below' : ¬ i < Slice.len lit := by scalar_tac
      simp only [below', ite_false, ite_self]
      refine (WP.spec_ok _).mpr ?_
      have at_end : i.val = lit.length := by scalar_tac
      show ok1 = true ↔ _
      rw [at_end, ← lit_len, List.take_length] at ok_says
      rw [ok_says, List.prefix_iff_eq_take]
      constructor
      · rintro ⟨a, _, c⟩
        exact ⟨a, by rw [lit_len]; exact c⟩
      · rintro ⟨a, c⟩
        refine ⟨a, ?_, by rw [lit_len] at c; exact c⟩
        have := (List.prefix_iff_eq_take.mpr (by rw [lit_len] at c; exact c)).length_le
        simp only [List.length_drop] at this
        omega
  · exact ⟨inside, ok_says⟩

/-- **`has`** answers `true` exactly when the place `at` is inside `s` and `lit` is the beginning of
`s` from there. -/
@[step] theorem has_is_the_beginning_from (s : Slice Std.U8) («at» : Std.Usize) (lit : Slice Std.U8) :
    has s «at» lit ⦃ r => r = true ↔ («at».val ≤ s.length ∧ lit.val <+: s.val.drop «at».val) ⦄ := by
  unfold has
  have s_len : (Slice.len s).val = s.length := Slice.len_val s
  have lit_len : (Slice.len lit).val = lit.length := Slice.len_val lit
  by_cases at_in : «at».val ≤ s.length
  · have at_in' : «at» ≤ Slice.len s := by scalar_tac
    simp only [at_in', ite_true]
    step as ⟨ i2, is_i2 ⟩
    apply has_loop_compares
    · simp
    · constructor
      · intro h
        have h' : i2 ≥ lit.len := by simpa using h
        exact ⟨at_in, by scalar_tac, by simp⟩
      · rintro ⟨_, f, _⟩
        simp only [decide_eq_true_eq]
        scalar_tac
  · have at_in' : ¬ «at» ≤ Slice.len s := by scalar_tac
    simp only [at_in', ite_false]
    have := has_loop_compares s «at» lit false 0#usize (by simp) (by simp [at_in])
    simpa [at_in] using this

/-- **`at_is`** answers `true` exactly when the byte at the place `at` is `b`. -/
@[step] theorem at_is_the_byte (s : Slice Std.U8) («at» : Std.Usize) (b : Std.U8) :
    at_is s «at» b ⦃ r => r = true ↔ s.val[«at».val]? = some b ⦄ := by
  unfold at_is
  have s_len : (Slice.len s).val = s.length := Slice.len_val s
  by_cases at_in : «at».val < s.length
  · have at_in' : «at» < Slice.len s := by scalar_tac
    simp only [at_in', ite_true]
    step as ⟨ x, is_x ⟩
    simp [List.getElem?_eq_getElem (show «at».val < s.val.length from at_in), is_x]
  · have at_in' : ¬ «at» < Slice.len s := by scalar_tac
    simp only [at_in', ite_false]
    refine (WP.spec_ok _).mpr ?_
    have : s.val[«at».val]? = none := List.getElem?_eq_none (by
      have : s.val.length = s.length := rfl
      omega)
    simp [this]

end AuthCore
