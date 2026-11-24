-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `same`, `starts_with` and `ends_with` answer: `same a b` is `true`
-- exactly when the two lists of bytes are equal, `starts_with name pfx` exactly when `pfx` is the
-- beginning of `name`, and `ends_with name suffix` exactly when `suffix` is the end of it.
-- Why it is needed: `governs`, `endpoint` and the loop of `endpoints` compare bytes with these
-- three, so every claim goes through them.
-- Read before this file: Spec.lean.
-- Notation: `l1 <+: l2` is "l1 is the beginning of l2" and `l1 <:+ l2` "l1 is the end of l2";
-- `loop.spec_decr_nat` proves that a loop returns because a number goes down at each turn while a
-- fact (the invariant) is kept by each turn; `step as ⟨ x, hx ⟩` runs one line of a Rust function
-- and names its result `x` and what is known of it `hx`.
import EndpointCore.Spec
import EndpointCore.PrefixesOfLists

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

/-- The loop of `same`: from the place `i`, `equal` says that the lists have the same length and
the same first `i` bytes; the loop ends with `true` exactly when the lists are equal. -/
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
      simp only [below', ite_false]
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
theorem same_is_equality (a b : Slice Std.U8) :
    same a b ⦃ r => r = true ↔ a.val = b.val ⦄ := by
  unfold same
  have lengths_say : (a.len = b.len) ↔ a.length = b.length := by
    constructor
    · intro same
      simpa using congrArg UScalar.val same
    · intro same
      exact UScalar.eq_of_val_eq (by simpa using same)
  exact same_loop_compares a b _ 0#usize (by simp) (by simpa using lengths_say)

/-- The loop of `starts_with`: from the place `i`, `yes` says that the prefix fits in the name and
its first `i` bytes are the first `i` bytes of the name; the loop ends with `true` exactly when the
prefix is the beginning of the name. -/
theorem starts_with_loop_compares (ref pfx : Slice Std.U8) (yes : Bool) (i : Std.Usize)
    (inside : i.val ≤ pfx.length)
    (yes_says : yes = true ↔
      (pfx.length ≤ ref.length ∧ pfx.val.take i.val = ref.val.take i.val)) :
    starts_with_loop ref pfx yes i ⦃ r => r = true ↔ pfx.val <+: ref.val ⦄ := by
  unfold starts_with_loop
  apply loop.spec_decr_nat (fun (q : Bool × Std.Usize) => pfx.length - q.2.val)
    (fun (q : Bool × Std.Usize) => q.2.val ≤ pfx.length ∧
      (q.1 = true ↔ (pfx.length ≤ ref.length ∧ pfx.val.take q.2.val = ref.val.take q.2.val)))
  · rintro ⟨yes, i⟩ ⟨inside, yes_says⟩
    simp only at inside yes_says ⊢
    unfold starts_with_loop.body
    by_cases below : i.val < pfx.length
    · have below' : i < Slice.len pfx := by scalar_tac
      simp only [below', ite_true]
      by_cases still_yes : yes = true
      · simp only [still_yes, ite_true]
        have fits := (yes_says.mp still_yes).1
        have same_prefix := (yes_says.mp still_yes).2
        have in_ref : i.val < ref.val.length := by
          have : ref.val.length = ref.length := rfl
          omega
        step as ⟨ x, is_x ⟩
        step as ⟨ y, is_y ⟩
        step as ⟨ next, is_next ⟩
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [is_next, equal_prefixes_grow pfx.val ref.val i.val below in_ref, is_x, is_y]
        simp [fits, same_prefix, eq_comm]
      · simp only [still_yes]
        refine (WP.spec_ok _).mpr ?_
        show false = true ↔ pfx.val <+: ref.val
        constructor
        · intro now_yes
          exact absurd now_yes (by simp)
        · intro begins
          have fits : pfx.length ≤ ref.length := by
            have := begins.length_le
            exact this
          have same_prefix : pfx.val.take i.val = ref.val.take i.val := by
            have : pfx.val.length = pfx.length := rfl
            rw [List.prefix_iff_eq_take] at begins
            rw [begins, List.take_take]
            congr 1
            omega
          exact absurd (yes_says.mpr ⟨fits, same_prefix⟩) still_yes
    · have below' : ¬ i < Slice.len pfx := by scalar_tac
      simp only [below', ite_false]
      refine (WP.spec_ok _).mpr ?_
      show yes = true ↔ pfx.val <+: ref.val
      have at_end : i.val = pfx.length := by scalar_tac
      rw [at_end, List.take_length] at yes_says
      rw [yes_says, List.prefix_iff_eq_take]
      constructor
      · rintro ⟨_, same_bytes⟩
        exact same_bytes
      · intro same_bytes
        refine ⟨?_, same_bytes⟩
        have := (List.prefix_iff_eq_take.mpr same_bytes).length_le
        exact this
  · exact ⟨inside, yes_says⟩

/-- **`starts_with`** answers `true` exactly when the prefix is the beginning of the name. -/
theorem starts_with_is_the_beginning (ref pfx : Slice Std.U8) :
    starts_with ref pfx ⦃ r => r = true ↔ pfx.val <+: ref.val ⦄ := by
  unfold starts_with
  exact starts_with_loop_compares ref pfx _ 0#usize (by simp) (by simp [Slice.length])

/-- The loop of `ends_with`: from the place `i`, `yes` says that the suffix fits in the name and its
first `i` bytes are the bytes of the end of the name from the place `name.len - suffix.len`; the
loop ends with `true` exactly when the suffix is the end of the name. -/
theorem ends_with_loop_compares (ref suffix : Slice Std.U8) (yes : Bool) (i : Std.Usize)
    (inside : i.val ≤ suffix.length)
    (yes_says : yes = true ↔ (suffix.length ≤ ref.length ∧
      suffix.val.take i.val = (ref.val.drop (ref.length - suffix.length)).take i.val)) :
    ends_with_loop ref suffix yes i ⦃ r => r = true ↔ suffix.val <:+ ref.val ⦄ := by
  unfold ends_with_loop
  apply loop.spec_decr_nat (fun (q : Bool × Std.Usize) => suffix.length - q.2.val)
    (fun (q : Bool × Std.Usize) => q.2.val ≤ suffix.length ∧
      (q.1 = true ↔ (suffix.length ≤ ref.length ∧
        suffix.val.take q.2.val = (ref.val.drop (ref.length - suffix.length)).take q.2.val)))
  · rintro ⟨yes, i⟩ ⟨inside, yes_says⟩
    simp only at inside yes_says ⊢
    unfold ends_with_loop.body
    have ref_length : ref.val.length = ref.length := rfl
    have suffix_length : suffix.val.length = suffix.length := rfl
    by_cases below : i.val < suffix.length
    · have below' : i < Slice.len suffix := by scalar_tac
      simp only [below', ite_true]
      by_cases still_yes : yes = true
      · simp only [still_yes, ite_true]
        have fits := (yes_says.mp still_yes).1
        have same_prefix := (yes_says.mp still_yes).2
        have in_end : i.val < (ref.val.drop (ref.length - suffix.length)).length := by
          simp only [List.length_drop]
          omega
        step as ⟨ i4, is_i4 ⟩
        step as ⟨ i5, is_i5 ⟩
        step as ⟨ x, is_x ⟩
        step as ⟨ y, is_y ⟩
        step as ⟨ next, is_next ⟩
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [is_next, equal_prefixes_grow suffix.val _ i.val below in_end, is_x, is_y]
        simp only [List.getElem_drop]
        have ref_len : ref.len.val = ref.length := Slice.len_val ref
        have suffix_len : suffix.len.val = suffix.length := Slice.len_val suffix
        have place : ref.length - suffix.length + i.val = i5.val := by omega
        simp [fits, same_prefix, place]
        exact eq_comm
      · simp only [still_yes]
        refine (WP.spec_ok _).mpr ?_
        show false = true ↔ suffix.val <:+ ref.val
        constructor
        · intro now_yes
          exact absurd now_yes (by simp)
        · intro ends
          have fits : suffix.length ≤ ref.length := ends.length_le
          have same_prefix : suffix.val.take i.val =
              (ref.val.drop (ref.length - suffix.length)).take i.val := by
            rw [List.suffix_iff_eq_drop] at ends
            rw [← ends]
          exact absurd (yes_says.mpr ⟨fits, same_prefix⟩) still_yes
    · have below' : ¬ i < Slice.len suffix := by scalar_tac
      simp only [below', ite_false]
      refine (WP.spec_ok _).mpr ?_
      show yes = true ↔ suffix.val <:+ ref.val
      have at_end : i.val = suffix.length := by scalar_tac
      rw [at_end, List.take_length] at yes_says
      rw [yes_says, List.suffix_iff_eq_drop]
      have whole : suffix.length ≤ ref.length →
          (ref.val.drop (ref.length - suffix.length)).take suffix.length =
            ref.val.drop (ref.length - suffix.length) := by
        intro fits
        apply List.take_of_length_le
        simp only [List.length_drop]
        omega
      constructor
      · rintro ⟨fits, same_bytes⟩
        rw [whole fits] at same_bytes
        exact same_bytes
      · intro same_bytes
        have fits : suffix.length ≤ ref.length := (List.suffix_iff_eq_drop.mpr same_bytes).length_le
        refine ⟨fits, ?_⟩
        rw [whole fits]
        exact same_bytes
  · exact ⟨inside, yes_says⟩

/-- **`ends_with`** answers `true` exactly when the suffix is the end of the name. -/
theorem ends_with_is_the_end (ref suffix : Slice Std.U8) :
    ends_with ref suffix ⦃ r => r = true ↔ suffix.val <:+ ref.val ⦄ := by
  unfold ends_with
  have lengths_say : (Slice.len suffix ≤ Slice.len ref) ↔ suffix.length ≤ ref.length := by
    simp [Slice.length]
  exact ends_with_loop_compares ref suffix _ 0#usize (by simp) (by simp [lengths_say])

end EndpointCore
