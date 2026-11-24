-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: where the three scans of the crate stop: `slash` stops at the first `/`
-- of a name (or its end), the first loop of `governs` at the first `/` or `@`, and the second loop
-- of `governs` at the last `:` before that place (or at that place when there is none).
-- Why it is needed: `Located`, `Rewritten` and the wildcard `Governs` of Spec.lean are said with
-- `takeWhile`, `dropWhile` and `HostOf`; these theorems say that the loops compute exactly that.
-- Read before this file: Spec.lean, TakeWhileFacts.lean.
-- Notation: `loop.spec_decr_nat` proves that a loop returns because a number goes down at each
-- turn while a fact (the invariant) is kept by each turn; `step as ⟨ x, hx ⟩` runs one line of a
-- Rust function and names its result `x` and what is known of it `hx`.
import EndpointCore.Spec
import EndpointCore.TakeWhileFacts
import EndpointCore.PrefixesOfLists

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

/-- **`slash`** goes to the first `/` of the name, or to its end: the length of what
`takeWhile` takes before it. -/
theorem slash_goes_to_the_first (ref : Slice Std.U8) :
    slash ref ⦃ r => r.val = (ref.val.takeWhile fun b => b ≠ Slash).length ⦄ := by
  unfold slash slash_loop
  apply loop.spec_decr_nat (fun (i : Std.Usize) => ref.length - i.val)
    (fun (i : Std.Usize) => i.val ≤ ref.length ∧
      ∀ j, (_ : j < i.val) → (_ : j < ref.val.length) → ref.val[j] ≠ Slash)
  · intro i ⟨inside, before⟩
    have same_length : ref.val.length = ref.length := rfl
    have all_before : ∀ j, (_ : j < i.val) → (_ : j < ref.val.length) →
        (decide (ref.val[j] ≠ Slash)) = true := fun j hj hj' => by simpa using before j hj hj'
    unfold slash_loop.body
    by_cases below : i.val < ref.length
    · have below' : i < Slice.len ref := by scalar_tac
      simp only [below', ite_true]
      step as ⟨ x, is_x ⟩
      by_cases is_slash : x = Slash
      · have : ¬ (x != 47#u8) = true := by simp [is_slash, Slash]
        simp only [this]
        refine (WP.spec_ok _).mpr ?_
        refine (take_while_stops_at _ ref.val i.val inside all_before fun _ => ?_).symm
        simp [← is_x, is_slash]
      · have : (x != 47#u8) = true := by simpa [Slash] using is_slash
        simp only [this, ite_true]
        step as ⟨ next, is_next ⟩
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        intro j hj hj'
        by_cases same : j = i.val
        · subst same
          rw [← is_x]
          exact is_slash
        · exact before j (by omega) hj'
    · have below' : ¬ i < Slice.len ref := by scalar_tac
      simp only [below', ite_false]
      refine (WP.spec_ok _).mpr ?_
      have at_end : i.val = ref.length := by scalar_tac
      have same_length : ref.val.length = ref.length := rfl
      refine (take_while_stops_at _ ref.val i.val (by omega) all_before fun outside => ?_).symm
      omega
  · exact ⟨by simp, by simp⟩

/-- The first loop of **`governs`** goes to the first `/` or `@` of the name, or to its end: the
length of what `takeWhile` takes before it. -/
theorem governs_goes_to_the_end_of_the_host (ref : Slice Std.U8) :
    governs_loop0 ref 0#usize ⦃ r =>
      r.val = (ref.val.takeWhile fun b => b ≠ Slash ∧ b ≠ AtSign).length ⦄ := by
  unfold governs_loop0
  apply loop.spec_decr_nat (fun (i : Std.Usize) => ref.length - i.val)
    (fun (i : Std.Usize) => i.val ≤ ref.length ∧
      ∀ j, (_ : j < i.val) → (_ : j < ref.val.length) → ref.val[j] ≠ Slash ∧ ref.val[j] ≠ AtSign)
  · intro i ⟨inside, before⟩
    have same_length : ref.val.length = ref.length := rfl
    have all_before : ∀ j, (_ : j < i.val) → (_ : j < ref.val.length) →
        (decide (ref.val[j] ≠ Slash ∧ ref.val[j] ≠ AtSign)) = true :=
      fun j hj hj' => by simpa using before j hj hj'
    unfold governs_loop0.body
    by_cases below : i.val < ref.length
    · have below' : i < Slice.len ref := by scalar_tac
      simp only [below', ite_true]
      step as ⟨ x, is_x ⟩
      by_cases is_slash : x = Slash
      · have : ¬ (x != 47#u8) = true := by simp [is_slash, Slash]
        simp only [this]
        refine (WP.spec_ok _).mpr ?_
        refine (take_while_stops_at _ ref.val i.val inside all_before fun _ => ?_).symm
        simp [← is_x, is_slash]
      · have not_slash : (x != 47#u8) = true := by simpa [Slash] using is_slash
        simp only [not_slash, ite_true]
        by_cases is_at : x = AtSign
        · have : ¬ (x != 64#u8) = true := by simp [is_at, AtSign]
          simp only [this]
          refine (WP.spec_ok _).mpr ?_
          refine (take_while_stops_at _ ref.val i.val inside all_before fun _ => ?_).symm
          simp [← is_x, is_at]
        · have not_at : (x != 64#u8) = true := by simpa [AtSign] using is_at
          simp only [not_at, ite_true]
          step as ⟨ next, is_next ⟩
          refine ⟨by scalar_tac, ?_, by scalar_tac⟩
          intro j hj hj'
          by_cases same : j = i.val
          · subst same
            rw [← is_x]
            exact ⟨is_slash, is_at⟩
          · exact before j (by omega) hj'
    · have below' : ¬ i < Slice.len ref := by scalar_tac
      simp only [below', ite_false]
      refine (WP.spec_ok _).mpr ?_
      have at_end : i.val = ref.length := by scalar_tac
      refine (take_while_stops_at _ ref.val i.val (by omega) all_before fun outside => ?_).symm
      omega
  · exact ⟨by simp, by simp⟩

/-- The second loop of **`governs`** goes over the first `stop` bytes of the name (the host and its
port) and finds the last `:` among them: its place `r`, so that the bytes before it are the host
and those after it the port, or `stop` itself when there is no `:`. -/
theorem governs_goes_to_the_last_colon (ref : Slice Std.U8) (stop : Std.Usize)
    (inside : stop.val ≤ ref.length) :
    governs_loop1 ref stop stop 0#usize ⦃ r =>
      r.val ≤ stop.val ∧
      ((Colon ∉ ref.val.take stop.val ∧ r = stop) ∨
        (r.val < stop.val ∧ (ref.val.take stop.val)[r.val]? = some Colon ∧
          Colon ∉ (ref.val.take stop.val).drop (r.val + 1))) ⦄ := by
  unfold governs_loop1
  apply loop.spec_decr_nat (fun (q : Std.Usize × Std.Usize) => stop.val - q.2.val)
    (fun (q : Std.Usize × Std.Usize) => q.2.val ≤ stop.val ∧ q.1.val ≤ stop.val ∧
      ((Colon ∉ ref.val.take q.2.val ∧ q.1 = stop) ∨
        (q.1.val < q.2.val ∧ (ref.val.take q.2.val)[q.1.val]? = some Colon ∧
          Colon ∉ (ref.val.take q.2.val).drop (q.1.val + 1))))
  · rintro ⟨port, i⟩ ⟨at_most, port_at_most, seen⟩
    simp only at at_most port_at_most seen ⊢
    unfold governs_loop1.body
    have same_length : ref.val.length = ref.length := rfl
    by_cases below : i.val < stop.val
    · have below' : i < stop := by scalar_tac
      simp only [below', ite_true]
      step as ⟨ x, is_x ⟩
      have grows : ref.val.take (i.val + 1) = ref.val.take i.val ++ [x] := by
        rw [take_one_more ref.val i.val (by omega), is_x]
      by_cases is_colon : x = Colon
      · have : x = 58#u8 := is_colon
        simp only [this, ite_true]
        step as ⟨ next, is_next ⟩
        refine ⟨by scalar_tac, by scalar_tac, Or.inr ⟨by omega, ?_, ?_⟩, by scalar_tac⟩
        · have i_in : i.val ≤ ref.val.length := by omega
          rw [is_next, grows, List.getElem?_append_right (by simp)]
          simp [is_colon, Nat.min_eq_left i_in]
        · rw [is_next, grows]
          simp
      · have : ¬ x = 58#u8 := is_colon
        simp only [this, ite_false]
        step as ⟨ next, is_next ⟩
        refine ⟨by scalar_tac, port_at_most, ?_, by scalar_tac⟩
        rw [is_next, grows]
        rcases seen with ⟨none_yet, at_stop⟩ | ⟨port_before, port_is_colon, none_after⟩
        · left
          refine ⟨?_, at_stop⟩
          simp only [List.mem_append, List.mem_singleton, not_or]
          exact ⟨none_yet, fun same => is_colon same.symm⟩
        · right
          have port_in : port.val < (ref.val.take i.val).length := by
            simp only [List.length_take]
            omega
          refine ⟨by omega, ?_, ?_⟩
          · rw [List.getElem?_append_left port_in]
            exact port_is_colon
          · rw [List.drop_append_of_le_length (by omega)]
            simp only [List.mem_append, List.mem_singleton, not_or]
            exact ⟨none_after, fun same => is_colon same.symm⟩
    · have below' : ¬ i < stop := by scalar_tac
      simp only [below', ite_false]
      refine (WP.spec_ok _).mpr ?_
      have at_end : i.val = stop.val := by scalar_tac
      rw [at_end] at seen
      refine ⟨port_at_most, ?_⟩
      rcases seen with ⟨none_in, is_stop⟩ | ⟨port_before, port_is_colon, none_after⟩
      · exact Or.inl ⟨none_in, is_stop⟩
      · exact Or.inr ⟨by omega, port_is_colon, none_after⟩
  · exact ⟨by simp, by simp, Or.inl ⟨by simp, rfl⟩⟩

end EndpointCore
