-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `tail` and `join` make: `tail a from` is the bytes of `a` from the
-- place `from` on, and `join a b` is the bytes of `a` and then those of `b`.  Both copy byte by
-- byte into a new vector, and the copy needs room: the vector it makes must fit in a `usize`
-- (`join` is only called with names that do: see `Fits` in Spec.lean).
-- Why it is needed: `endpoints` builds the name, the addresses of the registry and of the mirrors
-- and the host and the path of every endpoint with them.
-- Read before this file: Spec.lean.
-- Notation: `l.drop n` is `l` without its first `n` elements; `l ++ l'` is `l` and then `l'`.
import EndpointCore.Spec

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

/-- The loop of `tail`: from the place `i`, it pushes the bytes of `a` from `i` on after those of
`out`, which has room for them. -/
theorem tail_loop_copies (a : Slice Std.U8) (out : alloc.vec.Vec Std.U8) (i : Std.Usize)
    (room : out.length + (a.length - i.val) ≤ Std.Usize.max) :
    tail_loop a out i ⦃ r => r.val = out.val ++ a.val.drop i.val ⦄ := by
  unfold tail_loop
  apply loop.spec_decr_nat (fun (q : alloc.vec.Vec Std.U8 × Std.Usize) => a.length - q.2.val)
    (fun (q : alloc.vec.Vec Std.U8 × Std.Usize) =>
      q.1.val ++ a.val.drop q.2.val = out.val ++ a.val.drop i.val ∧
      out.length + (a.length - i.val) ≤ Std.Usize.max)
  · rintro ⟨copied, i'⟩ ⟨same_total, total_fits⟩
    simp only at same_total total_fits ⊢
    unfold tail_loop.body
    have a_length : a.val.length = a.length := rfl
    by_cases below : i'.val < a.length
    · have below' : i' < Slice.len a := by scalar_tac
      simp only [below', ite_true]
      have lengths := congrArg List.length same_total
      simp only [List.length_append, List.length_drop] at lengths
      have room : copied.val.length < Std.Usize.max := by
        have : copied.length = copied.val.length := rfl
        have : out.length = out.val.length := rfl
        omega
      step as ⟨ x, is_x ⟩
      step as ⟨ copied1, is_copied1 ⟩
      step as ⟨ next, is_next ⟩
      refine ⟨?_, total_fits, by scalar_tac⟩
      rw [is_copied1, is_next, ← same_total, List.append_assoc, is_x]
      congr 1
      rw [List.drop_eq_getElem_cons below]
      rfl
    · have below' : ¬ i' < Slice.len a := by scalar_tac
      simp only [below', ite_false]
      refine (WP.spec_ok _).mpr ?_
      rw [List.drop_of_length_le (by omega)] at same_total
      simpa using same_total
  · exact ⟨rfl, room⟩

/-- **`tail`** makes a vector of the bytes of `a` from the place `from` on. -/
theorem tail_is_the_end (a : Slice Std.U8) (start : Std.Usize) :
    tail a start ⦃ r => r.val = a.val.drop start.val ⦄ := by
  unfold tail
  have := tail_loop_copies a (alloc.vec.Vec.new Std.U8) start
    (by simp [alloc.vec.Vec.new]; scalar_tac)
  simpa using this

/-- The loop of `join`: from the place `i`, it pushes the bytes of `b` from `i` on after those of
`out`, which has room for them. -/
theorem join_loop_copies (b : Slice Std.U8) (out : alloc.vec.Vec Std.U8) (i : Std.Usize)
    (room : out.length + (b.length - i.val) ≤ Std.Usize.max) :
    join_loop b out i ⦃ r => r.val = out.val ++ b.val.drop i.val ⦄ := by
  unfold join_loop
  apply loop.spec_decr_nat (fun (q : alloc.vec.Vec Std.U8 × Std.Usize) => b.length - q.2.val)
    (fun (q : alloc.vec.Vec Std.U8 × Std.Usize) =>
      q.1.val ++ b.val.drop q.2.val = out.val ++ b.val.drop i.val ∧
      out.length + (b.length - i.val) ≤ Std.Usize.max)
  · rintro ⟨copied, i'⟩ ⟨same_total, total_fits⟩
    simp only at same_total total_fits ⊢
    unfold join_loop.body
    have b_length : b.val.length = b.length := rfl
    by_cases below : i'.val < b.length
    · have below' : i' < Slice.len b := by scalar_tac
      simp only [below', ite_true]
      have lengths := congrArg List.length same_total
      simp only [List.length_append, List.length_drop] at lengths
      have room : copied.val.length < Std.Usize.max := by
        have : copied.length = copied.val.length := rfl
        have : out.length = out.val.length := rfl
        omega
      step as ⟨ x, is_x ⟩
      step as ⟨ copied1, is_copied1 ⟩
      step as ⟨ next, is_next ⟩
      refine ⟨?_, total_fits, by scalar_tac⟩
      rw [is_copied1, is_next, ← same_total, List.append_assoc, is_x]
      congr 1
      rw [List.drop_eq_getElem_cons below]
      rfl
    · have below' : ¬ i' < Slice.len b := by scalar_tac
      simp only [below', ite_false]
      refine (WP.spec_ok _).mpr ?_
      rw [List.drop_of_length_le (by omega)] at same_total
      simpa using same_total
  · exact ⟨rfl, room⟩

/-- **`join`** makes a vector of the bytes of `a` and then those of `b`, when they fit in a
`usize`. -/
theorem join_is_the_two (a b : Slice Std.U8) (fits : a.length + b.length ≤ Std.Usize.max) :
    join a b ⦃ r => r.val = a.val ++ b.val ⦄ := by
  unfold join
  step with tail_is_the_end as ⟨ copy, is_copy ⟩
  have := join_loop_copies b copy 0#usize (by scalar_tac)
  simpa [is_copy] using this

end EndpointCore
