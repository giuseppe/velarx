-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of the last claim of Spec.lean, `TheWorkedExamples` (numbers of the
--   tests of the crate), and of `TheFunctionsAlwaysReturn`.
-- Why it is needed: the examples show that the exact claims give what a reader expects, and that a function that
--   refuses everything, or takes everything, does not pass; `TheFunctionsAlwaysReturn` reads off the exact claims.
-- Read before this file: Spec.lean, ClaimsOfTheReading.lean, ClaimsOfTheFilter.lean, ClaimsOfTheSeen.lean,
--   ClaimsOfTheNode.lean.
-- Notation: `simp [f]` unfolds `f` and computes what is fixed numbers; `step*` runs the lines of a function that
--   are left, proving that none overflows.
import RecvCore.ClaimsOfTheNode
open Aeneas Aeneas.Std Result velarx_recv_core
namespace RecvCore

/-- A size that `full_ok_is` says is taken, is taken. -/
theorem full_ok_accepts (bytes : Std.Usize) (hashes : Std.U8)
    (inside : bytes.val ≠ 0 ∧ bytes.val % 8 = 0 ∧ bytes.val ≤ 4194304 ∧
      1 ≤ hashes.val ∧ hashes.val ≤ 16) : full_ok bytes hashes ⦃ b => b = true ⦄ :=
  WP.spec_mono (full_ok_is bytes hashes) (fun _ verdict => verdict.mpr inside)

/-- A size that `full_ok_is` says is not taken, is refused. -/
theorem full_ok_refuses (bytes : Std.Usize) (hashes : Std.U8)
    (outside : ¬ (bytes.val ≠ 0 ∧ bytes.val % 8 = 0 ∧ bytes.val ≤ 4194304 ∧
      1 ≤ hashes.val ∧ hashes.val ≤ 16)) : full_ok bytes hashes ⦃ b => b = false ⦄ := by
  refine WP.spec_mono (full_ok_is bytes hashes) ?_
  intro b verdict
  cases b
  · rfl
  · exact absurd (verdict.mp rfl) outside

/-- A size that `delta_ok_is` says is taken, is taken. -/
theorem delta_ok_accepts (bytes : Std.Usize)
    (inside : bytes.val ≠ 0 ∧ bytes.val % 8 = 0 ∧ bytes.val / 8 ≤ 8192) :
    delta_ok bytes ⦃ b => b = true ⦄ :=
  WP.spec_mono (delta_ok_is bytes) (fun _ verdict => verdict.mpr inside)

/-- A size that `delta_ok_is` says is not taken, is refused. -/
theorem delta_ok_refuses (bytes : Std.Usize)
    (outside : ¬ (bytes.val ≠ 0 ∧ bytes.val % 8 = 0 ∧ bytes.val / 8 ≤ 8192)) :
    delta_ok bytes ⦃ b => b = false ⦄ := by
  refine WP.spec_mono (delta_ok_is bytes) ?_
  intro b verdict
  cases b
  · rfl
  · exact absurd (verdict.mp rfl) outside

set_option linter.unusedTactic false in
/-- Proof of `TheWorkedExamples`: the status bytes and the sizes are read off the exact claims, and the
chunks and the filter's messages are computed from the code with the numbers of the examples. -/
theorem the_worked_examples : TheWorkedExamples := by
  refine ⟨⟨?_, ?_, ?_, ?_, ?_, ?_⟩, ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩, ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_⟩, ⟨?_, ?_, ?_, ?_, ?_, ?_⟩⟩
  all_goals first
    | (simp [status, ABSENT, HERE, NO_ROOM, FAILED]; done)
    | (simp [Reading.take]; done)
    | (simp [Reading.take, room] <;> step*; done)
    | (simp [Seen.delta, Seen.added, Seen.says, Seen.behind, Seen.full, Behind]; done)
    | (apply full_ok_accepts <;> simp; done)
    | (apply full_ok_refuses; simp; done)
    | (apply delta_ok_accepts <;> simp; done)
    | (apply delta_ok_refuses; simp; done)

/-- Proof of `WhatAnItemIsTakenExactly`: `item` is `len != 0` and `len <= max`. -/
theorem what_an_item_is_taken_exactly : WhatAnItemIsTakenExactly := by
  intro len max
  unfold item
  split_ifs with nonzero
  · refine (WP.spec_ok _).mpr ?_
    simp_all [UScalar.eq_equiv, UScalar.le_equiv, bne_iff_ne]
  · refine (WP.spec_ok _).mpr ?_
    simp_all [UScalar.eq_equiv, bne_iff_ne]

/-- Proof of `TheFunctionsAlwaysReturn`: each exact claim says that its function returns; the rest are
a field read or a constant. -/
theorem the_functions_always_return : TheFunctionsAlwaysReturn := by
  refine ⟨fun b => WP.spec_mono (status_is b) (fun _ _ => trivial),
    fun b => WP.spec_mono (turn_is b) (fun _ _ => trivial),
    fun asked mi mp => WP.spec_mono (new_is asked mi mp) (fun _ _ => trivial),
    fun r => WP.spec_mono (claim_is r) (fun _ _ => trivial),
    fun r => WP.spec_mono (end_is r) (fun _ _ => trivial),
    fun r len size => WP.spec_mono (take_is r len size) (fun _ _ => trivial),
    fun payload len mp => WP.spec_mono (room_is payload len mp) (fun _ _ => trivial),
    fun len max => WP.spec_mono (what_an_item_is_taken_exactly len max) (fun _ _ => trivial),
    fun r => (WP.spec_ok _).mpr trivial, fun r => (WP.spec_ok _).mpr trivial,
    fun s => (WP.spec_ok _).mpr trivial,
    fun text max => WP.spec_mono (full_text_ok_is text max) (fun _ _ => trivial),
    fun bytes hashes => WP.spec_mono (full_ok_is bytes hashes) (fun _ _ => trivial),
    fun bytes => WP.spec_mono (delta_ok_is bytes) (fun _ _ => trivial),
    (WP.spec_ok _).mpr trivial,
    fun s e v held => WP.spec_mono (full_is s e v held) (fun _ _ => trivial),
    fun s e upto held => WP.spec_mono (delta_is s e upto held) (fun _ _ => trivial),
    fun s base upto => WP.spec_mono (added_is s base upto) (fun _ _ => trivial),
    fun s believed contains => WP.spec_mono (says_is s believed contains) (fun _ _ => trivial),
    fun s => WP.spec_mono (behind_is s) (fun _ _ => trivial)⟩

end RecvCore
