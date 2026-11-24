-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `CstrIsThePrefixToTheFirstNul`
-- (Spec.lean): `cstr` of crates/tarsplit-header returns the bytes of the
-- field up to its first NUL, whatever the field is.
--
-- Why it is needed: `number` reads an octal field through `cstr`, and the
-- loop that skips the spaces in front of the number has the same shape as
-- the loop of `cstr`; `scan_spec` below proves both at once, and
-- `take_is_takeWhile` is the one fact about lists it rests on.
--
-- Read before this file: the statement in Spec.lean.
--
-- Notation: `m ⦃ r => P r ⦄` is "`m` returns a result `r` (it does not
-- panic and does not loop for ever) and `P r` holds"; `l.take n` is the
-- first `n` elements of `l`, `l.takeWhile p` the longest beginning of `l`
-- of which every element satisfies `p`.  `step` is the Aeneas tactic that
-- goes through one line of the Rust function with the proved fact about the
-- function it calls (the facts marked `@[step]`); `loop.spec_decr_nat` is
-- Aeneas's rule for a loop: an invariant, kept by the body, and a number
-- that goes down on each turn (so the loop ends).
import TarsplitHeader.Spec

open Aeneas Aeneas.Std Result velarx_tarsplit_header

namespace TarsplitHeader

/-- The `n` first bytes of `l` are the longest beginning of `l` whose bytes
satisfy `p`, when they all do and the next one (if there is one) does not. -/
theorem take_is_takeWhile (p : Std.U8 → Bool) (l : List Std.U8) (n : Nat)
    (before : ∀ b ∈ l.take n, p b = true)
    (stop : ∀ b, l[n]? = some b → p b = false) :
    l.take n = l.takeWhile p := by
  induction l generalizing n with
  | nil => simp
  | cons a t ih =>
    cases n with
    | zero => simp [stop a rfl]
    | succ n =>
      rw [List.take_succ_cons, List.takeWhile_cons_of_pos (before a (by simp))]
      exact congrArg _ (ih n (fun b hb => before b (by simp [hb])) (fun b hb => stop b (by simpa)))

/-- The bytes of `l.takeWhile p` are bytes of `l` and satisfy `p`. -/
theorem mem_takeWhile (p : Std.U8 → Bool) (l : List Std.U8) (b : Std.U8)
    (h : b ∈ l.takeWhile p) : b ∈ l ∧ p b = true := by
  induction l with
  | nil => simp at h
  | cons a t ih =>
    by_cases ha : p a = true
    · rw [List.takeWhile_cons_of_pos ha, List.mem_cons] at h
      rcases h with rfl | h
      · exact ⟨by simp, ha⟩
      · exact ⟨List.mem_cons_of_mem _ (ih h).1, (ih h).2⟩
    · rw [List.takeWhile_cons_of_neg ha] at h
      simp at h

/-- A loop that steps over the bytes of `field` from the first while they
satisfy `p` (the body is written out here, as Aeneas wrote that of `cstr` and
of the loop that skips spaces in `octal`) ends at the first byte that does not,
or at the end of the field. -/
theorem scan_spec (p : Std.U8 → Bool) (field : Slice Std.U8)
    (body : Std.Usize → Result (ControlFlow Std.Usize Std.Usize))
    (is_scan : ∀ x, body x =
      if x < Slice.len field then do
        let b ← Slice.index_usize field x
        if p b then do
          let x1 ← x + 1#usize
          ok (ControlFlow.cont x1)
        else ok (ControlFlow.done x)
      else ok (ControlFlow.done x)) :
    loop body 0#usize ⦃ r => r.val ≤ field.length ∧
      field.val.take r.val = field.val.takeWhile p ⦄ := by
  -- the bytes before the position `x` satisfy `p`; the field that is left shrinks
  apply loop.spec_decr_nat (fun e => field.length - e.val)
    (fun e => e.val ≤ field.length ∧ ∀ b ∈ field.val.take e.val, p b = true)
  · intro x ⟨hx, hz⟩
    rw [is_scan]
    simp only [Slice.len]
    split
    · rename_i inside
      have hlt : x.val < field.val.length := by scalar_tac
      step as ⟨ b, hb ⟩
      split
      · -- a byte that satisfies `p`: on to the next
        rename_i yes
        step as ⟨ x1, hx1 ⟩
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [hx1, List.take_add_one, List.getElem?_eq_getElem hlt]
        intro c hc
        simp only [List.mem_append, Option.toList_some, List.mem_singleton] at hc
        rcases hc with hc | rfl
        · exact hz c hc
        · simpa [hb] using yes
      · -- a byte that does not: stop
        rename_i no
        simp only [Std.WP.spec_ok]
        refine ⟨hx, take_is_takeWhile _ _ _ hz ?_⟩
        intro c hc
        rw [List.getElem?_eq_getElem hlt] at hc
        rw [← Option.some.inj hc, ← hb]
        simpa using no
    · -- the end of the field: stop
      simp only [Std.WP.spec_ok]
      have : field.val.length ≤ x.val := by scalar_tac
      exact ⟨hx, take_is_takeWhile _ _ _ hz (by simp [List.getElem?_eq_none this])⟩
  · simp

/-- The loop of `cstr` stops at the first NUL or at the end of the field. -/
@[step]
theorem cstr_loop_spec (field : Slice Std.U8) :
    cstr_loop field 0#usize ⦃ r => r.val ≤ field.length ∧
      field.val.take r.val = field.val.takeWhile (· != 0#u8) ⦄ :=
  scan_spec _ field _ fun _ => rfl

/-- `cstr` is the prefix to the first NUL, as Spec.lean says: the loop gives
where the first NUL is, the slice is the beginning of the field up to it. -/
theorem cstr_is_the_prefix : CstrIsThePrefixToTheFirstNul := by
  intro field
  unfold cstr
  step as ⟨ stop, hstop, htake ⟩
  step as ⟨ r, hr ⟩
  simpa [hr, List.slice] using htake

end TarsplitHeader
