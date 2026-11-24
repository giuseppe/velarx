-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `der::element` and `der::sequence_items` answer, and the loop of the
-- latter, which reads the elements of a sequence one by one.
-- Why it is needed: to show that the items fill the sequence exactly, the loop keeps in `ItemsRun`
-- the elements read so far (`ElementsRun`), each beginning where the one before it ends; a refusal
-- ends the loop at its next turn.
-- Read before this file: Der.lean and Spec.lean (`ElementsFill`).
-- Notation: `loop.spec_decr_nat` proves that a loop returns because a number goes down at each turn
-- and a fact (the invariant) is kept by each turn.
import SigparseCore.Der
import SigparseCore.Spans
open Aeneas Aeneas.Std Result velarx_sigparse_core
namespace SigparseCore

/-- The first element of the data: `element` is `element_in` over all of it. -/
theorem element_reads (data : Slice Std.U8) :
    der.element data ⦃ r =>
      (∀ tag c, r = core.result.Result.Ok (tag, c) →
        data.val[0]? = some tag ∧
        DerContent data.val 0 data.val.length = some (c.off.val, c.len.val)) ∧
      (∀ e, r = core.result.Result.Err e → DerContent data.val 0 data.val.length = none) ⦄ := by
  unfold der.element
  have := element_in_reads data 0#usize (Slice.len data) (by simp) (by simp [Slice.len])
  simpa using this

/-- One more element at the end of a run of elements. -/
theorem run_one_more (bytes : List Std.U8) (stop : Nat) (start middle : Nat) (items : List Span)
    (item : Span) (run : ElementsRun bytes stop start middle items)
    (next : DerContent bytes middle stop = some (item.off.val, item.len.val)) :
    ElementsRun bytes stop start (item.off.val + item.len.val) (items ++ [item]) := by
  induction items generalizing start with
  | nil =>
    simp only [ElementsRun] at run
    subst run
    exact ⟨next, rfl⟩
  | cons first rest ih =>
    exact ⟨run.1, ih _ run.2⟩

/-- What the loop of `sequence_items` knows at each turn: the items it has are the elements that run
from the start of the content to `at1`, they are no more than the bytes they take (each takes at
least two), and `at1` is not past the end of the content. -/
def ItemsRun (data : Slice Std.U8) (start stop : Nat) (items : alloc.vec.Vec Span)
    (at1 : Std.Usize) : Prop :=
  start ≤ at1.val ∧ at1.val ≤ stop ∧ items.val.length ≤ at1.val - start ∧
  ElementsRun data.val stop start at1.val items.val

/-- The loop of `sequence_items` returns, and when it ends with no refusal, the items it holds are
the elements that fill the content (`ElementsFill`).  One turn reads the element at `at1` inside the
content: it is an item and the next turn starts after it, or it is refused and the loop ends. -/
theorem sequence_items_loop_fills (data : Slice Std.U8) (start len : Std.Usize)
    (items : alloc.vec.Vec Span) (at1 : Std.Usize) (fail1 : Option der.DerError)
    (content_inside : start.val + len.val ≤ data.val.length)
    (run : ItemsRun data start.val (start.val + len.val) items at1) :
    der.sequence_items_loop data start len items at1 fail1 ⦃ r =>
      r.2 = none → ElementsFill data.val start.val (start.val + len.val) r.1.val ⦄ := by
  unfold der.sequence_items_loop
  -- the loop is over when the content is used up or a refusal is held: each turn does one of the
  -- two, the second after the one that holds the refusal
  apply loop.spec_decr_nat
    (fun q => 2 * ((start.val + len.val) - q.2.1.val) + (if q.2.2.isNone then 1 else 0))
    (fun q => ItemsRun data start.val (start.val + len.val) q.1 q.2.1)
  · rintro ⟨items, at1, fail1⟩ run
    simp only at run ⊢
    obtain ⟨from_start, before_end, few, run⟩ := run
    unfold der.sequence_items_loop.body
    dsimp only
    split
    · rename_i unrefused
      have := data.property
      step with span_end_is_the_sum as ⟨ stop, hstop ⟩
      split
      · rename_i below
        have below : at1.val < stop.val := by scalar_tac
        step with element_in_reads as ⟨ r, accepted, refused ⟩
        cases r with
        | Ok found =>
          obtain ⟨tag, item⟩ := found
          obtain ⟨_, content⟩ := accepted tag item rfl
          obtain ⟨after_header, within⟩ := der_content_is_inside _ _ _ _ _ content
          simp only
          step as ⟨ items1, hitems1 ⟩
          step with span_end_is_the_sum as ⟨ after, hafter ⟩
          have next_item : ElementsRun data.val (start.val + len.val) start.val after.val
              (items.val ++ [item]) := by
            rw [hafter]
            refine run_one_more _ _ _ _ _ item run ?_
            rw [← hstop]
            exact content
          refine ⟨⟨by omega, by omega, ?_, by rw [hitems1]; exact next_item⟩, by omega⟩
          rw [hitems1]
          simp only [List.length_append, List.length_singleton]
          omega
        | Err e =>
          simp only [WP.spec_ok]
          refine ⟨⟨from_start, before_end, few, run⟩, ?_⟩
          have : fail1 = none := by cases fail1 <;> simp_all [core.option.Option.is_none]
          simp [this]
      · rename_i not_below
        -- the content is used up
        have at_end : at1.val = start.val + len.val := by scalar_tac
        simp only [WP.spec_ok]
        intro _
        rw [at_end] at run
        exact run
    · rename_i refused
      simp only [WP.spec_ok]
      intro none_refused
      simp_all [core.option.Option.is_none]
  · have := data.property
    exact run

/-- `sequence_items` returns, and when it accepts, the data begins with a sequence (tag 0x30) with a
definite length, and the items are the elements that fill its content. -/
theorem sequence_items_reads (data : Slice Std.U8) :
    der.sequence_items data ⦃ r =>
      ∀ items, r = core.result.Result.Ok items →
        ∃ content : Span, data.val[0]? = some 48#u8 ∧
          DerContent data.val 0 data.val.length = some (content.off.val, content.len.val) ∧
          ElementsFill data.val content.off.val (content.off.val + content.len.val) items.val ⦄
            := by
  unfold der.sequence_items
  step with element_reads as ⟨ r, accepted, refused ⟩
  cases r with
  | Ok found =>
    obtain ⟨tag, content⟩ := found
    obtain ⟨first, whole⟩ := accepted tag content rfl
    obtain ⟨_, within⟩ := der_content_is_inside _ _ _ _ _ whole
    step as ⟨ cf, hcf ⟩
    rw [hcf]
    change (if (tag != 48#u8) = true then _ else _) ⦃ _ ⦄
    by_cases is_sequence : tag = 48#u8
    · subst is_sequence
      have same : (48#u8 != 48#u8) = false := by decide
      simp only [same, Bool.false_eq_true, ↓reduceIte]
      step with sequence_items_loop_fills as ⟨ r, filled ⟩
      · exact ⟨le_refl _, by omega, by simp, rfl⟩
      cases filled with
      | none =>
        simp only [WP.spec_ok, core.result.Result.Ok.injEq]
        rintro items rfl
        exact ⟨content, first, whole, by simpa using ‹_ = none → _› rfl⟩
      | some e =>
        simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true]
    · have : (tag != 48#u8) = true := by simpa using is_sequence
      simp only [this, ↓reduceIte, WP.spec_ok, reduceCtorEq, false_implies, implies_true]
  | Err e =>
    step as ⟨ cf, hcf ⟩
    rw [hcf]
    simp [core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, WP.spec_ok]

end SigparseCore
