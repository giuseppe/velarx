-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of `PathOrderIsByComponents` and
-- `ComponentOrderIsStrictTotal` (Spec.lean): `path_order` of
-- crates/tarsplit-header/src/emit.rs, the order of the paths of a canonical tar,
-- is the comparison of their components, each as bytes, and that comparison is
-- a strict total order.
--
-- Why it is needed: a layer is valid only if its entries are in this order, and
-- the checker, the sort of the walk and the lists of changes all use this one
-- function: if it were not an order (not transitive, say) a sort would give an
-- answer that depends on the algorithm, and two writers of the same layer would
-- not agree.
--
-- The argument has two halves:
--   1. `path_order` skips what the two paths have in common (`path_order_loop_spec`)
--      and then looks at the byte where they differ, with `/` before any other
--      byte.  That is `slashFirst`, a function of two lists written the way the
--      loop reads (`path_order_spec`).
--   2. `slashFirst` is the comparison of the components (`components_compare`),
--      and it is a strict total order, because it is the order of the lists of
--      `rank`s of the bytes, where `rank` puts `/` first (`slashFirst_eq`,
--      `slashFirst_swap`, `slashFirst_trans`).
--
-- Read before this file: the statements in Spec.lean and Number.lean (the shape of
-- a loop proof).
--
-- Notation: as in Number.lean.  `.lt`, `.eq` and `.gt` are the three answers of a
-- comparison; `o.swap` turns `.lt` into `.gt` and the other way round; `o.then p` is
-- `o` unless it is `.eq`, then `p`.
import TarsplitHeader.Spec
open Aeneas Aeneas.Std Result velarx_tarsplit_header
namespace TarsplitHeader

/-- The comparison `path_order` makes, written as a function of the two lists of bytes: the first
byte that differs decides, `/` is before any other byte, and a list that is the beginning of
the other is before it. -/
def slashFirst : List Std.U8 → List Std.U8 → Ordering
  | [], [] => .eq
  | [], _ :: _ => .lt
  | _ :: _, [] => .gt
  | x :: xs, y :: ys =>
    if x = y then slashFirst xs ys
    else if x = 47#u8 then .lt
    else if y = 47#u8 then .gt
    else compareBytes x y

/-- Two bytes compare equal exactly when they are the same byte. -/
theorem compareBytes_eq (x y : Std.U8) : compareBytes x y = .eq ↔ x = y := by
  unfold compareBytes
  rw [compare_eq_iff_eq]
  constructor
  · exact UScalar.eq_of_val_eq
  · rintro rfl; rfl

/-- Whatever follows an answer that is not `.eq` does not matter. -/
theorem then_of_ne (o p : Ordering) (h : o ≠ .eq) : o.then p = o := by
  cases o <;> simp_all [Ordering.then]

/-- The comparison of the components of two paths, each as bytes, is `slashFirst`: the first
place the paths differ decides, and the end of a component (a `/` or the end of the path) is
before any other byte. -/
theorem components_compare (a b : List Std.U8) :
    compareComponents a b = slashFirst a b := by
  induction a generalizing b with
  | nil =>
    cases b with
    | nil => simp [compareComponents, components, pieces, lexCompare, slashFirst]
    | cons y ys =>
      rcases hp : pieces ys with ⟨c, r⟩
      by_cases hy : y = 47#u8
      · simp [compareComponents, components, pieces, lexCompare, slashFirst, hp, hy]
      · simp [compareComponents, components, pieces, lexCompare, slashFirst, hp, hy]
  | cons x xs ih =>
    rcases hpx : pieces xs with ⟨c, r⟩
    cases b with
    | nil =>
      by_cases hx : x = 47#u8
      · simp [compareComponents, components, pieces, lexCompare, slashFirst, hpx, hx]
      · simp [compareComponents, components, pieces, lexCompare, slashFirst, hpx, hx]
    | cons y ys =>
      rcases hpy : pieces ys with ⟨c', r'⟩
      have ihy := ih ys
      simp only [compareComponents, components, hpx, hpy] at ihy
      by_cases hxy : x = y
      · subst hxy
        by_cases hx : x = 47#u8
        · simp [compareComponents, components, pieces, lexCompare, slashFirst, hpx, hpy, hx]
          exact ihy
        · simp [compareComponents, components, pieces, lexCompare, slashFirst, hpx, hpy, hx]
          rw [(compareBytes_eq x x).2 rfl, ← ihy]
          simp [lexCompare, Ordering.then]
      · by_cases hx : x = 47#u8
        · have hy : y ≠ 47#u8 := by rintro rfl; exact hxy hx
          simp [compareComponents, components, pieces, lexCompare, slashFirst, hpx, hpy, hx, hy]
          exact fun h => absurd h.symm hy
        · by_cases hy : y = 47#u8
          · simp [compareComponents, components, pieces, lexCompare, slashFirst, hpx, hpy, hx, hy]
          · simp [compareComponents, components, pieces, lexCompare, slashFirst, hpx, hpy, hx, hy, hxy]
            have hne : compareBytes x y ≠ .eq := fun h => hxy ((compareBytes_eq x y).1 h)
            rw [then_of_ne _ _ hne, then_of_ne _ _ hne]

/-- A byte as the order sees it: `/` is before every other byte. -/
def rank (x : Std.U8) : Nat := if x = 47#u8 then 0 else x.val + 1

/-- Where two paths differ the answer is the comparison of the ranks of the two bytes. -/
theorem slashFirst_cons_ne (x y : Std.U8) (xs ys : List Std.U8) (h : x ≠ y) :
    slashFirst (x :: xs) (y :: ys) = compare (rank x) (rank y) := by
  have vx : x.val ≠ y.val := fun e => h (UScalar.eq_of_val_eq e)
  have v47 : (47#u8).val = 47 := rfl
  simp only [slashFirst, h, ite_false, rank, compareBytes]
  by_cases hx : x = 47#u8
  · have hy : y ≠ 47#u8 := fun e => h (hx.trans e.symm)
    have : y.val ≠ 47 := fun e => hy (UScalar.eq_of_val_eq (by rw [e]; rfl))
    simp [hx, hy]
    exact (compare_lt_iff_lt.2 (by omega)).symm
  · have hx' : x.val ≠ 47 := fun e => hx (UScalar.eq_of_val_eq (by rw [e]; rfl))
    by_cases hy : y = 47#u8
    · simp [hx, hy]
      exact (compare_gt_iff_gt.2 (by omega)).symm
    · simp [hx, hy]
      rcases lt_trichotomy x.val y.val with h | h | h
      · rw [compare_lt_iff_lt.2 h, compare_lt_iff_lt.2 (by omega)]
      · rw [h]; simp
      · rw [compare_gt_iff_gt.2 h, compare_gt_iff_gt.2 (by omega)]

/-- A path is equal to itself. -/
theorem slashFirst_refl (a : List Std.U8) : slashFirst a a = .eq := by
  induction a with
  | nil => rfl
  | cons x xs ih => simp [slashFirst, ih]

/-- Two bytes of the same rank are the same byte. -/
theorem rank_inj (x y : Std.U8) (h : rank x = rank y) : x = y := by
  unfold rank at h
  by_cases hx : x = 47#u8 <;> by_cases hy : y = 47#u8 <;> simp only [hx, hy, ite_true, ite_false] at h
  · rw [hx, hy]
  · omega
  · omega
  · exact UScalar.eq_of_val_eq (by omega)

/-- Paths that compare equal are the same path. -/
theorem slashFirst_eq (a b : List Std.U8) (h : slashFirst a b = .eq) : a = b := by
  induction a generalizing b with
  | nil => cases b <;> simp_all [slashFirst]
  | cons x xs ih =>
    cases b with
    | nil => simp [slashFirst] at h
    | cons y ys =>
      by_cases hxy : x = y
      · subst hxy; simp [slashFirst] at h; rw [ih ys h]
      · rw [slashFirst_cons_ne x y xs ys hxy] at h
        exact absurd (rank_inj x y (compare_eq_iff_eq.1 h)) hxy

/-- Comparing in the other order gives the other answer. -/
theorem slashFirst_swap (a b : List Std.U8) : slashFirst b a = (slashFirst a b).swap := by
  induction a generalizing b with
  | nil => cases b <;> simp [slashFirst]
  | cons x xs ih =>
    cases b with
    | nil => simp [slashFirst]
    | cons y ys =>
      by_cases hxy : x = y
      · subst hxy; simp [slashFirst, ih]
      · rw [slashFirst_cons_ne x y xs ys hxy, slashFirst_cons_ne y x ys xs (Ne.symm hxy)]
        exact (Nat.compare_swap _ _).symm

/-- The order is transitive: before, and before, is before. -/
theorem slashFirst_trans (a b c : List Std.U8) (hab : slashFirst a b = .lt)
    (hbc : slashFirst b c = .lt) : slashFirst a c = .lt := by
  induction a generalizing b c with
  | nil =>
    cases c with
    | nil => cases b <;> simp [slashFirst] at hbc
    | cons z zs => simp [slashFirst]
  | cons x xs ih =>
    cases b with
    | nil => simp [slashFirst] at hab
    | cons y ys =>
      cases c with
      | nil => simp [slashFirst] at hbc
      | cons z zs =>
        by_cases hxy : x = y
        · subst hxy
          by_cases hxz : x = z
          · subst hxz
            simp only [slashFirst, ite_true] at *
            exact ih ys zs hab hbc
          · rw [slashFirst_cons_ne x z xs zs hxz]
            rw [slashFirst_cons_ne x z ys zs hxz] at hbc
            exact hbc
        · rw [slashFirst_cons_ne x y xs ys hxy] at hab
          by_cases hyz : y = z
          · subst hyz
            have hxz : x ≠ y := hxy
            rw [slashFirst_cons_ne x y xs zs hxz]
            exact hab
          · rw [slashFirst_cons_ne y z ys zs hyz] at hbc
            have lt1 := compare_lt_iff_lt.1 hab
            have lt2 := compare_lt_iff_lt.1 hbc
            have hxz : x ≠ z := by
              rintro rfl
              omega
            rw [slashFirst_cons_ne x z xs zs hxz]
            exact compare_lt_iff_lt.2 (by omega)

/-- What two paths have in common at the start does not change the answer. -/
theorem slashFirst_append (p s t : List Std.U8) : slashFirst (p ++ s) (p ++ t) = slashFirst s t := by
  induction p with
  | nil => rfl
  | cons x xs ih => simp [slashFirst, ih]

/-- The loop that skips what two paths have in common ends where one of them ends or where they
differ. -/
theorem path_order_loop_spec (a b : Slice Std.U8) (pos : Std.Usize)
    (same : a.val.take pos.val = b.val.take pos.val) (ha : pos.val ≤ a.length)
    (hb : pos.val ≤ b.length) :
    emit.path_order_loop a b pos ⦃ r => r.val ≤ a.length ∧ r.val ≤ b.length ∧
      a.val.take r.val = b.val.take r.val ∧
      (r.val = a.length ∨ r.val = b.length ∨ a.val[r.val]? ≠ b.val[r.val]?) ⦄ := by
  unfold emit.path_order_loop
  apply loop.spec_decr_nat (fun p => a.length - p.val)
    (fun p => a.val.take p.val = b.val.take p.val ∧ p.val ≤ a.length ∧ p.val ≤ b.length)
  · rintro p ⟨same, ha, hb⟩
    unfold emit.path_order_loop.body
    simp only [Slice.len]
    split
    · rename_i inside_a
      split
      · rename_i inside_b
        step as ⟨ x, hx ⟩
        step as ⟨ y, hy ⟩
        split
        · rename_i equal
          step as ⟨ p1, hp1 ⟩
          have hlta : p.val < a.val.length := by scalar_tac
          have hltb : p.val < b.val.length := by scalar_tac
          refine ⟨?_, by scalar_tac, by scalar_tac, by scalar_tac⟩
          rw [hp1, List.take_add_one, List.take_add_one, same, List.getElem?_eq_getElem hlta,
            List.getElem?_eq_getElem hltb]
          simp only [Option.toList_some, List.append_cancel_left_eq, List.cons.injEq, and_true]
          rw [← hx, ← hy, equal]
        · -- they differ here
          rename_i differ
          simp only [Std.WP.spec_ok]
          have hlta : p.val < a.val.length := by scalar_tac
          have hltb : p.val < b.val.length := by scalar_tac
          refine ⟨ha, hb, same, Or.inr (Or.inr ?_)⟩
          rw [List.getElem?_eq_getElem hlta, List.getElem?_eq_getElem hltb]
          intro h
          exact differ (by rw [hx, hy]; exact Option.some.inj h)
      · simp only [Std.WP.spec_ok]
        refine ⟨ha, hb, same, Or.inr (Or.inl ?_)⟩
        scalar_tac
    · simp only [Std.WP.spec_ok]
      refine ⟨ha, hb, same, Or.inl ?_⟩
      scalar_tac
  · exact ⟨same, ha, hb⟩

/-- `path_order` returns `slashFirst` of the two paths, for any paths (no panic, no index outside
a path). -/
theorem path_order_spec (a b : Slice Std.U8) :
    emit.path_order a b ⦃ r => r = slashFirst a.val b.val ⦄ := by
  unfold emit.path_order
  step with path_order_loop_spec a b 0#usize (by simp) (by simp) (by simp) as
    ⟨ pos, hpa, hpb, hsame, hend ⟩
  -- both paths are the common beginning, then what is left of each
  have split_a := List.take_append_drop pos.val a.val
  have split_b := List.take_append_drop pos.val b.val
  have both : slashFirst a.val b.val = slashFirst (a.val.drop pos.val) (b.val.drop pos.val) := by
    conv_lhs => rw [← split_a, ← split_b, ← hsame]
    exact slashFirst_append _ _ _
  rw [both]
  have la : (a.val.drop pos.val).length = a.length - pos.val := by simp [Slice.length]
  have lb : (b.val.drop pos.val).length = b.length - pos.val := by simp [Slice.length]
  simp only [Slice.len]
  split
  · rename_i at_end
    have da : a.val.drop pos.val = [] := by
      apply List.drop_of_length_le; simp [Slice.length] at hpa ⊢; scalar_tac
    split
    · rename_i also
      have db : b.val.drop pos.val = [] := by
        apply List.drop_of_length_le; scalar_tac
      simp [da, db, slashFirst]
    · rename_i more
      have hlt : pos.val < b.val.length := by scalar_tac
      rw [da, List.drop_eq_getElem_cons hlt]
      simp [slashFirst]
  · rename_i inside
    have hlta : pos.val < a.val.length := by scalar_tac
    split
    · rename_i at_end
      have db : b.val.drop pos.val = [] := by
        apply List.drop_of_length_le; scalar_tac
      rw [db, List.drop_eq_getElem_cons hlta]
      simp [slashFirst]
    · rename_i more
      have hltb : pos.val < b.val.length := by scalar_tac
      rw [List.drop_eq_getElem_cons hlta, List.drop_eq_getElem_cons hltb]
      step as ⟨ x, hx ⟩
      have differ : a.val[pos.val] ≠ b.val[pos.val] := by
        rcases hend with h | h | h
        · scalar_tac
        · scalar_tac
        · intro e
          apply h
          rw [List.getElem?_eq_getElem hlta, List.getElem?_eq_getElem hltb, e]
      simp only [slashFirst, differ, ite_false]
      subst hx
      by_cases h47 : (a.val[pos.val]) = 47#u8
      · simp [h47]
      · simp only [h47, ite_false]
        step as ⟨ y, hy ⟩
        subst hy
        by_cases g47 : (b.val[pos.val]) = 47#u8
        · simp [g47]
        · simp [g47, compareBytes]


/-- `path_order` is the comparison of the components, as Spec.lean says. -/
theorem path_order_is_by_components : PathOrderIsByComponents := by
  intro a b
  have := path_order_spec a b
  refine Std.WP.spec_mono this (fun r h => ?_)
  rw [h, components_compare]

/-- The comparison of components is a strict total order, as Spec.lean says. -/
theorem component_order_is_strict_total : ComponentOrderIsStrictTotal := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro a; rw [components_compare]; exact slashFirst_refl a
  · intro a b h; rw [components_compare] at h; exact slashFirst_eq a b h
  · intro a b; rw [components_compare, components_compare]; exact slashFirst_swap a b
  · intro a b c hab hbc
    rw [components_compare] at *
    exact slashFirst_trans a b c hab hbc

end TarsplitHeader
