-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `break_insert`, which adds an entry to a mapping and cuts out of the old
-- entries the ids that the new one takes.  The proof follows the function: `common` finds what the
-- new entry covers of an old one, `push_part` writes a piece of an old entry, the body of the loop
-- cuts one entry into at most three pieces, and the loop goes over the entries.
--
-- Read before this file: Spec.lean, MapsFacts.lean, SplitOn.lean (`PairsOf`).
import IdmapCore.SplitOn
import IdmapCore.ValidMeansFunction

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- `fits` is true exactly for an entry whose container ids and parent ids end at `2^32` at most. -/
theorem fits_is_ends_in_32_bits (m : Map) : fits m ⦃ b => b = true ↔ EndsIn32Bits m ⦄ := by
  unfold fits EndsIn32Bits
  have hc := core.convert.num.FromU64U32.from_val_eq m.container_id
  have hp := core.convert.num.FromU64U32.from_val_eq m.parent_id
  have hs := core.convert.num.FromU64U32.from_val_eq m.size
  simp only [Std.lift, Std.bind_ok]
  step as ⟨ i2, is_i2 ⟩
  rw [id_limit_is_the_largest_u32]
  simp only [Std.bind_ok]
  step as ⟨ i4, is_i4 ⟩
  split
  · rename_i first
    have first := (UScalar.le_equiv i2 i4).mp first
    step as ⟨ i7, is_i7 ⟩
    step as ⟨ i8, is_i8 ⟩
    have : (decide (i7 ≤ i8) = true) ↔ i7.val ≤ i8.val := by simp [UScalar.le_equiv]
    rw [this]
    omega
  · rename_i last
    refine (WP.spec_ok _).mpr ?_
    have := (UScalar.le_equiv i2 i4).not.mp last
    simp only [Bool.false_eq_true, false_iff]
    omega

/-- `common` gives the offsets, from the first id of the old entry, of the ids that are in the
range `[start, start + len)` and in `[pstart, pstart + n)`: the answer `(lo, hi)` is the offsets
`lo` to `hi - 1` (none if `lo = hi`). -/
theorem common_is_the_ids_in_both (start len pstart n : U64) (fit1 : start.val + len.val < 2 ^ 64)
    (fit2 : pstart.val + n.val < 2 ^ 64) :
    common start len pstart n ⦃ r => r.1.val ≤ r.2.val ∧ r.2.val ≤ n.val ∧
      ∀ o, (o < n.val ∧ start.val ≤ pstart.val + o ∧ pstart.val + o < start.val + len.val) ↔
        (r.1.val ≤ o ∧ o < r.2.val) ⦄ := by
  unfold common
  -- the two `if`s that choose the larger start and the smaller end
  split <;> rename_i first <;> simp only [Std.bind_ok] <;>
    step as ⟨ i, is_i ⟩ <;> step as ⟨ i1, is_i1 ⟩ <;> split <;> rename_i second <;>
    simp only [Std.bind_ok] <;> split
  all_goals simp only [gt_iff_lt, UScalar.lt_equiv] at *
  -- the range is not empty: the offsets are the two differences; or it is: `(0, 0)`
  all_goals first
    | (step as ⟨ i2, is_i2 ⟩
       step as ⟨ i3, is_i3 ⟩
       refine ⟨by omega, by omega, fun o => by omega⟩)
    | refine (WP.spec_ok _).mpr ⟨by simp, by simp, fun o => by simp; omega⟩

/-- `push_part` adds to `out` the ids of the entry `p` from offset `start` up to (not including)
offset `stop`, as one entry (nothing if `start ≥ stop`), when `p` ends in time. -/
@[local step]
theorem push_part_adds_the_ids_between (out : alloc.vec.Vec Map) (p : Map) (start stop : U64)
    (ends : EndsIn32Bits p) (inside : stop.val ≤ p.size.val)
    (room : out.val.length < Usize.max) :
    push_part out p start stop ⦃ r => (∀ x y, Maps r.val x y ↔ Maps out.val x y ∨
        PairsOf (p.container_id.val + start.val) (p.parent_id.val + start.val)
          (stop.val - start.val) x y) ∧ r.val.length ≤ out.val.length + 1 ⦄ := by
  unfold push_part
  split
  · rename_i some
    have some := (UScalar.lt_equiv start stop).mp some
    have hc := core.convert.num.FromU64U32.from_val_eq p.container_id
    have hp := core.convert.num.FromU64U32.from_val_eq p.parent_id
    simp only [Std.lift, Std.bind_ok]
    unfold EndsIn32Bits at ends
    have size_bound := p.size.hBounds
    simp [UScalarTy.numBits] at size_bound
    step as ⟨ i1, is_i1 ⟩
    step as ⟨ i4, is_i4 ⟩
    step as ⟨ i6, is_i6 ⟩
    have cast1 : (UScalar.cast UScalarTy.U32 i1).val = i1.val := by
      rw [UScalar.cast_val_eq]
      simp
      omega
    have cast4 : (UScalar.cast UScalarTy.U32 i4).val = i4.val := by
      rw [UScalar.cast_val_eq]
      simp
      omega
    have cast6 : (UScalar.cast UScalarTy.U32 i6).val = i6.val := by
      rw [UScalar.cast_val_eq]
      simp
      omega
    step as ⟨ r, is_r ⟩
    refine ⟨fun x y => ?_, by simp [is_r]⟩
    rw [is_r, maps_of_append, maps_of_one_entry_are_its_pairs]
    simp only [cast1, cast4, cast6, hc, hp, is_i1, is_i4, is_i6]
  · rename_i none
    have none := (UScalar.lt_equiv start stop).not.mp none
    refine (WP.spec_ok _).mpr ⟨fun x y => ?_, by omega⟩
    have : ¬ PairsOf (p.container_id.val + start.val) (p.parent_id.val + start.val)
        (stop.val - start.val) x y := by
      unfold PairsOf
      omega
    simp [this]

/-- What an entry `e` of the old mapping leaves of its pairs (`x`, `y`) when `ext` is inserted: all
if it does not end in time, else those with no container id and no parent id of `ext`. -/
def Left (ext e : Map) (x y : Nat) : Prop :=
  Maps [e] x y ∧ (EndsIn32Bits e → ¬ InContainers ext x ∧ ¬ InParents ext y)

/-- What the first `j + 1` entries leave is what the first `j` leave, and what the entry `j`
leaves. -/
theorem left_of_one_more_entry (l : List Map) (j : Nat) (inside : j < l.length) (ext : Map)
    (x y : Nat) :
    (∃ e ∈ l.take (j + 1), Left ext e x y) ↔
      (∃ e ∈ l.take j, Left ext e x y) ∨ Left ext l[j] x y := by
  rw [take_one_more l j inside]
  simp only [List.mem_append, List.mem_singleton]
  constructor
  · rintro ⟨e, in_before | rfl, left⟩
    · exact Or.inl ⟨e, in_before, left⟩
    · exact Or.inr left
  · rintro (⟨e, in_before, left⟩ | left)
    · exact ⟨e, Or.inl in_before, left⟩
    · exact ⟨_, Or.inr rfl, left⟩

-- (the heartbeats: the last step of each of the eleven ways the loop body can go is one
-- `omega` over the offsets of the three pieces)
set_option maxHeartbeats 1600000 in
/-- The loop of `break_insert` over the entries: after the first `i` it has written entries that
map what those entries leave (`Left`), and at most three for each. -/
theorem break_insert_goes_over_the_entries (mapping : Slice Map) (ext : Map) (ec eh en : U64)
    (is_ec : ec.val = ext.container_id.val) (is_eh : eh.val = ext.parent_id.val)
    (is_en : en.val = ext.size.val) (out : alloc.vec.Vec Map) (i : Usize)
    (bound : i.val ≤ mapping.val.length) (room : 3 * mapping.val.length + 1 ≤ Usize.max)
    (same : ∀ x y, Maps out.val x y ↔ ∃ e ∈ mapping.val.take i.val, Left ext e x y)
    (size : out.val.length ≤ 3 * i.val) :
    break_insert_loop mapping out ec eh en i ⦃ r =>
      (∀ x y, Maps r.val x y ↔ ∃ e ∈ mapping.val, Left ext e x y) ∧
        r.val.length ≤ 3 * mapping.val.length ⦄ := by
  unfold break_insert_loop
  apply loop.spec_decr_nat (fun q => mapping.val.length - q.2.val)
    (fun q => q.2.val ≤ mapping.val.length ∧
      (∀ x y, Maps q.1.val x y ↔ ∃ e ∈ mapping.val.take q.2.val, Left ext e x y) ∧
      q.1.val.length ≤ 3 * q.2.val)
  · rintro ⟨written, j⟩ ⟨bound, same, size⟩
    simp only at bound same size ⊢
    unfold break_insert_loop.body
    dsimp only
    have same_length : mapping.length = mapping.val.length := rfl
    split
    · rename_i inside
      have inside : j.val < mapping.val.length := by scalar_tac
      step as ⟨ p, is_p ⟩
      have p_is : mapping.val[j.val] = p := is_p.symm
      have in_list : j.val < mapping.val.length := inside
      clear is_p
      step with fits_is_ends_in_32_bits p as ⟨ b, is_fits ⟩
      split
      · -- the entry fits: it is cut around what `ext` covers of it
        rename_i fitting
        have ends_in := is_fits.mp fitting
        have ends := ends_in
        unfold EndsIn32Bits at ends
        have hc := core.convert.num.FromU64U32.from_val_eq p.container_id
        have hp := core.convert.num.FromU64U32.from_val_eq p.parent_id
        have hs := core.convert.num.FromU64U32.from_val_eq p.size
        simp only [Std.lift, Std.bind_ok]
        have size_bound := p.size.hBounds
        simp [UScalarTy.numBits] at size_bound
        have ext_c := ext.container_id.hBounds
        have ext_h := ext.parent_id.hBounds
        have ext_n := ext.size.hBounds
        simp [UScalarTy.numBits] at ext_c ext_h ext_n
        -- what `ext` covers of `p`, by container id (`a`) and by parent id (`b`)
        step with common_is_the_ids_in_both ec en
          (core.convert.num.FromU64U32.from p.container_id)
          (core.convert.num.FromU64U32.from p.size) (by omega) (by omega)
          as ⟨ a0, a_le, a_n, a_iff ⟩
        step with common_is_the_ids_in_both eh en
          (core.convert.num.FromU64U32.from p.parent_id)
          (core.convert.num.FromU64U32.from p.size) (by omega) (by omega)
          as ⟨ b0, b_le, b_n, b_iff ⟩
        simp only at *
        obtain ⟨b_lo, b_hi⟩ := b0
        obtain ⟨a_lo, a_hi⟩ := a0
        -- the code puts first the one of the two ranges that begins first (`a` by container id,
        -- `b` by parent id), then writes up to three pieces: before the first, between, after both
        dsimp only [uncurry]
        repeat' split
        all_goals simp only [uncurry, Std.bind_ok]
        repeat' split
        all_goals try simp only [uncurry, Std.bind_ok]
        all_goals simp only [gt_iff_lt, UScalar.lt_equiv, UScalar.le_equiv] at *
        all_goals (repeat' (first | omega | step as ⟨ r, same_r ⟩ | split))
        -- in every case the pieces written are what `p` leaves of its pairs
        all_goals (
          refine ⟨by omega, fun x y => ?_, by omega, by omega⟩
          rw [same_r, left_of_one_more_entry mapping.val j.val in_list, p_is]
          simp only [*]
          try simp only [or_assoc]
          apply or_congr_right
          have in_c := a_iff (x - p.container_id.val)
          have in_p := b_iff (y - p.parent_id.val)
          simp only [Left, ends_in, true_implies, maps_of_one_entry, InContainers, InParents,
            PairsOf]
          constructor
          · intro piece
            omega
          · intro kept
            omega)
      · -- the entry does not fit: it is copied as it is
        rename_i not_fitting
        have not_ends : ¬ EndsIn32Bits p := fun ends => by
          have := is_fits.mpr ends
          simp_all
        have room_push : written.val.length < Usize.max := by omega
        step as ⟨ written1, is_written1 ⟩
        step as ⟨ j1, is_j1 ⟩
        refine ⟨by omega, fun x y => ?_, by simp [is_written1]; omega, by omega⟩
        rw [is_written1, maps_of_append, same x y, is_j1,
          left_of_one_more_entry mapping.val j.val in_list, p_is]
        simp only [Left, not_ends, false_implies, and_true, maps_of_one_entry]
    · -- every entry is done
      rename_i outside
      have : j.val = mapping.val.length := by scalar_tac
      refine (WP.spec_ok _).mpr ⟨fun x y => ?_, by omega⟩
      rw [same x y, this, List.take_length]
  · exact ⟨bound, same, size⟩

/-- **`break_insert`**: it returns, and its answer maps the inserted entry and what the entries of
`mapping` leave (`Left`). -/
theorem break_insert_maps_the_new_and_what_is_left (mapping : Slice Map) (ext : Map)
    (room : 3 * mapping.val.length + 1 ≤ Usize.max) :
    break_insert mapping ext ⦃ out => ∀ c p, Maps out.val c p ↔ Maps [ext] c p ∨
      ∃ e ∈ mapping.val, Left ext e c p ⦄ := by
  unfold break_insert
  have hc := core.convert.num.FromU64U32.from_val_eq ext.container_id
  have hp := core.convert.num.FromU64U32.from_val_eq ext.parent_id
  have hs := core.convert.num.FromU64U32.from_val_eq ext.size
  simp only [Std.lift, Std.bind_ok]
  step with break_insert_goes_over_the_entries mapping ext
    (core.convert.num.FromU64U32.from ext.container_id)
    (core.convert.num.FromU64U32.from ext.parent_id)
    (core.convert.num.FromU64U32.from ext.size) hc hp hs (alloc.vec.Vec.new Map) 0#usize
    (by simp) room (fun x y => by simp [alloc.vec.Vec.new, maps_of_nothing])
    (by simp [alloc.vec.Vec.new]) as ⟨ out, same, size ⟩
  have room_push : out.val.length < Usize.max := by omega
  step as ⟨ out1, is_out1 ⟩
  rename_i c p
  rw [is_out1, maps_of_append, same c p, or_comm]

/-- A pair of the inserted entry has a container id of it and a parent id of it. -/
theorem a_pair_of_the_entry_has_its_ids (ext : Map) (c p : Nat) (pair : Maps [ext] c p) :
    InContainers ext c ∧ InParents ext p := by
  rw [maps_of_one_entry] at pair
  unfold InContainers InParents at *
  omega

/-- **`break_insert` on a valid mapping**: it returns, and its answer maps no container id to two
parent ids and no parent id from two container ids, whatever the entry `ext`.  Those of `mapping`
that `ext` touches are cut, so that the ids of `ext` are not given twice. -/
theorem break_insert_makes_a_function_both_ways (mapping : Slice Map) (ext : Map)
    (room : 3 * mapping.val.length + 1 ≤ Usize.max) (valid : Valid mapping.val) :
    break_insert mapping ext ⦃ out => FunctionBothWays out.val ⦄ := by
  refine WP.spec_mono (break_insert_maps_the_new_and_what_is_left mapping ext room) ?_
  intro out same
  have function := valid_lists_are_functions_both_ways mapping.val valid
  have ends : ∀ e ∈ mapping.val, EndsIn32Bits e := fun e e_in => by
    have sane := valid.2.1 e e_in
    unfold Sane IdLimit at sane
    unfold EndsIn32Bits
    omega
  have of_old : ∀ e ∈ mapping.val, ∀ c p, Left ext e c p →
      Maps mapping.val c p ∧ ¬ InContainers ext c ∧ ¬ InParents ext p :=
    fun e e_in c p ⟨pair, kept⟩ =>
      ⟨⟨e, e_in, (maps_of_one_entry e c p).mp pair⟩, kept (ends e e_in)⟩
  constructor
  · intro c p q hp hq
    rw [same] at hp hq
    rcases hp with hp | ⟨e, e_in, hp⟩ <;> rcases hq with hq | ⟨f, f_in, hq⟩
    · rw [maps_of_one_entry] at hp hq
      omega
    · exact absurd (a_pair_of_the_entry_has_its_ids ext c p hp).1 (of_old f f_in c q hq).2.1
    · exact absurd (a_pair_of_the_entry_has_its_ids ext c q hq).1 (of_old e e_in c p hp).2.1
    · exact function.1 c p q (of_old e e_in c p hp).1 (of_old f f_in c q hq).1
  · intro c d p hc hd
    rw [same] at hc hd
    rcases hc with hc | ⟨e, e_in, hc⟩ <;> rcases hd with hd | ⟨f, f_in, hd⟩
    · rw [maps_of_one_entry] at hc hd
      unfold InContainers at hc hd
      omega
    · exact absurd (a_pair_of_the_entry_has_its_ids ext c p hc).2 (of_old f f_in d p hd).2.2
    · exact absurd (a_pair_of_the_entry_has_its_ids ext d p hd).2 (of_old e e_in c p hc).2.2
    · exact function.2 c d p (of_old e e_in c p hc).1 (of_old f f_in d p hd).1

end IdmapCore
