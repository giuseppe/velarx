-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `split_on`, which cuts the entries of a mapping where the extents of the
-- parent's mapping end, keeps every pair (container id, parent id) its input maps.  The proof
-- follows the three loops of the function: the one that finds the nearest end of an extent, the
-- one that cuts an entry into pieces, and the one that goes over the entries.
--
-- Read before this file: Spec.lean, MapsFacts.lean, Lists.lean.
import IdmapCore.MapsFacts
import IdmapCore.Lists
import IdmapCore.Limits

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- The ids `c`, `c + 1`, ... that go to `h`, `h + 1`, ...: `len` of them, as a pair (container id,
parent id). -/
def PairsOf (c h len x y : Nat) : Prop := c ≤ x ∧ x < c + len ∧ y = h + (x - c)

/-- Cutting the ids of a piece after its first `n` ids gives the first `n` and the rest. -/
theorem pairs_of_a_cut_piece (c h len n x y : Nat) (le : n ≤ len) :
    PairsOf c h len x y ↔ PairsOf c h n x y ∨ PairsOf (c + n) (h + n) (len - n) x y := by
  unfold PairsOf
  omega

/-- A list of one entry maps the pairs of its ids. -/
theorem maps_of_one_entry_are_its_pairs (e : Map) (x y : Nat) :
    Maps [e] x y ↔ PairsOf e.container_id.val e.parent_id.val e.size.val x y := by
  rw [maps_of_one_entry]
  unfold InContainers PairsOf
  rw [and_assoc]

/-- The loop of `split_on` that looks for the nearest end of an extent of `parent` past `h`: what
it finds is at least 1 and at most `n`. -/
theorem split_on_finds_the_nearest_end (parent : Slice Map) (h n : U64) (k : Usize)
    (positive : 0 < n.val) :
    split_on_loop0_loop0_loop0 parent h n k ⦃ r => 0 < r.val ∧ r.val ≤ n.val ⦄ := by
  unfold split_on_loop0_loop0_loop0
  apply loop.spec_decr_nat (fun q => parent.val.length - q.2.val)
    (fun q => 0 < q.1.val ∧ q.1.val ≤ n.val)
  · rintro ⟨near, j⟩ ⟨pos, le⟩
    simp only at pos le ⊢
    unfold split_on_loop0_loop0_loop0.body
    dsimp only
    have same_length : parent.length = parent.val.length := rfl
    split
    · rename_i inside
      have inside : j.val < parent.val.length := by scalar_tac
      step as ⟨ m, is_m ⟩
      have hc := core.convert.num.FromU64U32.from_val_eq m.container_id
      have hs := core.convert.num.FromU64U32.from_val_eq m.size
      simp only [Std.lift, Std.bind_ok]
      step as ⟨ e, is_e ⟩
      refine WP.spec_bind (Pₘ := fun n1 : U64 => 0 < n1.val ∧ n1.val ≤ n.val) ?_ ?_
      · split
        · rename_i past
          step as ⟨ i3, is_i3 ⟩
          split
          · rename_i smaller
            have := (UScalar.lt_equiv i3 near).mp smaller
            refine (WP.spec_ok _).mpr ?_
            have := (UScalar.lt_equiv h e).mp past
            omega
          · rename_i not_smaller
            refine (WP.spec_ok _).mpr ⟨pos, le⟩
        · exact (WP.spec_ok _).mpr ⟨pos, le⟩
      · intro n1 ⟨pos1, le1⟩
        step as ⟨ k1, is_k1 ⟩
        refine ⟨pos1, le1, by omega⟩
    · exact (WP.spec_ok _).mpr ⟨pos, le⟩
  · exact ⟨positive, le_refl _⟩

/-- The loop of `split_on` that cuts one entry, of which `left` ids from `c` (container) and `h`
(parent) are still to write, into pieces.  `base` is what the entries written and the rest
(`PairsOf c h left`) map together; at the end the entries written map exactly `base`, and there
are no more than `out` and the ids that were left. -/
theorem split_on_cuts_an_entry (parent : Slice Map) (out : alloc.vec.Vec Map) (c h left : U64)
    (base : Nat → Nat → Prop) (fits_c : c.val + left.val ≤ 4294967296)
    (fits_h : h.val + left.val ≤ 4294967296) (small : left.val < 4294967296)
    (room : out.val.length + left.val ≤ Usize.max)
    (same : ∀ x y, Maps out.val x y ∨ PairsOf c.val h.val left.val x y ↔ base x y) :
    split_on_loop0_loop0 parent out c h left ⦃ r =>
      (∀ x y, Maps r.val x y ↔ base x y) ∧ r.val.length ≤ out.val.length + left.val ⦄ := by
  unfold split_on_loop0_loop0
  apply loop.spec_decr_nat (fun q => q.2.2.2.val)
    (fun q => q.2.1.val + q.2.2.2.val ≤ 4294967296 ∧ q.2.2.1.val + q.2.2.2.val ≤ 4294967296 ∧
      q.2.2.2.val < 4294967296 ∧ q.1.val.length + q.2.2.2.val ≤ Usize.max ∧
      (∀ x y, Maps q.1.val x y ∨ PairsOf q.2.1.val q.2.2.1.val q.2.2.2.val x y ↔ base x y) ∧
      q.1.val.length + q.2.2.2.val ≤ out.val.length + left.val)
  · rintro ⟨written, cut, here, rest⟩ ⟨fits_c, fits_h, small, room, same, few⟩
    simp only at fits_c fits_h small room same few ⊢
    unfold split_on_loop0_loop0.body
    split
    · rename_i more
      have more : 0 < rest.val := by
        have := (UScalar.lt_equiv 0#u64 rest).mp more
        simpa using this
      step with split_on_finds_the_nearest_end parent here rest 0#usize more as ⟨ n, pos, le ⟩
      have cut_cast : (UScalar.cast UScalarTy.U32 cut).val = cut.val := by
        rw [UScalar.cast_val_eq]
        simp
        omega
      have here_cast : (UScalar.cast UScalarTy.U32 here).val = here.val := by
        rw [UScalar.cast_val_eq]
        simp
        omega
      have n_cast : (UScalar.cast UScalarTy.U32 n).val = n.val := by
        rw [UScalar.cast_val_eq]
        simp
        omega
      simp only [Std.lift, Std.bind_ok]
      have room_push : written.val.length < Usize.max := by omega
      step as ⟨ written1, is_written1 ⟩
      step as ⟨ cut1, is_cut1 ⟩
      step as ⟨ here1, is_here1 ⟩
      step as ⟨ rest1, is_rest1 ⟩
      refine ⟨by omega, by omega, by omega, by simp [is_written1]; omega, ?_,
        by simp [is_written1]; omega, by omega⟩
      intro x y
      rw [is_written1, maps_of_append, maps_of_one_entry_are_its_pairs, ← same x y,
        pairs_of_a_cut_piece cut.val here.val rest.val n.val x y le]
      simp only [cut_cast, here_cast, n_cast, is_cut1, is_here1, is_rest1]
      tauto
    · rename_i none_left
      have : rest.val = 0 := by
        have := (UScalar.lt_equiv 0#u64 rest).not.mp none_left
        simpa using this
      refine (WP.spec_ok _).mpr ⟨fun x y => ?_, by omega⟩
      have nothing : ¬ PairsOf cut.val here.val 0 x y := by
        unfold PairsOf
        omega
      rw [← same x y, this]
      simp [nothing]
  · exact ⟨fits_c, fits_h, small, room, same, le_refl _⟩

/-- `fits` is true only for an entry whose container ids and parent ids end at `2^32` at most (one
past the last id). -/
theorem fits_means_the_ids_end_in_time (m : Map) :
    fits m ⦃ b => b = true →
      m.container_id.val + m.size.val ≤ 4294967296 ∧
        m.parent_id.val + m.size.val ≤ 4294967296 ⦄ := by
  unfold fits
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
    intro is_true
    have := (UScalar.le_equiv i7 i8).mp (by simpa using is_true)
    omega
  · refine (WP.spec_ok _).mpr ?_
    intro is_true
    cases is_true

/-- The loop of `split_on` over the entries: after the first `i` it has written entries that map
what the first `i` entries map (and at most `2^32` entries for each one of them). -/
theorem split_on_goes_over_the_entries (maps parent : Slice Map) (out : alloc.vec.Vec Map)
    (i : Usize) (bound : i.val ≤ maps.val.length) (few : maps.val.length ≤ ExtentLimit)
    (wide : 340 * 4294967296 ≤ Usize.max)
    (same : ∀ x y, Maps out.val x y ↔ Maps (maps.val.take i.val) x y)
    (size : out.val.length ≤ i.val * 4294967296) :
    split_on_loop0 maps parent out i ⦃ r => ∀ x y, Maps r.val x y ↔ Maps maps.val x y ⦄ := by
  unfold split_on_loop0
  apply loop.spec_decr_nat (fun q => maps.val.length - q.2.val)
    (fun q => q.2.val ≤ maps.val.length ∧
      (∀ x y, Maps q.1.val x y ↔ Maps (maps.val.take q.2.val) x y) ∧
      q.1.val.length ≤ q.2.val * 4294967296)
  · rintro ⟨written, j⟩ ⟨bound, same, size⟩
    simp only at bound same size ⊢
    unfold split_on_loop0.body
    dsimp only
    have same_length : maps.length = maps.val.length := rfl
    have extent_limit : ExtentLimit = 340 := rfl
    split
    · rename_i inside
      have inside : j.val < maps.val.length := by scalar_tac
      step as ⟨ m, is_m ⟩
      have m_is : maps.val[j.val] = m := is_m.symm
      have next_pairs : ∀ x y, Maps (maps.val.take (j.val + 1)) x y ↔
          Maps (maps.val.take j.val) x y ∨
            PairsOf m.container_id.val m.parent_id.val m.size.val x y := by
        intro x y
        rw [take_one_more maps.val j.val inside, maps_of_append, m_is,
          maps_of_one_entry_are_its_pairs]
      have size_m := m.size.hBounds
      simp [UScalarTy.numBits] at size_m
      have j_few : j.val < 340 := by omega
      step with fits_means_the_ids_end_in_time m as ⟨ b, is_fits ⟩
      split
      · -- the entry fits: it is cut into pieces
        rename_i fitting
        have ⟨fits_c, fits_h⟩ := is_fits fitting
        have hc := core.convert.num.FromU64U32.from_val_eq m.container_id
        have hp := core.convert.num.FromU64U32.from_val_eq m.parent_id
        have hs := core.convert.num.FromU64U32.from_val_eq m.size
        simp only [Std.lift, Std.bind_ok]
        -- the pieces and the rest of the entry map what the first `j + 1` entries map
        step with split_on_cuts_an_entry parent written
          (core.convert.num.FromU64U32.from m.container_id)
          (core.convert.num.FromU64U32.from m.parent_id)
          (core.convert.num.FromU64U32.from m.size)
          (fun x y => Maps (maps.val.take (j.val + 1)) x y) (by omega) (by omega) (by omega)
          (by omega) (fun x y => by rw [next_pairs x y, same x y, hc, hp, hs])
          as ⟨ out1, same1, size1 ⟩
        step as ⟨ j1, is_j1 ⟩
        refine ⟨by omega, fun x y => ?_, by omega, by omega⟩
        rw [same1 x y, is_j1]
      · -- the entry does not fit: it is copied as it is
        rename_i not_fitting
        have room_push : written.val.length < Usize.max := by omega
        step as ⟨ written1, is_written1 ⟩
        step as ⟨ j1, is_j1 ⟩
        refine ⟨by omega, fun x y => ?_, by simp [is_written1]; omega, by omega⟩
        rw [is_written1, maps_of_append, same x y, maps_of_one_entry_are_its_pairs,
          ← next_pairs x y, is_j1]
    · -- every entry is done
      rename_i outside
      have : j.val = maps.val.length := by scalar_tac
      refine (WP.spec_ok _).mpr (fun x y => ?_)
      rw [same x y, this, List.take_length]
  · exact ⟨bound, same, size⟩

/-- **`split_on`**: it returns, and its answer maps exactly the pairs that its input maps, whatever
the mapping `parent` is. -/
theorem split_on_keeps_the_pairs (maps parent : Slice Map) (few : maps.val.length ≤ ExtentLimit)
    (wide : 340 * 4294967296 ≤ Usize.max) :
    split_on maps parent ⦃ r => ∀ x y, Maps r.val x y ↔ Maps maps.val x y ⦄ :=
  split_on_goes_over_the_entries maps parent (alloc.vec.Vec.new Map) 0#usize (by simp) few wide
    (fun x y => by simp [alloc.vec.Vec.new, maps_of_nothing]) (by simp [alloc.vec.Vec.new])

end IdmapCore
