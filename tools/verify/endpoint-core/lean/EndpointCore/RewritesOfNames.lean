-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `registered` and `moved` make: `registered` the address where the
-- registry of a block has a name (`RegistryName` of Spec.lean) and `moved` the address of a mirror
-- of the block for the name (`Rewritten` of Spec.lean).  Both copy the name into a new vector, and
-- the copy needs room (`Fits` of Spec.lean).
-- Why it is needed: `endpoints` makes the address of the registry with `registered` and the
-- address of every mirror with `moved`.
-- Read before this file: Spec.lean, ComparingBytes.lean, CopyingBytes.lean, ScanningTheName.lean.
-- Notation: `step as ⟨ x, hx ⟩` runs one line of a Rust function and names its result `x` and what
-- is known of it `hx`; `blocks.val[b]?` is `some` of the block at the place `b`, or `none`.
import EndpointCore.Spec
import EndpointCore.ComparingBytes
import EndpointCore.CopyingBytes
import EndpointCore.ScanningTheName
import EndpointCore.TakeWhileFacts
import EndpointCore.VectorsAreSlices
import EndpointCore.GovernsMeansGoverns

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

/-- **`registered`** makes the address where the registry of the block has the name. -/
theorem registered_is_the_registry_name (blocks : Slice Block) (b : Std.Usize) (ref : Slice Std.U8)
    (block : Block) (is_block : blocks.val[b.val]? = some block)
    (room : ∀ location, block.location = some location →
      location.length + ref.length ≤ Std.Usize.max) :
    registered blocks b ref ⦃ v => v.val = RegistryName block ref.val ⦄ := by
  have inside : b.val < blocks.val.length := (List.getElem?_eq_some_iff.mp is_block).1
  unfold registered
  step as ⟨ blk, is_blk ⟩
  have blk_is : blk = block := by
    have := List.getElem?_eq_getElem inside
    rw [is_block] at this
    simp [is_blk, Option.some.inj this]
  subst blk_is
  unfold RegistryName
  cases is_location : blk.location with
  | none =>
    simp only
    step with tail_is_the_end as ⟨ copy, is_copy ⟩
    simpa using is_copy
  | some location =>
    simp only
    step with starts_with_is_the_beginning as ⟨ begins, is_begins ⟩
    by_cases starts : begins = true
    · simp only [starts, ite_true]
      have begins' : blk.prefix.val <+: ref.val := by simpa using is_begins.mp starts
      have prefix_len : blk.prefix.len.val = blk.prefix.val.length := alloc.vec.Vec.len_val _
      have fits : blk.prefix.val.length ≤ ref.length := begins'.length_le
      step as ⟨ rest, is_rest, rest_length ⟩
      step with join_is_the_two as ⟨ joined, is_joined ⟩
      · have := room location is_location
        have : location.deref.length = location.length := by simp [Slice.length]
        omega
      · simp [begins', is_joined, is_rest, prefix_len]
    · have no_begin : ¬ blk.prefix.val <+: ref.val := by
        intro begins'
        exact starts (is_begins.mpr (by simpa using begins'))
      have not_starts : begins = false := by simpa using starts
      simp only [not_starts, Bool.false_eq_true, ↓reduceIte]
      step with tail_is_the_end as ⟨ copy, is_copy ⟩
      simp [no_begin, is_copy]

/-- **`moved`** makes the address of the mirror number `mirror` of the block for the name: the
location of the mirror in place of the prefix (of the host, up to the first `/`, for a wildcard
prefix). -/
theorem moved_is_the_address_of_the_mirror (blocks : Slice Block) (b mirror : Std.Usize)
    (ref : Slice Std.U8) (block : Block) (m : Mirror) (is_block : blocks.val[b.val]? = some block)
    (is_mirror : block.mirrors.val[mirror.val]? = some m)
    (room : m.location.length + ref.length ≤ Std.Usize.max) :
    moved blocks b mirror ref ⦃ v =>
      v.val = Rewritten block.prefix.val m.location.val ref.val ⦄ := by
  have inside : b.val < blocks.val.length := (List.getElem?_eq_some_iff.mp is_block).1
  have mirror_inside : mirror.val < block.mirrors.val.length :=
    (List.getElem?_eq_some_iff.mp is_mirror).1
  unfold moved
  step as ⟨ blk, is_blk ⟩
  have blk_is : blk = block := by
    have := List.getElem?_eq_getElem inside
    rw [is_block] at this
    simp [is_blk, Option.some.inj this]
  subst blk_is
  step as ⟨ mirror', is_mirror' ⟩
  have mirror_is : m = mirror' := by
    have := List.getElem?_eq_getElem mirror_inside
    rw [is_mirror] at this
    simp [is_mirror', Option.some.inj this]
  subst mirror_is
  step with wildcard_says as ⟨ is_wild, is_wild_says ⟩
  have ref_length : ref.val.length = ref.length := rfl
  by_cases wild : is_wild = true
  · have wild_prefix : IsWildcard blk.prefix.val := by simpa using is_wild_says.mp wild
    simp only [wild, ite_true]
    step with slash_goes_to_the_first as ⟨ i, is_i ⟩
    have target : Rewritten blk.prefix.val m.location.val ref.val =
        m.location.val ++ ref.val.drop i.val := by
      unfold Rewritten
      simp only [wild_prefix, ↓reduceIte]
      rw [drop_while_is_the_rest, is_i]
    rw [target]
    have ref_len : (Slice.len ref).val = ref.length := Slice.len_val ref
    by_cases at_end : i = Slice.len ref
    · simp only [at_end, ite_true]
      step with tail_is_the_end as ⟨ copy, is_copy ⟩
      simp [is_copy]
    · simp only [at_end, ite_false]
      have short : i.val ≤ ref.length := by
        have := take_while_is_not_longer (fun b => decide (b ≠ Slash)) ref.val
        omega
      step as ⟨ rest, is_rest, rest_length ⟩
      step with join_is_the_two as ⟨ joined, is_joined ⟩
      · have : m.location.deref.length = m.location.length := by simp [Slice.length]
        omega
      · simp [is_joined, is_rest]
  · have not_wild_prefix : ¬ IsWildcard blk.prefix.val := by
      intro is_wild_prefix
      exact wild (is_wild_says.mpr (by simpa using is_wild_prefix))
    have not_wild : is_wild = false := by simpa using wild
    simp only [not_wild, Bool.false_eq_true, ↓reduceIte]
    step with starts_with_is_the_beginning as ⟨ begins, is_begins ⟩
    have prefix_len : blk.prefix.len.val = blk.prefix.val.length := alloc.vec.Vec.len_val _
    unfold Rewritten
    simp only [not_wild_prefix, ↓reduceIte]
    by_cases starts : begins = true
    · have begins' : blk.prefix.val <+: ref.val := by simpa using is_begins.mp starts
      simp only [starts, ite_true]
      have fits : blk.prefix.val.length ≤ ref.length := begins'.length_le
      step as ⟨ rest, is_rest, rest_length ⟩
      step with join_is_the_two as ⟨ joined, is_joined ⟩
      · have : m.location.deref.length = m.location.length := by simp [Slice.length]
        omega
      · simp [begins', is_joined, is_rest, prefix_len]
    · have no_begin : ¬ blk.prefix.val <+: ref.val := by
        intro begins'
        exact starts (is_begins.mpr (by simpa using begins'))
      have not_starts : begins = false := by simpa using starts
      simp only [not_starts, Bool.false_eq_true, ↓reduceIte]
      step with tail_is_the_end as ⟨ copy, is_copy ⟩
      simp [no_begin, is_copy]

end EndpointCore
