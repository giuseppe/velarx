-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the small functions that read one field answer: `mirror_mode` and
-- `mirror_insecure` read the mode and the `insecure` flag of a mirror; `serves` says whether a
-- mode serves a request (`Serves` of Spec.lean); and `unverified` says whether the request turned
-- the verification of TLS off.
-- Why it is needed: `mirrored` and `endpoints` read the mirrors and the request with them.
-- Read before this file: Spec.lean.
-- Notation: `blocks.val[b]?` is `some` of the block at the place `b`, or `none`.
import EndpointCore.Spec

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

/-- **`serves`** says whether a mirror of this mode serves a request with or without a digest. -/
theorem serves_says_the_mode_serves (mode : Mode) (has_digest : Bool) :
    serves mode has_digest ⦃ r => r = true ↔ Serves mode has_digest ⦄ := by
  unfold serves
  cases mode <;> simp [Serves]

/-- **`unverified`** says whether the request turned the verification of TLS off. -/
theorem unverified_says_verification_is_off (ask : Ask) :
    unverified ask ⦃ r => r = true ↔ ask.tls_verify = false ⦄ := by
  unfold unverified
  simp

/-- **`mirror_mode`** reads the mode of the mirror number `m` of the block number `b`. -/
theorem mirror_mode_reads_the_mode (blocks : Slice Block) (b m : Std.Usize) (block : Block)
    (mir : Mirror) (is_block : blocks.val[b.val]? = some block)
    (is_mirror : block.mirrors.val[m.val]? = some mir) :
    mirror_mode blocks b m ⦃ r => r = mir.mode ⦄ := by
  have inside : b.val < blocks.val.length := (List.getElem?_eq_some_iff.mp is_block).1
  have mirror_inside : m.val < block.mirrors.val.length :=
    (List.getElem?_eq_some_iff.mp is_mirror).1
  unfold mirror_mode
  step as ⟨ blk, is_blk ⟩
  have blk_is : blk = block := by
    have := List.getElem?_eq_getElem inside
    rw [is_block] at this
    simp [is_blk, Option.some.inj this]
  subst blk_is
  step as ⟨ mir', is_mir' ⟩
  have := List.getElem?_eq_getElem mirror_inside
  rw [is_mirror] at this
  simp [is_mir', Option.some.inj this]

/-- **`mirror_insecure`** reads the `insecure` flag of the mirror number `m` of the block number
`b`. -/
theorem mirror_insecure_reads_the_flag (blocks : Slice Block) (b m : Std.Usize) (block : Block)
    (mir : Mirror) (is_block : blocks.val[b.val]? = some block)
    (is_mirror : block.mirrors.val[m.val]? = some mir) :
    mirror_insecure blocks b m ⦃ r => r = mir.insecure ⦄ := by
  have inside : b.val < blocks.val.length := (List.getElem?_eq_some_iff.mp is_block).1
  have mirror_inside : m.val < block.mirrors.val.length :=
    (List.getElem?_eq_some_iff.mp is_mirror).1
  unfold mirror_insecure
  step as ⟨ blk, is_blk ⟩
  have blk_is : blk = block := by
    have := List.getElem?_eq_getElem inside
    rw [is_block] at this
    simp [is_blk, Option.some.inj this]
  subst blk_is
  step as ⟨ mir', is_mir' ⟩
  have := List.getElem?_eq_getElem mirror_inside
  rw [is_mirror] at this
  simp [is_mir', Option.some.inj this]

end EndpointCore
