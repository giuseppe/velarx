-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `PaddingFillsTheBlock` (Spec.lean):
-- `padding` of crates/tarsplit-header returns the bytes that fill the last
-- block of an entry, or `None` when the blocks do not fit in 64 bits, and
-- never panics (so never overflows).
--
-- The argument follows the Rust, two lines:
--   1. `size.checked_next_multiple_of(512)` is the next whole number of
--      blocks, or `None` when it does not fit (Models.lean);
--   2. the `?` leaves with `None` in that case; otherwise the padding is the
--      difference, which cannot underflow, since the next multiple is not
--      below `size`.
-- The rest is arithmetic on numbers, which `omega` does.
--
-- Read before this file: the statement in Spec.lean, and Models.lean (the
-- three functions it models are those of the two lines above).
--
-- Notation: as in Cstr.lean; `n % 512` is the rest of `n` divided by 512.
import TarsplitHeader.Spec

open Aeneas Aeneas.Std Result velarx_tarsplit_header

namespace TarsplitHeader

/-- `padding` fills the last block, as Spec.lean says. -/
theorem padding_fills_the_block : PaddingFillsTheBlock := by
  intro size
  unfold padding
  -- (the block, 512, as a number the arithmetic below can see)
  have hb : BLOCK.val = 512 := by simp [BLOCK]
  step as ⟨ i, hi ⟩
  have hi : i.val = 512 := by scalar_tac
  simp only [core.num.U64.checked_next_multiple_of, core.option.Option.Insts.CoreOpsTry_traitTry.branch,
    core.option.Option.Insts.CoreOpsTry_traitFromResidualOptionNever.from_residual]
  split
  · simp only [Std.bind_ok]
    rename_i fits
    have hv : ∀ n, n ≤ U64.max → (UScalar.mk (BitVec.ofNat UScalarTy.U64.numBits n) : U64).val = n := by
      intro n hn
      simp only [UScalar.val, BitVec.toNat_ofNat]
      scalar_tac
    step as ⟨ k, hk ⟩
    · rw [hv _ (by simpa [hi] using fits.2), hi]
      omega
    · -- (the next multiple fits in 64 bits, so the sum is the multiple itself)
      have limit := fits.2
      have hmax : Std.U64.max = 2 ^ 64 - 1 := by scalar_tac
      rw [hi, hmax] at limit
      rw [hv _ (by simpa [hi] using fits.2), hi] at hk
      omega
  · simp only [Std.bind_ok, Std.WP.spec_ok]
    rename_i nofit
    rw [hi] at nofit
    have hmax : Std.U64.max = 2 ^ 64 - 1 := by scalar_tac
    rw [hmax] at nofit
    omega

end TarsplitHeader
