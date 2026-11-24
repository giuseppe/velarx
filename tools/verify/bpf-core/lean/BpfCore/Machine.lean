-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that on a 64-bit machine the largest `usize` is `2^64 - 1`.
--
-- Why it is needed: the claims of Spec.lean are for tables smaller than `2^32` entries on a 64-bit
-- machine (`OnA64BitMachine`); the proofs use this to see that no `usize` overflows.
--
-- Read before this file: Spec.lean.
import BpfCore.Spec

open Aeneas Aeneas.Std Result velarx_bpf_core

namespace BpfCore

/-- On a 64-bit machine the largest `usize` is `2^64 - 1`. -/
theorem usize_max_is (on64 : OnA64BitMachine) : Usize.max = 2 ^ 64 - 1 := by
  unfold OnA64BitMachine at on64
  simp [Usize.max, Usize.numBits, on64]

end BpfCore
