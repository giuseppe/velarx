-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the two constants of crates/idmap-core as numbers, `ID_LIMIT` (no mapping
-- may end past this id) and `MAX_EXTENTS` (the most lines of a mapping).  The Rust code writes
-- the first as `u32::MAX as u64`; the proofs need to know it is 4294967295.
--
-- Read before this file: nothing.  Notation: `x.val` is the natural number a machine integer is.
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- `ID_LIMIT` returns, and is 4294967295, the largest 32 bit number. -/
theorem id_limit_is_the_largest_u32 : ID_LIMIT = ok 4294967295#u64 := by
  unfold ID_LIMIT
  rfl

/-- `MAX_EXTENTS` is 340. -/
theorem max_extents_is_340 : MAX_EXTENTS.val = 340 := by
  unfold MAX_EXTENTS
  rfl

end IdmapCore
