-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that reading a vector as a slice (`deref`, what Rust does when it passes
-- `&v` where `&[u8]` is wanted) keeps the same bytes.
-- Why it is needed: the crate keeps names, prefixes and locations in vectors and compares and
-- copies them as slices, so each proof has to see that the bytes did not change on the way.
-- Read before this file: nothing.
-- Notation: `v.val` is the list of the bytes inside a vector or a slice.
import Aeneas

open Aeneas Aeneas.Std

namespace EndpointCore

/-- A vector read as a slice has the bytes of the vector. -/
@[simp] theorem deref_keeps_the_bytes {α : Type} (v : alloc.vec.Vec α) :
    (alloc.vec.Vec.deref v).val = v.val := by
  simp [alloc.vec.Vec.deref]

end EndpointCore
