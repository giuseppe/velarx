-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the claims ProvedTest.lean proves, or fails to,
-- as the Spec.lean of a crate writes them.  ./run builds it before it
-- reads ProvedTest.lean.
--
-- Why it is needed: `#proved` takes only a claim declared in a module
-- `….Spec`, and `#all_claims_proved` lists the claims of one; a test of
-- them needs such a module.
--
-- Read before this file: ../Proved.lean.
import Proved

namespace ProvedTest

/-- A claim. -/
def Claim : Prop := 1 + 1 = 2

/-- A claim written as an `abbrev`: it is a claim all the same. -/
abbrev Short : Prop := 2 + 2 = 4

/-- What the claims would assume: marked, it is not a claim, and nothing
needs to prove it. -/
@[not_a_claim] def Assumption : Prop := 3 + 3 = 6

end ProvedTest
