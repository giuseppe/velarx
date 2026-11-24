-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: a statement of a `Prop` made up outside a Spec,
-- with the name of a claim; ProvedTest.lean checks that `#proved` does
-- not take a proof of it.  ./run builds it before it reads
-- ProvedTest.lean.
--
-- Read before this file: ../Proved.lean.

/-- A claim that says nothing, written in a proof file. -/
def Fake.NoNameAgainstTheMeasure : Prop := True
