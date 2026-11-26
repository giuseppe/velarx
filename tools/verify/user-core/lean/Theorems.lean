-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/user-core.  The statements are in
-- UserCore/Spec.lean; the proofs are in the other files of UserCore/, from Claims.lean.
-- ../../run ends on this file: it fails unless every line `#proved T` below prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean
-- and the library functions the crate has no model of (there are none).
--
-- Read before this file: UserCore/Spec.lean.
import Proved
import UserCore.Claims

example : UserCore.ResolveAlwaysReturns := UserCore.resolve_always_returns
example : UserCore.AnIdIsTheNumberWritten := UserCore.parse_id_spec
example : UserCore.ANumericUserKeepsItsId := UserCore.a_numeric_user_keeps_its_id
example : UserCore.ANamedUserIsAnEntryOfTheFile := UserCore.a_named_user_is_an_entry_of_the_file
example : UserCore.TheGroupsAreIdsOnceAndBounded := UserCore.the_groups_are_ids_once_and_bounded
example : UserCore.WhereAGroupComesFrom := UserCore.where_a_group_comes_from
example : UserCore.TheRefusalsOfTheUserString := UserCore.the_refusals_of_the_user_string
example : UserCore.TheEmptyUserIsZero := UserCore.the_empty_user_is_zero

#proved UserCore.resolve_always_returns
#proved UserCore.parse_id_spec
#proved UserCore.a_numeric_user_keeps_its_id
#proved UserCore.a_named_user_is_an_entry_of_the_file
#proved UserCore.the_groups_are_ids_once_and_bounded
#proved UserCore.where_a_group_comes_from
#proved UserCore.the_refusals_of_the_user_string
#proved UserCore.the_empty_user_is_zero
