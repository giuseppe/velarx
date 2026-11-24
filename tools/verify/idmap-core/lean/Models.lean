-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that crates/idmap-core has NO model of a function of the Rust standard
-- library: nothing is written here by hand and nothing is trusted from it.
--
-- Why the file exists: ../../run wants a Models.lean next to the template of the external
-- functions Aeneas writes.  For this crate the template has three functions, all behind the
-- derived `Debug`, `PartialEq` and `Default` of `IdSet` (the library's impls for a pair and for
-- an empty vector).  They are left as axioms nothing is known of, and no claim of Spec.lean
-- speaks of `IdSet`'s `Debug`, `==` or `default`, so no proof rests on them.
--
-- Read before this file: nothing.
module
public import Aeneas
