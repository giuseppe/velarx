-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: nothing.  crates/auth-core needs no model of a function of the Rust
-- standard library, so nothing is trusted here; ../../run only wants the file to exist, because
-- Aeneas writes a template of the functions the derived traits of the types call (`Debug`,
-- `Clone`, `PartialEq`), which no proof uses.
module
public import Aeneas
