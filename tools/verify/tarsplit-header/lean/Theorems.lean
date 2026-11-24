-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/tarsplit-header.
-- The statements are in TarsplitHeader/Spec.lean, the proofs in
-- TarsplitHeader/Cstr.lean, TarsplitHeader/Number.lean,
-- TarsplitHeader/Padding.lean, TarsplitHeader/Crc64.lean, TarsplitHeader/Pax.lean,
-- TarsplitHeader/Emit.lean and TarsplitHeader/Order.lean.
-- ../../run ends on this file: it fails unless every line `#proved T` below
-- prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing
-- says that the theorem is the one of the statement or that no `sorry`
-- or new axiom is behind it.  `#proved T` (../../Proved.lean) prints the
-- axioms `T` rests on and fails unless they are the three of Lean and the
-- library functions Models.lean does not define.
--
-- Read before this file: TarsplitHeader/Spec.lean.
import Proved
import TarsplitHeader.Cstr
import TarsplitHeader.Number
import TarsplitHeader.Padding
import TarsplitHeader.Crc64
import TarsplitHeader.Pax
import TarsplitHeader.Emit
import TarsplitHeader.Order

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean
-- checks the type of each line below, so Theorems.lean and Spec.lean suffice.
example : TarsplitHeader.CstrIsThePrefixToTheFirstNul :=
  TarsplitHeader.cstr_is_the_prefix
example : TarsplitHeader.NumberOfBlanksIsZero := TarsplitHeader.number_of_blanks_is_zero
example : TarsplitHeader.NumberOfOctalDigitsIsTheirValue :=
  TarsplitHeader.number_of_octal_digits_is_their_value
example : TarsplitHeader.NumberNeverFails := TarsplitHeader.number_never_fails
example : TarsplitHeader.PaddingFillsTheBlock := TarsplitHeader.padding_fills_the_block
example : TarsplitHeader.Crc64NeverFails := TarsplitHeader.crc64_never_fails
example : TarsplitHeader.DecimalNeverFails := TarsplitHeader.decimal_never_fails
example : TarsplitHeader.PaxTimeNeverFails := TarsplitHeader.pax_time_never_fails
example : TarsplitHeader.PaxRecordStaysInside := TarsplitHeader.pax_record_stays_inside
example : TarsplitHeader.PutOctalFitsOrIsRefused := TarsplitHeader.put_octal_fits_or_is_refused
example : TarsplitHeader.PutOctalWritesTheDigits := TarsplitHeader.put_octal_writes_the_digits
example : TarsplitHeader.PutOctalIsReadBack := TarsplitHeader.put_octal_is_read_back
example : TarsplitHeader.PutDecimalWritesTheDigits := TarsplitHeader.put_decimal_writes_the_digits
example : TarsplitHeader.DecimalOfDigitsIsTheirValue :=
  TarsplitHeader.decimal_of_digits_is_their_value
example : TarsplitHeader.RecordLenCountsItself := TarsplitHeader.record_len_counts_itself
example : TarsplitHeader.PathOrderIsByComponents := TarsplitHeader.path_order_is_by_components
example : TarsplitHeader.ComponentOrderIsStrictTotal :=
  TarsplitHeader.component_order_is_strict_total

#proved TarsplitHeader.cstr_is_the_prefix
#proved TarsplitHeader.number_of_blanks_is_zero
#proved TarsplitHeader.number_of_octal_digits_is_their_value
#proved TarsplitHeader.number_never_fails
#proved TarsplitHeader.padding_fills_the_block
#proved TarsplitHeader.crc64_never_fails
#proved TarsplitHeader.decimal_never_fails
#proved TarsplitHeader.pax_time_never_fails
#proved TarsplitHeader.pax_record_stays_inside
#proved TarsplitHeader.put_octal_fits_or_is_refused
#proved TarsplitHeader.put_octal_writes_the_digits
#proved TarsplitHeader.put_octal_is_read_back
#proved TarsplitHeader.put_decimal_writes_the_digits
#proved TarsplitHeader.decimal_of_digits_is_their_value
#proved TarsplitHeader.record_len_counts_itself
#proved TarsplitHeader.path_order_is_by_components
#proved TarsplitHeader.component_order_is_strict_total
