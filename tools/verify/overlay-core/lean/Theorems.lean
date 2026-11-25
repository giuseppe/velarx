-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/overlay-core.  The statements are in
-- OverlayCore/Spec.lean, the proofs in the other files of OverlayCore/ (the ones named Claims...,
-- which use the files before them).
-- ../../run ends on this file: it fails unless every line `#proved T` below prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean
-- and the library functions the crate has no model of (the run prints none for this crate).
--
-- Read before this file: OverlayCore/Spec.lean.
import Proved
import OverlayCore.ClaimsOfExamples

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean checks the type of each
-- line below, so Theorems.lean and Spec.lean suffice.
example : OverlayCore.TheFunctionsAlwaysReturn :=
  OverlayCore.the_functions_always_return
#proved OverlayCore.the_functions_always_return
example : OverlayCore.NoOverlayNameGetsThrough :=
  OverlayCore.no_overlay_name_gets_through
#proved OverlayCore.no_overlay_name_gets_through
example : OverlayCore.TheNamesOfLayersAreKept :=
  OverlayCore.the_names_of_layers_are_kept
#proved OverlayCore.the_names_of_layers_are_kept
example : OverlayCore.TheNamesOfRealLayersAreKept :=
  OverlayCore.the_names_of_real_layers_are_kept
#proved OverlayCore.the_names_of_real_layers_are_kept
example : OverlayCore.WhatIsRefusedExactly :=
  OverlayCore.what_is_refused_exactly
#proved OverlayCore.what_is_refused_exactly
example : OverlayCore.WhatIsOverlayAndWhatIsLabelExactly :=
  OverlayCore.what_is_overlay_and_what_is_label_exactly
#proved OverlayCore.what_is_overlay_and_what_is_label_exactly
example : OverlayCore.DevicesFitExactly :=
  OverlayCore.devices_fit_exactly
#proved OverlayCore.devices_fit_exactly
example : OverlayCore.TheNumbersComeBack :=
  OverlayCore.the_numbers_come_back
#proved OverlayCore.the_numbers_come_back
example : OverlayCore.EveryNumberIsOneDevice :=
  OverlayCore.every_number_is_one_device
#proved OverlayCore.every_number_is_one_device
example : OverlayCore.OnlyDeviceZeroIsNumberZero :=
  OverlayCore.only_device_zero_is_number_zero
#proved OverlayCore.only_device_zero_is_number_zero
example : OverlayCore.TheWhiteoutIsACharacterDeviceZero :=
  OverlayCore.the_whiteout_is_a_character_device_zero
#proved OverlayCore.the_whiteout_is_a_character_device_zero
example : OverlayCore.WorkedExamples :=
  OverlayCore.worked_examples
#proved OverlayCore.worked_examples
