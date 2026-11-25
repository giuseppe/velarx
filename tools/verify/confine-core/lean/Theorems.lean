-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/confine-core.  The statements are in
-- ConfineCore/Spec.lean, the proofs in ConfineCore/ClaimsOf*.lean.
-- ../../run ends on this file: it fails unless every line `#proved T` below prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean
-- and the library functions the crate has no model of (the run prints none for this crate).
--
-- Read before this file: ConfineCore/Spec.lean.
import Proved
import ConfineCore.ClaimsOfTheDecision
import ConfineCore.ClaimsOfIndependence
import ConfineCore.ClaimsOfTheCri

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean checks the type of each
-- line below, so Theorems.lean and Spec.lean suffice.
example : ConfineCore.DecideAndFromCriAlwaysReturn :=
  ConfineCore.decide_and_from_cri_always_return
#proved ConfineCore.decide_and_from_cri_always_return
example : ConfineCore.NotPrivilegedDeniesAllDevicesFirst :=
  ConfineCore.not_privileged_denies_all_devices_first
#proved ConfineCore.not_privileged_denies_all_devices_first
example : ConfineCore.NotPrivilegedHasAFilterUnlessUnconfined :=
  ConfineCore.not_privileged_has_a_filter_unless_unconfined
#proved ConfineCore.not_privileged_has_a_filter_unless_unconfined
example : ConfineCore.NotPrivilegedKeepsTheDefaultPaths :=
  ConfineCore.not_privileged_keeps_the_default_paths
#proved ConfineCore.not_privileged_keeps_the_default_paths
example : ConfineCore.NotPrivilegedHasSysReadOnly :=
  ConfineCore.not_privileged_has_sys_readonly
#proved ConfineCore.not_privileged_has_sys_readonly
example : ConfineCore.TheHostSysKernelIsMasked :=
  ConfineCore.the_host_sys_kernel_is_masked
#proved ConfineCore.the_host_sys_kernel_is_masked
example : ConfineCore.PrivilegedTurnsOffExactlyThese :=
  ConfineCore.privileged_turns_off_exactly_these
#proved ConfineCore.privileged_turns_off_exactly_these
example : ConfineCore.TheDevicePartFollowsPrivilegedOnly :=
  ConfineCore.the_device_part_follows_privileged_only
#proved ConfineCore.the_device_part_follows_privileged_only
example : ConfineCore.TheSeccompPartFollowsPrivilegedAndSeccompOnly :=
  ConfineCore.the_seccomp_part_follows_privileged_and_seccomp_only
#proved ConfineCore.the_seccomp_part_follows_privileged_and_seccomp_only
example : ConfineCore.TheMaskedPathsFollowPrivilegedAndUnmaskOnly :=
  ConfineCore.the_masked_paths_follow_privileged_and_unmask_only
#proved ConfineCore.the_masked_paths_follow_privileged_and_unmask_only
example : ConfineCore.TheReadonlyPathsFollowPrivilegedAndUnmaskOnly :=
  ConfineCore.the_readonly_paths_follow_privileged_and_unmask_only
#proved ConfineCore.the_readonly_paths_follow_privileged_and_unmask_only
example : ConfineCore.TheSysReadonlyPartFollowsPrivilegedOnly :=
  ConfineCore.the_sys_readonly_part_follows_privileged_only
#proved ConfineCore.the_sys_readonly_part_follows_privileged_only
example : ConfineCore.TheSysKernelPartFollowsPrivilegedAndHostSysfsOnly :=
  ConfineCore.the_sys_kernel_part_follows_privileged_and_host_sysfs_only
#proved ConfineCore.the_sys_kernel_part_follows_privileged_and_host_sysfs_only
example : ConfineCore.TheNoNewPrivilegesPartFollowsItsOptionOnly :=
  ConfineCore.the_no_new_privileges_part_follows_its_option_only
#proved ConfineCore.the_no_new_privileges_part_follows_its_option_only
example : ConfineCore.NoNewPrivilegesPassesThrough :=
  ConfineCore.no_new_privileges_passes_through
#proved ConfineCore.no_new_privileges_passes_through
example : ConfineCore.NoContextGivesTheEngineDefaults :=
  ConfineCore.no_context_gives_the_engine_defaults
#proved ConfineCore.no_context_gives_the_engine_defaults
example : ConfineCore.APrivilegedContextGivesUnconfinedAndNoPaths :=
  ConfineCore.a_privileged_context_gives_unconfined_and_no_paths
#proved ConfineCore.a_privileged_context_gives_unconfined_and_no_paths
example : ConfineCore.AProfileMeansWhatItNames :=
  ConfineCore.a_profile_means_what_it_names
#proved ConfineCore.a_profile_means_what_it_names
example : ConfineCore.ANamedProfileNeverGivesUnconfined :=
  ConfineCore.a_named_profile_never_gives_unconfined
#proved ConfineCore.a_named_profile_never_gives_unconfined
example : ConfineCore.OwnPathsOnlyWithAContext :=
  ConfineCore.own_paths_only_with_a_context
#proved ConfineCore.own_paths_only_with_a_context
