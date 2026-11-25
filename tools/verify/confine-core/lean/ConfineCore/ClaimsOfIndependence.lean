-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the seven claims of Spec.lean that each part of the decision
-- follows the options named for it only.
-- Why it is needed: Theorems.lean ties each claim to its proof.
-- Read before this file: Spec.lean.
-- Notation: `rw [decide_answers, WP.spec_ok]` replaces `decide r` by its answer, so each claim
-- is about `answer r` and `answer r'`; `simp [f, h]` computes with `f` and rewrites by the
-- equalities `h` that the claim assumes; `cases x` splits on the values of an option.
import ConfineCore.WhatDecideAnswers

open Aeneas Aeneas.Std Result
open velarx_confine_core hiding decide

namespace ConfineCore

/-- Two requests that agree on `privileged` have the same device rule. -/
theorem the_device_part_follows_privileged_only :
    TheDevicePartFollowsPrivilegedOnly := by
  intro r r' same_privileged
  rw [decide_answers, WP.spec_ok, decide_answers, WP.spec_ok]
  simp [answer, same_privileged]

/-- Two requests that agree on `privileged` and `seccomp` have the same filter. -/
theorem the_seccomp_part_follows_privileged_and_seccomp_only :
    TheSeccompPartFollowsPrivilegedAndSeccompOnly := by
  intro r r' same_privileged same_seccomp
  rw [decide_answers, WP.spec_ok, decide_answers, WP.spec_ok]
  simp [answer, filterOf, same_privileged, same_seccomp]

/-- Two requests that agree on `privileged` and the unmask options have the same masked paths. -/
theorem the_masked_paths_follow_privileged_and_unmask_only :
    TheMaskedPathsFollowPrivilegedAndUnmaskOnly := by
  intro r r' same_privileged same_unmask_all same_unmask_some
  rw [decide_answers, WP.spec_ok, decide_answers, WP.spec_ok]
  simp [answer, pathsOf, same_privileged, same_unmask_all, same_unmask_some]

/-- Two requests that agree on `privileged` and the unmask options have the same read-only paths. -/
theorem the_readonly_paths_follow_privileged_and_unmask_only :
    TheReadonlyPathsFollowPrivilegedAndUnmaskOnly := by
  intro r r' same_privileged same_unmask_all same_unmask_some
  rw [decide_answers, WP.spec_ok, decide_answers, WP.spec_ok]
  simp [answer, pathsOf, same_privileged, same_unmask_all, same_unmask_some]

/-- Two requests that agree on `privileged` have the same `/sys` read-only. -/
theorem the_sys_readonly_part_follows_privileged_only :
    TheSysReadonlyPartFollowsPrivilegedOnly := by
  intro r r' same_privileged
  rw [decide_answers, WP.spec_ok, decide_answers, WP.spec_ok]
  simp [answer, same_privileged]

/-- Two requests that agree on `privileged` and `host_sysfs` have the same mask of `/sys/kernel`. -/
theorem the_sys_kernel_part_follows_privileged_and_host_sysfs_only :
    TheSysKernelPartFollowsPrivilegedAndHostSysfsOnly := by
  intro r r' same_privileged same_host_sysfs
  rw [decide_answers, WP.spec_ok, decide_answers, WP.spec_ok]
  simp [answer, same_privileged, same_host_sysfs]

/-- Two requests that agree on `no_new_privileges` have the same one in the decision. -/
theorem the_no_new_privileges_part_follows_its_option_only :
    TheNoNewPrivilegesPartFollowsItsOptionOnly := by
  intro r r' same_option
  rw [decide_answers, WP.spec_ok, decide_answers, WP.spec_ok]
  simp [answer, same_option]

end ConfineCore
