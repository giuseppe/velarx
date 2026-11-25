-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about what `decide` answers for a
-- container that is privileged or not, and of the claim that no-new-privileges passes through.
-- Why it is needed: Theorems.lean ties each claim to its proof.
-- Read before this file: Spec.lean.
-- Notation: `rw [decide_answers, WP.spec_ok]` replaces `decide r` by its answer, so the claim is
-- about `answer r`; `cases x` splits on the values of an option; `simp [f]` computes with `f`.
import ConfineCore.WhatDecideAnswers

open Aeneas Aeneas.Std Result
open velarx_confine_core hiding decide

namespace ConfineCore

/-- `decide` returns: it has no loop, no division and no index, only choices on the options. -/
theorem decide_always_returns : ∀ r : Request, decideRequest r ⦃ _ => True ⦄ := by
  intro r
  rw [decide_answers, WP.spec_ok]
  trivial

/-- Not privileged: the device rule that denies everything is first. -/
theorem not_privileged_denies_all_devices_first : NotPrivilegedDeniesAllDevicesFirst := by
  intro r not_privileged
  rw [decide_answers, WP.spec_ok]
  simp [answer, not_privileged]

/-- Not privileged: the filter is the one asked for (the default one when none is named), and
none only when `unconfined` is. -/
theorem not_privileged_has_a_filter_unless_unconfined :
    NotPrivilegedHasAFilterUnlessUnconfined := by
  intro r not_privileged
  rw [decide_answers, WP.spec_ok]
  rcases r with ⟨privileged, seccomp, unmask_all, unmask_some, host_sysfs, nnp⟩
  simp only at not_privileged
  subst not_privileged
  cases seccomp <;> simp [answer, filterOf]

/-- Not privileged: the two lists are what the unmask options say, in each of their three cases. -/
theorem not_privileged_keeps_the_default_paths : NotPrivilegedKeepsTheDefaultPaths := by
  intro r not_privileged
  rw [decide_answers, WP.spec_ok]
  rcases r with ⟨privileged, seccomp, unmask_all, unmask_some, host_sysfs, nnp⟩
  simp only at not_privileged
  subst not_privileged
  cases unmask_all <;> cases unmask_some <;> simp [answer, pathsOf, PathsKept]

/-- Not privileged: `/sys` is read-only. -/
theorem not_privileged_has_sys_readonly : NotPrivilegedHasSysReadOnly := by
  intro r not_privileged
  rw [decide_answers, WP.spec_ok]
  simp [answer, not_privileged]

/-- Not privileged: `/sys/kernel` is masked when `/sys` is the host's, and only then; the unmask
options are not looked at. -/
theorem the_host_sys_kernel_is_masked : TheHostSysKernelIsMasked := by
  intro r not_privileged
  rw [decide_answers, WP.spec_ok]
  simp [answer, not_privileged]

/-- Privileged: each part is what the privileged branch of the code puts there. -/
theorem privileged_turns_off_exactly_these : PrivilegedTurnsOffExactlyThese := by
  intro r privileged
  rw [decide_answers, WP.spec_ok]
  rcases r with ⟨privileged', seccomp, unmask_all, unmask_some, host_sysfs, nnp⟩
  simp only at privileged
  subst privileged
  cases seccomp <;> simp [answer, filterOf, pathsOf]

/-- No-new-privileges is copied from the request. -/
theorem no_new_privileges_passes_through : NoNewPrivilegesPassesThrough := by
  intro r
  rw [decide_answers, WP.spec_ok]
  rfl

end ConfineCore
