-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean, from the results of the other files.
-- Why it is needed: Theorems.lean ties each claim to its proof here.
-- Read before this file: Size.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` (or `x.val`) is the number
--    a machine integer is.
import LimitCore.Size
open Aeneas Aeneas.Std Aeneas.Data.Coinductive Result velarx_limit_core
namespace LimitCore

/-- Proof of `TheSharesOfWeight`. -/
theorem shares_of_weight_spec : TheSharesOfWeight := shares_of_weight_post

/-- Proof of `TheCpuMax`. -/
theorem cpu_max_spec : TheCpuMax := cpu_max_post

/-- Proof of `TheNanoCpus`: the three parts. -/
theorem nano_cpus_spec : TheNanoCpus :=
  ⟨nano_cpus_max_post, nano_cpus_of_post, nano_round_trip⟩

/-- Proof of `TheQuotaOfASecond`. -/
theorem quota_per_sec_spec : TheQuotaOfASecond := quota_per_sec_post

/-- Proof of `TheOomScore`. -/
theorem oom_score_spec : TheOomScore := oom_post

/-- Proof of `TheSandboxLimits`: the five parts. -/
theorem sandbox_limits_spec : TheSandboxLimits :=
  ⟨with_overhead_post, sandbox_shares_post, sandbox_swap_post, sandbox_quota_post,
    sandbox_period_post⟩

/-- Proof of `TheCpusetMask`. -/
theorem cpuset_mask_spec : TheCpusetMask := cpuset_mask_post

/-- Proof of `TheSizeIsBelowTheTop`. -/
theorem size_is_below_the_top : TheSizeIsBelowTheTop := parse_size_post

/-- Each function returns: the claim about its answer says so. -/
theorem every_function_returns : EveryFunctionReturns := by
  have t := fun {α : Type} {m : Result α} {P : α → Prop} (h : m ⦃ r => P r ⦄) =>
    WP.spec_mono h (fun _ _ => trivial)
  refine ⟨fun a => t (weight_of_shares_spec a), fun a => t (shares_of_weight_spec a),
    fun a => t (shares_ok_spec a), fun a => t (io_weight_spec.1 a), fun a => t (limit_of_spec a),
    fun a b => t (swap_max_spec a b), fun a b => t (cpu_max_spec a b),
    fun a => t (nano_cpus_spec.1 a), fun a b => t (nano_cpus_spec.2.1 a b),
    fun a b => t (quota_per_sec_spec a b), fun a => t (oom_score_spec a),
    fun a b => t (sandbox_limits_spec.1 a b), fun a b => t (sandbox_limits_spec.2.1 a b),
    fun a b c => t (sandbox_limits_spec.2.2.1 a b c),
    fun a b c d => t (sandbox_limits_spec.2.2.2.1 a b c d),
    fun a b => t (sandbox_limits_spec.2.2.2.2 a b),
    fun a b h => t (cpuset_mask_spec a b h), fun a h => t (size_is_below_the_top a h)⟩

end LimitCore
